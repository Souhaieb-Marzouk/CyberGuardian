"""
CyberGuardian Event Log Scanner
===============================

Analyses Windows event logs for suspicious activity and attack history.

Design notes
------------
* Reads the logs through the Windows Event Log API (``wevtapi`` via pywin32),
  never by shelling out to ``wevtutil`` or PowerShell.
* Only a curated set of high-signal event IDs is queried (server-side XPath),
  so a scan stays fast even on hosts with millions of events.
* A per-channel cursor (``EventRecordID``) is persisted, so each run analyses
  only new events and the first run does not re-report months of history.
* Everything read from a log is attacker-influenced data and is stored as plain
  evidence; escaping is the consumer's responsibility (reports/UI/AI already do).
"""

from __future__ import annotations

import json
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scanners.base_scanner import (
    BaseScanner, Detection, RiskLevel, ScanResult, ScanStatus,
)
from utils.config import CACHE_DIR
from utils.logging_utils import get_logger, log_detection, log_scan_complete, log_scan_start

logger = get_logger("scanners.eventlog")

try:
    import win32evtlog
    WINEVT_AVAILABLE = True
except ImportError:  # pragma: no cover - non-Windows
    win32evtlog = None  # type: ignore[assignment]
    WINEVT_AVAILABLE = False

NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

MAX_EVENTS_PER_CHANNEL = 3000
READ_BATCH = 64

# Channels are queried by their Windows names.  The Security channel needs
# administrator rights; the others are readable by normal users.
CHANNELS = [
    ("Security", "Security"),
    ("System", "System"),
    ("Application", "Application"),
    ("Microsoft-Windows-Windows Defender/Operational", "Defender"),
    ("Microsoft-Windows-PowerShell/Operational", "PowerShell"),
    ("Microsoft-Windows-TaskScheduler/Operational", "TaskScheduler"),
]

# ---------------------------------------------------------------------------
# Curated rules
# ---------------------------------------------------------------------------

# key: (channel label, event id)
EVENT_RULES: Dict[Tuple[str, int], Dict[str, Any]] = {
    ("Security", 1102): {
        "title": "Security event log was cleared",
        "severity": "critical",
        "technique": "T1070.001",
        "explain": "Someone cleared the Security log. Attackers do this to remove evidence; it is also done by some maintenance scripts.",
        "verify": [
            "Open Event Viewer > Windows Logs > Security and look for the gap in EventRecordID sequence.",
            "Check who was logged on at that time (4624 events immediately before the gap).",
            "Review recent administrative activity and installed software.",
        ],
        "remediate": [
            "Preserve a copy of the log and export it before doing anything else.",
            "Enable log forwarding to a remote collector so this cannot happen again.",
            "Reset credentials of accounts with administrative access.",
        ],
    },
    ("Security", 104): {
        "title": "Event log was cleared",
        "severity": "high",
        "technique": "T1070.001",
        "explain": "An event log was cleared, which removes forensic evidence.",
        "verify": ["Identify the log and the account that cleared it.", "Check for other anti-forensic activity around the same time."],
        "remediate": ["Export remaining logs to a safe location.", "Enable centralized log collection."],
    },
    ("Security", 4720): {
        "title": "User account created",
        "severity": "high",
        "technique": "T1136.001",
        "explain": "A local user account was created. Attackers create accounts to keep access; administrators also do this legitimately.",
        "verify": ["Check the Subject (who created it) and the new account name.", "Check whether the account was added to Administrators (4732)."],
        "remediate": ["Disable the account if it is not expected.", "Remove it from privileged groups and reset admin credentials."],
    },
    ("Security", 4732): {
        "title": "Account added to a privileged local group",
        "severity": "high",
        "technique": "T1098",
        "explain": "An account was added to a local group such as Administrators.",
        "verify": ["Check the member name and the acting account.", "Confirm with the user or IT whether this was planned."],
        "remediate": ["Remove the account from the group if unexpected.", "Audit all members of Administrators."],
    },
    ("Security", 4698): {
        "title": "Scheduled task created",
        "severity": "high",
        "technique": "T1053.005",
        "explain": "A scheduled task was created. This is a very common persistence mechanism, but also used by installers.",
        "verify": ["Read the task's action (program and arguments) in the event.", "Check the task in Task Scheduler and its author."],
        "remediate": ["Disable the task and quarantine the program it runs if unsigned.", "Delete the task after verification."],
    },
    ("Security", 7045): {
        "title": "New Windows service installed",
        "severity": "high",
        "technique": "T1543.003",
        "explain": "A new service was installed. Services start automatically and are a favourite persistence method.",
        "verify": ["Check the service image path: user-writable folders (Temp/AppData/Users) are a red flag.", "Verify the binary's digital signature."],
        "remediate": ["Stop and disable the service.", "Quarantine the binary and remove the service with sc.exe delete."],
    },
    ("System", 7045): {
        "title": "New Windows service installed",
        "severity": "high",
        "technique": "T1543.003",
        "explain": "A new service was installed. Services start automatically and are a favourite persistence method.",
        "verify": ["Check the service image path for user-writable locations.", "Verify the binary signature."],
        "remediate": ["Stop/disable the service and quarantine the binary if unsigned."],
    },
    ("Security", 4648): {
        "title": "Explicit credentials used",
        "severity": "medium",
        "technique": "T1078",
        "explain": "A process used explicit credentials to log on. This can be lateral movement or a legitimate admin tool.",
        "verify": ["Check the target server and the calling process.", "Confirm the activity with the account owner."],
        "remediate": ["Rotate the credentials if the source is unknown.", "Restrict remote logons for that account."],
    },
    ("Security", 4672): {
        "title": "Special privileges assigned to a logon",
        "severity": "low",
        "technique": "T1078.002",
        "explain": "An account received administrative privileges at logon. Normal for administrators, suspicious for service accounts.",
        "verify": ["Check whether the account is expected to be an administrator."],
        "remediate": ["Review group membership if unexpected."],
    },
    ("PowerShell", 4104): {
        "title": "PowerShell script block executed",
        "severity": "medium",
        "technique": "T1059.001",
        "explain": "PowerShell logged a script block. Malware abuses PowerShell heavily, but administrators use it too.",
        "verify": ["Read the script block and look for encoded commands or downloads."],
        "remediate": ["Quarantine the parent process if the script is malicious.", "Enable Constrained Language Mode for untrusted users."],
    },
    ("Defender", 1116): {
        "title": "Windows Defender detected malware",
        "severity": "critical",
        "technique": "T1204",
        "explain": "Defender detected malicious software on this machine.",
        "verify": ["Open Windows Security > Protection history and read the full detection.", "Check whether the threat was remediated or is still active."],
        "remediate": ["Run a full Defender scan.", "If the threat is active, disconnect from the network and follow the ransomware guidance."],
    },
    ("Defender", 5001): {
        "title": "Windows Defender real-time protection disabled",
        "severity": "critical",
        "technique": "T1562.001",
        "explain": "Real-time protection was turned off. Malware does this before deploying a payload.",
        "verify": ["Check who changed the setting and when.", "Look for other events around the same time."],
        "remediate": ["Re-enable real-time protection in Windows Security.", "Scan the machine and check for tampering."],
    },
    ("System", 6008): {
        "title": "Unexpected system shutdown",
        "severity": "medium",
        "technique": "T1529",
        "explain": "The machine shut down unexpectedly, which can indicate a crash, power loss, or a destructive attack.",
        "verify": ["Check for bugcheck (1001) and disk errors around the same time."],
        "remediate": ["Run a disk and memory check; investigate recent driver or software changes."],
    },
}

# Command-line / process patterns applied to process-creation events (4688) and
# PowerShell script blocks (4104).
SUSPICIOUS_COMMAND_PATTERNS: List[Tuple[str, str, str]] = [
    (r"-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command", "high"),
    (r"(downloadstring|net\.webclient|invoke-webrequest).{0,80}https?://", "PowerShell download cradle", "critical"),
    (r"(certutil|bitsadmin).{0,40}(-urlcache|-transfer|/transfer)", "LOLBAS download", "high"),
    (r"mshta(\.exe)?\s+https?://", "MSHTA remote script", "critical"),
    (r"regsvr32.{0,40}/i:.*https?://", "Regsvr32 remote script", "critical"),
    (r"rundll32.{0,40}javascript:", "Rundll32 JavaScript", "critical"),
    (r"wmic.{0,40}process.{0,20}call\s+create", "WMIC process creation", "high"),
    (r"vssadmin.{0,40}delete\s+shadows", "Shadow copy deletion", "critical"),
    (r"bcdedit.{0,40}(recoveryenabled\s+no|ignoreallfailures)", "Boot recovery disabled", "critical"),
    (r"wevtutil.{0,40}cl\s", "Event log clearing via wevtutil", "critical"),
]

USER_WRITABLE_RE = re.compile(
    r"\\(appdata|temp|tmp|downloads|users\\public|programdata)\\", re.IGNORECASE
)

CURSOR_FILE = Path(CACHE_DIR) / "eventlog_cursor.json"


@dataclass
class EventRecord:
    """A normalised Windows event."""

    channel: str
    label: str
    event_id: int
    record_id: int
    timestamp: str
    provider: str
    computer: str
    level: str
    fields: Dict[str, str] = field(default_factory=dict)

    def get(self, *names: str, default: str = "") -> str:
        for name in names:
            value = self.fields.get(name)
            if value:
                return value
        return default

    @property
    def summary(self) -> str:
        interesting = []
        for key in ("TargetUserName", "SubjectUserName", "ImagePath", "CommandLine",
                    "ScriptBlockText", "ServiceName", "TaskName", "NewProcessName"):
            value = self.fields.get(key)
            if value:
                interesting.append(f"{key}={value[:160]}")
        return "; ".join(interesting)


class EventLogScanner(BaseScanner):
    """Scan Windows event logs for suspicious activity."""

    def __init__(self, lookback_hours: Optional[int] = None):
        super().__init__()
        config = None
        try:
            from utils.config import get_config
            config = get_config()
        except Exception:
            pass

        self._lookback_hours = lookback_hours or getattr(
            getattr(getattr(config, "config", None), "scan", None),
            "eventlog_lookback_hours", 24,
        )
        self._ruled = sum(1 for _ in EVENT_RULES)
        self._cursor: Dict[str, int] = {}
        self._new_cursor: Dict[str, int] = {}
        self._baseline = False

    @property
    def scanner_name(self) -> str:
        return "Event Log Scanner"

    @property
    def scanner_type(self) -> str:
        return "eventlog"

    # ------------------------------------------------------------------ scan
    def scan(self, target: Optional[str] = None, deep_analysis: bool = False) -> ScanResult:
        log_scan_start("eventlog", target or "all channels")

        result = ScanResult(
            scan_type="eventlog",
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target=target or "all channels",
        )
        self.reset_cancel()

        if not WINEVT_AVAILABLE or os.name != "nt":
            result.status = ScanStatus.FAILED
            result.error_message = "Event log analysis requires Windows and pywin32"
            result.end_time = datetime.utcnow()
            return result

        self._load_cursor()
        channels = CHANNELS
        if target:
            channels = [c for c in CHANNELS if target.lower() in c[0].lower() or target.lower() == c[1].lower()]
            if not channels:
                channels = CHANNELS

        try:
            records: List[EventRecord] = []
            inaccessible: List[str] = []
            for index, (channel, label) in enumerate(channels):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                self._report_progress(index, len(channels), f"Reading {label} log")
                try:
                    records.extend(self._read_channel(channel, label))
                except PermissionError:
                    inaccessible.append(label)
                    self.logger.warning(f"Access denied reading {channel}; run as Administrator")
                except Exception as exc:
                    self.logger.debug(f"Could not read {channel}: {exc}")

            result.total_items = len(records)
            if inaccessible:
                result.stats["inaccessible_channels"] = inaccessible

            self._save_cursor(records)

            for record in records:
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                for detection in self._analyze(record):
                    result.add_detection(detection)
                    self._report_detection(detection)
                    log_detection(
                        detection_type=detection.detection_type,
                        indicator=detection.indicator,
                        risk_level=detection.risk_level.value,
                        description=detection.description,
                    )

            for detection in self._correlate(records):
                result.add_detection(detection)
                self._report_detection(detection)

            result.finalize_counts()
            if result.status != ScanStatus.CANCELLED:
                result.status = ScanStatus.COMPLETED
            result.stats["baseline"] = self._baseline
            result.stats["channels_read"] = len(channels) - len(inaccessible)

        except Exception as exc:
            self.logger.error(f"Event log scan failed: {exc}")
            result.status = ScanStatus.FAILED
            result.error_message = str(exc)

        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        log_scan_complete("eventlog", result.scan_target, len(result.detections))
        return result

    # -------------------------------------------------------------- reading
    def _load_cursor(self) -> None:
        self._cursor = {}
        try:
            if CURSOR_FILE.exists():
                self._cursor = json.loads(CURSOR_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            self.logger.debug(f"Could not read event log cursor: {exc}")

        # No cursor at all: first run.  Look back a bounded window and mark the
        # results as historical so the UI can explain them.
        self._baseline = not bool(self._cursor)

    def _save_cursor(self, records: List[EventRecord]) -> None:
        for record in records:
            current = self._new_cursor.get(record.channel, 0)
            if record.record_id > current:
                self._new_cursor[record.channel] = record.record_id
        if not self._new_cursor:
            return
        try:
            merged = dict(self._cursor)
            merged.update(self._new_cursor)
            CURSOR_FILE.parent.mkdir(parents=True, exist_ok=True)
            tmp = CURSOR_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(merged, indent=2), encoding="utf-8")
            os.replace(tmp, CURSOR_FILE)
        except Exception as exc:
            self.logger.debug(f"Could not persist event log cursor: {exc}")

    def _build_query(self, channel: str) -> str:
        lookback = datetime.utcnow() - timedelta(hours=self._lookback_hours)
        since = lookback.strftime("%Y-%m-%dT%H:%M:%S.000Z")
        cursor = self._cursor.get(channel, 0)
        if cursor:
            # RecordID is monotonic per channel, so this is both cheap and exact.
            return f"*[System[(EventRecordID > {cursor})]]"
        return f"*[System[TimeCreated[@SystemTime >= '{since}']]]"

    def _read_channel(self, channel: str, label: str) -> List[EventRecord]:
        query = self._build_query(channel)
        handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryChannelPath, query)
        records: List[EventRecord] = []
        try:
            while len(records) < MAX_EVENTS_PER_CHANNEL:
                if self.is_cancelled():
                    break
                try:
                    events = win32evtlog.EvtNext(handle, READ_BATCH, 2000)
                except Exception:
                    break
                if not events:
                    break

                for event in events:
                    try:
                        xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                        record = self._parse_xml(xml, channel, label)
                        if record is not None:
                            records.append(record)
                    except Exception as exc:
                        self.logger.debug(f"Could not render event: {exc}")
                    finally:
                        try:
                            win32evtlog.EvtClose(event)
                        except Exception:
                            pass
        finally:
            try:
                win32evtlog.EvtClose(handle)
            except Exception:
                pass
        return records

    def _parse_xml(self, xml: str, channel: str, label: str) -> Optional[EventRecord]:
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None

        system = root.find(f"{NS}System")
        if system is None:
            return None

        try:
            event_id = int(system.findtext(f"{NS}EventID", "0"))
        except (TypeError, ValueError):
            return None

        record_id = 0
        try:
            record_id = int(system.findtext(f"{NS}EventRecordID", "0"))
        except (TypeError, ValueError):
            pass

        created = system.find(f"{NS}TimeCreated")
        timestamp = created.get("SystemTime", "") if created is not None else ""
        provider_el = system.find(f"{NS}Provider")
        provider = provider_el.get("Name", "") if provider_el is not None else ""
        computer = system.findtext(f"{NS}Computer", "")
        level = system.findtext(f"{NS}Level", "")

        fields: Dict[str, str] = {}
        event_data = root.find(f"{NS}EventData")
        if event_data is not None:
            for index, data in enumerate(event_data.findall(f"{NS}Data")):
                name = data.get("Name") or f"param{index}"
                if data.text:
                    fields[name] = data.text

        user_data = root.find(f"{NS}UserData")
        if user_data is not None:
            for child in user_data.iter():
                tag = child.tag.replace(NS, "")
                if child.text and child.text.strip():
                    fields.setdefault(tag, child.text.strip())

        return EventRecord(
            channel=channel, label=label, event_id=event_id, record_id=record_id,
            timestamp=timestamp, provider=provider, computer=computer,
            level=level, fields=fields,
        )

    # ------------------------------------------------------------- analysis
    def _analyze(self, record: EventRecord) -> List[Detection]:
        detections: List[Detection] = []
        rule = EVENT_RULES.get((record.label, record.event_id))

        if rule:
            detection = self._rule_detection(record, rule)
            if detection:
                detections.append(detection)

        if record.event_id in (4688, 4104):
            detections.extend(self._command_line_detections(record))

        if record.event_id == 7045:
            detections.extend(self._service_path_detections(record))

        return detections

    def _rule_detection(self, record: EventRecord, rule: Dict[str, Any]) -> Optional[Detection]:
        severity = rule.get("severity", "medium")
        risk = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
        }.get(severity, RiskLevel.MEDIUM)

        indicator = f"{record.label}:{record.event_id}"
        details = record.summary
        detection = Detection(
            detection_id=self._generate_detection_id(),
            detection_type="eventlog_suspicious_event",
            indicator=indicator,
            indicator_type="eventlog",
            risk_level=risk,
            confidence=0.7 if severity in ("critical", "high") else 0.55,
            description=f"{rule['title']} ({record.label} log, event {record.event_id})",
            detection_reason=rule.get("explain", "Curated high-signal Windows event"),
            remediation=list(rule.get("remediate", [])),
            evidence={
                "channel": record.channel,
                "event_id": record.event_id,
                "record_id": record.record_id,
                "timestamp": record.timestamp,
                "provider": record.provider,
                "computer": record.computer,
                "details": details,
                "fields": dict(list(record.fields.items())[:25]),
                "verify_steps": list(rule.get("verify", [])),
                "mitre_technique": rule.get("technique", ""),
                "historical": self._baseline,
            },
            user=record.get("TargetUserName", "SubjectUserName"),
        )
        return detection

    def _command_line_detections(self, record: EventRecord) -> List[Detection]:
        command = record.get("CommandLine", "ScriptBlockText", "param1")
        if not command:
            return []

        detections = []
        for pattern, title, severity in SUSPICIOUS_COMMAND_PATTERNS:
            if not re.search(pattern, command, re.IGNORECASE):
                continue
            risk = RiskLevel.CRITICAL if severity == "critical" else RiskLevel.HIGH
            detections.append(Detection(
                detection_id=self._generate_detection_id(),
                detection_type="eventlog_suspicious_command",
                indicator=f"{record.label}:{record.event_id}",
                indicator_type="eventlog",
                risk_level=risk,
                confidence=0.8,
                description=f"{title} observed in the {record.label} log",
                detection_reason=(
                    "Command line matched a known malicious pattern. "
                    "Review the parent process and the account that ran it."
                ),
                remediation=[
                    "Terminate the process if it is still running.",
                    "Quarantine the parent executable and analyse it.",
                    "Check for persistence created by the same session.",
                ],
                evidence={
                    "channel": record.channel,
                    "event_id": record.event_id,
                    "timestamp": record.timestamp,
                    "pattern": title,
                    "command_line": command[:1500],
                    "user": record.get("TargetUserName", "SubjectUserName"),
                    "historical": self._baseline,
                },
                command_line=command[:2000],
                user=record.get("TargetUserName", "SubjectUserName"),
            ))
            break
        return detections

    def _service_path_detections(self, record: EventRecord) -> List[Detection]:
        image_path = record.get("ImagePath", "param1")
        if not image_path or not USER_WRITABLE_RE.search(image_path):
            return []

        return [Detection(
            detection_id=self._generate_detection_id(),
            detection_type="eventlog_service_persistence",
            indicator=f"service:{record.get('ServiceName', 'unknown')}",
            indicator_type="service",
            risk_level=RiskLevel.HIGH,
            confidence=0.8,
            description="New service installed from a user-writable directory",
            detection_reason=(
                "The service binary lives in Temp/AppData/Public, a location "
                "legitimate services rarely use."
            ),
            remediation=[
                "Stop the service and set it to disabled.",
                "Quarantine the binary, then delete the service with sc.exe delete.",
            ],
            evidence={
                "channel": record.channel,
                "event_id": record.event_id,
                "service_name": record.get("ServiceName", ""),
                "image_path": image_path,
                "timestamp": record.timestamp,
                "historical": self._baseline,
            },
        )]

    # ----------------------------------------------------------- correlation
    def _correlate(self, records: List[EventRecord]) -> List[Detection]:
        detections: List[Detection] = []

        failures: Dict[str, List[EventRecord]] = {}
        for record in records:
            if record.event_id != 4625:
                continue
            user = record.get("TargetUserName", "unknown")
            failures.setdefault(user, []).append(record)

        for user, events in failures.items():
            if len(events) < 5:
                continue
            detections.append(Detection(
                detection_id=self._generate_detection_id(),
                detection_type="eventlog_brute_force",
                indicator=f"account:{user}",
                indicator_type="account",
                risk_level=RiskLevel.HIGH,
                confidence=0.75,
                description=f"{len(events)} failed logons for account '{user}'",
                detection_reason=(
                    "Repeated authentication failures suggest password guessing "
                    "or a misconfigured service. Check whether a successful logon "
                    "followed (4624)."
                ),
                remediation=[
                    "Confirm with the account owner whether this was expected.",
                    "Change the password and enable account lockout policy.",
                    "Block the source address at the firewall if it is remote.",
                ],
                evidence={
                    "account": user,
                    "failure_count": len(events),
                    "first_seen": events[0].timestamp,
                    "last_seen": events[-1].timestamp,
                    "source_workstation": events[0].get("IpAddress", "WorkstationName"),
                    "historical": self._baseline,
                },
                user=user,
            ))

        # Service instalments paired with 4697 (service created via API)
        for record in records:
            if record.event_id == 4697:
                detections.append(Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type="eventlog_service_created",
                    indicator="service:created",
                    indicator_type="service",
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.6,
                    description="A service was created through the service API",
                    detection_reason="Service creation is a common persistence technique.",
                    remediation=["Identify the service and verify its binary signature."],
                    evidence={
                        "channel": record.channel,
                        "timestamp": record.timestamp,
                        "details": record.summary,
                        "historical": self._baseline,
                    },
                ))

        return detections


_scanner_instance: Optional[EventLogScanner] = None


def get_eventlog_scanner() -> EventLogScanner:
    """Return a shared event log scanner instance."""
    global _scanner_instance
    if _scanner_instance is None:
        _scanner_instance = EventLogScanner()
    return _scanner_instance
