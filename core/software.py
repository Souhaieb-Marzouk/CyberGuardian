"""
CyberGuardian Software Inventory & Update Check
==============================================

Two questions, two sources:

* **Is anything dangerously old?**  A local advisory feed maps products to the
  minimum safe version and (optionally) a CVE.
* **Is a newer version actually available?**  Windows Package Manager
  (``winget upgrade``) is queried read-only; nothing is installed.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.config import APP_DIR, DATA_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.software")

UNINSTALL_KEYS: List[Tuple[str, str, str]] = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "64-bit"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall", "32-bit"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "user"),
]

BUILTIN_ADVISORIES: Dict[str, Dict[str, str]] = {
    "google chrome": {"min_version": "120.0", "url": "https://chrome.google.com/update"},
    "mozilla firefox": {"min_version": "121.0", "url": "https://www.mozilla.org/firefox/"},
    "microsoft edge": {"min_version": "120.0", "url": "https://www.microsoft.com/edge"},
    "7-zip": {"min_version": "23.0", "url": "https://www.7-zip.org/download.html"},
    "vlc media player": {"min_version": "3.0.20", "url": "https://www.videolan.org/vlc/"},
    "notepad++": {"min_version": "8.6", "url": "https://notepad-plus-plus.org/downloads/"},
    "adobe acrobat": {"min_version": "23.0", "url": "https://get.adobe.com/reader/"},
    "java": {"min_version": "8.0.401", "url": "https://www.java.com/download/"},
    "zoom": {"min_version": "5.16", "url": "https://zoom.us/download"},
    "python": {"min_version": "3.9", "url": "https://www.python.org/downloads/"},
    "git": {"min_version": "2.40", "url": "https://git-scm.com/download/win"},
    "visual studio code": {"min_version": "1.85", "url": "https://code.visualstudio.com/download"},
    "node.js": {"min_version": "18.19", "url": "https://nodejs.org/en/download"},
    "microsoft office": {"min_version": "16.0.17000", "url": "https://support.microsoft.com/office"},
    "libreoffice": {"min_version": "7.6", "url": "https://www.libreoffice.org/download/"},
    "thunderbird": {"min_version": "115.0", "url": "https://www.thunderbird.net/"},
    "putty": {"min_version": "0.80", "url": "https://www.putty.org/"},
    "wireshark": {"min_version": "4.2", "url": "https://www.wireshark.org/download.html"},
    "keepass": {"min_version": "2.56", "url": "https://keepass.info/download.html"},
    "obs studio": {"min_version": "30.0", "url": "https://obsproject.com/download"},
    "discord": {"min_version": "1.0.9020", "url": "https://discord.com/download"},
    "slack": {"min_version": "4.36", "url": "https://slack.com/downloads/windows"},
    "teams": {"min_version": "1.6", "url": "https://www.microsoft.com/microsoft-teams/download-app"},
    "dropbox": {"min_version": "180.4", "url": "https://www.dropbox.com/install"},
    "everything": {"min_version": "1.4.1", "url": "https://www.voidtools.com/downloads/"},
    "winrar": {"min_version": "6.24", "url": "https://www.win-rar.com/download.html"},
    "bitwarden": {"min_version": "2024.1", "url": "https://bitwarden.com/download/"},
    "microsoft visual c++ redistributable": {
        "min_version": "14.38",
        "url": "https://learn.microsoft.com/cpp/windows/latest-supported-vc-redist",
    },
    "microsoft .net runtime": {"min_version": "6.0", "url": "https://dotnet.microsoft.com/download"},
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class SoftwareEntry:
    """One installed application, with update status when known."""

    name: str
    version: str
    publisher: str = ""
    location: str = ""
    scope: str = ""
    status: str = "unknown"        # current | update_available | unknown
    min_version: str = ""
    advisory_url: str = ""
    latest_version: str = ""
    package_id: str = ""
    severity: str = ""
    cve: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name, "version": self.version, "publisher": self.publisher,
            "location": self.location, "scope": self.scope, "status": self.status,
            "min_version": self.min_version, "advisory_url": self.advisory_url,
            "latest_version": self.latest_version, "package_id": self.package_id,
            "severity": self.severity, "cve": self.cve,
        }


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------

def parse_version(version: str) -> Tuple[int, ...]:
    """Turn '1.2.3-beta (x64)' into (1, 2, 3)."""
    match = re.match(r"\s*v?(\d+(?:\.\d+){0,3})", version or "")
    if not match:
        return (0,)
    return tuple(int(part) for part in match.group(1).split("."))


def compare_versions(left: str, right: str) -> int:
    """Return -1/0/1 comparing dotted versions of different lengths."""
    a, b = parse_version(left), parse_version(right)
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return (a > b) - (a < b)


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------

def _read_uninstall_key(hive: str, path: str, scope: str) -> List[SoftwareEntry]:
    import winreg

    root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
    entries: List[SoftwareEntry] = []
    try:
        with winreg.OpenKey(root, path) as key:
            index = 0
            while index < 2000:
                try:
                    subkey_name = winreg.EnumKey(key, index)
                    index += 1
                except OSError:
                    break
                try:
                    with winreg.OpenKey(key, subkey_name) as sub:
                        def value(name: str, default: str = "") -> str:
                            try:
                                return str(winreg.QueryValueEx(sub, name)[0])
                            except OSError:
                                return default

                        name = value("DisplayName")
                        if not name or value("SystemComponent") == "1":
                            continue
                        entries.append(SoftwareEntry(
                            name=name,
                            version=value("DisplayVersion"),
                            publisher=value("Publisher"),
                            location=value("InstallLocation"),
                            scope=scope,
                        ))
                except OSError:
                    continue
    except OSError:
        pass
    return entries


def get_installed_software() -> List[SoftwareEntry]:
    """Return every installed application, de-duplicated by name+version."""
    found: Dict[Tuple[str, str], SoftwareEntry] = {}
    for hive, path, scope in UNINSTALL_KEYS:
        for entry in _read_uninstall_key(hive, path, scope):
            found.setdefault((entry.name.lower(), entry.version), entry)
    return sorted(found.values(), key=lambda item: item.name.lower())


# ---------------------------------------------------------------------------
# Advisory feed
# ---------------------------------------------------------------------------

def load_advisories() -> Dict[str, Dict[str, str]]:
    advisories = dict(BUILTIN_ADVISORIES)
    for candidate in (Path(DATA_DIR) / "software_advisories.json",
                      Path(APP_DIR) / "data" / "software_advisories.json"):
        try:
            if candidate.exists():
                data = json.loads(candidate.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    advisories.update(data)
                break
        except Exception as exc:
            logger.debug(f"Could not read advisories {candidate}: {exc}")
    return advisories


def _advisory_for(name: str, advisories: Dict[str, Dict[str, str]]) -> Optional[Dict[str, str]]:
    lowered = (name or "").lower()
    for pattern, advisory in advisories.items():
        if pattern.lower() in lowered:
            return advisory
    return None


# ---------------------------------------------------------------------------
# winget
# ---------------------------------------------------------------------------

_WINGET_ROW = re.compile(
    r"^(?P<name>.+?)\s{2,}(?P<id>[A-Za-z0-9][\w.\-+]*)\s+"
    r"(?P<version>[\w.\-+]+)\s+(?P<available>[\w.\-+]+|Unknown|<[^>]+>)\s*(?P<source>winget|msstore)?\s*$"
)


def parse_winget_upgrade(output: str) -> List[Dict[str, str]]:
    """Parse ``winget upgrade`` table output into records."""
    records: List[Dict[str, str]] = []
    for raw in (output or "").splitlines():
        line = raw.strip().replace("\b", "")
        if not line or line.startswith(("Name", "Nom", "----", "-")):
            continue
        match = _WINGET_ROW.match(line)
        if not match:
            continue
        records.append({
            "name": match.group("name").strip(),
            "package_id": match.group("id"),
            "version": match.group("version"),
            "available": match.group("available"),
            "source": match.group("source") or "",
        })
    return records


def check_winget_updates(timeout: int = 90) -> Tuple[List[Dict[str, str]], str]:
    """Run ``winget upgrade`` read-only. Returns (records, error)."""
    executable = shutil.which("winget")
    if not executable:
        return [], "winget is not installed"

    command = [
        executable, "upgrade",
        "--include-unknown",
        "--accept-source-agreements",
        "--disable-interactivity",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [], f"winget timed out after {timeout}s"
    except Exception as exc:
        return [], f"winget failed: {exc}"

    output = (completed.stdout or "") + "\n" + (completed.stderr or "")
    records = parse_winget_upgrade(output)
    if not records:
        lowered = output.lower()
        if "no installed package" in lowered or "no applicable update" in lowered:
            return [], ""
        if completed.returncode != 0:
            return [], f"winget exited with {completed.returncode}"
    return records, ""


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

def _normalise(name: str) -> str:
    text = (name or "").lower()
    text = re.sub(r"\((x64|x86|64-bit|32-bit|user|machine)\)", "", text)
    text = re.sub(r"\b(version|v)\s*[\d.]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _merge_winget(entries: List[SoftwareEntry], records: List[Dict[str, str]]) -> None:
    by_name = {_normalise(record["name"]): record for record in records}
    by_id = {record["package_id"].lower(): record for record in records if record.get("package_id")}

    for entry in entries:
        record = by_name.get(_normalise(entry.name))
        if record is None:
            for key, candidate in by_id.items():
                if key and key in _normalise(entry.name):
                    record = candidate
                    break
        if record is None:
            continue
        entry.package_id = record.get("package_id", "")
        available = record.get("available", "")
        if available and available.lower() not in ("unknown", "<unknown>"):
            entry.latest_version = available
            if compare_versions(available, entry.version) > 0:
                entry.status = "update_available"
                entry.severity = entry.severity or "medium"


def audit(entries: Optional[List[SoftwareEntry]] = None,
          check_updates: bool = False) -> List[SoftwareEntry]:
    """Assess versions against the advisory feed and, optionally, winget."""
    advisories = load_advisories()
    entries = entries if entries is not None else get_installed_software()

    for entry in entries:
        entry.status = "unknown"
        entry.min_version = ""
        entry.advisory_url = ""
        entry.latest_version = ""
        entry.package_id = ""
        entry.severity = ""
        advisory = _advisory_for(entry.name, advisories)
        if not advisory:
            continue
        minimum = advisory.get("min_version", "")
        entry.min_version = minimum
        entry.advisory_url = advisory.get("url", "")
        entry.severity = advisory.get("severity", "")
        entry.cve = advisory.get("cve", "")
        if not minimum or not entry.version:
            continue
        entry.status = "current" if compare_versions(entry.version, minimum) >= 0 else "update_available"

    if check_updates:
        records, error = check_winget_updates()
        if error:
            logger.warning(f"Update check unavailable: {error}")
        _merge_winget(entries, records)

    status_order = {"update_available": 0, "unknown": 1, "current": 2}
    return sorted(entries, key=lambda item: (status_order.get(item.status, 3), item.name.lower()))


def updates_available(entries: List[SoftwareEntry]) -> List[SoftwareEntry]:
    """Entries with a newer version available."""
    return [entry for entry in entries if entry.status == "update_available"]


# ---------------------------------------------------------------------------
# Performing updates
# ---------------------------------------------------------------------------

PACKAGE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")


def is_safe_package_id(package_id: str) -> bool:
    """Reject anything that could be interpreted as a winget option or shell text."""
    return bool(package_id) and bool(PACKAGE_ID_RE.fullmatch(package_id))


def build_winget_upgrade_command(package_id: str, executable: str = "winget"):
    """Return the argv list used to upgrade one package.

    The id comes from winget's own output, but it is still validated before it
    is passed to a process: never build a command from arbitrary UI strings.
    """
    if not is_safe_package_id(package_id):
        raise ValueError(f"Unsafe package id: {package_id!r}")
    return [
        executable,
        "upgrade",
        "--id", package_id,
        "--exact",
        "--silent",
        "--accept-package-agreements",
        "--accept-source-agreements",
        "--disable-interactivity",
    ]
