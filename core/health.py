"""
CyberGuardian Health Score and Change Timeline
==============================================

Turns raw scan results into something a non-technical user can act on:

* :func:`compute_health` produces a 0-100 score, a plain-language status and a
  short list of recommendations.
* :class:`TimelineStore` records the startup entries, services and scheduled
  tasks seen on this machine and reports what changed since the previous run
  ("what changed on my PC").
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from utils.config import CACHE_DIR

TIMELINE_FILE = Path(CACHE_DIR) / "timeline.json"

# Points deducted per finding, by risk level.
WEIGHTS = {
    "critical": 25,
    "high": 12,
    "medium": 4,
    "low": 1,
    "info": 0,
}

STATUS_COLORS = {
    "good": "#00e5a0",
    "attention": "#ffd166",
    "action": "#ff5c7a",
}


@dataclass
class HealthReport:
    """Plain-language summary of the most recent scans."""

    score: int = 100
    status: str = "good"          # good | attention | action
    headline: str = "Everything looks good"
    detail: str = ""
    counts: Dict[str, int] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)

    @property
    def color(self) -> str:
        return STATUS_COLORS.get(self.status, STATUS_COLORS["good"])


def _risk_value(detection) -> str:
    risk = getattr(detection, "risk_level", None)
    return getattr(risk, "value", str(risk or "info"))


def compute_health(results: List) -> HealthReport:
    """Compute a health report from a list of ``ScanResult`` objects."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    seen = set()

    for result in results or []:
        for detection in getattr(result, "detections", []) or []:
            key = (getattr(detection, "detection_type", ""), getattr(detection, "indicator", ""))
            if key in seen:
                continue
            seen.add(key)
            counts[_risk_value(detection)] = counts.get(_risk_value(detection), 0) + 1

    penalty = sum(WEIGHTS.get(level, 0) * count for level, count in counts.items())
    score = max(0, min(100, 100 - penalty))

    critical, high = counts["critical"], counts["high"]
    medium, low = counts["medium"], counts["low"]
    total = critical + high + medium + low

    if critical:
        status = "action"
        headline = "Act now - a serious threat was found"
        detail = (
            f"{critical} critical and {high} high-risk finding(s). "
            "Follow the remediation steps in the detection details."
        )
    elif high:
        status = "action"
        headline = "Needs your attention today"
        detail = f"{high} high-risk finding(s) should be reviewed and resolved."
    elif medium:
        status = "attention"
        headline = "A few things are worth checking"
        detail = f"{medium} medium-risk finding(s). Most are configuration or unsigned software."
    elif total:
        status = "good"
        headline = "Mostly clean - minor notes only"
        detail = f"{low} low-risk finding(s); no action is usually required."
    else:
        status = "good"
        headline = "Everything looks good"
        detail = "No threats were detected in the scans you have run."

    recommendations: List[str] = []
    if critical or high:
        recommendations.append("Open each red/orange finding and follow the guided steps.")
        recommendations.append("Disconnect from the network if ransomware is suspected.")
    if medium:
        recommendations.append("Review the amber findings; many are unsigned portable apps.")
    if not results:
        recommendations.append("Run 'Quick Scan' to get a health score for this PC.")
    recommendations.append("Run a scan weekly, or leave Real-Time Monitoring on.")

    return HealthReport(
        score=score,
        status=status,
        headline=headline,
        detail=detail,
        counts=counts,
        recommendations=recommendations,
    )


@dataclass
class Change:
    """A single item that appeared or disappeared since the last snapshot."""

    kind: str        # startup | service | task
    action: str      # added | removed
    name: str
    detail: str = ""
    at: str = ""


class TimelineStore:
    """Persist a lightweight inventory and diff it between runs."""

    def __init__(self, path: Path = TIMELINE_FILE):
        self.path = Path(path)

    # -------------------------------------------------------------- snapshot
    def snapshot(self) -> Dict[str, Dict[str, str]]:
        """Collect startup entries, services and scheduled tasks."""
        items: Dict[str, Dict[str, str]] = {}
        items.update(self._startup_entries())
        items.update(self._services())
        items.update(self._scheduled_tasks())
        return items

    @staticmethod
    def _startup_entries() -> Dict[str, Dict[str, str]]:
        import winreg

        found: Dict[str, Dict[str, str]] = {}
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
        ]
        for hive, path, label in keys:
            try:
                with winreg.OpenKey(hive, path) as key:
                    index = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, index)
                            index += 1
                        except OSError:
                            break
                        found[f"startup:{label}:{name}"] = {
                            "kind": "startup",
                            "name": f"{name} ({label})",
                            "detail": str(value)[:300],
                        }
            except OSError:
                continue
        return found

    @staticmethod
    def _services() -> Dict[str, Dict[str, str]]:
        import winreg

        found: Dict[str, Dict[str, str]] = {}
        base = r"SYSTEM\CurrentControlSet\Services"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
                index = 0
                while index < 4000:
                    try:
                        name = winreg.EnumKey(root, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(root, name) as svc:
                            try:
                                image, _ = winreg.QueryValueEx(svc, "ImagePath")
                            except OSError:
                                image = ""
                            try:
                                start_type, _ = winreg.QueryValueEx(svc, "Start")
                            except OSError:
                                start_type = -1
                    except OSError:
                        continue
                    found[f"service:{name.lower()}"] = {
                        "kind": "service",
                        "name": name,
                        "detail": f"ImagePath={str(image)[:240]} Start={start_type}",
                    }
        except OSError:
            pass
        return found

    @staticmethod
    def _scheduled_tasks() -> Dict[str, Dict[str, str]]:
        found: Dict[str, Dict[str, str]] = {}
        tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
        try:
            for path in tasks_dir.rglob("*"):
                if path.is_file():
                    found[f"task:{str(path).lower()}"] = {
                        "kind": "task",
                        "name": path.name,
                        "detail": str(path),
                    }
        except OSError:
            pass
        return found

    # ---------------------------------------------------------------- diffing
    def load(self) -> Dict[str, Dict[str, str]]:
        try:
            if self.path.exists():
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return data.get("items", {})
        except Exception:
            pass
        return {}

    def save(self, items: Dict[str, Dict[str, str]]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "captured_at": datetime.utcnow().isoformat(),
                "items": items,
            }
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=1), encoding="utf-8")
            os.replace(tmp, self.path)
        except Exception:
            pass

    def diff(self, new: Optional[Dict[str, Dict[str, str]]] = None) -> List[Change]:
        """Return changes since the previous snapshot, and store the new one."""
        new = new if new is not None else self.snapshot()
        old = self.load()

        changes: List[Change] = []
        now = datetime.now().strftime("%Y-%m-%d %H:%M")

        for key, item in new.items():
            if key not in old:
                changes.append(Change(
                    kind=item.get("kind", "item"),
                    action="added",
                    name=item.get("name", key),
                    detail=item.get("detail", ""),
                    at=now,
                ))

        for key, item in old.items():
            if key not in new:
                changes.append(Change(
                    kind=item.get("kind", "item"),
                    action="removed",
                    name=item.get("name", key),
                    detail=item.get("detail", ""),
                    at=now,
                ))

        if not old:
            # First run: do not present the whole machine as "new".
            self.save(new)
            return []

        self.save(new)
        return changes
