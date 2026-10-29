"""
CyberGuardian Software Inventory
================================

Lists installed software and flags versions that are older than the minimum safe
version in a bundled advisory feed.

The feed (``data/software_advisories.json``, with a built-in fallback) maps a
product pattern to a minimum version and an advisory URL.  It is intentionally
local and human-curated: the scanner never scrapes vendor sites.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
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
}


@dataclass
class SoftwareEntry:
    """One installed application."""

    name: str
    version: str
    publisher: str = ""
    location: str = ""
    scope: str = ""
    status: str = "unknown"        # current | update_available | unknown
    min_version: str = ""
    advisory_url: str = ""

    def to_dict(self) -> Dict:
        return {
            "name": self.name, "version": self.version, "publisher": self.publisher,
            "location": self.location, "scope": self.scope, "status": self.status,
            "min_version": self.min_version, "advisory_url": self.advisory_url,
        }


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


def load_advisories() -> Dict[str, Dict[str, str]]:
    """Load the advisory feed, falling back to the built-in entries."""
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


def audit(entries: Optional[List[SoftwareEntry]] = None) -> List[SoftwareEntry]:
    """Mark entries as current or update_available using the advisory feed."""
    advisories = load_advisories()
    entries = entries if entries is not None else get_installed_software()

    for entry in entries:
        advisory = _advisory_for(entry.name, advisories)
        entry.status = "unknown"
        entry.min_version = ""
        entry.advisory_url = ""
        if not advisory:
            continue
        minimum = advisory.get("min_version", "")
        entry.min_version = minimum
        entry.advisory_url = advisory.get("url", "")
        if not minimum or not entry.version:
            continue
        entry.status = "current" if compare_versions(entry.version, minimum) >= 0 else "update_available"

    status_order = {"update_available": 0, "unknown": 1, "current": 2}
    return sorted(entries, key=lambda item: (status_order.get(item.status, 3), item.name.lower()))
