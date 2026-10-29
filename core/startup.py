"""
CyberGuardian Startup Impact Manager
====================================

Inventories everything that starts automatically - Run/RunOnce keys, Startup
folders, auto-start services and scheduled tasks - and explains, in plain
language, how risky each entry is and why.

Disabling is non-destructive:
* Run entries are toggled through ``StartupApproved`` (the same mechanism Task
  Manager uses), so the original command is preserved.
* Services are switched between ``Start`` = 2 (auto) and 4 (disabled).
* Scheduled tasks are listed but not modified by this module.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from utils.logging_utils import get_logger
from utils.signature_check import verify_file

logger = get_logger("core.startup")

RUN_KEYS: List[Tuple[str, str, str]] = [
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM Run"),
    ("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce"),
    ("HKLM", r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM Run (32-bit)"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU Run"),
    ("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce"),
]

STARTUP_FOLDERS: List[Tuple[str, str]] = [
    ("user", r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ("common", r"ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"),
]

USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\programdata\\")

TRUSTED_PUBLISHERS = ("microsoft", "google", "mozilla", "apple", "nvidia", "intel", "adobe", "valve")


@dataclass
class StartupEntry:
    """One automatic-start item."""

    entry_id: str
    name: str
    command: str
    source: str                 # run | startup_folder | service | task
    location: str = ""
    publisher: str = ""
    signed: bool = False
    enabled: bool = True
    impact: str = "medium"      # low | medium | high
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "entry_id": self.entry_id, "name": self.name, "command": self.command,
            "source": self.source, "location": self.location, "publisher": self.publisher,
            "signed": self.signed, "enabled": self.enabled,
            "impact": self.impact, "reasons": list(self.reasons),
        }


def parse_command(command: str) -> str:
    """Extract the executable path from a Run-style command line."""
    text = (command or "").strip().strip('"')
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end] if end > 0 else text.lstrip('"')
    if text.lower().endswith((".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js")):
        return text
    match = __import__("re").match(r"^(.+?\.(?:exe|dll|bat|cmd|ps1|vbs|js))\b", text, __import__("re").I)
    return match.group(1) if match else text.split(" ")[0]


def classify_impact(
    signed: bool,
    publisher: str,
    path: str,
    source: str,
    is_binary: bool = True,
) -> Tuple[str, List[str]]:
    """Return (impact, reasons) for an entry, using only observable facts."""
    reasons: List[str] = []
    lowered = (path or "").lower()
    publisher_lower = (publisher or "").lower()

    if not is_binary:
        # Startup-folder shortcuts/scripts are not signed binaries; saying
        # "not validly signed" for a .lnk file was misleading.
        reasons.append("Runs from a Startup folder")
        return "medium", reasons

    if not signed:
        reasons.append("Binary is not validly signed")
    if any(marker in lowered for marker in USER_WRITABLE):
        reasons.append("Runs from a user-writable folder")
    if source in ("service", "task"):
        reasons.append(f"Starts as a Windows {source}")

    if not signed and any(marker in lowered for marker in USER_WRITABLE):
        return "high", reasons
    if not signed:
        return "medium", reasons
    if any(marker in lowered for marker in USER_WRITABLE):
        # Even a signed binary launched from Downloads/AppData deserves a look.
        return "medium", reasons
    if source in ("service", "task") and not any(
        trusted in publisher_lower for trusted in TRUSTED_PUBLISHERS
    ):
        return "medium", reasons
    if signed and any(trusted in publisher_lower for trusted in TRUSTED_PUBLISHERS):
        reasons.append("Signed by a well-known publisher")
        return "low", reasons
    return "low", reasons


def _open_hive(hive: str):
    import winreg
    return winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER


def _is_enabled_by_approval(hive: str, name: str) -> bool:
    """Read StartupApproved; absent means enabled (Task Manager semantics)."""
    import winreg
    try:
        with winreg.OpenKey(_open_hive(hive),
                            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run") as key:
            data, _ = winreg.QueryValueEx(key, name)
        return not data or len(data) < 1 or data[0] not in (3, 7)
    except OSError:
        return True


def _enumerate_run() -> List[StartupEntry]:
    import winreg

    entries: List[StartupEntry] = []
    for hive_name, path, label in RUN_KEYS:
        try:
            with winreg.OpenKey(_open_hive(hive_name), path) as key:
                index = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, index)
                        index += 1
                    except OSError:
                        break
                    command = str(value)
                    exe = parse_command(command)
                    info = verify_file(exe) if exe and Path(exe).is_file() else None
                    signed = bool(info and info.is_valid)
                    publisher = info.signer if info else ""
                    impact, reasons = classify_impact(signed, publisher, exe, "run")
                    entries.append(StartupEntry(
                        entry_id=f"run:{label}:{name}",
                        name=name,
                        command=command[:500],
                        source="run",
                        location=f"{hive_name}\\{path}",
                        publisher=publisher,
                        signed=signed,
                        enabled=_is_enabled_by_approval(hive_name, name),
                        impact=impact,
                        reasons=reasons,
                    ))
        except OSError:
            continue
    return entries


def _enumerate_startup_folders() -> List[StartupEntry]:
    entries: List[StartupEntry] = []
    for scope, relative in STARTUP_FOLDERS:
        if scope == "user":
            base = Path(os.environ.get("APPDATA", ""))
        else:
            base = Path(os.environ.get("ProgramData", ""))
        folder = base / relative
        try:
            for item in folder.iterdir():
                if not item.is_file():
                    continue
                info = verify_file(str(item)) if item.suffix.lower() in (".exe", ".dll") else None
                signed = bool(info and info.is_valid)
                publisher = info.signer if info else ""
                impact, reasons = classify_impact(
                    signed, publisher, str(item), "startup_folder",
                    is_binary=item.suffix.lower() in (".exe", ".dll"),
                )
                entries.append(StartupEntry(
                    entry_id=f"folder:{item.name}", name=item.name,
                    command=str(item), source="startup_folder",
                    location=str(folder), publisher=publisher, signed=signed,
                    impact=impact, reasons=reasons,
                ))
        except OSError:
            continue
    return entries


def _enumerate_services(limit: int = 400) -> List[StartupEntry]:
    import winreg

    entries: List[StartupEntry] = []
    base = r"SYSTEM\CurrentControlSet\Services"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as root:
            index = 0
            while index < limit:
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
                            continue
                        try:
                            start_type, _ = winreg.QueryValueEx(svc, "Start")
                        except OSError:
                            start_type = 3
                except OSError:
                    continue
                if start_type not in (0, 1, 2):
                    continue
                exe = parse_command(str(image))
                info = verify_file(exe) if exe and Path(exe).is_file() else None
                signed = bool(info and info.is_valid)
                publisher = info.signer if info else ""
                impact, reasons = classify_impact(signed, publisher, exe, "service")
                entries.append(StartupEntry(
                    entry_id=f"service:{name.lower()}", name=name,
                    command=str(image)[:500], source="service",
                    location=base, publisher=publisher, signed=signed,
                    enabled=True, impact=impact, reasons=reasons,
                ))
        return entries
    except OSError:
        return entries


def _enumerate_tasks(limit: int = 200) -> List[StartupEntry]:
    entries: List[StartupEntry] = []
    tasks_dir = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "Tasks"
    try:
        count = 0
        for path in tasks_dir.rglob("*"):
            if not path.is_file() or count >= limit:
                break
            count += 1
            entries.append(StartupEntry(
                entry_id=f"task:{path.name.lower()}", name=path.name,
                command=str(path), source="task", location=str(path.parent),
                enabled=True, impact="medium",
                reasons=["Starts as a scheduled task"],
            ))
    except OSError:
        pass
    return entries


def enumerate_startup(include_services: bool = True, include_tasks: bool = True) -> List[StartupEntry]:
    """Return every automatic-start entry, sorted by impact then name."""
    entries = _enumerate_run() + _enumerate_startup_folders()
    if include_services:
        entries += _enumerate_services()
    if include_tasks:
        entries += _enumerate_tasks()
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(entries, key=lambda item: (order.get(item.impact, 3), item.name.lower()))


def set_enabled(entry: StartupEntry, enabled: bool) -> bool:
    """Enable or disable a Run entry or service non-destructively."""
    import winreg

    try:
        if entry.source == "run":
            hive_name = entry.location.split("\\", 1)[0]
            with winreg.CreateKeyEx(
                _open_hive(hive_name),
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run",
                0, winreg.KEY_SET_VALUE,
            ) as key:
                value = b"\x02" + b"\x00" * 11 if enabled else b"\x03" + b"\x00" * 11
                winreg.SetValueEx(key, entry.name, 0, winreg.REG_BINARY, value)
            entry.enabled = enabled
            return True

        if entry.source == "service":
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                rf"SYSTEM\CurrentControlSet\Services\{entry.name}",
                0, winreg.KEY_SET_VALUE,
            ) as key:
                winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, 2 if enabled else 4)
            entry.enabled = enabled
            return True
    except OSError as exc:
        logger.warning(f"Could not change startup state for {entry.name}: {exc}")
    return False
