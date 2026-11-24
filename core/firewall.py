"""
Windows Firewall rules used by the live traffic page.

Each block is an explicit, named rule so it can be audited and removed:

    CyberGuardian_<direction>_<proto>_<ip>_<port>

The rule blocks the remote endpoint in one direction only, which is what the
per-connection "download" (inbound) and "upload" (outbound) toggles expose.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

from utils.config import CACHE_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.firewall")

STATE_FILE = Path(CACHE_DIR) / "firewall_rules.json"
CREATE_NO_WINDOW = 0x08000000


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


class FirewallManager:
    def __init__(self, state_file: Path = STATE_FILE):
        self.state_file = Path(state_file)
        self._rules: Dict[str, Dict[str, str]] = {}
        self._load()

    def _load(self):
        try:
            if self.state_file.exists():
                self._rules = json.loads(self.state_file.read_text(encoding="utf-8"))
        except Exception:
            self._rules = {}

    def _save(self):
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            temp = Path(str(self.state_file) + ".tmp")
            temp.write_text(json.dumps(self._rules, indent=2), encoding="utf-8")
            os.replace(temp, self.state_file)
        except OSError as exc:
            logger.debug(f"Could not save firewall state: {exc}")

    @staticmethod
    def _key(direction: str, ip: str, port: int, protocol: str) -> str:
        return f"{direction}|{protocol}|{ip}|{port}"

    @staticmethod
    def _name(direction: str, ip: str, port: int, protocol: str) -> str:
        safe_ip = ip.replace(":", "-")
        return f"CyberGuardian_{direction}_{protocol}_{safe_ip}_{port}"

    def is_blocked(self, ip: str, port: int, direction: str, protocol: str) -> bool:
        return self._key(direction, ip, port, protocol) in self._rules

    def blocked_map(self) -> Dict[str, Dict[str, str]]:
        return dict(self._rules)

    def _validate(self, ip: str, port: int, direction: str, protocol: str):
        ipaddress.ip_address(ip)
        if not 1 <= int(port) <= 65535:
            raise ValueError("invalid port")
        if direction not in ("in", "out"):
            raise ValueError("invalid direction")
        if protocol not in ("TCP", "UDP"):
            raise ValueError("invalid protocol")

    def set_blocked(self, ip: str, port: int, direction: str,
                    protocol: str, blocked: bool) -> Tuple[bool, str]:
        try:
            self._validate(ip, port, direction, protocol)
        except ValueError:
            return False, "invalid"
        if not is_admin():
            return False, "admin"

        key = self._key(direction, ip, port, protocol)
        name = self._name(direction, ip, port, protocol)
        if blocked:
            if key in self._rules:
                return True, ""
            args = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}", f"dir={direction}", "action=block",
                f"remoteip={ip}", f"remoteport={port}", f"protocol={protocol}",
                "enable=yes", "profile=any",
            ]
            ok, message = self._run(args)
            if ok:
                self._rules[key] = {
                    "name": name, "direction": direction, "ip": ip,
                    "port": str(port), "protocol": protocol,
                }
                self._save()
            return ok, message
        if key not in self._rules:
            return True, ""
        ok, message = self._run([
            "netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}",
        ])
        if ok:
            self._rules.pop(key, None)
            self._save()
        return ok, message

    def remove_all(self) -> int:
        removed = 0
        for rule in list(self._rules.values()):
            ok, _ = self._run([
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule['name']}",
            ])
            if ok:
                removed += 1
        self._rules = {}
        self._save()
        return removed

    def _run(self, args) -> Tuple[bool, str]:
        try:
            completed = subprocess.run(
                args, capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=30, creationflags=CREATE_NO_WINDOW,
            )
        except Exception as exc:
            logger.warning(f"netsh failed: {exc}")
            return False, str(exc)
        if completed.returncode == 0:
            return True, ""
        message = ((completed.stdout or "") + (completed.stderr or "")).strip()
        return False, message[:400]


_manager: Optional[FirewallManager] = None


def get_firewall_manager() -> FirewallManager:
    global _manager
    if _manager is None:
        _manager = FirewallManager()
    return _manager
