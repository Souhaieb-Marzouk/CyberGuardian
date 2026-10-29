"""
CyberGuardian Ransomware Canaries
================================

Small decoy files placed in user folders.  Ransomware encrypts everything it can
reach, including the decoys; a change to a canary is therefore a high-confidence
signal that encryption is happening *right now*.

The module only records and verifies decoys - watching for changes is the
realtime monitor's job (it calls :meth:`CanaryManager.check`).
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from utils.config import CACHE_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.canary")

STATE_FILE = Path(CACHE_DIR) / "canaries.json"

CANARY_NAMES = (
    "Financial_Report_2026.docx",
    "Passwords_and_Accounts.xlsx",
    "Family_Photos_Backup.txt",
)

CANARY_CONTENT = (
    "This is a CyberGuardian decoy file.\n"
    "It contains no real data. If this file changed, malware is encrypting files.\n"
)


@dataclass
class Canary:
    """A decoy file registered with the manager."""

    path: str
    sha256: str
    created_at: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


class CanaryManager:
    """Create, verify and remove decoy files."""

    def __init__(self, state_file: Path = STATE_FILE):
        self.state_file = Path(state_file)
        self.canaries: List[Canary] = self._load()

    # ------------------------------------------------------------------ state
    def _load(self) -> List[Canary]:
        try:
            if self.state_file.exists():
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                return [Canary(**item) for item in data.get("canaries", [])]
        except Exception as exc:
            logger.debug(f"Could not load canary state: {exc}")
        return []

    def _save(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {"canaries": [c.to_dict() for c in self.canaries]}
            tmp = Path(str(self.state_file) + ".tmp")
            tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            os.replace(tmp, self.state_file)
        except Exception as exc:
            logger.warning(f"Could not save canary state: {exc}")

    # --------------------------------------------------------------- targets
    @staticmethod
    def _target_directories() -> List[Path]:
        home = Path(os.path.expanduser("~"))
        candidates = [home / "Documents", home / "Desktop", home / "Pictures"]
        return [path for path in candidates if path.is_dir()]

    # ------------------------------------------------------------------ create
    def install(self) -> List[Canary]:
        """Create any missing decoys and remember their hashes."""
        created: List[Canary] = []
        existing = {c.path.lower() for c in self.canaries}

        for directory in self._target_directories():
            for name in CANARY_NAMES:
                target = directory / name
                if str(target).lower() in existing or target.exists():
                    continue
                try:
                    target.write_text(CANARY_CONTENT, encoding="utf-8")
                    canary = Canary(
                        path=str(target),
                        sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                        created_at=datetime.utcnow().isoformat(),
                    )
                    self.canaries.append(canary)
                    created.append(canary)
                except OSError as exc:
                    logger.debug(f"Could not create canary {target}: {exc}")

        if created:
            self._save()
            logger.info(f"Installed {len(created)} ransomware canaries")
        return created

    # ------------------------------------------------------------------ check
    def check(self) -> List[Canary]:
        """Return canaries that were modified, deleted or renamed."""
        triggered: List[Canary] = []
        for canary in list(self.canaries):
            path = Path(canary.path)
            try:
                if not path.exists():
                    triggered.append(canary)
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if digest != canary.sha256:
                    triggered.append(canary)
            except OSError:
                triggered.append(canary)
        return triggered

    # ----------------------------------------------------------------- remove
    def remove(self) -> int:
        """Delete the decoy files and clear the state."""
        removed = 0
        for canary in self.canaries:
            try:
                Path(canary.path).unlink(missing_ok=True)
                removed += 1
            except OSError as exc:
                logger.debug(f"Could not remove canary {canary.path}: {exc}")
        self.canaries = []
        self._save()
        return removed

    def is_installed(self) -> bool:
        return bool(self.canaries)


_manager: Optional[CanaryManager] = None


def get_canary_manager() -> CanaryManager:
    """Return the shared canary manager."""
    global _manager
    if _manager is None:
        _manager = CanaryManager()
    return _manager
