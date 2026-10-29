"""
CyberGuardian Quarantine Vault
==============================

Files removed by the user are never deleted outright: they are moved into an
encrypted container, recorded in metadata, and can be restored or purged later.

Design
------
* File bytes are encrypted with Windows DPAPI (per-user, per-machine) so a
  quarantined sample cannot be executed or read by another user, and no extra
  dependency is required.
* Metadata (original path, SHA-256, detection, timestamps) is stored next to the
  container so the vault can be listed without decrypting anything.
* Restores verify the SHA-256 before and after writing and never overwrite an
  existing file.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import os
import shutil
import uuid
from ctypes import wintypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from utils.config import DATA_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.quarantine")

QUARANTINE_DIR = Path(DATA_DIR) / "quarantine"
CONTAINER_SUFFIX = ".qtn"
METADATA_SUFFIX = ".json"
DEFAULT_RETENTION_DAYS = 30

# DPAPI works on one contiguous buffer, so a file has to fit in memory while it
# is encrypted.  Refuse absurdly large samples instead of exhausting RAM.
MAX_QUARANTINE_BYTES = 512 * 1024 * 1024


# ---------------------------------------------------------------------------
# DPAPI
# ---------------------------------------------------------------------------

class _Blob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_char)),
    ]


def _blob_from(data: bytes) -> _Blob:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _Blob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))


def _dpapi(data: bytes, protect: bool) -> bytes:
    """Encrypt (protect=True) or decrypt *data* with the current user's DPAPI key."""
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    crypt32.CryptProtectData.restype = wintypes.BOOL
    crypt32.CryptUnprotectData.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]

    blob_in = _blob_from(data)
    blob_out = _Blob()
    blob_out.cbData = 0
    blob_out.pbData = None

    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        )
    if not ok:
        raise OSError(f"DPAPI call failed (error {ctypes.get_last_error()})")

    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        if blob_out.pbData:
            kernel32.LocalFree(blob_out.pbData)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class QuarantineEntry:
    """Metadata for one quarantined file."""

    entry_id: str
    original_path: str
    name: str
    size: int
    sha256: str
    detection_id: str = ""
    reason: str = ""
    quarantined_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    expires_at: str = ""
    vault_dir: str = ""

    @property
    def directory(self) -> Path:
        return Path(self.vault_dir) if self.vault_dir else QUARANTINE_DIR

    @property
    def container_path(self) -> Path:
        return self.directory / f"{self.entry_id}{CONTAINER_SUFFIX}"

    @property
    def metadata_path(self) -> Path:
        return self.directory / f"{self.entry_id}{METADATA_SUFFIX}"

    def to_dict(self) -> Dict:
        return asdict(self)


class QuarantineError(Exception):
    """Raised when a quarantine operation cannot be completed safely."""


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------

class QuarantineVault:
    """Encrypted store for removed files, with restore and retention."""

    def __init__(self, directory: Optional[Path] = None,
                 retention_days: int = DEFAULT_RETENTION_DAYS):
        self.directory = Path(directory) if directory else QUARANTINE_DIR
        self.retention_days = retention_days
        try:
            self.directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            logger.warning(f"Could not create quarantine directory {self.directory}: {exc}")

    # ------------------------------------------------------------------ write
    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def quarantine(self, source: Path, detection_id: str = "", reason: str = "") -> QuarantineEntry:
        """Move *source* into the encrypted vault and return its entry."""
        source = Path(source)
        if not source.is_file():
            raise QuarantineError(f"Not a file: {source}")

        try:
            size = source.stat().st_size
        except OSError as exc:
            raise QuarantineError(f"Could not read {source}: {exc}") from exc
        if size > MAX_QUARANTINE_BYTES:
            raise QuarantineError(
                f"{source.name} is too large to quarantine safely "
                f"({size / (1024 * 1024):.0f} MB; limit is "
                f"{MAX_QUARANTINE_BYTES / (1024 * 1024):.0f} MB)"
            )

        try:
            sha256 = self._hash_file(source)
            data = source.read_bytes()
            encrypted = _dpapi(data, protect=True)
        except OSError as exc:
            raise QuarantineError(f"Could not encrypt {source}: {exc}") from exc

        entry_id = uuid.uuid4().hex
        entry = QuarantineEntry(
            entry_id=entry_id,
            original_path=str(source),
            name=source.name,
            size=size,
            sha256=sha256,
            detection_id=detection_id,
            reason=reason,
            expires_at=(datetime.utcnow() + timedelta(days=self.retention_days)).isoformat(),
            vault_dir=str(self.directory),
        )

        container_tmp = Path(str(entry.container_path) + ".tmp")
        metadata_tmp = Path(str(entry.metadata_path) + ".tmp")
        try:
            container_tmp.write_bytes(encrypted)
            metadata_tmp.write_text(json.dumps(entry.to_dict(), indent=2), encoding="utf-8")
            os.replace(container_tmp, entry.container_path)
            os.replace(metadata_tmp, entry.metadata_path)
            # Only remove the original once the vault copy is durable.
            source.unlink()
        except Exception as exc:
            # Roll the vault back as well: a half-committed entry would make the
            # file appear quarantined while the original is still on disk (or
            # vice-versa).  Removing a path that was never created is harmless.
            for leftover in (
                container_tmp, metadata_tmp,
                entry.container_path, entry.metadata_path,
            ):
                try:
                    leftover.unlink(missing_ok=True)
                except OSError:
                    pass
            raise QuarantineError(f"Could not quarantine {source}: {exc}") from exc

        logger.info(f"Quarantined {source} as {entry_id}")
        return entry

    # ------------------------------------------------------------------- read
    def list_entries(self) -> List[QuarantineEntry]:
        entries: List[QuarantineEntry] = []
        try:
            for path in self.directory.glob(f"*{METADATA_SUFFIX}"):
                try:
                    data = json.loads(path.read_text(encoding="utf-8"))
                    entries.append(QuarantineEntry(**data))
                except Exception as exc:
                    logger.debug(f"Skipping unreadable quarantine metadata {path}: {exc}")
        except OSError as exc:
            logger.warning(f"Could not list quarantine: {exc}")
        return sorted(entries, key=lambda item: item.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> Optional[QuarantineEntry]:
        for entry in self.list_entries():
            if entry.entry_id == entry_id:
                return entry
        return None

    # ---------------------------------------------------------------- restore
    def restore(self, entry_id: str, destination: Optional[Path] = None) -> Path:
        """Decrypt an entry and write it back, verifying its hash."""
        entry = self.get(entry_id)
        if entry is None:
            raise QuarantineError(f"Unknown quarantine entry: {entry_id}")
        if not entry.container_path.exists():
            raise QuarantineError(f"Container missing for entry {entry_id}")

        try:
            encrypted = entry.container_path.read_bytes()
            data = _dpapi(encrypted, protect=False)
        except OSError as exc:
            raise QuarantineError(
                "Quarantined data could not be decrypted (corrupt or created by another user/machine)"
            ) from exc
        if hashlib.sha256(data).hexdigest() != entry.sha256:
            raise QuarantineError("Quarantined data failed integrity verification")

        target = Path(destination) if destination else Path(entry.original_path)
        if target.is_dir():
            target = target / entry.name

        # Never overwrite: pick the first free "<name>.restored-N" variant.
        final = target
        counter = 1
        while final.exists():
            final = target.with_name(f"{target.stem}.restored-{counter}{target.suffix}")
            counter += 1

        try:
            final.parent.mkdir(parents=True, exist_ok=True)
            final.write_bytes(data)
            if self._hash_file(final) != entry.sha256:
                raise QuarantineError("Restored file failed integrity verification")
        except QuarantineError:
            try:
                final.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        except OSError as exc:
            try:
                final.unlink(missing_ok=True)
            except OSError:
                pass
            raise QuarantineError(f"Could not restore {entry.name}: {exc}") from exc

        self._remove_entry_files(entry)
        logger.info(f"Restored {entry.name} to {final}")
        return final

    # ------------------------------------------------------------------ purge
    def delete(self, entry_id: str) -> bool:
        entry = self.get(entry_id)
        if entry is None:
            return False
        return self._remove_entry_files(entry)

    def purge_expired(self, now: Optional[datetime] = None) -> int:
        """Delete entries older than the retention window."""
        now = now or datetime.utcnow()
        removed = 0
        for entry in self.list_entries():
            try:
                expires = datetime.fromisoformat(entry.expires_at) if entry.expires_at else None
            except ValueError:
                expires = None
            if expires is None:
                continue
            if now >= expires:
                self._remove_entry_files(entry)
                removed += 1
        if removed:
            logger.info(f"Purged {removed} expired quarantine entries")
        return removed

    def total_size(self) -> int:
        return sum(entry.size for entry in self.list_entries())

    def _remove_entry_files(self, entry: QuarantineEntry) -> bool:
        """Delete an entry's files, returning True only when both are gone."""
        removed = True
        for path in (entry.container_path, entry.metadata_path):
            try:
                path.unlink(missing_ok=True)
                if path.exists():
                    removed = False
            except OSError as exc:
                removed = False
                logger.warning(f"Could not delete {path}: {exc}")
        return removed


_vault: Optional[QuarantineVault] = None


def get_vault() -> QuarantineVault:
    """Return the shared quarantine vault."""
    global _vault
    if _vault is None:
        _vault = QuarantineVault()
    return _vault
