"""Quarantine vault tests: round-trip, integrity and safety guarantees."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.quarantine import QuarantineError, QuarantineVault  # noqa: E402


class QuarantineTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_quarantine"
        if self.base.exists():
            import shutil
            shutil.rmtree(self.base, ignore_errors=True)
        self.base.mkdir(parents=True, exist_ok=True)
        self.vault = QuarantineVault(self.base / "vault")
        self.sample = self.base / "malware.bin"
        self.sample.write_bytes(b"MZ" + b"\x90" * 256)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_quarantine_moves_and_encrypts(self):
        entry = self.vault.quarantine(self.sample, "DET-1", "unit test")
        self.assertFalse(self.sample.exists(), "original must be removed")
        self.assertTrue(entry.container_path.exists())
        self.assertEqual(entry.size, 258)
        raw = entry.container_path.read_bytes()
        self.assertNotIn(b"MZ\x90", raw, "container must not store plaintext")

    def test_restore_round_trip(self):
        entry = self.vault.quarantine(self.sample, "DET-2", "restore test")
        restored = self.vault.restore(entry.entry_id)
        self.assertTrue(restored.exists())
        self.assertEqual(restored.read_bytes(), b"MZ" + b"\x90" * 256)
        self.assertIsNone(self.vault.get(entry.entry_id), "entry removed after restore")

    def test_restore_never_overwrites(self):
        entry = self.vault.quarantine(self.sample, "DET-3", "overwrite test")
        self.sample.write_bytes(b"new file at the same path")
        restored = self.vault.restore(entry.entry_id)
        self.assertNotEqual(restored, self.sample)
        self.assertEqual(self.sample.read_bytes(), b"new file at the same path")
        self.assertIn("restored-1", restored.name)

    def test_corrupt_container_is_rejected(self):
        entry = self.vault.quarantine(self.sample, "DET-4", "corruption test")
        entry.container_path.write_bytes(b"not encrypted data")
        with self.assertRaises(QuarantineError):
            self.vault.restore(entry.entry_id)

    def test_purge_expired(self):
        from datetime import datetime, timedelta
        entry = self.vault.quarantine(self.sample, "DET-5", "purge test")
        self.assertEqual(self.vault.purge_expired(datetime.utcnow()), 0)
        future = datetime.utcnow() + timedelta(days=365)
        self.assertEqual(self.vault.purge_expired(future), 1)
        self.assertIsNone(self.vault.get(entry.entry_id))

    def test_list_and_total_size(self):
        self.vault.quarantine(self.sample, "DET-6", "list test")
        entries = self.vault.list_entries()
        self.assertEqual(len(entries), 1)
        self.assertEqual(self.vault.total_size(), 258)


if __name__ == "__main__":
    unittest.main()
