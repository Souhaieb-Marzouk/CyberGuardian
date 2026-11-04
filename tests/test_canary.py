"""Canary tests: realistic documents, tamper/rename/delete detection, history."""

import shutil
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.canary import CANARY_SPECS, CanaryManager  # noqa: E402


class CanaryTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / "tests" / "_tmp_canary"
        shutil.rmtree(self.base, ignore_errors=True)
        self.roots = {}
        for name in ("documents", "desktop", "downloads", "onedrive", "public"):
            path = self.base / name
            path.mkdir(parents=True, exist_ok=True)
            self.roots[name] = path
        self.manager = CanaryManager(self.base / "state.json", roots=self.roots)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def by_key(self, key: str):
        return next(canary for canary in self.manager.canaries if canary.key == key)

    def test_install_creates_valid_documents(self):
        created = self.manager.install()
        self.assertEqual(len(created), len(CANARY_SPECS))
        for canary in created:
            path = Path(canary.path)
            self.assertTrue(path.exists())
            self.assertGreater(path.stat().st_size, 100)
        docx = Path(self.by_key("tax").path)
        self.assertTrue(zipfile.is_zipfile(docx))
        xlsx = Path(self.by_key("payroll").path)
        self.assertTrue(zipfile.is_zipfile(xlsx))
        self.assertNotIn(b"canary", docx.read_bytes().lower())

    def test_install_is_idempotent(self):
        self.manager.install()
        self.assertEqual(self.manager.install(), [])

    def test_modified_is_detected(self):
        self.manager.install()
        path = Path(self.by_key("invoices").path)
        path.write_text("tampered", encoding="utf-8")
        events = self.manager.check()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0].kind, "modified")
        self.assertEqual(events[0].modification_count, 2)

    def test_encrypted_is_detected(self):
        self.manager.install()
        path = Path(self.by_key("recovery").path)
        path.write_bytes(bytes(range(256)) * 16)
        events = self.manager.check()
        self.assertEqual(events[0].kind, "encrypted")
        self.assertGreater(events[0].entropy, 7.4)

    def test_deleted_is_detected(self):
        self.manager.install()
        Path(self.by_key("handbook").path).unlink()
        events = self.manager.check()
        self.assertEqual(events[0].kind, "deleted")
        self.assertEqual(events[0].current_size, 0)

    def test_renamed_is_detected_with_new_path(self):
        self.manager.install()
        original = Path(self.by_key("contracts").path)
        renamed = original.with_name("Client_Contracts_2026.locked")
        original.rename(renamed)
        events = self.manager.check()
        self.assertEqual(events[0].kind, "renamed")
        self.assertEqual(events[0].renamed_to, str(renamed))

    def test_history_and_persistence(self):
        self.manager.install()
        path = Path(self.by_key("invoices").path)
        path.write_text("one", encoding="utf-8")
        self.manager.check()
        path.write_text("two", encoding="utf-8")
        self.manager.check()
        self.assertGreaterEqual(len(self.manager.events), 2)

        reloaded = CanaryManager(self.base / "state.json", roots=self.roots)
        self.assertEqual(len(reloaded.canaries), len(CANARY_SPECS))
        self.assertGreaterEqual(len(reloaded.events), 2)

    def test_remove_cleans_everything(self):
        self.manager.install()
        paths = [Path(canary.path) for canary in self.manager.canaries]
        self.assertEqual(self.manager.remove(), len(paths))
        self.assertFalse(any(path.exists() for path in paths))
        self.assertFalse(self.manager.is_installed())


    def test_deleted_reports_once(self):
        self.manager.install()
        Path(self.by_key("handbook").path).unlink()
        self.assertEqual(len(self.manager.check()), 1)
        self.assertEqual(self.manager.check(), [])

    def test_modification_reports_once_and_rebaselines(self):
        self.manager.install()
        path = Path(self.by_key("invoices").path)
        path.write_text("tampered", encoding="utf-8")
        self.assertEqual(len(self.manager.check()), 1)
        self.assertEqual(self.manager.check(), [])
        path.write_text("tampered again", encoding="utf-8")
        self.assertEqual(len(self.manager.check()), 1)

    def test_restored_canary_clears_missing_state(self):
        self.manager.install()
        canary = self.by_key("handbook")
        data = Path(canary.path).read_bytes()
        Path(canary.path).unlink()
        self.manager.check()
        Path(canary.path).write_bytes(data)
        self.manager.check()
        self.assertEqual(canary.missing_since, "")


if __name__ == "__main__":
    unittest.main()
