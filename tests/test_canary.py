"""Ransomware canary tests: install, detect, remove."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.canary import CanaryManager  # noqa: E402


class CanaryTests(unittest.TestCase):
    def setUp(self):
        import shutil
        self.base = ROOT / "tests" / "_tmp_canary"
        shutil.rmtree(self.base, ignore_errors=True)
        self.base.mkdir(parents=True, exist_ok=True)
        self.manager = CanaryManager(self.base / "state.json")
        # Point the manager at the temporary directory only.
        self.manager._target_directories = staticmethod(lambda: [self.base])

    def tearDown(self):
        import shutil
        shutil.rmtree(self.base, ignore_errors=True)

    def test_install_creates_files_and_is_idempotent(self):
        created = self.manager.install()
        self.assertTrue(created)
        again = self.manager.install()
        self.assertEqual(again, [])
        self.assertEqual(len(self.manager.canaries), len(created))

    def test_modified_canary_triggers(self):
        self.manager.install()
        target = Path(self.manager.canaries[0].path)
        target.write_text("encrypted!", encoding="utf-8")
        triggered = self.manager.check()
        self.assertEqual(len(triggered), 1)

    def test_missing_canary_triggers(self):
        self.manager.install()
        Path(self.manager.canaries[0].path).unlink()
        self.assertEqual(len(self.manager.check()), 1)

    def test_untouched_canaries_do_not_trigger(self):
        self.manager.install()
        self.assertEqual(self.manager.check(), [])

    def test_remove_cleans_up(self):
        self.manager.install()
        paths = [Path(c.path) for c in self.manager.canaries]
        self.assertEqual(self.manager.remove(), len(paths))
        self.assertFalse(any(p.exists() for p in paths))
        self.assertFalse(self.manager.is_installed())


if __name__ == "__main__":
    unittest.main()
