"""Software inventory tests: version comparison and advisory audit."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.software import (  # noqa: E402
    SoftwareEntry, audit, compare_versions, get_installed_software, parse_version,
)


class VersionTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_version("1.2.3-beta (x64)"), (1, 2, 3))
        self.assertEqual(parse_version(""), (0,))

    def test_numeric_not_lexical(self):
        self.assertEqual(compare_versions("1.2.10", "1.2.9"), 1)
        self.assertEqual(compare_versions("1.2.9", "1.2.10"), -1)

    def test_missing_segments(self):
        self.assertEqual(compare_versions("1.2", "1.2.0"), 0)
        self.assertEqual(compare_versions("2", "1.9.9"), 1)


class AuditTests(unittest.TestCase):
    def test_update_available(self):
        entries = [SoftwareEntry(name="Google Chrome", version="110.0")]
        result = audit(entries)
        self.assertEqual(result[0].status, "update_available")
        self.assertEqual(result[0].min_version, "120.0")

    def test_current_version(self):
        entries = [SoftwareEntry(name="7-Zip 24.07", version="24.07")]
        result = audit(entries)
        self.assertEqual(result[0].status, "current")

    def test_unknown_product(self):
        entries = [SoftwareEntry(name="Some Internal Tool", version="1.0")]
        result = audit(entries)
        self.assertEqual(result[0].status, "unknown")

    def test_updates_sorted_first(self):
        entries = [
            SoftwareEntry(name="7-Zip", version="24.0"),
            SoftwareEntry(name="VLC media player", version="3.0.0"),
        ]
        result = audit(entries)
        self.assertEqual(result[0].name, "VLC media player")

    def test_live_inventory_returns_entries(self):
        entries = get_installed_software()
        self.assertTrue(entries)
        self.assertTrue(all(entry.name for entry in entries))


if __name__ == "__main__":
    unittest.main()
