"""Regression tests for the AI JSON parse failure and the whitelist bypass."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_analysis.analyzer import _loads_json_tolerant  # noqa: E402
from scanners.process_scanner import ProcessInfo, ProcessScanner  # noqa: E402


class JsonRepairTests(unittest.TestCase):
    def test_apostrophe_inside_string(self):
        payload = '{"summary": "It doesn\'t look malicious", "risk_score": 10}'
        data = _loads_json_tolerant(payload)
        self.assertEqual(data["risk_score"], 10)
        self.assertIn("doesn't", data["summary"])

    def test_trailing_comma(self):
        data = _loads_json_tolerant('{"verdict": "malicious", "confidence": 0.9,}')
        self.assertEqual(data["verdict"], "malicious")

    def test_single_quoted_python_dict(self):
        data = _loads_json_tolerant("{'verdict': 'suspicious', 'confidence': 0.5}")
        self.assertEqual(data["verdict"], "suspicious")

    def test_newline_inside_string(self):
        payload = '{"summary": "line one\nline two", "verdict": "safe"}'
        self.assertEqual(_loads_json_tolerant(payload)["verdict"], "safe")

    def test_invalid_payload_raises(self):
        with self.assertRaises(ValueError):
            _loads_json_tolerant("not json at all")


class FakeWhitelist:
    def __init__(self, trusted_paths):
        self.trusted_paths = {p.lower() for p in trusted_paths}

    def is_whitelisted(self, identifier, entry_type="path"):
        return entry_type == "path" and identifier.lower() in self.trusted_paths

    def is_trusted_path(self, path):
        return False

    def is_system_process(self, name):
        return False


class WhitelistSkipTests(unittest.TestCase):
    @staticmethod
    def _proc(path: str) -> ProcessInfo:
        return ProcessInfo(
            pid=1234, name=Path(path).name, path=path, command_line="",
            username="", parent_pid=0, parent_name="", create_time=0.0,
            cpu_percent=0.0, memory_percent=0.0, memory_bytes=0,
            status="running", num_threads=1, num_handles=1,
        )

    def test_whitelisted_path_is_skipped(self):
        scanner = ProcessScanner()
        target = r"C:\Tools\legit-tool.exe"
        scanner.whitelist = FakeWhitelist([target])
        self.assertEqual(scanner._analyze_process(self._proc(target)), [])

    def test_unlisted_path_is_still_analyzed(self):
        scanner = ProcessScanner()
        scanner.whitelist = FakeWhitelist([r"C:\Other\tool.exe"])
        for name in (
            "_check_yara_rules", "_check_behavioral_heuristics",
            "_check_hash_reputation", "_check_digital_signature",
            "_check_resource_usage", "_check_command_line",
        ):
            setattr(scanner, name, lambda proc: [])
        self.assertEqual(
            scanner._analyze_process(self._proc(r"C:\Tools\legit-tool.exe")), []
        )


if __name__ == "__main__":
    unittest.main()
