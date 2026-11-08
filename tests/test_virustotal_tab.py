"""VirusTotal IoC extraction and AI prompt integration tests."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ai_analysis.analyzer import AIAnalyzer  # noqa: E402
from scanners.base_scanner import Detection, RiskLevel  # noqa: E402
from ui.findings import collect_iocs  # noqa: E402


def make_detection(evidence):
    return Detection(
        detection_id="D1", detection_type="network_suspicious", indicator="203.0.113.9",
        indicator_type="network", risk_level=RiskLevel.HIGH, confidence=0.8,
        description="test", detection_reason="test", evidence=evidence,
    )


class IoCCollectionTests(unittest.TestCase):
    def test_collects_hash_url_domain_and_public_ip(self):
        detection = make_detection({
            "process": {"sha256": "a" * 64, "command_line": "evil.exe http://bad.example/x"},
            "connection": {"remote_ip": "8.8.4.4", "remote_hostname": "cdn.bad.example"},
        })
        iocs = collect_iocs(detection)
        kinds = {kind for kind, _ in iocs}
        values = {value for _, value in iocs}
        self.assertIn("hash", kinds)
        self.assertIn("url", kinds)
        self.assertIn("domain", kinds)
        self.assertIn("ip", kinds)
        self.assertIn("8.8.4.4", values)
        self.assertIn("cdn.bad.example", values)

    def test_private_ips_and_filenames_are_not_iocs(self):
        detection = make_detection({
            "process": {"sha256": "", "command_line": "run report.exe and connect 10.0.0.5"},
            "connection": {"remote_ip": "10.0.0.5", "remote_hostname": ""},
        })
        values = {value for _, value in collect_iocs(detection)}
        self.assertNotIn("10.0.0.5", values)
        self.assertNotIn("report.exe", values)

    def test_no_duplicate_iocs(self):
        detection = make_detection({
            "process": {"sha256": "b" * 64},
            "file": {"sha256": "b" * 64},
        })
        iocs = collect_iocs(detection)
        self.assertEqual(len(iocs), 1)


class VirusTotalPromptTests(unittest.TestCase):
    def test_ai_prompt_includes_vt_intelligence(self):
        vt = {
            "iocs_checked": 3, "iocs_malicious": 2, "iocs_clean": 1,
            "highest_risk_level": "critical", "overall_risk_adjustment": 0.5,
            "vt_summary": "2 of 3 IOCs are malicious",
            "all_iocs": {"hashes": ["a" * 64]},
            "hash_results": [{
                "hash_value": "a" * 16 + "...", "is_malicious": True,
                "detection_ratio": "54/70", "malicious_count": 54,
                "total_engines": 70, "threat_names": ["Trojan.Win32"],
                "file_type": "PE32",
            }],
            "ip_results": [], "domain_results": [], "url_results": [],
        }
        data = {
            "detection_type": "yara_critical", "risk_level": "critical",
            "indicator": "evil.exe", "evidence": {"process": {"pid": 1}},
            "virustotal_result": vt,
        }
        prompt = AIAnalyzer._build_analysis_prompt(None, data)
        self.assertIn("VIRUSTOTAL INTELLIGENCE RESULTS", prompt)
        self.assertIn("2 of 3 IOCs are malicious", prompt)
        self.assertIn("Trojan.Win32", prompt)
        self.assertIn("54/70", prompt)


if __name__ == "__main__":
    unittest.main()
