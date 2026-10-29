"""Regression tests for the v1.3.0 features (stdlib unittest, no extra deps)."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core.health import HealthReport, TimelineStore, compute_health  # noqa: E402
from scanners.base_scanner import Detection, RiskLevel, ScanResult, ScanStatus  # noqa: E402
from scanners.eventlog_scanner import EventLogScanner  # noqa: E402

SERVICE_XML = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
<System>
  <Provider Name='Service Control Manager'/>
  <EventID>7045</EventID><Level>4</Level>
  <TimeCreated SystemTime='2026-10-28T20:00:00.0000000Z'/>
  <EventRecordID>4242</EventRecordID><Computer>test-pc</Computer>
</System>
<EventData>
  <Data Name='ServiceName'>EvilSvc</Data>
  <Data Name='ImagePath'>C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe</Data>
  <Data Name='ServiceType'>user mode service</Data>
  <Data Name='StartType'>auto start</Data>
</EventData>
</Event>"""


def make_detection(risk: RiskLevel, dtype: str = "x", indicator: str = "i") -> Detection:
    return Detection(
        detection_id="D1", detection_type=dtype, indicator=indicator,
        indicator_type="test", risk_level=risk, confidence=0.5,
        description="d", detection_reason="r",
    )


class EventLogTests(unittest.TestCase):
    def test_parse_xml_extracts_fields(self):
        scanner = EventLogScanner()
        record = scanner._parse_xml(SERVICE_XML, "System", "System")
        self.assertIsNotNone(record)
        self.assertEqual(record.event_id, 7045)
        self.assertEqual(record.record_id, 4242)
        self.assertEqual(record.fields["ServiceName"], "EvilSvc")
        self.assertIn("AppData", record.fields["ImagePath"])

    def test_service_in_user_writable_path_is_flagged(self):
        scanner = EventLogScanner()
        record = scanner._parse_xml(SERVICE_XML, "System", "System")
        detections = scanner._service_path_detections(record)
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].risk_level, RiskLevel.HIGH)

    def test_service_in_system32_is_not_flagged(self):
        scanner = EventLogScanner()
        xml = SERVICE_XML.replace(
            r"C:\Users\bob\AppData\Local\Temp\evil.exe",
            r"C:\Windows\System32\svchost.exe",
        )
        record = scanner._parse_xml(xml, "System", "System")
        self.assertEqual(scanner._service_path_detections(record), [])

    def test_encoded_powershell_is_flagged(self):
        scanner = EventLogScanner()
        xml = SERVICE_XML.replace("<EventID>7045</EventID>", "<EventID>4688</EventID>")
        xml = xml.replace(
            "<Data Name='ServiceName'>EvilSvc</Data>",
            "<Data Name='CommandLine'>powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=</Data>",
        )
        record = scanner._parse_xml(xml, "Security", "Security")
        detections = scanner._command_line_detections(record)
        self.assertTrue(detections)
        self.assertEqual(detections[0].risk_level, RiskLevel.HIGH)

    def test_brute_force_correlation(self):
        scanner = EventLogScanner()
        records = []
        for _ in range(6):
            xml = SERVICE_XML.replace("<EventID>7045</EventID>", "<EventID>4625</EventID>")
            xml = xml.replace("<Data Name='ServiceName'>EvilSvc</Data>",
                              "<Data Name='TargetUserName'>alice</Data>")
            records.append(scanner._parse_xml(xml, "Security", "Security"))
        detections = [d for d in scanner._correlate(records) if d.detection_type == "eventlog_brute_force"]
        self.assertEqual(len(detections), 1)
        self.assertEqual(detections[0].evidence["failure_count"], 6)


class HealthTests(unittest.TestCase):
    def test_clean_scan_scores_100(self):
        result = ScanResult(scan_type="process", status=ScanStatus.COMPLETED, start_time=__import__("datetime").datetime.now())
        report = compute_health([result])
        self.assertEqual(report.score, 100)
        self.assertEqual(report.status, "good")

    def test_critical_finding_requires_action(self):
        result = ScanResult(scan_type="process", status=ScanStatus.COMPLETED, start_time=__import__("datetime").datetime.now())
        result.add_detection(make_detection(RiskLevel.CRITICAL, "a", "x"))
        report = compute_health([result])
        self.assertEqual(report.status, "action")
        self.assertLess(report.score, 80)

    def test_duplicate_findings_counted_once(self):
        result = ScanResult(scan_type="process", status=ScanStatus.COMPLETED, start_time=__import__("datetime").datetime.now())
        result.add_detection(make_detection(RiskLevel.HIGH, "same", "same"))
        result.add_detection(make_detection(RiskLevel.HIGH, "same", "same"))
        report = compute_health([result])
        self.assertEqual(report.counts["high"], 1)


class TimelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = ROOT / "tests" / "_tmp_timeline"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.path = self.tmp / "t.json"
        if self.path.exists():
            self.path.unlink()

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()

    def test_first_snapshot_is_baseline(self):
        store = TimelineStore(self.path)
        changes = store.diff({"a": {"kind": "startup", "name": "A"}})
        self.assertEqual(changes, [])
        self.assertTrue(self.path.exists())

    def test_added_and_removed_items(self):
        store = TimelineStore(self.path)
        store.diff({"a": {"kind": "startup", "name": "A"}})
        changes = store.diff({
            "b": {"kind": "service", "name": "B"},
        })
        actions = {(c.action, c.name) for c in changes}
        self.assertIn(("added", "B"), actions)
        self.assertIn(("removed", "A"), actions)


class AIPlaybookTests(unittest.TestCase):
    def test_playbook_is_parsed_and_capped(self):
        from ai_analysis.analyzer import AIAnalyzer, AIProvider

        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        payload = {
            "verdict": "malicious",
            "confidence": 0.9,
            "risk_score": 88,
            "summary": "s",
            "detailed_analysis": "d",
            "recommendations": ["r"],
            "verification_steps": ["Open Task Manager", "Check publisher"],
            "containment_steps": ["Disconnect the network"],
            "remediation_steps": ["Quarantine the file", "Remove the service"],
            "validation_steps": ["Re-run the scan"],
        }
        result = analyzer._parse_ai_response(
            json.dumps(payload), AIProvider.OPENAI, {}
        )
        self.assertEqual(len(result.verification_steps), 2)
        self.assertEqual(result.containment_steps[0], "Disconnect the network")
        self.assertEqual(len(result.remediation_steps), 2)
        self.assertEqual(result.validation_steps, ["Re-run the scan"])

    def test_missing_playbook_does_not_break_parsing(self):
        from ai_analysis.analyzer import AIAnalyzer, AIProvider

        analyzer = AIAnalyzer.__new__(AIAnalyzer)
        result = analyzer._parse_ai_response(
            json.dumps({"verdict": "legitimate", "confidence": 0.8}),
            AIProvider.OPENAI, {},
        )
        self.assertEqual(result.verification_steps, [])


if __name__ == "__main__":
    unittest.main()
