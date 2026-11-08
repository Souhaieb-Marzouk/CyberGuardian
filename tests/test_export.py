"""Detection export tests: flattening, YARA detail, JSON/CSV output."""

import json
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from reporting.export import CSV_COLUMNS, export_results, flatten  # noqa: E402
from scanners.base_scanner import Detection, RiskLevel, ScanResult, ScanStatus  # noqa: E402


def make_result() -> ScanResult:
    detection = Detection(
        detection_id="D1",
        detection_type="yara_critical",
        indicator="evil.exe",
        indicator_type="process",
        risk_level=RiskLevel.CRITICAL,
        confidence=0.95,
        description="Critical Yara rule match: credential_dumping",
        detection_reason="YARA rules matched",
        remediation=["Quarantine the file", "Investigate the parent process"],
        process_name="evil.exe",
        process_id=4242,
        file_path=r"C:\Users\bob\AppData\Local\Temp\evil.exe",
        command_line="evil.exe -silent",
        user="bob",
        evidence={
            "yara_matches": [{
                "rule": "credential_dumping",
                "namespace": "default",
                "tags": ["credentials", "malware"],
                "severity": "critical",
                "description": "Dumps credentials",
                "meta": {"author": "CyberGuardian"},
                "strings": [
                    {"identifier": "$cred1", "offset": 1024, "preview": "mimikatz",
                     "data_hex": "6d696d696b61747a"},
                    {"identifier": "$cred2", "offset": 4096, "preview": "lsass.exe",
                     "data_hex": "6c736173732e657865"},
                ],
            }],
            "process": {"pid": 4242, "ppid": 1000, "parent": "explorer.exe",
                        "path": r"C:\Users\bob\AppData\Local\Temp\evil.exe"},
            "signature_status": "Unsigned",
            "signer": "",
        },
    )
    result = ScanResult(
        scan_type="process",
        status=ScanStatus.COMPLETED,
        start_time=datetime.now(),
        total_items=82,
        scan_target="all",
    )
    result.add_detection(detection)
    return result


class ExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = ROOT / "tests" / "_tmp_export"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_flatten_includes_process_and_yara_details(self):
        rows = flatten([make_result()])
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["process_name"], "evil.exe")
        self.assertEqual(str(row["pid"]), "4242")
        self.assertEqual(str(row["ppid"]), "1000")
        self.assertEqual(row["parent_process"], "explorer.exe")
        self.assertEqual(row["yara_rule"], "credential_dumping")
        self.assertIn("$cred1", row["matched_identifiers"])
        self.assertIn("1024", row["matched_offsets"])
        self.assertIn("mimikatz", row["matched_preview"])
        self.assertEqual(set(row.keys()), set(CSV_COLUMNS))

    def test_csv_has_all_columns(self):
        path = export_results([make_result()], self.tmp / "out.csv")
        text = path.read_text(encoding="utf-8-sig")
        header = text.splitlines()[0].split(",")
        self.assertEqual(header, CSV_COLUMNS)
        self.assertIn("credential_dumping", text)

    def test_json_keeps_full_evidence(self):
        path = export_results([make_result()], self.tmp / "out.json")
        payload = json.loads(path.read_text(encoding="utf-8"))
        scan = payload["scans"][0]
        self.assertEqual(scan["counts"]["critical"], 1)
        evidence = scan["detections"][0]["evidence"]
        self.assertEqual(evidence["yara_matches"][0]["rule"], "credential_dumping")
        self.assertEqual(evidence["process"]["ppid"], 1000)
        self.assertEqual(evidence["yara_matches"][0]["strings"][0]["identifier"], "$cred1")


class ScanPageExportTests(unittest.TestCase):
    def test_scan_page_exposes_title_and_export_button(self):
        import os
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PyQt5.QtWidgets import QApplication
        app = QApplication.instance() or QApplication([])
        from ui.studio import ScanPage
        page = ScanPage({"muted": "#666", "ink": "#111"}, "Processes", "desc", lambda: None)
        self.assertEqual(page.title_text, "Processes")
        self.assertEqual(page.export_btn.text(), "Export results")
        page.deleteLater()


if __name__ == "__main__":
    unittest.main()
