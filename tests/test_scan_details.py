"""Cancellation and rich-evidence tests."""

import sys
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanners.base_scanner import Detection, RiskLevel, ScanStatus  # noqa: E402
from scanners.evidence import (  # noqa: E402
    connection_payload, event_payload, file_payload, merge_evidence,
    process_payload, registry_payload,
)
from scanners.process_scanner import ProcessScanner  # noqa: E402


class FakeProcess:
    pid = 4242
    name = "evil.exe"
    path = r"C:\Users\bob\AppData\Local\Temp\evil.exe"
    command_line = "evil.exe -silent"
    username = "bob"
    parent_pid = 1000
    parent_name = "explorer.exe"
    create_time = 1700000000.0
    cpu_percent = 1.0
    memory_percent = 2.0
    memory_bytes = 8 * 1024 * 1024
    status = "running"
    num_threads = 4
    num_handles = 120
    is_signed = False
    signer = ""
    sha256 = "a" * 64


def detection(**kwargs):
    base = dict(
        detection_id="D1", detection_type="yara_critical", indicator="evil.exe",
        indicator_type="process", risk_level=RiskLevel.CRITICAL, confidence=0.9,
        description="test", detection_reason="test",
    )
    base.update(kwargs)
    return Detection(**base)


class EvidenceTests(unittest.TestCase):
    def test_process_payload_has_tree_and_context(self):
        payload = process_payload(FakeProcess())
        self.assertEqual(payload["pid"], 4242)
        self.assertEqual(payload["ppid"], 1000)
        self.assertEqual(payload["parent"], "explorer.exe")
        self.assertEqual(payload["user"], "bob")
        self.assertIn("Temp", payload["directory"])
        self.assertEqual(payload["command_line"], "evil.exe -silent")

    def test_merge_keeps_existing_keys(self):
        target = detection(evidence={"process": {"custom": "kept"}})
        merge_evidence(target, "process", process_payload(FakeProcess()))
        self.assertEqual(target.evidence["process"]["custom"], "kept")
        self.assertEqual(target.evidence["process"]["ppid"], 1000)

    def test_file_connection_registry_event_payloads(self):
        class Info:
            path = Path(r"C:\Temp\invoice.csv")
            name = "invoice.csv"
            size = 1234
            extension = ".csv"
            mime_type = "text/csv"
            entropy = 4.2
            sha256 = "b" * 64
            md5 = "c" * 32
            is_pe = False
            is_office = False
            is_archive = False
            pe_info = {}

        class Conn:
            local_ip, local_port = "10.0.0.1", 51515
            remote_ip, remote_port = "203.0.113.9", 443
            remote_hostname = "example.org"
            status, protocol = "ESTABLISHED", "TCP"
            pid, process_name = 4242, "evil.exe"
            process_path, process_owner = r"C:\evil.exe", "bob"
            process_cmdline = "evil.exe"
            connection_age, bytes_sent, bytes_recv = 3.5, 10, 20
            mac_address = adapter_name = ""
            loaded_modules, related_files = [], []

        class Reg:
            hive, key_path = "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"
            value_name, value_type, value_data = "Updater", "REG_SZ", r"C:\evil.exe"

        class Event:
            channel, label = "Security", "Logon"
            event_id, record_id = 4624, 99
            timestamp, provider = "2026-11-01T10:00:00", "Microsoft-Windows-Security"
            computer, level = "PC", "Information"
            fields = {"TargetUserName": "bob"}

        self.assertEqual(file_payload(Info())["mime"], "text/csv")
        self.assertEqual(connection_payload(Conn())["remote"], "203.0.113.9:443")
        self.assertEqual(registry_payload(Reg())["value_name"], "Updater")
        self.assertEqual(event_payload(Event())["event_id"], 4624)


class CancellationTests(unittest.TestCase):
    def test_cancel_during_scan_stops_it(self):
        scanner = ProcessScanner()
        # Keep the scan local/fast: no rate-limited online lookups.
        scanner._online_lookups = scanner.MAX_ONLINE_LOOKUPS

        def progress(current, total, message):
            if current >= 1:
                scanner.cancel()

        scanner.set_progress_callback(progress)
        result = scanner.scan()
        self.assertEqual(result.status, ScanStatus.CANCELLED)
        self.assertGreater(result.total_items, 1)

    def test_scan_worker_stop_requests_cancel(self):
        from ui.studio import ScanWorker
        called = {}

        class Stub:
            def cancel(self):
                called["cancel"] = True

        worker = ScanWorker(Stub())
        worker.stop()
        self.assertTrue(called.get("cancel"))


if __name__ == "__main__":
    unittest.main()
