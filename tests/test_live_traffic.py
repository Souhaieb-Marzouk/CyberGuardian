"""Live traffic monitor, firewall and traffic-page tests."""

import os
import socket
import sys
import shutil
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.live_traffic as live  # noqa: E402
from core.firewall import FirewallManager  # noqa: E402
from core.live_traffic import TrafficMonitor  # noqa: E402


class Address:
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port


class FakeConnection:
    def __init__(self, pid, local, remote, status="ESTABLISHED", proto=socket.SOCK_STREAM):
        self.pid = pid
        self.laddr = Address(*local)
        self.raddr = Address(*remote) if remote else None
        self.status = status
        self.type = proto


class FakeIO:
    read_bytes = 1024
    write_bytes = 2048


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid

    def name(self):
        return "chrome.exe" if self.pid == 100 else "evil.exe"

    def exe(self):
        if self.pid == 100:
            return r"C:\Program Files\Google\Chrome\chrome.exe"
        return r"C:\Users\bob\AppData\Local\Temp\evil.exe"

    def username(self):
        return "bob"

    def create_time(self):
        return 1700000000

    def ppid(self):
        return 42

    def cmdline(self):
        return ["evil.exe", "-silent"]

    def io_counters(self):
        return FakeIO()


class LiveTrafficTests(unittest.TestCase):
    def setUp(self):
        self.tmp = ROOT / "tests" / "_tmp_live"
        shutil.rmtree(self.tmp, ignore_errors=True)
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.blacklist = self.tmp / "blacklist.txt"
        self.blacklist.write_text("1.2.3.4\n", encoding="utf-8")
        self.connections = [
            FakeConnection(100, ("192.168.1.10", 50000), ("8.8.8.8", 443)),
            FakeConnection(200, ("192.168.1.10", 50001), ("1.2.3.4", 4444)),
            FakeConnection(0, ("0.0.0.0", 445), None, "LISTEN"),
            FakeConnection(100, ("192.168.1.10", 50002), ("192.168.1.20", 80)),
        ]

    def test_snapshot_classifies_and_flags(self):
        counter = SimpleNamespace(bytes_sent=1000, bytes_recv=2000)
        with patch.object(live.psutil, "net_connections", return_value=self.connections), \
             patch.object(live.psutil, "net_io_counters", return_value={"Ethernet": counter}), \
             patch.object(live.psutil, "Process", FakeProcess):
            monitor = TrafficMonitor(blacklist_path=self.blacklist)
            first = monitor.snapshot()
            counter.bytes_sent += 500
            counter.bytes_recv += 2000
            second = monitor.snapshot()

        self.assertGreaterEqual(len(second.connections), 4)
        flagged = [c for c in second.connections if c.risk != "info"]
        self.assertTrue(flagged)
        evil = next(c for c in second.connections if c.remote_port == 4444)
        self.assertIn("blacklist", evil.reasons)
        self.assertIn("suspicious_port", evil.reasons)
        self.assertTrue(evil.is_public)
        chrome = next(c for c in second.connections if c.remote_port == 443)
        self.assertEqual(chrome.risk, "info")
        self.assertEqual(chrome.domain, "")
        system = next(c for c in second.connections if c.pid == 0)
        self.assertEqual(system.risk, "info")
        self.assertGreater(second.download_bps, 0)
        self.assertGreater(second.upload_bps, 0)

    def test_blacklist_cidr_and_adapter(self):
        self.blacklist.write_text("10.0.0.0/8\n", encoding="utf-8")
        with patch.object(live.psutil, "net_connections", return_value=[
                FakeConnection(100, ("10.1.2.3", 1000), ("8.8.4.4", 53), "ESTABLISHED", socket.SOCK_DGRAM)
             ]), \
             patch.object(live.psutil, "net_io_counters", return_value={}), \
             patch.object(live.psutil, "Process", FakeProcess):
            monitor = TrafficMonitor(blacklist_path=self.blacklist)
            snap = monitor.snapshot()
        self.assertEqual(len(snap.connections), 1)
        self.assertTrue(snap.connections[0].is_public)


class FirewallTests(unittest.TestCase):
    def setUp(self):
        self.tmp = ROOT / "tests" / "_tmp_live" / "rules.json"
        shutil.rmtree(self.tmp.parent, ignore_errors=True)
        self.tmp.parent.mkdir(parents=True, exist_ok=True)
        self.firewall = FirewallManager(self.tmp)

    def test_rejects_invalid_values(self):
        self.assertEqual(self.firewall.set_blocked("not-an-ip", 443, "out", "TCP", True)[1], "invalid")
        self.assertEqual(self.firewall.set_blocked("8.8.8.8", 70000, "out", "TCP", True)[1], "invalid")
        self.assertEqual(self.firewall.set_blocked("8.8.8.8", 443, "sideways", "TCP", True)[1], "invalid")

    def test_requires_admin(self):
        with patch("core.firewall.is_admin", return_value=False):
            ok, message = self.firewall.set_blocked("8.8.8.8", 443, "out", "TCP", True)
        self.assertFalse(ok)
        self.assertEqual(message, "admin")

    def test_add_and_remove_rule(self):
        with patch("core.firewall.is_admin", return_value=True), \
             patch.object(self.firewall, "_run", return_value=(True, "")):
            ok, _ = self.firewall.set_blocked("8.8.8.8", 443, "out", "TCP", True)
            self.assertTrue(ok)
            self.assertTrue(self.firewall.is_blocked("8.8.8.8", 443, "out", "TCP"))
            ok, _ = self.firewall.set_blocked("8.8.8.8", 443, "out", "TCP", False)
            self.assertTrue(ok)
            self.assertFalse(self.firewall.is_blocked("8.8.8.8", 443, "out", "TCP"))

    def test_rule_name_is_safe(self):
        name = FirewallManager._name("in", "2001:db8::1", 443, "TCP")
        self.assertNotIn(":", name)
        self.assertIn("2001-db8--1", name)


class TrafficUiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from PyQt5.QtWidgets import QApplication
        cls.app = QApplication.instance() or QApplication([])

    def test_page_columns_and_filters(self):
        from ui.studio import LIGHT
        from ui.traffic import TrafficPage
        shell = SimpleNamespace(tray=None)
        page = TrafficPage(LIGHT, shell)
        try:
            self.assertEqual(page.table.columnCount(), 10)
            self.assertIn("Block download", [page.table.horizontalHeaderItem(i).text() for i in range(10)])
            self.assertGreaterEqual(page.scope.count(), 4)
        finally:
            page.shutdown()

    def test_filtering_and_detection_context(self):
        from ui.studio import LIGHT
        from ui.traffic import TrafficPage
        from core.live_traffic import ConnectionView
        shell = SimpleNamespace(tray=None)
        page = TrafficPage(LIGHT, shell)
        try:
            public = ConnectionView(
                key="k1", pid=10, app="evil.exe", exe=r"C:\Temp\evil.exe",
                username="bob", ppid=4, parent="explorer.exe",
                cmdline="evil.exe", started="", local_ip="10.0.0.2", local_port=5000,
                remote_ip="8.8.8.8", remote_port=443, protocol="TCP",
                state="ESTABLISHED", family="IPv4", domain="dns.google",
                service="HTTPS", age=12, first_seen=0, is_public=True, is_lan=False,
                risk="medium", reasons=["suspicious_port"],
            )
            page.scope.setCurrentIndex(1)  # Internet
            self.assertEqual(len(page._filtered([public])), 1)
            page.risk_filter.setCurrentIndex(1)  # To review only
            self.assertEqual(len(page._filtered([public])), 1)
            detection = page._detection(public)
            self.assertEqual(detection.indicator, "dns.google:443")
            self.assertEqual(detection.evidence["process"]["ppid"], 4)
            self.assertEqual(detection.evidence["connection"]["remote_ip"], "8.8.8.8")
        finally:
            page.shutdown()

    def test_blockable_requires_public_remote(self):
        from core.live_traffic import ConnectionView
        common = dict(key="k", pid=1, app="a", exe="", username="", ppid=1,
                      parent="", cmdline="", started="", local_ip="10.0.0.1",
                      local_port=1, remote_port=443, protocol="TCP", state="ESTABLISHED",
                      family="IPv4", domain="", service="", age=1, first_seen=0,
                      is_lan=False, risk="info", reasons=[])
        loopback = ConnectionView(remote_ip="127.0.0.1", is_public=False, **common)
        public = ConnectionView(remote_ip="8.8.8.8", is_public=True, **common)
        self.assertFalse(loopback.blockable)
        self.assertTrue(public.blockable)

    def test_detail_dialog_constructs(self):
        from ui.studio import LIGHT
        from ui.traffic import ConnectionDetailDialog, TrafficPage
        from core.live_traffic import ConnectionView
        shell = SimpleNamespace(tray=None)
        page = TrafficPage(LIGHT, shell)
        try:
            conn = ConnectionView(
                key="k", pid=1, app="chrome.exe", exe=r"C:\chrome.exe", username="bob",
                ppid=4, parent="explorer.exe", cmdline="chrome", started="",
                local_ip="10.0.0.2", local_port=5000, remote_ip="8.8.8.8",
                remote_port=443, protocol="TCP", state="ESTABLISHED", family="IPv4",
                domain="dns.google", service="HTTPS", age=5, first_seen=0,
                is_public=True, is_lan=False, risk="medium", reasons=["suspicious_port"],
            )
            dialog = ConnectionDetailDialog(LIGHT, conn, page)
            dialog.show()
            dialog.close()
        finally:
            page.shutdown()

    def test_guide_dialog_constructs(self):
        from ui.studio import LIGHT
        from ui.traffic import TrafficGuideDialog
        dialog = TrafficGuideDialog(LIGHT)
        dialog.show()
        dialog.close()

    def test_finding_dialog_initial_tab(self):
        from ui.studio import LIGHT
        from ui.findings import FindingDialog
        from scanners.base_scanner import Detection, RiskLevel
        detection = Detection(
            detection_id="D1", detection_type="live_connection", indicator="8.8.8.8:443",
            indicator_type="network", risk_level=RiskLevel.MEDIUM, confidence=0.5,
            description="test", detection_reason="test", evidence={},
        )
        dialog = FindingDialog(LIGHT, detection, initial_tab="vt")
        try:
            self.assertEqual(dialog.tabs.currentIndex(), dialog._tab_indices["vt"])
        finally:
            dialog.close()


if __name__ == "__main__":
    unittest.main()
