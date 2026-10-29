"""Headless UI regression test: every button on every surface is exercised.

Runs with Qt's offscreen platform plugin, stubs modal dialogs and destructive
actions, and fails if any click raises or any button is left untested.
"""

import os
import shutil
import sys
import tempfile
import time
import traceback
import unittest
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PyQt5.QtCore import Qt
from PyQt5.QtTest import QTest
from PyQt5.QtWidgets import (
    QApplication, QDialog, QFileDialog, QMessageBox, QPushButton,
)

import psutil
import ui.main_window as mw
import ui.tools_dialog as td
from scanners.base_scanner import Detection, RiskLevel, ScanResult, ScanStatus

ERRORS = []
CLICKED = set()
ANSWERS = {"yes": False}


class ProbeApplication(QApplication):
    def notify(self, receiver, event):
        try:
            return super().notify(receiver, event)
        except Exception:
            ERRORS.append(traceback.format_exc())
            return False


def _question(parent, title, text, *args, **kwargs):
    return QMessageBox.Yes if ANSWERS["yes"] else QMessageBox.No


def _message(parent, title, text, *args, **kwargs):
    return QMessageBox.Ok


def _save(parent=None, caption="", directory="", filter="", *args, **kwargs):
    return str(Path(tempfile.gettempdir()) / "cg_ui_test_output.bin"), filter


def _open(parent=None, caption="", directory="", filter="", *args, **kwargs):
    target = Path(tempfile.gettempdir()) / "cg_ui_test_open.bin"
    target.write_bytes(b"MZ")
    return str(target), filter


def _directory(parent=None, caption="", directory="", *args, **kwargs):
    target = Path(tempfile.gettempdir()) / "cg_ui_test_scan"
    target.mkdir(exist_ok=True)
    (target / "sample.txt").write_text("probe", encoding="utf-8")
    return str(target)


def _no_exec(self):
    return 0


def _fake_scan(name):
    def scan(scanner_self, target=None, deep_analysis=False):
        if scanner_self.is_cancelled():
            return ScanResult(name, ScanStatus.CANCELLED, __import__("datetime").datetime.now())
        result = ScanResult(name, ScanStatus.COMPLETED, __import__("datetime").datetime.now())
        result.total_items = 3
        detection = Detection(
            detection_id="DET-UI", detection_type="ui_probe", indicator=str(ROOT / "tests" / "sample.txt"),
            indicator_type="file", risk_level=RiskLevel.HIGH, confidence=0.8,
            description="ui probe", detection_reason="ui probe",
        )
        result.add_detection(detection)
        result.finalize_counts()
        return result

    return scan


class FakeProcess:
    def __init__(self, pid):
        self.pid = pid

    def as_dict(self, *args, **kwargs):
        return {"pid": self.pid, "name": "fake.exe", "username": "tester",
                "exe": r"C:\Temp\fake.exe", "cmdline": [], "cpu_percent": 0.0,
                "memory_percent": 0.1, "create_time": 0.0, "status": "running"}

    def kill(self):
        pass

    def suspend(self):
        pass


class FakeMonitor:
    def __init__(self):
        self.running = False

    def is_running(self):
        return self.running

    def start(self, *args, **kwargs):
        self.running = True
        return True

    def stop(self):
        self.running = False

    def set_detection_callback(self, callback):
        pass


def buttons(widget):
    return [
        b for b in widget.findChildren(QPushButton)
        if b.objectName() != "qt_configureButton" and b.window() is widget
    ]


class ButtonTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or ProbeApplication([])
        cls.saved = {
            "question": QMessageBox.question,
            "information": QMessageBox.information,
            "warning": QMessageBox.warning,
            "critical": QMessageBox.critical,
            "exec_": QDialog.exec_,
            "getExistingDirectory": QFileDialog.getExistingDirectory,
            "getOpenFileName": QFileDialog.getOpenFileName,
            "getSaveFileName": QFileDialog.getSaveFileName,
            "webbrowser": mw.webbrowser.open,
            "subprocess": mw.subprocess,
            "secure_storage": mw.get_secure_storage,
            "load_keys": mw.load_all_api_keys,
            "canary_dirs": __import__("core.canary", fromlist=["CanaryManager"]).CanaryManager._target_directories,
            "set_enabled": td.set_enabled,
            "process": psutil.Process,
            "show_admin": mw.MainWindow._show_admin_warning,
        }

        QMessageBox.question = staticmethod(_question)
        QMessageBox.information = staticmethod(_message)
        QMessageBox.warning = staticmethod(_message)
        QMessageBox.critical = staticmethod(_message)
        QDialog.exec_ = _no_exec
        QFileDialog.getExistingDirectory = staticmethod(_directory)
        QFileDialog.getOpenFileName = staticmethod(_open)
        QFileDialog.getSaveFileName = staticmethod(_save)
        mw.webbrowser.open = lambda *a, **k: None
        mw.subprocess = type("FakeSubprocess", (), {"Popen": staticmethod(lambda *a, **k: None)})()
        storage = type("Storage", (), {
            "save_api_key": lambda self, *a, **k: True,
            "get_key": lambda self, *a, **k: "",
            "get_storage_type": lambda self: "test",
        })()
        mw.get_secure_storage = lambda: storage
        mw.load_all_api_keys = lambda: {}
        psutil.Process = FakeProcess

        from core import canary

        cls.canary_dir = ROOT / "tests" / "_tmp_ui_canary"
        shutil.rmtree(cls.canary_dir, ignore_errors=True)
        cls.canary_dir.mkdir(parents=True)
        canary.CanaryManager._target_directories = staticmethod(lambda: [cls.canary_dir])
        td.set_enabled = lambda entry, enabled: True

        cls.saved_scans = {
            scanner.__name__: scanner.scan
            for scanner in (mw.ProcessScanner, mw.FileScanner, mw.RegistryScanner, mw.NetworkScanner)
        }
        from scanners.eventlog_scanner import EventLogScanner

        cls.saved_scans["EventLogScanner"] = EventLogScanner.scan

        mw.ProcessScanner.scan = _fake_scan("process")
        mw.FileScanner.scan = _fake_scan("file")
        mw.RegistryScanner.scan = _fake_scan("registry")
        mw.NetworkScanner.scan = _fake_scan("network")
        EventLogScanner.scan = _fake_scan("eventlog")

        mw.MainWindow._show_admin_warning = lambda self: None
        cls.window = mw.MainWindow()
        cls.window.realtime_monitor = FakeMonitor()
        cls.window.show()
        cls.app.processEvents()

    @classmethod
    def tearDownClass(cls):
        try:
            cls.window.close()
            cls.app.processEvents()
        finally:
            QMessageBox.question = cls.saved["question"]
            QMessageBox.information = cls.saved["information"]
            QMessageBox.warning = cls.saved["warning"]
            QMessageBox.critical = cls.saved["critical"]
            QDialog.exec_ = cls.saved["exec_"]
            QFileDialog.getExistingDirectory = cls.saved["getExistingDirectory"]
            QFileDialog.getOpenFileName = cls.saved["getOpenFileName"]
            QFileDialog.getSaveFileName = cls.saved["getSaveFileName"]
            mw.webbrowser.open = cls.saved["webbrowser"]
            mw.subprocess = cls.saved["subprocess"]
            mw.get_secure_storage = cls.saved["secure_storage"]
            mw.load_all_api_keys = cls.saved["load_keys"]
            mw.MainWindow._show_admin_warning = cls.saved["show_admin"]
            psutil.Process = cls.saved["process"]
            td.set_enabled = cls.saved["set_enabled"]
            from core.canary import CanaryManager

            CanaryManager._target_directories = staticmethod(cls.saved["canary_dirs"])
            mw.ProcessScanner.scan = cls.saved_scans["ProcessScanner"]
            mw.FileScanner.scan = cls.saved_scans["FileScanner"]
            mw.RegistryScanner.scan = cls.saved_scans["RegistryScanner"]
            mw.NetworkScanner.scan = cls.saved_scans["NetworkScanner"]
            from scanners.eventlog_scanner import EventLogScanner

            EventLogScanner.scan = cls.saved_scans["EventLogScanner"]
            shutil.rmtree(cls.canary_dir, ignore_errors=True)

    def click(self, button, wait=0):
        CLICKED.add(id(button))
        if not button.isEnabled():
            return
        button.ensurePolished()
        QTest.mouseClick(button, Qt.LeftButton)
        self.app.processEvents()
        if wait:
            QTest.qWait(wait)

    def wait_for_scan(self, timeout=20):
        deadline = time.time() + timeout
        while time.time() < deadline:
            self.app.processEvents()
            worker = self.window.current_worker
            if worker is None or not worker.isRunning():
                return
            QTest.qWait(25)
        self.fail("scan did not finish")

    def assert_all_clicked(self, surface, widget):
        missing = [b.text() for b in buttons(widget) if id(b) not in CLICKED]
        self.assertEqual(missing, [], f"untested buttons in {surface}: {missing}")

    def test_01_main_window_buttons(self):
        window = self.window
        for attribute in (
            "process_btn", "file_btn", "registry_btn", "network_btn",
            "eventlog_btn", "health_btn", "tools_btn",
        ):
            self.click(getattr(window, attribute), wait=10)
            self.wait_for_scan()
        self.assertIn("completed", window.status_label.text().lower())

        # Stop an in-flight scan (the stop button is hidden until then).
        slow_scan = mw.ProcessScanner.scan

        def blocking_scan(scanner_self, target=None, deep_analysis=False):
            for _ in range(100):
                if scanner_self.is_cancelled():
                    return ScanResult("process", ScanStatus.CANCELLED,
                                      __import__("datetime").datetime.now())
                time.sleep(0.01)
            return ScanResult("process", ScanStatus.COMPLETED,
                              __import__("datetime").datetime.now())

        mw.ProcessScanner.scan = blocking_scan
        try:
            self.click(window.process_btn, wait=50)
            ANSWERS["yes"] = True
            self.click(window.stop_btn)
            self.wait_for_scan()
        finally:
            mw.ProcessScanner.scan = slow_scan

        for button in buttons(window):
            if button in (window.process_btn, window.file_btn, window.registry_btn,
                          window.network_btn, window.eventlog_btn, window.stop_btn):
                continue
            if button is window.realtime_btn:
                ANSWERS["yes"] = False
            self.click(button, wait=10)
        self.assert_all_clicked("main", window)
        self.assertEqual(ERRORS, [])

    def test_02_settings_dialog_buttons(self):
        dialog = mw.SettingsDialog(self.window)
        dialog.show()
        for button in buttons(dialog):
            ANSWERS["yes"] = True  # Reset confirmation
            self.click(button, wait=5)
        self.assert_all_clicked("settings", dialog)
        dialog.close()
        self.assertEqual(ERRORS, [])

    def test_03_detection_dialog_buttons(self):
        target = Path(tempfile.gettempdir()) / "cg_ui_delete.exe"
        target.write_bytes(b"MZ")
        detection = Detection(
            detection_id="DET-UI-2", detection_type="file", indicator=str(target),
            indicator_type="file", risk_level=RiskLevel.HIGH, confidence=0.5,
            description="ui", detection_reason="ui", file_path=str(target),
            process_name="fake.exe", process_id=4242,
        )
        dialog = mw.DetectionDialog(detection, self.window)
        dialog.action_requested.connect(self.window.handle_detection_action)
        dialog.show()
        ANSWERS["yes"] = True
        for button in buttons(dialog):
            self.click(button, wait=5)
        self.assert_all_clicked("detection", dialog)
        self.assertFalse(target.exists(), "Delete File should have removed the test file")
        dialog.close()
        self.assertEqual(ERRORS, [])

    def test_04_tools_dialog_buttons(self):
        from core.quarantine import get_vault

        seed = Path(tempfile.gettempdir()) / "cg_ui_seed.exe"
        seed.write_bytes(b"MZ seed")
        get_vault().quarantine(seed, "DET-UI-SEED", "ui test")

        dialog = td.ToolsDialog(self.window)
        dialog.show()
        for button in buttons(dialog):
            if "Restore" in button.text() or "Delete permanently" in button.text():
                if dialog.quarantine_table.rowCount() == 0:
                    seed2 = Path(tempfile.gettempdir()) / "cg_ui_seed2.exe"
                    seed2.write_bytes(b"MZ seed2")
                    get_vault().quarantine(seed2, "DET-UI-SEED2", "ui test")
                    dialog.refresh_quarantine()
                dialog.quarantine_table.selectRow(0)
            if "Disable selected" in button.text() or "Enable selected" in button.text():
                if dialog.startup_table.rowCount():
                    dialog.startup_table.selectRow(0)
            if button.text() == "Check":
                dialog.check_input.setText(str(ROOT / "tests" / "sample.txt"))
            ANSWERS["yes"] = "Delete permanently" in button.text()
            self.click(button, wait=5)
        self.assert_all_clicked("tools", dialog)
        dialog.close()
        self.assertEqual(ERRORS, [])

    def test_05_health_dialog_button(self):
        from core.health import compute_health

        dialog = mw.HealthDialog(compute_health([]), [], self.window)
        dialog.show()
        for button in buttons(dialog):
            self.click(button)
        self.assert_all_clicked("health", dialog)
        self.assertEqual(ERRORS, [])


if __name__ == "__main__":
    unittest.main()
