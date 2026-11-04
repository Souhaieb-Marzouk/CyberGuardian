"""
CyberGuardian — Studio UI
=========================

The adopted application design: light and dark variants of the same editorial
layout.  All scanners are wired through one generic :class:`ScanPage`, and the
theme is a token set, so adding a page or a third theme stays cheap.
"""

from __future__ import annotations

import sys
from typing import Callable, Dict, List, Optional

from PyQt5.QtCore import QSettings, Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QFrame, QGraphicsDropShadowEffect,
    QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QProgressBar,
    QPushButton, QScrollArea, QStackedWidget, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget, QHeaderView, QCheckBox,
)

from ui.design_common import Bars, Gauge, load_fonts, micro
from ui.findings import FindingDialog, FindingsPage
from ui.canaries import CanariesPage, CanaryReportDialog

# ---------------------------------------------------------------------------
# Themes
# ---------------------------------------------------------------------------

LIGHT = {
    "name": "light",
    "bg": "#f3f4f6", "surface": "#ffffff", "line": "#e4e7ec",
    "ink": "#1b2430", "muted": "#6b7785",
    "accent": "#2f7f6f", "accent_soft": "#e6f4ef",
    "hero_a": "#e6f4ef", "hero_b": "#e8effa",
    "chip_bg": "#eef0f3", "shadow": 26,
    "critical": "#b23b57", "high": "#cf6b47", "medium": "#b7791f", "low": "#2f7f6f",
}

DARK = {
    "name": "dark",
    "bg": "#0f141b", "surface": "#161d27", "line": "#27303d",
    "ink": "#e9eef5", "muted": "#93a0b3",
    "accent": "#4fd1b5", "accent_soft": "#17352f",
    "hero_a": "#14251f", "hero_b": "#141d2c",
    "chip_bg": "#1d2632", "shadow": 70,
    "critical": "#ef7d92", "high": "#f09a72", "medium": "#e5c07b", "low": "#6fd6b8",
}

THEMES = {"light": LIGHT, "dark": DARK}

def qss(t: Dict) -> str:
    return f"""
    QMainWindow, QWidget {{ background: {t['bg']}; color: {t['ink']};
        font-family: '{{font}}'; font-size: 13px; }}
    QLabel {{ background: transparent; }}
    QFrame#card {{ background: {t['surface']}; border: 1px solid {t['line']};
        border-radius: 20px; }}
    QFrame#row {{ background: transparent; border: none;
        border-bottom: 1px solid {t['line']}; }}
    QFrame#tile {{ background: {t['surface']}; border: 1px solid {t['line']};
        border-radius: 16px; }}
    QPushButton {{ background: {t['surface']}; color: {t['ink']};
        border: 1px solid {t['line']}; border-radius: 12px; padding: 9px 16px; }}
    QPushButton:hover {{ border-color: {t['accent']}; color: {t['accent']}; }}
    QPushButton#primary {{ background: {t['accent']}; color: #ffffff;
        border: none; font-weight: 700; }}
    QPushButton#primary:hover {{ background: {t['accent']}; color: #ffffff; }}
    QPushButton#ghost {{ border: none; background: transparent;
        color: {t['accent']}; font-weight: 600; }}
    QPushButton#pill {{ border: none; background: transparent; color: {t['muted']};
        padding: 8px 14px; border-radius: 11px; font-weight: 600; }}
    QPushButton#pill:checked {{ background: {t['accent_soft']};
        color: {t['accent']}; font-weight: 700; }}
    QPushButton#nav {{ text-align: left; border: none; background: transparent;
        color: {t['muted']}; padding: 9px 12px; border-radius: 10px; }}
    QPushButton#nav:checked {{ background: {t['accent_soft']}; color: {t['accent']}; }}
    QTableWidget {{ background: {t['surface']}; border: 1px solid {t['line']};
        border-radius: 16px; gridline-color: {t['line']};
        alternate-background-color: {t['bg']}; }}
    QHeaderView::section {{ background: {t['bg']}; color: {t['muted']};
        border: none; padding: 9px; font-weight: 600; }}
    QTableWidget::item:selected {{ background: {t['accent_soft']}; color: {t['ink']}; }}
    QProgressBar {{ background: {t['line']}; border: none; border-radius: 4px;
        height: 6px; color: transparent; }}
    QProgressBar::chunk {{ background: {t['accent']}; border-radius: 4px; }}
    QComboBox, QLineEdit {{ background: {t['surface']}; border: 1px solid {t['line']};
        border-radius: 10px; padding: 8px 10px; color: {t['ink']}; }}
    QCheckBox {{ color: {t['ink']}; }}
    QScrollArea {{ border: none; background: transparent; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; }}
    QScrollBar::handle:vertical {{ background: {t['line']}; border-radius: 5px; min-height: 30px; }}
    """


def card(t: Dict, radius: int = 20, padding: int = 24) -> QFrame:
    frame = QFrame()
    frame.setObjectName("card")
    frame.body = QVBoxLayout(frame)
    frame.body.setContentsMargins(padding, padding, padding, padding)
    frame.body.setSpacing(12)
    return frame


def soft_shadow(widget: QWidget, t: Dict, blur: int = 26, dy: int = 5):
    effect = QGraphicsDropShadowEffect(widget)
    effect.setBlurRadius(blur)
    effect.setOffset(0, dy)
    effect.setColor(QColor(15, 23, 35, t["shadow"]))
    widget.setGraphicsEffect(effect)


def pill(text: str, t: Dict) -> QLabel:
    label = QLabel(text)
    label.setStyleSheet(
        f"background: {t['chip_bg']}; color: {t['muted']}; border-radius: 10px;"
        " padding: 3px 10px; font-size: 11px; font-weight: 600;"
    )
    return label


# ---------------------------------------------------------------------------
# Scan plumbing
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    progress = pyqtSignal(int, int, str)
    detection = pyqtSignal(object)
    finished_scan = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, scanner, target=None, deep: bool = False):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.deep = deep

    def run(self):
        try:
            self.scanner.reset_cancel()
            self.scanner.set_progress_callback(
                lambda c, total, m: self.progress.emit(c, total, m)
            )
            self.scanner.set_detection_callback(self.detection.emit)
            import inspect
            if self.deep and "deep_analysis" in inspect.signature(self.scanner.scan).parameters:
                self.finished_scan.emit(self.scanner.scan(self.target, deep_analysis=True))
            else:
                self.finished_scan.emit(self.scanner.scan(self.target))
        except Exception as exc:  # pragma: no cover
            self.failed.emit(str(exc))

    def stop(self):
        try:
            self.scanner.cancel()
        except Exception:
            pass


class ScanPage(QWidget):
    def __init__(self, t: Dict, title: str, description: str,
                 factory: Callable, needs_target: bool = False, shell=None):
        super().__init__()
        self.t, self.factory, self.needs_target = t, factory, needs_target
        self.shell = shell
        self.title_text = title
        self.description = description
        self.worker: Optional[ScanWorker] = None
        self.target = None
        self.detections = []
        self.result = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 26, 36, 30)
        layout.setSpacing(16)
        layout.addWidget(micro(title, t["muted"]))
        heading = QLabel(description)
        heading.setWordWrap(True)
        heading.setStyleSheet(f"color: {t['ink']}; font-size: 26px; font-weight: 700;")
        layout.addWidget(heading)

        actions = QHBoxLayout()
        self.run_btn = QPushButton("Run scan")
        self.run_btn.setObjectName("primary")
        self.run_btn.clicked.connect(self.start)
        actions.addWidget(self.run_btn)

        self.detail_btn = QPushButton("View details")
        self.detail_btn.clicked.connect(self._open_details)
        actions.addWidget(self.detail_btn)

        self.export_btn = QPushButton("Export results")
        self.export_btn.clicked.connect(self._export)
        actions.addWidget(self.export_btn)
        self.state = QLabel("Ready when you are.")
        self.state.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
        actions.addWidget(self.state, 1)
        layout.addLayout(actions)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Risk", "Finding", "Indicator", "Confidence"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.doubleClicked.connect(self._open_details)
        layout.addWidget(self.table, 1)

    def start(self):
        if self.worker and self.worker.isRunning():
            return
        if self.needs_target:
            path = QFileDialog.getExistingDirectory(self, "Choose a folder to scan")
            if not path:
                return
            self.target = path
        self.table.setRowCount(0)
        self.detections = []
        self.result = None
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.run_btn.setEnabled(False)
        self.state.setText("Scanning…")
        if self.shell:
            self.shell.set_busy(True)
        deep = False
        try:
            from utils.config import get_config
            deep = bool(get_config().config.scan.deep_analysis)
        except Exception:
            deep = False
        self.worker = ScanWorker(self.factory(), self.target, deep=deep)
        self.worker.progress.connect(self._progress)
        self.worker.detection.connect(self._detection)
        self.worker.finished_scan.connect(self._finished)
        self.worker.failed.connect(self._failed)
        self.worker.start()

    def _progress(self, current, total, message):
        if total > 0:
            self.progress.setRange(0, total)
            self.progress.setValue(current)
        self.state.setText(message[:120])

    def _export(self):
        from PyQt5.QtWidgets import QFileDialog, QMessageBox
        from reporting.export import export_results

        if self.result is None or not self.result.detections:
            QMessageBox.information(self, "Export", "Run a scan with findings first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export scan results", f"{self.title_text.lower()}_findings.csv",
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        try:
            written = export_results([self.result], path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        QMessageBox.information(self, "Export", f"Saved {len(self.result.detections)} finding(s) to:\n{written}")

    def _open_details(self, *_):
        row = self.table.currentRow()
        if 0 <= row < len(self.detections):
            FindingDialog(self.t, self.detections[row], self).exec_()

    def _detection(self, detection):
        self.detections.append(detection)
        row = self.table.rowCount()
        self.table.insertRow(row)
        risk = detection.risk_level.value
        values = [risk.upper(), detection.detection_type, detection.indicator,
                  f"{detection.confidence:.0%}"]
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if column == 0:
                item.setForeground(QColor(self.t.get(risk, self.t["ink"])))
            self.table.setItem(row, column, item)

    def _finished(self, result):
        self.result = result
        self.run_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.state.setText(
            f"Complete · {result.total_items} items · {len(result.detections)} findings"
        )
        if self.shell:
            self.shell.on_scan_done(result)

    def _failed(self, message):
        self.run_btn.setEnabled(True)
        self.progress.setVisible(False)
        self.state.setText(f"Scan failed: {message}")
        if self.shell:
            self.shell.set_busy(False)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

class OverviewPage(QWidget):
    def __init__(self, t: Dict, shell):
        super().__init__()
        self.t, self.shell = t, shell
        from utils.config import get_config
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        scroll.setWidget(inner)
        layout = QVBoxLayout(inner)
        layout.setContentsMargins(36, 26, 36, 30)
        layout.setSpacing(18)

        hero = card(t, radius=24, padding=28)
        hero.setStyleSheet(
            f"QFrame#card {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1,"
            f" stop:0 {t['hero_a']}, stop:1 {t['hero_b']});"
            f" border: 1px solid {t['line']}; border-radius: 24px; }}"
        )
        soft_shadow(hero, t)

        row = QHBoxLayout()
        row.setSpacing(26)
        copy = QVBoxLayout()
        copy.setSpacing(9)
        copy.addWidget(micro("local session  ·  private by design", t["muted"]))
        self.headline = QLabel("Your PC looks healthy.")
        self.headline.setStyleSheet(f"color: {t['ink']}; font-size: 33px; font-weight: 700;")
        copy.addWidget(self.headline)
        self.subline = QLabel(
            "Check what starts with Windows, what is running now, and the last "
            "24 hours of activity — all on this machine."
        )
        self.subline.setWordWrap(True)
        self.subline.setStyleSheet(f"color: {t['muted']}; font-size: 13px;")
        copy.addWidget(self.subline)

        chips = QHBoxLayout()
        chips.setSpacing(8)
        self.chip_findings = pill("No findings yet", t)
        chips.addWidget(pill("Real-time ready", t))
        chips.addWidget(self.chip_findings)
        chips.addStretch(1)
        copy.addLayout(chips)

        buttons = QHBoxLayout()
        run = QPushButton("Run a quick check")
        run.setObjectName("primary")
        run.clicked.connect(shell.quick_check)
        buttons.addWidget(run)
        findings = QPushButton("All scans")
        findings.setObjectName("ghost")
        findings.clicked.connect(lambda: shell.go_to("Scans"))
        buttons.addWidget(findings)
        buttons.addStretch(1)
        copy.addLayout(buttons)
        copy.addStretch(1)
        row.addLayout(copy, 5)

        self.gauge = Gauge(t["accent"], t["line"], t["ink"], t["muted"], "health score")
        self.gauge.set_value(100)
        self.gauge.setMinimumSize(250, 195)
        row.addWidget(self.gauge, 2, Qt.AlignCenter)
        hero.body.addLayout(row)
        layout.addWidget(hero)

        stats = QHBoxLayout()
        stats.setSpacing(16)
        self.stat_values = {}
        for key, caption in (("items", "objects checked"), ("findings", "findings"),
                             ("apps", "applications"), ("events", "log events")):
            tile = QFrame()
            tile.setObjectName("tile")
            tile.body = QVBoxLayout(tile)
            tile.body.setContentsMargins(20, 18, 20, 18)
            tile.body.setSpacing(4)
            tile.body.addWidget(micro(caption, t["muted"]))
            value = QLabel("—")
            value.setStyleSheet(f"color: {t['ink']}; font-size: 28px; font-weight: 700;")
            tile.body.addWidget(value)
            soft_shadow(tile, t, blur=20, dy=4)
            stats.addWidget(tile, 1)
            self.stat_values[key] = value
        layout.addLayout(stats)

        bottom = QHBoxLayout()
        bottom.setSpacing(16)

        attention = card(t)
        soft_shadow(attention, t)
        head = QHBoxLayout()
        head.addWidget(QLabel("Worth a look"))
        head.itemAt(0).widget().setStyleSheet(
            f"color: {t['ink']}; font-size: 16px; font-weight: 700;"
        )
        head.addStretch(1)
        head.addWidget(micro("sorted by risk", t["muted"]))
        attention.body.addLayout(head)
        self.attention_box = QVBoxLayout()
        self.attention_box.setSpacing(0)
        attention.body.addLayout(self.attention_box)
        attention.body.addStretch(1)
        bottom.addWidget(attention, 3)

        checked = card(t)
        soft_shadow(checked, t)
        title = QLabel("What we checked")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 16px; font-weight: 700;")
        checked.body.addWidget(title)
        self.checked_box = QVBoxLayout()
        self.checked_box.setSpacing(0)
        checked.body.addLayout(self.checked_box)
        self.checked_marks = {}
        for text in ("Startup programs and services", "Running processes and signatures",
                     "Windows event logs", "Installed software", "Network connections"):
            self._checked_row(text, False)
        checked.body.addStretch(1)
        bottom.addWidget(checked, 2)

        layout.addLayout(bottom, 1)
        outer.addWidget(scroll)

    def _checked_row(self, text: str, done: bool):
        row = QFrame()
        row.setObjectName("row")
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 7, 0, 7)
        mark = QLabel("✓" if done else "○")
        mark.setStyleSheet(f"color: {self.t['accent'] if done else self.t['muted']};")
        line.addWidget(mark)
        self.checked_marks[text] = mark
        item = QLabel(text)
        item.setStyleSheet(f"color: {self.t['ink'] if done else self.t['muted']}; font-size: 12px;")
        line.addWidget(item, 1)
        self.checked_box.addWidget(row)

    def set_findings(self, detections: List):
        while self.attention_box.count():
            item = self.attention_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        if not detections:
            empty = QLabel("Nothing needs attention right now.")
            empty.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
            self.attention_box.addWidget(empty)
            return
        for detection in detections[:5]:
            self.attention_box.addWidget(self._finding_row(detection))

    def _finding_row(self, detection) -> QFrame:
        tone = self.t.get(detection.risk_level.value, self.t["muted"])
        row = QFrame()
        row.setObjectName("row")
        line = QHBoxLayout(row)
        line.setContentsMargins(0, 11, 0, 11)
        dot = QLabel("●")
        dot.setStyleSheet(f"color: {tone}; font-size: 9px;")
        line.addWidget(dot)
        text = QVBoxLayout()
        text.setSpacing(2)
        name = QLabel(detection.description[:70])
        name.setStyleSheet(f"color: {self.t['ink']}; font-size: 13px; font-weight: 600;")
        sub = QLabel(f"{detection.detection_type} · {detection.indicator[:60]}")
        sub.setStyleSheet(f"color: {self.t['muted']}; font-size: 11px;")
        text.addWidget(name)
        text.addWidget(sub)
        line.addLayout(text, 1)
        pill_label = pill(detection.risk_level.value.upper(), self.t)
        pill_label.setStyleSheet(
            f"background: {tone}22; color: {tone}; border-radius: 9px;"
            " padding: 2px 8px; font-size: 10px; font-weight: 700;"
        )
        line.addWidget(pill_label)
        return row


class ScansPage(QWidget):
    def __init__(self, t: Dict, shell):
        super().__init__()
        self.t = t
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        header = QWidget()
        header_layout = QVBoxLayout(header)
        header_layout.setContentsMargins(36, 26, 36, 10)
        title = QLabel("Scans")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        header_layout.addWidget(title)
        header_layout.addWidget(QLabel("Pick a scanner. Results stay on this machine."))
        header_layout.itemAt(1).widget().setStyleSheet(f"color: {t['muted']};")
        layout.addWidget(header)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        tabs = QHBoxLayout()
        tabs.setContentsMargins(36, 0, 36, 10)
        tabs.setSpacing(6)
        from scanners.process_scanner import ProcessScanner
        from scanners.file_scanner import FileScanner
        from scanners.network_scanner import NetworkScanner
        from scanners.registry_scanner import RegistryScanner
        from scanners.eventlog_scanner import EventLogScanner

        self.pages = {}
        for key, desc, factory, target in (
            ("Processes", "What is running right now, and what looks wrong.", ProcessScanner, False),
            ("Files", "Static analysis of a folder: YARA, entropy, PE, Office, stego.", FileScanner, True),
            ("Network", "Live connections, listeners and C2-style patterns.", NetworkScanner, False),
            ("Registry", "Autoruns, services and persistence locations.", RegistryScanner, False),
            ("Activity", "Logons, services, tasks and tampering in Windows logs.", EventLogScanner, False),
        ):
            page = ScanPage(t, key, desc, factory, needs_target=target, shell=shell)
            page.setVisible(False)
            self.pages[key] = page
            self.stack.addWidget(page)

        for index, key in enumerate(self.pages):
            button = QPushButton(key)
            button.setObjectName("pill")
            button.setCheckable(True)
            button.setChecked(index == 0)
            button.clicked.connect(lambda _=False, name=key: self.show_page(name))
            tabs.addWidget(button)
        tabs.addStretch(1)
        layout.insertLayout(1, tabs)
        self.show_page("Processes")

    def show_page(self, key: str):
        page = self.pages.get(key)
        if not page:
            return
        self.stack.setCurrentWidget(page)
        for button in self.findChildren(QPushButton, "pill"):
            button.setChecked(button.text() == key)


class ToolsPage(QWidget):
    def __init__(self, t: Dict, shell):
        super().__init__()
        self.t = t
        self.shell = shell
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 26, 36, 30)
        layout.setSpacing(16)
        title = QLabel("Tools")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        layout.addWidget(title)
        layout.addWidget(QLabel("Startup, software, reputation checks, canaries and quarantine."))
        layout.itemAt(1).widget().setStyleSheet(f"color: {t['muted']};")

        row = QHBoxLayout()
        row.setSpacing(16)
        for heading, body, handler in (
            ("Toolbox", "Startup impact, installed software, file/link checks, canaries, quarantine.", self._tools),
            ("PC health", "Score, recommendations and what changed since last time.", self._health),
        ):
            frame = card(t)
            soft_shadow(frame, t)
            name = QLabel(heading)
            name.setStyleSheet(f"color: {t['ink']}; font-size: 17px; font-weight: 700;")
            frame.body.addWidget(name)
            description = QLabel(body)
            description.setWordWrap(True)
            description.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
            frame.body.addWidget(description)
            button = QPushButton("Open")
            button.setObjectName("primary")
            button.clicked.connect(handler)
            frame.body.addWidget(button, 0, Qt.AlignLeft)
            frame.body.addStretch(1)
            row.addWidget(frame, 1)
        layout.addLayout(row)
        layout.addStretch(1)

    def _tools(self):
        from ui import tools_dialog
        # The dialog builds its inline styles at construction time, so map the
        # active theme into its palette first.
        t = self.t
        tools_dialog.COLORS.update({
            "bg": t["bg"], "card": t["surface"], "border": t["line"],
            "text": t["ink"], "muted": t["muted"], "primary": t["accent"],
            "medium": t["medium"], "high": t["high"], "critical": t["critical"],
        })
        tools_dialog.ToolsDialog(self).exec_()

    def _health(self):
        from core.health import TimelineStore, compute_health
        from ui.main_window import HealthDialog
        try:
            changes = TimelineStore().diff()
        except Exception:
            changes = []
        HealthDialog(compute_health([]), changes, self).exec_()


class LogsPage(QWidget):
    def __init__(self, t: Dict):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 26, 36, 30)
        title = QLabel("Activity log")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        layout.addWidget(title)
        self.view = QTableWidget(0, 2)
        self.view.setHorizontalHeaderLabels(["Time", "Event"])
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.view.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.view, 1)

    def append(self, text: str):
        from datetime import datetime
        row = self.view.rowCount()
        self.view.insertRow(row)
        self.view.setItem(row, 0, QTableWidgetItem(datetime.now().strftime("%H:%M:%S")))
        self.view.setItem(row, 1, QTableWidgetItem(text))


class SettingsPage(QWidget):
    def __init__(self, t: Dict, shell):
        super().__init__()
        self.t, self.shell = t, shell
        from utils.config import get_config
        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 26, 36, 30)
        layout.setSpacing(16)
        title = QLabel("Settings")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        layout.addWidget(title)

        appearance = card(t)
        appearance.body.addWidget(QLabel("Appearance"))
        appearance.body.itemAt(0).widget().setStyleSheet(
            f"color: {t['ink']}; font-size: 15px; font-weight: 700;"
        )
        row = QHBoxLayout()
        row.addWidget(QLabel("Theme"))
        self.theme_box = QComboBox()
        self.theme_box.addItems(["Light", "Dark"])
        self.theme_box.setCurrentText(t["name"].title())
        self.theme_box.currentTextChanged.connect(shell.change_theme)
        row.addWidget(self.theme_box, 1)
        appearance.body.addLayout(row)
        layout.addWidget(appearance)

        engine = card(t)
        engine.body.addWidget(QLabel("Detection"))
        engine.body.itemAt(0).widget().setStyleSheet(
            f"color: {t['ink']}; font-size: 15px; font-weight: 700;"
        )
        self.deep = QCheckBox("Enable deep analysis on supported scans")
        self.deep.setChecked(bool(get_config().config.scan.deep_analysis))
        self.deep.toggled.connect(self._toggle_deep)
        engine.body.addWidget(self.deep)

        from utils.config import get_config
        self.online = QCheckBox("Check hashes with VirusTotal (slower, needs API key)")
        self.online.setChecked(bool(get_config().config.scan.online_reputation))
        self.online.toggled.connect(self._toggle_online)
        engine.body.addWidget(self.online)
        open_settings = QPushButton("Open advanced settings (API keys, whitelist, YARA)")
        open_settings.clicked.connect(shell.open_advanced_settings)
        engine.body.addWidget(open_settings, 0, Qt.AlignLeft)
        layout.addWidget(engine)
        layout.addStretch(1)

    def _toggle_deep(self, enabled: bool):
        from utils.config import get_config
        config = get_config()
        config.set("scan.deep_analysis", bool(enabled))
        config.save()

    def _toggle_online(self, enabled: bool):
        from utils.config import get_config
        config = get_config()
        config.set("scan.online_reputation", bool(enabled))
        config.save()


# ---------------------------------------------------------------------------
# Shell
# ---------------------------------------------------------------------------

class StudioWindow(QMainWindow):
    def __init__(self, theme: str = "light", results: Optional[List] = None, page: str = "Overview"):
        super().__init__()
        self.theme_name = theme if theme in THEMES else "light"
        self.t = THEMES[self.theme_name]
        self.results: List = results or []
        self.findings: List = []

        self.setWindowTitle("CyberGuardian")
        self.resize(1280, 840)
        self.setStyleSheet(qss(self.t).replace("{font}", load_fonts()))

        root = QWidget()
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addWidget(self._header())

        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)

        self.pages: Dict[str, QWidget] = {}
        self.overview = OverviewPage(self.t, self)
        self.scans = ScansPage(self.t, self)
        self.tools = ToolsPage(self.t, self)
        self.logs = LogsPage(self.t)
        self.settings = SettingsPage(self.t, self)
        self.findings_page = FindingsPage(self.t, self)
        self.canaries = CanariesPage(self.t, self)
        for key, widget in (("Overview", self.overview), ("Scans", self.scans),
                            ("Findings", self.findings_page), ("Canaries", self.canaries),
                            ("Tools", self.tools), ("Logs", self.logs),
                            ("Settings", self.settings)):
            self.pages[key] = widget
            self.stack.addWidget(widget)

        self.all_findings = []
        self.canaries.events_detected.connect(self._on_canary_events)
        self._setup_tray()
        self.statusBar().showMessage("Ready")
        self.go_to(page)
        self.refresh_overview()

    # ------------------------------------------------------------------ header
    def _header(self) -> QWidget:
        bar = QWidget()
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(34, 18, 34, 14)
        layout.setSpacing(14)

        mark = QLabel("CG")
        mark.setFixedSize(36, 36)
        mark.setAlignment(Qt.AlignCenter)
        mark.setStyleSheet(
            f"background: {self.t['accent']}; color: white; border-radius: 11px; font-weight: 800;"
        )
        layout.addWidget(mark)
        brand = QLabel("CyberGuardian")
        brand.setStyleSheet(f"color: {self.t['ink']}; font-size: 17px; font-weight: 700;")
        layout.addWidget(brand)
        layout.addSpacing(14)

        self.nav_buttons = {}
        for key in ("Overview", "Scans", "Findings", "Canaries", "Tools", "Logs"):
            button = QPushButton(key)
            button.setObjectName("pill")
            button.setCheckable(True)
            button.clicked.connect(lambda _=False, name=key: self.go_to(name))
            layout.addWidget(button)
            self.nav_buttons[key] = button
        layout.addStretch(1)

        theme_button = QPushButton("Dark mode" if self.theme_name == "light" else "Light mode")
        theme_button.clicked.connect(self.toggle_theme)
        layout.addWidget(theme_button)

        settings = QPushButton("Settings")
        settings.clicked.connect(lambda: self.go_to("Settings"))
        layout.addWidget(settings)
        return bar

    # --------------------------------------------------------------- behaviour
    def go_to(self, key: str):
        page = self.pages.get(key)
        if page is None:
            return
        self.stack.setCurrentWidget(page)
        for name, button in self.nav_buttons.items():
            button.setChecked(name == key)
        self.statusBar().showMessage(key)

    def toggle_theme(self):
        self.change_theme("Dark" if self.theme_name == "light" else "Light")

    def change_theme(self, name: str):
        target = "dark" if str(name).lower().startswith("d") else "light"
        if target == self.theme_name:
            return
        QSettings("CyberGuardian", "CyberGuardian").setValue("ui/theme", target)
        current = self.stack.currentWidget()
        page_key = next((key for key, page in self.pages.items() if page is current), "Overview")
        geometry = self.saveGeometry()
        maximised = self.isMaximized()
        replacement = StudioWindow(target, self.results, page_key)
        replacement.show()
        if maximised:
            replacement.showMaximized()
        else:
            replacement.restoreGeometry(geometry)
        self.close()

    def quick_check(self):
        self.go_to("Scans")
        self.scans.show_page("Processes")
        self.scans.pages["Processes"].start()

    def set_busy(self, busy: bool):
        self.statusBar().showMessage("Scanning…" if busy else "Ready")

    SCAN_TO_CHECK = {
        "process": "Running processes and signatures",
        "registry": "Startup programs and services",
        "eventlog": "Windows event logs",
        "file": "Files and downloads",
        "network": "Network connections",
    }

    def on_scan_done(self, result):
        item = self.SCAN_TO_CHECK.get(getattr(result, "scan_type", ""))
        mark = self.overview.checked_marks.get(item) if item else None
        if mark is not None:
            mark.setText("✓")
            mark.setStyleSheet(f"color: {self.t['accent']};")

        self.results.append(result)
        self.findings.extend(result.detections)
        for detection in result.detections:
            self.all_findings.append((result.scan_type.title(), detection))
        self.findings_page.set_detections(self.all_findings)

        self.logs.append(
            f"{result.scan_type}: {result.total_items} items, {len(result.detections)} findings"
        )
        self.refresh_overview()
        self.set_busy(False)

    def refresh_overview(self):
        from core.health import compute_health

        report = compute_health(self.results)
        self.overview.gauge.set_value(report.score)
        self.overview.chip_findings.setText(
            "No findings yet" if not self.findings else f"{len(self.findings)} findings"
        )
        if report.score >= 85:
            self.overview.headline.setText("Your PC looks healthy.")
        elif report.score >= 60:
            self.overview.headline.setText("A few things are worth checking.")
        else:
            self.overview.headline.setText("This PC needs your attention.")
        self.overview.subline.setText(report.detail)

        items = sum(result.total_items for result in self.results)
        self.overview.stat_values["items"].setText(f"{items:,}".replace(",", " "))
        self.overview.stat_values["findings"].setText(str(len(self.findings)))

        events = sum(r.total_items for r in self.results if getattr(r, "scan_type", "") == "eventlog")
        if events:
            self.overview.stat_values["events"].setText(f"{events:,}".replace(",", " "))
        if getattr(self, "_app_count", None) is None:
            try:
                from core.software import get_installed_software
                self._app_count = len(get_installed_software())
            except Exception:
                self._app_count = 0
        if self._app_count:
            self.overview.stat_values["apps"].setText(str(self._app_count))
        self.overview.set_findings(self.findings)

    # ------------------------------------------------------------ canary alerts
    def _setup_tray(self):
        try:
            self.tray = QSystemTrayIcon(
                self.style().standardIcon(QStyle.SP_ComputerIcon), self
            )
            self.tray.setToolTip("CyberGuardian · ransomware canaries armed")
            self.tray.show()
        except Exception:
            self.tray = None

    def _on_canary_events(self, events):
        if not events or getattr(self, "_canary_alert_open", False):
            return
        self._canary_alert_open = True
        first = events[0]
        location = first.renamed_to or first.path
        if self.tray is not None:
            self.tray.showMessage(
                "Possible ransomware activity",
                f"{first.name}\n{location}",
                QSystemTrayIcon.Warning,
                15000,
            )
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle("Canary alert")
        box.setText(f"<b>{first.name}</b> was {first.kind}.")
        box.setInformativeText(
            f"Location: {location}\n"
            f"Detected: {first.detected_at[:19].replace('T', ' ')}\n\n"
            f"{first.guidance[0]}"
        )
        open_btn = box.addButton("Open report", QMessageBox.AcceptRole)
        box.addButton("Dismiss", QMessageBox.RejectRole)
        try:
            box.exec_()
            if box.clickedButton() is open_btn:
                self.go_to("Canaries")
                CanaryReportDialog(self.t, first, self).exec_()
        finally:
            self._canary_alert_open = False

    def closeEvent(self, event):
        try:
            QSettings("CyberGuardian", "CyberGuardian").setValue("ui/geometry", self.saveGeometry())
            QSettings("CyberGuardian", "CyberGuardian").setValue("ui/maximised", self.isMaximized())
        except Exception:
            pass
        try:
            self.canaries.shutdown()
            if getattr(self, "tray", None) is not None:
                self.tray.hide()
        except Exception:
            pass
        super().closeEvent(event)

    def export_all_results(self):
        from PyQt5.QtWidgets import QFileDialog, QMessageBox
        from reporting.export import export_results

        if not self.results:
            QMessageBox.information(self, "Export", "No scan results to export yet.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export all results", "cyberguardian_findings.csv",
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        try:
            written = export_results(self.results, path)
        except Exception as exc:
            QMessageBox.critical(self, "Export failed", str(exc))
            return
        total = sum(len(result.detections) for result in self.results)
        QMessageBox.information(self, "Export", f"Saved {total} finding(s) to:\n{written}")

    def open_advanced_settings(self):
        from ui.main_window import SettingsDialog
        SettingsDialog(self).exec_()


def run() -> int:
    app = QApplication(sys.argv)
    theme = QSettings("CyberGuardian", "CyberGuardian").value("ui/theme", "light")
    window = StudioWindow(str(theme))
    window.show()
    try:
        settings = QSettings("CyberGuardian", "CyberGuardian")
        geometry = settings.value("ui/geometry")
        if geometry:
            window.restoreGeometry(geometry)
        if settings.value("ui/maximised", False, type=bool):
            window.showMaximized()
    except Exception:
        pass
    return app.exec_()
