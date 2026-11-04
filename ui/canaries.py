"""
Ransomware canary workspace for the Studio UI.

Shows the armed decoys, a live incident feed, and a detailed report for each
event: full timeline, technical evidence and a step-by-step response guide.
"""

from __future__ import annotations

import os
import subprocess
from datetime import datetime

from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView, QLabel, QMessageBox,
    QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from core.canary import CanaryEvent, get_canary_manager
from ui.design_common import micro

KIND_COLORS = {
    "encrypted": "#c71f37", "modified": "#c56a1b", "deleted": "#c71f37",
    "renamed": "#c56a1b", "touched": "#8a6d1f",
}


def _fmt(stamp: str) -> str:
    try:
        return datetime.fromisoformat(stamp).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return stamp


class CanaryReportDialog(QDialog):
    """Detailed incident report for one canary event."""

    def __init__(self, t, event: CanaryEvent, parent=None):
        super().__init__(parent)
        self.t = t
        self.event = event
        self.setWindowTitle(f"Canary alert — {event.name}")
        self.setMinimumSize(780, 700)
        self.setStyleSheet(
            f"QDialog {{ background: {t['bg']}; color: {t['ink']}; }}"
            f"QLabel {{ color: {t['ink']}; }}"
            f"QTextEdit {{ background: {t['surface']}; border: 1px solid {t['line']};"
            f" border-radius: 10px; color: {t['ink']}; padding: 10px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(10)

        banner = QLabel("  POSSIBLE INTRUSION  ")
        banner.setAlignment(Qt.AlignCenter)
        banner.setStyleSheet(
            "background: #c71f37; color: white; font-weight: 800;"
            " border-radius: 8px; padding: 6px; letter-spacing: 1px;"
        )
        layout.addWidget(banner)

        title = QLabel(event.name)
        title.setStyleSheet(f"font-size: 22px; font-weight: 700; color: {t['ink']};")
        layout.addWidget(title)

        path = QLabel(event.path)
        path.setWordWrap(True)
        path.setTextInteractionFlags(Qt.TextSelectableByMouse)
        path.setStyleSheet(f"color: {t['muted']};")
        layout.addWidget(path)

        summary = QLabel(
            f"{event.kind.upper()} · detected {_fmt(event.detected_at)} · "
            f"{event.modification_count} event(s) on this file since {_fmt(event.first_seen)}"
        )
        summary.setStyleSheet("font-weight: 600; color: #c56a1b;")
        layout.addWidget(summary)

        layout.addWidget(micro("timeline", t["muted"]))
        timeline = QTextEdit()
        timeline.setReadOnly(True)
        timeline.setMaximumHeight(140)
        lines = [f"{index}.  {_fmt(stamp)}" for index, stamp in enumerate(event.timestamps, 1)]
        if not lines:
            lines = [f"1.  {_fmt(event.detected_at)}"]
        timeline.setPlainText("\n".join(lines))
        layout.addWidget(timeline)

        layout.addWidget(micro("technical evidence", t["muted"]))
        details = QTextEdit()
        details.setReadOnly(True)
        details.setFont(QFont("Consolas", 9))
        detail_lines = [
            f"event id        : {event.event_id}",
            f"canary key      : {event.canary_key}",
            f"detection       : {event.kind}",
            f"path            : {event.path}",
            f"renamed / moved : {event.renamed_to or '-'}",
            f"size            : {event.previous_size} -> {event.current_size} bytes",
            f"sha256 before   : {event.previous_hash}",
            f"sha256 now      : {event.current_hash or '-'}",
            f"entropy now     : {event.entropy}",
        ]
        details.setPlainText("\n".join(detail_lines))
        layout.addWidget(details, 1)

        layout.addWidget(micro("what to do now", t["muted"]))
        guide = QTextEdit()
        guide.setReadOnly(True)
        guide.setPlainText("\n\n".join(
            f"{index}. {step}" for index, step in enumerate(event.guidance, 1)
        ))
        layout.addWidget(guide, 2)

        buttons = QDialogButtonBox()
        open_btn = QPushButton("Open folder")
        open_btn.clicked.connect(self._open_folder)
        buttons.addButton(open_btn, QDialogButtonBox.ActionRole)

        copy_btn = QPushButton("Copy report")
        copy_btn.clicked.connect(self._copy)
        buttons.addButton(copy_btn, QDialogButtonBox.ActionRole)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        buttons.addButton(close_btn, QDialogButtonBox.RejectRole)
        layout.addWidget(buttons)

    def _open_folder(self):
        folder = os.path.dirname(self.event.renamed_to or self.event.path)
        try:
            os.startfile(folder)  # noqa: S606 - Windows shell open
        except Exception as exc:
            QMessageBox.warning(self, "Open folder", str(exc))

    def _copy(self):
        text = (
            f"CyberGuardian canary alert\n"
            f"File: {self.event.name}\nPath: {self.event.path}\n"
            f"Type: {self.event.kind}\nDetected: {_fmt(self.event.detected_at)}\n"
            f"First seen: {_fmt(self.event.first_seen)}\n"
            f"Events: {self.event.modification_count}\n\n"
            + "\n".join(f"- {_fmt(s)}" for s in self.event.timestamps)
        )
        from PyQt5.QtWidgets import QApplication
        QApplication.clipboard().setText(text)
        QMessageBox.information(self, "Copied", "Incident summary copied to the clipboard.")


class CanariesPage(QWidget):
    """Status, controls and incident history for the decoy files."""

    events_detected = pyqtSignal(object)

    def __init__(self, t, shell):
        super().__init__()
        self.t = t
        self.shell = shell
        self.manager = get_canary_manager()

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 26, 36, 30)
        layout.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("Ransomware canaries")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch(1)
        self.status_chip = QLabel("")
        header.addWidget(self.status_chip)
        layout.addLayout(header)

        intro = QLabel(
            "Decoy documents are placed in the folders ransomware encrypts first. "
            "If one is changed, renamed or deleted, you get an immediate alert with "
            "a full incident report."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {t['muted']};")
        layout.addWidget(intro)

        controls = QHBoxLayout()
        self.arm_btn = QPushButton("Arm canaries")
        self.arm_btn.setObjectName("primary")
        self.arm_btn.clicked.connect(self._arm)
        controls.addWidget(self.arm_btn)

        self.check_btn = QPushButton("Check now")
        self.check_btn.clicked.connect(self.check_now)
        controls.addWidget(self.check_btn)

        self.remove_btn = QPushButton("Disarm")
        self.remove_btn.clicked.connect(self._disarm)
        controls.addWidget(self.remove_btn)
        controls.addStretch(1)
        layout.addLayout(controls)

        self.summary = QLabel("")
        self.summary.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
        layout.addWidget(self.summary)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Detected", "Canary", "Event", "Location"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.doubleClicked.connect(self.open_selected)
        layout.addWidget(self.table, 1)

        open_btn = QPushButton("Open report")
        open_btn.setObjectName("primary")
        open_btn.clicked.connect(self.open_selected)
        row = QHBoxLayout()
        row.addWidget(open_btn)
        row.addStretch(1)
        layout.addLayout(row)

        self._timer = QTimer(self)
        self._timer.setInterval(3000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self.refresh()

    # ------------------------------------------------------------------ state
    def refresh(self):
        summary = self.manager.summary()
        armed = summary["armed"]
        self.arm_btn.setEnabled(armed == 0)
        self.check_btn.setEnabled(armed > 0)
        self.remove_btn.setEnabled(armed > 0)
        self.status_chip.setText(
            f"{armed} armed" if armed else "Not armed"
        )
        self.status_chip.setStyleSheet(
            "background: #123a2c; color: #7fd8b0; border-radius: 10px;"
            " padding: 3px 10px; font-weight: 700; font-size: 11px;"
            if armed else
            "background: #3a2a12; color: #e0b26b; border-radius: 10px;"
            " padding: 3px 10px; font-weight: 700; font-size: 11px;"
        )
        self.summary.setText(
            f"{summary['events']} recorded event(s)"
            + (f" · last {_fmt(summary['last_event'])}" if summary["last_event"] else "")
        )

        events = list(reversed(self.manager.events))
        self.table.setRowCount(0)
        for event in events:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [_fmt(event.detected_at), event.name, event.kind.upper(),
                      event.renamed_to or event.path]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 2:
                    item.setForeground(QColor(KIND_COLORS.get(event.kind, self.t["ink"])))
                self.table.setItem(row, column, item)

    def _arm(self):
        created = self.manager.install()
        self.refresh()
        QMessageBox.information(
            self, "Canaries armed",
            f"Created {len(created)} decoy document(s) in Documents, Desktop, "
            "Downloads, OneDrive and Public Documents.\n\n"
            "Leave them alone; CyberGuardian checks them every few seconds.",
        )

    def _disarm(self):
        if QMessageBox.question(
            self, "Disarm canaries",
            "Remove the decoy files and clear the incident history?",
        ) == QMessageBox.Yes:
            removed = self.manager.remove()
            self.refresh()
            QMessageBox.information(self, "Disarmed", f"Removed {removed} canary file(s).")

    def check_now(self):
        events = self.manager.check()
        self.refresh()
        if events:
            self.events_detected.emit(events)
        else:
            QMessageBox.information(self, "Canaries", "All canary files are intact.")

    def _tick(self):
        if not self.manager.is_installed():
            return
        events = self.manager.check()
        if events:
            self.refresh()
            self.events_detected.emit(events)

    def open_selected(self, *_):
        row = self.table.currentRow()
        events = list(reversed(self.manager.events))
        if 0 <= row < len(events):
            CanaryReportDialog(self.t, events[row], self).exec_()

    def shutdown(self):
        self._timer.stop()
