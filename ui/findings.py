"""
Finding drill-down for the Studio UI.

One dialog answers "what exactly was found, why, what do I do, and what does the
AI think", and an aggregate page lists every finding from every scan.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)

from ui.design_common import micro


class AIWorker(QThread):
    """Run the AI analysis off the GUI thread."""

    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, detection_data: Dict, provider=None):
        super().__init__()
        self.data = detection_data
        self.provider = provider

    def run(self):
        try:
            from ai_analysis.analyzer import get_ai_analyzer
            result = get_ai_analyzer().analyze_detection(self.data, self.provider)
            self.done.emit(result)
        except Exception as exc:  # pragma: no cover - network dependent
            self.failed.emit(str(exc))


class FindingDialog(QDialog):
    """Details, remediation and AI analysis for one detection."""

    def __init__(self, t: Dict, detection, parent=None):
        super().__init__(parent)
        self.t = t
        self.detection = detection
        self.ai_worker: Optional[AIWorker] = None

        risk = detection.risk_level.value
        color = t.get(risk, t["accent"])
        self.setWindowTitle(f"{risk.upper()} · {detection.detection_type}")
        self.setMinimumSize(760, 620)
        self.setStyleSheet(
            f"QDialog {{ background: {t['bg']}; color: {t['ink']}; }}"
            f"QLabel {{ color: {t['ink']}; }}"
            f"QTabWidget::pane {{ border: 1px solid {t['line']}; border-radius: 10px; }}"
            f"QTabBar::tab {{ background: transparent; color: {t['muted']}; padding: 8px 14px; }}"
            f"QTabBar::tab:selected {{ color: {t['accent']}; border-bottom: 2px solid {t['accent']}; }}"
            f"QTextEdit {{ background: {t['surface']}; border: 1px solid {t['line']};"
            f" border-radius: 10px; color: {t['ink']}; padding: 10px; }}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 22, 24, 20)
        layout.setSpacing(12)

        badge = QLabel(risk.upper())
        badge.setStyleSheet(
            f"background: {color}22; color: {color}; border-radius: 9px;"
            " padding: 3px 10px; font-size: 11px; font-weight: 800;"
        )
        header = QHBoxLayout()
        header.addWidget(badge)
        header.addWidget(QLabel(detection.detection_type))
        header.addStretch(1)
        layout.addLayout(header)

        title = QLabel(str(detection.indicator)[:220])
        title.setWordWrap(True)
        title.setStyleSheet(f"font-size: 20px; font-weight: 700; color: {t['ink']};")
        layout.addWidget(title)

        description = QLabel(detection.description)
        description.setWordWrap(True)
        description.setStyleSheet(f"color: {t['muted']};")
        layout.addWidget(description)

        tabs = QTabWidget()
        tabs.addTab(self._details_tab(), "Details")
        tabs.addTab(self._remediation_tab(), "Remediation")
        tabs.addTab(self._ai_tab(), "AI analysis")
        layout.addWidget(tabs, 1)

        buttons = QDialogButtonBox()
        self.whitelist_btn = QPushButton("Add to whitelist")
        self.whitelist_btn.clicked.connect(self._whitelist)
        buttons.addButton(self.whitelist_btn, QDialogButtonBox.ActionRole)

        self.locate_btn = QPushButton("Open file location")
        self.locate_btn.clicked.connect(self._open_location)
        self.locate_btn.setEnabled(bool(getattr(detection, "file_path", "")))
        buttons.addButton(self.locate_btn, QDialogButtonBox.ActionRole)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.reject)
        buttons.addButton(close_btn, QDialogButtonBox.RejectRole)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------ tabs
    def _details_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        layout.addWidget(micro("why it was flagged", self.t["muted"]))
        reason = QTextEdit()
        reason.setReadOnly(True)
        reason.setMaximumHeight(110)
        reason.setPlainText(self.detection.detection_reason or "No reason recorded.")
        layout.addWidget(reason)

        layout.addWidget(micro("evidence", self.t["muted"]))
        evidence = QTextEdit()
        evidence.setReadOnly(True)
        evidence.setFont(QFont("Consolas", 9))
        try:
            evidence.setPlainText(json.dumps(self.detection.evidence or {}, indent=2, default=str))
        except Exception:
            evidence.setPlainText(str(self.detection.evidence))
        layout.addWidget(evidence, 1)
        return page

    def _remediation_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(micro("recommended steps", self.t["muted"]))

        steps = self.detection.remediation or ["No specific remediation was recorded."]
        for index, step in enumerate(steps, 1):
            item = QLabel(f"{index}.  {step}")
            item.setWordWrap(True)
            item.setStyleSheet(f"color: {self.t['ink']}; font-size: 13px; padding: 4px 0;")
            layout.addWidget(item)
        layout.addStretch(1)
        return page

    def _ai_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        text = QLabel(
            "Send this finding and its evidence to your configured AI provider for a "
            "verdict, a step-by-step verification plan and remediation guidance."
        )
        text.setWordWrap(True)
        text.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
        layout.addWidget(text)

        row = QHBoxLayout()
        self.ai_btn = QPushButton("Analyze with AI")
        self.ai_btn.setStyleSheet(
            f"background: {self.t['accent']}; color: white; border: none;"
            " border-radius: 10px; padding: 9px 16px; font-weight: 700;"
        )
        self.ai_btn.clicked.connect(self._analyze)
        row.addWidget(self.ai_btn)
        self.ai_status = QLabel("")
        self.ai_status.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
        row.addWidget(self.ai_status, 1)
        layout.addLayout(row)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(self.ai_output, 1)
        return page

    # ---------------------------------------------------------------- actions
    def _detection_data(self) -> Dict:
        d = self.detection
        return {
            "detection_type": d.detection_type,
            "risk_level": d.risk_level.value,
            "indicator": d.indicator,
            "description": d.description,
            "detection_reason": d.detection_reason,
            "evidence": d.evidence or {},
            "process_name": d.process_name or "",
            "process_id": d.process_id or 0,
            "file_path": d.file_path or "",
            "command_line": d.command_line or "",
            "user": d.user or "",
        }

    def _analyze(self):
        self.ai_btn.setEnabled(False)
        self.ai_btn.setText("Analyzing…")
        self.ai_status.setText("Contacting provider…")
        self.ai_worker = AIWorker(self._detection_data())
        self.ai_worker.done.connect(self._ai_done)
        self.ai_worker.failed.connect(self._ai_failed)
        self.ai_worker.start()

    def _ai_failed(self, message: str):
        self.ai_btn.setEnabled(True)
        self.ai_btn.setText("Analyze with AI")
        self.ai_status.setText("")
        self.ai_output.setPlainText(f"Analysis failed:\n\n{message}")

    def _ai_done(self, result):
        self.ai_btn.setEnabled(True)
        self.ai_btn.setText("Analyze with AI")
        if result is None:
            self.ai_status.setText("No provider configured.")
            self.ai_output.setPlainText(
                "Add an API key in Settings → Advanced settings → AI Analysis."
            )
            return
        if getattr(result, "error", None):
            self.ai_output.setPlainText(f"Analysis failed:\n\n{result.error}")
            return

        lines = [
            f"VERDICT: {result.verdict.value.replace('_', ' ').upper()}",
            f"Confidence: {result.confidence:.0%}    Risk score: {result.risk_score}/100",
            "",
            result.summary,
            "",
            "DETAILED ANALYSIS",
            "-" * 60,
            result.detailed_analysis,
        ]
        for title, items in (
            ("STEP 1 — VERIFY BEFORE YOU ACT", getattr(result, "verification_steps", [])),
            ("STEP 2 — CONTAIN / ISOLATE", getattr(result, "containment_steps", [])),
            ("STEP 3 — REMOVE AND RESTORE", getattr(result, "remediation_steps", [])),
            ("STEP 4 — CONFIRM IT IS GONE", getattr(result, "validation_steps", [])),
        ):
            if items:
                lines += ["", title, "-" * 60]
                lines += [f"{i}. {step}" for i, step in enumerate(items, 1)]
        if result.mitre_techniques:
            lines += ["", "MITRE ATT&CK: " + ", ".join(result.mitre_techniques)]
        self.ai_status.setText(f"{result.provider.value} · {result.verdict.value}")
        self.ai_output.setPlainText("\n".join(lines))

    def _whitelist(self):
        from utils.whitelist import get_whitelist

        d = self.detection
        entry_type, identifier = "name", d.indicator
        if d.indicator_type == "file" and d.file_path:
            entry_type, identifier = "path", d.file_path
        elif d.indicator_type == "process" and d.file_path:
            entry_type, identifier = "path", d.file_path
        elif d.indicator_type in ("network", "ip"):
            entry_type = "ip"
        elif d.indicator_type == "registry_key":
            entry_type, identifier = "registry_key", d.evidence.get("key_path", d.indicator)

        try:
            added = get_whitelist().add_entry(
                identifier=identifier, entry_type=entry_type, source="user",
                description=f"Whitelisted from finding {d.detection_type}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Whitelist", str(exc))
            return
        if added:
            QMessageBox.information(self, "Whitelist", f"Added {entry_type}:\n{identifier}")
        else:
            QMessageBox.information(self, "Whitelist", "This entry is already whitelisted.")

    def _open_location(self):
        path = getattr(self.detection, "file_path", "")
        if not path or not os.path.exists(path):
            QMessageBox.information(self, "Open location", "The file no longer exists.")
            return
        try:
            if os.path.isdir(path):
                os.startfile(path)  # noqa: S606 - Windows shell open
            else:
                subprocess.Popen(["explorer", "/select,", path])
        except Exception as exc:
            QMessageBox.warning(self, "Open location", str(exc))


class FindingsPage(QWidget):
    """Every finding from every scan, newest first."""

    def __init__(self, t: Dict, shell):
        super().__init__()
        self.t = t
        self.shell = shell
        self.detections: List = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(36, 26, 36, 30)
        layout.setSpacing(14)

        header = QHBoxLayout()
        title = QLabel("Findings")
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch(1)
        self.filter = QComboBox()
        self.filter.addItems(["All risks", "Critical", "High", "Medium", "Low"])
        self.filter.currentTextChanged.connect(self.refresh)
        header.addWidget(self.filter)
        layout.addLayout(header)

        self.subtitle = QLabel("Nothing found yet. Run a scan to populate this page.")
        self.subtitle.setStyleSheet(f"color: {t['muted']};")
        layout.addWidget(self.subtitle)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Risk", "Finding", "Indicator", "Scan"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.doubleClicked.connect(self._open_selected)
        layout.addWidget(self.table, 1)

        self.detail_btn = QPushButton("View details")
        self.detail_btn.setObjectName("primary")
        self.detail_btn.clicked.connect(self._open_selected)
        row = QHBoxLayout()
        row.addWidget(self.detail_btn)
        self.export_btn = QPushButton("Export all results")
        self.export_btn.clicked.connect(self._export)
        row.addWidget(self.export_btn)
        row.addStretch(1)
        layout.addLayout(row)

    def set_detections(self, detections: List):
        self.detections = list(detections)
        self.refresh()

    def refresh(self, *_):
        wanted = self.filter.currentText().lower()
        rows = [
            (scan_type, detection)
            for scan_type, detection in self.detections
            if wanted in ("all risks", detection.risk_level.value)
        ]
        self.table.setRowCount(0)
        for scan_type, detection in rows:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = [detection.risk_level.value.upper(), detection.detection_type,
                      str(detection.indicator)[:120], scan_type]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setForeground(QColor(self.t.get(detection.risk_level.value, self.t["ink"])))
                self.table.setItem(row, column, item)
        self.subtitle.setText(
            f"{len(rows)} finding(s)" if rows else "Nothing found yet. Run a scan to populate this page."
        )

    def _export(self):
        export = getattr(self.shell, "export_all_results", None)
        if callable(export):
            export()

    def _open_selected(self, *_):
        row = self.table.currentRow()
        if row < 0:
            return
        # Table rows were rebuilt by refresh; map via the visible ordering.
        wanted = self.filter.currentText().lower()
        visible = [
            (scan_type, detection)
            for scan_type, detection in self.detections
            if wanted in ("all risks", detection.risk_level.value)
        ]
        if row < len(visible):
            FindingDialog(self.t, visible[row][1], self).exec_()
