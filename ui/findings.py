"""
Finding drill-down for the Studio UI.

One dialog answers "what exactly was found, why, what do I do, and what does the
AI think", and an aggregate page lists every finding from every scan.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import webbrowser
import subprocess
from typing import Dict, List, Optional

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QColor, QFont
from PyQt5.QtWidgets import (
    QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel,
    QMessageBox, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QTextEdit, QVBoxLayout, QWidget,
)

from ui.design_common import micro
from utils.i18n import field_label, tr

# Analyses are cached per finding so closing the dialog does not
# throw away a paid/long-running AI or VirusTotal result.
_AI_CACHE: dict = {}
_VT_CACHE: dict = {}


def clear_analysis_cache():
    _AI_CACHE.clear()
    _VT_CACHE.clear()


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


class VTWorker(QThread):
    """Check every IoC in a finding against VirusTotal."""

    done = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, indicator: str, detection_type: str, evidence: dict):
        super().__init__()
        self.indicator = indicator
        self.detection_type = detection_type
        self.evidence = evidence

    def run(self):
        try:
            from threat_intel.virustotal_checker import get_virustotal_checker
            checker = get_virustotal_checker()
            result = checker.check_iocs_from_detection(
                self.indicator, self.detection_type, self.evidence
            )
            self.done.emit(result)
        except Exception as exc:  # pragma: no cover - network dependent
            self.failed.emit(str(exc))


_FILE_TLDS = {
    "exe", "dll", "sys", "txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx",
    "csv", "json", "xml", "log", "zip", "rar", "7z", "png", "jpg", "jpeg", "gif",
    "bmp", "ico", "msi", "bat", "cmd", "ps1", "py", "js", "html", "htm", "tmp",
    "dat", "bin", "lnk", "ini", "cfg", "db", "sqlite", "md", "yml", "yaml", "psd",
    "mp4", "mp3", "iso", "img", "vhd", "vhdx", "jar", "war", "class", "sh", "vbs",
}


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback or address.is_link_local
                or address.is_reserved or address.is_multicast)


def _looks_like_domain(value: str) -> bool:
    host = value.rsplit(".", 1)[-1].lower()
    return host not in _FILE_TLDS


def collect_iocs(detection) -> list:
    """Return the IoCs worth checking for this finding (deduplicated)."""
    evidence = detection.evidence if isinstance(detection.evidence, dict) else {}
    process = evidence.get("process") or {}
    file_info = evidence.get("file") or {}
    connection = evidence.get("connection") or {}
    event = evidence.get("event") or {}

    hashes, ips, domains, urls = [], [], [], []

    def add_hash(value):
        if not value:
            return
        value = str(value).strip().lower()
        if len(value) in (32, 40, 64) and all(c in "0123456789abcdef" for c in value):
            if value not in hashes:
                hashes.append(value)

    add_hash(process.get("sha256"))
    add_hash(file_info.get("sha256"))
    add_hash(file_info.get("md5"))
    add_hash(evidence.get("sha256"))

    def add_ip(value):
        if value and _is_public_ip(str(value)) and str(value) not in ips:
            ips.append(str(value))

    def add_domain(value):
        if value and str(value) not in domains:
            domains.append(str(value))

    def add_url(value):
        if value and str(value) not in urls:
            urls.append(str(value))

    for key in ("remote_ip", "local_ip"):
        add_ip(connection.get(key))
    fields = event.get("fields") or {}
    for key in ("IpAddress", "SourceIp", "DestinationIp"):
        add_ip(fields.get(key))
    add_domain(connection.get("remote_hostname"))

    text = " ".join(str(part) for part in (
        detection.indicator, detection.command_line, detection.description,
        connection.get("remote_hostname"), process.get("command_line"),
        fields.get("CommandLine"), fields.get("ImagePath"),
    ) if part)
    for match in re.findall(r"https?://[^\s\"'<>]+", text):
        add_url(match.rstrip(".,;)"))
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        add_ip(match)
    for match in re.findall(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b", text, re.IGNORECASE):
        if not match.replace(".", "").isdigit() and _looks_like_domain(match):
            add_domain(match.lower())

    iocs = [("hash", value) for value in hashes]
    iocs += [("url", value) for value in urls]
    iocs += [("domain", value) for value in domains if not any(value in url for url in urls)]
    iocs += [("ip", value) for value in ips]
    return iocs


class FindingDialog(QDialog):
    """Details, remediation and AI analysis for one detection."""

    def __init__(self, t: Dict, detection, parent=None):
        super().__init__(parent)
        self.t = t
        self.detection = detection
        self.ai_worker: Optional[AIWorker] = None
        self.vt_worker: Optional[VTWorker] = None
        self.vt_result = None
        self.ai_result = None
        self._vt_then_ai = False

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
        tabs.addTab(self._details_tab(), tr("detail.tab.details"))
        tabs.addTab(self._remediation_tab(), tr("detail.tab.remediation"))
        tabs.addTab(self._ai_tab(), tr("detail.tab.ai"))
        tabs.addTab(self._vt_tab(), tr("detail.tab.vt"))
        layout.addWidget(tabs, 1)

        buttons = QDialogButtonBox()
        self.whitelist_btn = QPushButton(tr("detail.whitelist"))
        self.whitelist_btn.clicked.connect(self._whitelist)
        buttons.addButton(self.whitelist_btn, QDialogButtonBox.ActionRole)

        self.locate_btn = QPushButton(tr("detail.locate"))
        self.locate_btn.clicked.connect(self._open_location)
        self.locate_btn.setEnabled(bool(getattr(detection, "file_path", "")))
        buttons.addButton(self.locate_btn, QDialogButtonBox.ActionRole)

        close_btn = QPushButton(tr("detail.close"))
        close_btn.clicked.connect(self.reject)
        buttons.addButton(close_btn, QDialogButtonBox.RejectRole)
        layout.addWidget(buttons)

        self._restore_cached()

    def _cache_key(self) -> str:
        detection = self.detection
        return "|".join((
            str(getattr(detection, "detection_id", "")),
            str(getattr(detection, "detection_type", "")),
            str(getattr(detection, "indicator", "")),
        ))

    def _restore_cached(self):
        key = self._cache_key()
        cached_ai = _AI_CACHE.get(key)
        if cached_ai is not None:
            self.ai_result = cached_ai
            self._render_ai(cached_ai)
            self.ai_status.setText(tr("detail.ai_cached"))
            self.ai_export_btn.setEnabled(True)
        cached_vt = _VT_CACHE.get(key)
        if cached_vt is not None:
            self.vt_result = cached_vt
            self._render_vt(cached_vt)
            self.vt_export_btn.setEnabled(True)

    # ------------------------------------------------------------------ tabs
    def _details_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        tree = self._process_tree()
        if tree:
            label = QLabel(tree)
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            label.setFont(QFont("Consolas", 10))
            label.setStyleSheet(
                f"background: {self.t['surface']}; border: 1px solid {self.t['line']};"
                f" border-radius: 8px; padding: 8px; color: {self.t['ink']};"
            )
            layout.addWidget(label)

        layout.addWidget(micro(tr("detail.event_fields"), self.t["muted"]))
        fields = self._event_fields()
        grid = QTableWidget(len(fields), 2)
        grid.setHorizontalHeaderLabels([tr("detail.field"), tr("detail.value")])
        grid.verticalHeader().setVisible(False)
        grid.setEditTriggers(QTableWidget.NoEditTriggers)
        grid.setSelectionBehavior(QTableWidget.SelectRows)
        grid.setShowGrid(False)
        grid.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        grid.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        grid.setMaximumHeight(300)
        for row, (name, value) in enumerate(fields):
            grid.setItem(row, 0, QTableWidgetItem(name))
            item = QTableWidgetItem(str(value))
            item.setToolTip(str(value))
            grid.setItem(row, 1, item)
        grid.resizeRowsToContents()
        layout.addWidget(grid)

        layout.addWidget(micro(tr("detail.why"), self.t["muted"]))
        reason = QTextEdit()
        reason.setReadOnly(True)
        reason.setMaximumHeight(90)
        reason.setPlainText(self.detection.detection_reason or tr("detail.reason_none"))
        layout.addWidget(reason)

        layout.addWidget(micro(tr("detail.raw"), self.t["muted"]))
        evidence = QTextEdit()
        evidence.setReadOnly(True)
        evidence.setFont(QFont("Consolas", 9))
        try:
            evidence.setPlainText(json.dumps(self.detection.evidence or {}, indent=2, default=str))
        except Exception:
            evidence.setPlainText(str(self.detection.evidence))
        layout.addWidget(evidence, 1)
        return page

    def _process_tree(self) -> str:
        d = self.detection
        evidence = d.evidence if isinstance(d.evidence, dict) else {}
        process = evidence.get("process") or {}
        parent = process.get("parent", "")
        ppid = process.get("ppid", "")
        name = process.get("name") or d.process_name or ""
        pid = process.get("pid") or d.process_id or ""
        if not name and not parent:
            return ""
        left = f"{parent} (PPID {ppid})" if parent else tr("detail.unknown_parent")
        right = f"{name} (PID {pid})" if name else tr("detail.unknown_process")
        return f"{left}  →  {right}"

    def _event_fields(self):
        d = self.detection
        evidence = d.evidence if isinstance(d.evidence, dict) else {}
        process = evidence.get("process") or {}
        file_info = evidence.get("file") or {}
        connection = evidence.get("connection") or {}
        registry = evidence.get("registry") or {}
        event = evidence.get("event") or {}
        matches = evidence.get("yara_matches") or []

        rows = [
            ("Risk", d.risk_level.value.upper()),
            ("Finding", d.detection_type),
            ("Confidence", f"{d.confidence:.0%}"),
            ("Indicator", d.indicator),
            ("Detected", getattr(d, "timestamp", "")),
        ]

        if process:
            rows += [
                ("Process", process.get("name", "")),
                ("PID", process.get("pid", "")),
                ("PPID", process.get("ppid", "")),
                ("Parent process", process.get("parent", "")),
                ("User", process.get("user", "")),
                ("Signed", "yes" if process.get("signed") else "no"),
                ("Signer", process.get("signer", "")),
                ("Image path", process.get("path", "")),
                ("Directory", process.get("directory", "")),
                ("Command line", process.get("command_line", "")),
                ("Started", process.get("started", "")),
                ("SHA-256", process.get("sha256", "")),
            ]
        if file_info:
            size = file_info.get("size", "")
            rows += [
                ("File", file_info.get("name", "")),
                ("Size", f"{size:,} bytes" if isinstance(size, int) else size),
                ("MIME type", file_info.get("mime", "")),
                ("Entropy", file_info.get("entropy", "")),
                ("Created", file_info.get("created", "")),
                ("Modified", file_info.get("modified", "")),
                ("SHA-256", file_info.get("sha256", "")),
                ("MD5", file_info.get("md5", "")),
            ]
        if connection:
            rows += [
                ("Local endpoint", connection.get("local", "")),
                ("Remote endpoint", connection.get("remote", "")),
                ("Remote host", connection.get("remote_hostname", "")),
                ("Protocol", connection.get("protocol", "")),
                ("State", connection.get("status", "")),
                ("Process", connection.get("process_name", "")),
                ("PID", connection.get("pid", "")),
                ("Connection age (s)", connection.get("age_seconds", "")),
                ("Bytes sent / received", f"{connection.get('bytes_sent', 0)} / {connection.get('bytes_recv', 0)}"),
            ]
        if registry:
            rows += [
                ("Hive", registry.get("hive", "")),
                ("Key", registry.get("key", "")),
                ("Value name", registry.get("value_name", "")),
                ("Value type", registry.get("value_type", "")),
                ("Value data", registry.get("value_data", "")),
            ]
        if event:
            rows += [
                ("Channel", event.get("channel", "")),
                ("Event ID", event.get("event_id", "")),
                ("Provider", event.get("provider", "")),
                ("Record ID", event.get("record_id", "")),
                ("Event time", event.get("timestamp", "")),
                ("Level", event.get("level", "")),
            ]
            fields = event.get("fields") or {}
            for key in ("TargetUserName", "SubjectUserName", "ImagePath", "CommandLine",
                        "ServiceName", "TaskName", "IpAddress", "ProcessName"):
                if fields.get(key):
                    rows.append((key, fields[key]))
        if matches:
            rules = [str(match.get("rule", "")) for match in matches if match.get("rule")]
            identifiers = sorted({
                str(item.get("identifier", ""))
                for match in matches for item in (match.get("strings") or [])
                if item.get("identifier")
            })
            rows.append(("YARA rules", ", ".join(rules)))
            if identifiers:
                rows.append(("Matched strings", ", ".join(identifiers[:12])))

        cleaned = []
        seen = set()
        for name, value in rows:
            if value in ("", None, [], {}):
                continue
            if name in seen:
                continue
            seen.add(name)
            cleaned.append((field_label(name), value))
        return cleaned

    def _remediation_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(micro(tr("detail.steps"), self.t["muted"]))

        steps = self.detection.remediation or [tr("detail.remediation_none")]
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

        text = QLabel(tr("detail.ai_intro"))
        text.setWordWrap(True)
        text.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
        layout.addWidget(text)

        row = QHBoxLayout()
        self.ai_btn = QPushButton(tr("detail.ai_run"))
        self.ai_btn.setStyleSheet(
            f"background: {self.t['accent']}; color: white; border: none;"
            " border-radius: 10px; padding: 9px 16px; font-weight: 700;"
        )
        self.ai_btn.clicked.connect(self._analyze)
        row.addWidget(self.ai_btn)

        self.ai_export_btn = QPushButton(tr("detail.ai_export"))
        self.ai_export_btn.setEnabled(False)
        self.ai_export_btn.clicked.connect(self._export_ai)
        row.addWidget(self.ai_export_btn)
        self.ai_status = QLabel("")
        self.ai_status.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
        row.addWidget(self.ai_status, 1)
        layout.addLayout(row)

        self.ai_output = QTextEdit()
        self.ai_output.setReadOnly(True)
        layout.addWidget(self.ai_output, 1)
        return page

    def _vt_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 10, 0, 0)
        layout.setSpacing(8)

        from threat_intel.virustotal_checker import is_virustotal_available

        available = False
        try:
            available = is_virustotal_available()
        except Exception:
            available = False

        intro = QLabel(tr("vt.intro"))
        intro.setWordWrap(True)
        intro.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
        layout.addWidget(intro)

        self.vt_key_status = QLabel(tr("vt.key_ok") if available else tr("vt.key_missing"))
        self.vt_key_status.setWordWrap(True)
        self.vt_key_status.setStyleSheet(
            f"color: {self.t['ink'] if available else '#c56a1b'}; font-size: 12px;"
        )
        layout.addWidget(self.vt_key_status)

        row = QHBoxLayout()
        self.vt_check_btn = QPushButton(tr("vt.run"))
        self.vt_check_btn.setEnabled(available)
        self.vt_check_btn.clicked.connect(lambda: self._start_vt())
        row.addWidget(self.vt_check_btn)

        self.vt_open_btn = QPushButton(tr("vt.open"))
        self.vt_open_btn.setEnabled(False)
        self.vt_open_btn.clicked.connect(self._open_vt)
        row.addWidget(self.vt_open_btn)

        self.vt_export_btn = QPushButton(tr("detail.vt_export"))
        self.vt_export_btn.setEnabled(False)
        self.vt_export_btn.clicked.connect(self._export_vt)
        row.addWidget(self.vt_export_btn)
        row.addStretch(1)
        layout.addLayout(row)

        self.vt_status = QLabel(
            tr("vt.ioc_count", count=len(collect_iocs(self.detection)))
            if collect_iocs(self.detection) else tr("vt.no_iocs")
        )
        self.vt_status.setWordWrap(True)
        self.vt_status.setStyleSheet(f"color: {self.t['muted']}; font-size: 12px;")
        layout.addWidget(self.vt_status)

        self.vt_table = QTableWidget(0, 5)
        self.vt_table.setHorizontalHeaderLabels(
            [tr("vt.col_type"), tr("vt.col_indicator"), tr("vt.col_verdict"),
             tr("vt.col_detections"), tr("vt.col_details")]
        )
        self.vt_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.vt_table.horizontalHeader().setStretchLastSection(True)
        self.vt_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.vt_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.vt_table.setAlternatingRowColors(True)
        layout.addWidget(self.vt_table, 1)
        return page

    def _start_vt(self, then_ai: bool = False):
        from threat_intel.virustotal_checker import is_virustotal_available

        self._vt_then_ai = then_ai
        try:
            available = is_virustotal_available()
        except Exception:
            available = False
        if not available:
            self.vt_status.setText(
                tr("vt.not_configured")
            )
            if then_ai:
                self._vt_then_ai = False
                self._start_ai()
            return

        self.vt_check_btn.setEnabled(False)
        self.vt_check_btn.setText(tr("vt.running"))
        self.vt_status.setText(tr("vt.contacting"))
        self.vt_worker = VTWorker(
            self.detection.indicator,
            self.detection.detection_type,
            self.detection.evidence or {},
        )
        self.vt_worker.done.connect(self._vt_finished)
        self.vt_worker.failed.connect(self._vt_failed)
        self.vt_worker.start()

    def _vt_finished(self, result):
        self.vt_result = result
        _VT_CACHE[self._cache_key()] = result
        if hasattr(self, "vt_export_btn"):
            self.vt_export_btn.setEnabled(True)
        self.vt_check_btn.setEnabled(True)
        self.vt_check_btn.setText(tr("vt.run"))
        self._render_vt(result)
        if self._vt_then_ai:
            self._vt_then_ai = False
            self._start_ai()

    def _vt_failed(self, message: str):
        self.vt_check_btn.setEnabled(True)
        self.vt_check_btn.setText(tr("vt.run"))
        self.vt_status.setText(tr("vt.failed", message=message))
        if self._vt_then_ai:
            self._vt_then_ai = False
            self._start_ai()

    def _render_vt(self, result):
        rows = []
        for item in getattr(result, "hash_results", []):
            rows.append((tr("vt.hash"), item.hash_value[:24] + "…", item))
        for item in getattr(result, "ip_results", []):
            rows.append((tr("vt.ip"), item.ip_address, item))
        for item in getattr(result, "domain_results", []):
            rows.append((tr("vt.domain"), item.domain, item))
        for item in getattr(result, "url_results", []):
            rows.append((tr("vt.url"), item.url[:80], item))

        self.vt_table.setRowCount(0)
        for kind, value, item in rows:
            row = self.vt_table.rowCount()
            self.vt_table.insertRow(row)
            if getattr(item, "error", None):
                verdict = tr("vt.error")
            elif getattr(item, "is_malicious", False):
                verdict = tr("vt.malicious")
            elif getattr(item, "detection_ratio", ""):
                verdict = tr("vt.clean")
            else:
                verdict = tr("vt.unknown")

            details = []
            if getattr(item, "threat_names", None):
                details.append(", ".join(item.threat_names[:3]))
            if getattr(item, "country", ""):
                details.append(item.country)
            if getattr(item, "as_owner", ""):
                details.append(item.as_owner)
            if getattr(item, "categories", None):
                details.append(", ".join(item.categories[:3]))
            if getattr(item, "file_type", ""):
                details.append(item.file_type)

            values = [
                kind, value, verdict,
                getattr(item, "detection_ratio", "") or "—",
                "; ".join(details) or "—",
            ]
            for column, text in enumerate(values):
                cell = QTableWidgetItem(str(text))
                if column == 2:
                    colour = {
                        tr("vt.malicious"): "#c71f37",
                        tr("vt.clean"): "#1c7c54",
                    }.get(verdict)
                    if colour:
                        cell.setForeground(QColor(colour))
                self.vt_table.setItem(row, column, cell)

        self.vt_open_btn.setEnabled(bool(rows))
        summary = getattr(result, "vt_summary", "") or (
            f"{result.iocs_malicious} malicious / {result.iocs_checked} checked"
        )
        self.vt_status.setText(tr(
            "vt.summary", summary=summary,
            risk=str(result.highest_risk_level).upper(),
        ))

    def _open_vt(self, *_):
        row = self.vt_table.currentRow()
        if row < 0:
            return
        item = self.vt_table.item(row, 1)
        if item is None:
            return
        from urllib.parse import quote
        webbrowser.open(
            f"https://www.virustotal.com/gui/search/{quote(item.text().replace('…', ''))}"
        )

    # ---------------------------------------------------------------- actions
    def _detection_data(self) -> Dict:
        d = self.detection
        evidence = d.evidence if isinstance(d.evidence, dict) else {}
        process = evidence.get("process") or {}
        file_info = evidence.get("file") or {}
        connection = evidence.get("connection") or {}
        registry = evidence.get("registry") or {}
        event = evidence.get("event") or {}

        data = {
            "language": __import__("utils.i18n", fromlist=["current_language"]).current_language(),
            "detection_type": d.detection_type,
            "risk_level": d.risk_level.value,
            "indicator": d.indicator,
            "indicator_type": d.indicator_type,
            "description": d.description,
            "detection_reason": d.detection_reason,
            "remediation": list(d.remediation or []),
            "evidence": evidence,
            "process_name": d.process_name or process.get("name", ""),
            "process_id": d.process_id or process.get("pid", 0),
            "ppid": process.get("ppid", 0),
            "parent_process": process.get("parent", ""),
            "file_path": d.file_path or process.get("path") or file_info.get("path", ""),
            "command_line": d.command_line or process.get("command_line", ""),
            "user": d.user or process.get("user", ""),
            "sha256": process.get("sha256") or file_info.get("sha256", ""),
            "signed": process.get("signed"),
            "signer": process.get("signer", ""),
            "timestamp": getattr(d, "timestamp", ""),
        }
        if connection:
            data["network"] = connection
        if registry:
            data["registry"] = registry
        if event:
            data["event"] = event
        if file_info:
            data["file"] = file_info
        if self.vt_result is not None:
            try:
                vt = self.vt_result.to_dict()
                if data["language"] == "fr":
                    vt["vt_summary"] = (
                        f"{vt.get('iocs_malicious', 0)} IOC malveillant(s) sur "
                        f"{vt.get('iocs_checked', 0)} vérifié(s)"
                    )
                data["virustotal_result"] = vt
            except Exception:
                pass
        return data

    def _analyze(self):
        # VirusTotal intelligence materially changes the verdict: when a key is
        # configured and no check has run yet, collect it first and feed it to
        # the model automatically.
        if self.vt_result is None and not self._vt_then_ai:
            try:
                from threat_intel.virustotal_checker import is_virustotal_available
                if is_virustotal_available():
                    self.ai_status.setText("Checking VirusTotal first…")
                    self._start_vt(then_ai=True)
                    return
            except Exception:
                pass
        self._start_ai()

    def _start_ai(self):
        self.ai_btn.setEnabled(False)
        self.ai_btn.setText(tr("detail.ai_busy"))
        self.ai_status.setText(tr("detail.ai_contact"))
        self.ai_worker = AIWorker(self._detection_data())
        self.ai_worker.done.connect(self._ai_done)
        self.ai_worker.failed.connect(self._ai_failed)
        self.ai_worker.start()

    def _ai_failed(self, message: str):
        self.ai_btn.setEnabled(True)
        self.ai_btn.setText(tr("detail.ai_run"))
        self.ai_status.setText("")
        self.ai_output.setPlainText(tr("detail.ai_failed", message=message))

    def _ai_done(self, result):
        self.ai_btn.setEnabled(True)
        self.ai_btn.setText(tr("detail.ai_run"))
        if result is None:
            self.ai_status.setText(tr("detail.ai_no_provider"))
            self.ai_output.setPlainText(tr("detail.ai_api_key"))
            return
        if getattr(result, "error", None):
            self.ai_output.setPlainText(tr("detail.ai_failed", message=result.error))
            return
        self.ai_result = result
        _AI_CACHE[self._cache_key()] = result
        if hasattr(self, "ai_export_btn"):
            self.ai_export_btn.setEnabled(True)
        self._render_ai(result)

    def _render_ai(self, result):
        lines = [
            tr("detail.ai_verdict", verdict=result.verdict.value.replace("_", " ").upper()),
            tr("detail.ai_confidence", confidence=f"{result.confidence:.0%}", score=result.risk_score),
            "",
            result.summary,
            "",
            tr("detail.ai_detailed"),
            "-" * 60,
            result.detailed_analysis,
        ]
        for title, items in (
            ("detail.ai_verify", getattr(result, "verification_steps", [])),
            ("detail.ai_contain", getattr(result, "containment_steps", [])),
            ("detail.ai_remediate", getattr(result, "remediation_steps", [])),
            ("detail.ai_validate", getattr(result, "validation_steps", [])),
        ):
            if items:
                lines += ["", tr(title), "-" * 60]
                lines += [f"{index}. {step}" for index, step in enumerate(items, 1)]
        if result.mitre_techniques:
            lines += ["", tr("detail.ai_mitre") + " " + ", ".join(result.mitre_techniques)]
        self.ai_status.setText(f"{result.provider.value} · {result.verdict.value}")
        self.ai_output.setPlainText("\n".join(lines))

    def _export_ai(self):
        if self.ai_result is None:
            return
        from reporting.html_export import export_ai_html
        suggestion = f"ai_report_{getattr(self.detection, 'detection_id', 'finding')[:12]}.html"
        path, _ = QFileDialog.getSaveFileName(self, tr("detail.ai_export"), suggestion, tr("export.html"))
        if not path:
            return
        try:
            written = export_ai_html(self.detection, self.ai_result, path, self.vt_result)
        except Exception as exc:
            QMessageBox.critical(self, tr("detail.ai_export"), str(exc))
            return
        QMessageBox.information(self, tr("detail.ai_export"), tr("export.saved", path=written))

    def _export_vt(self):
        if self.vt_result is None:
            return
        from reporting.html_export import export_vt_html
        suggestion = f"virustotal_report_{getattr(self.detection, 'detection_id', 'finding')[:12]}.html"
        path, _ = QFileDialog.getSaveFileName(self, tr("detail.vt_export"), suggestion, tr("export.html"))
        if not path:
            return
        try:
            written = export_vt_html(self.detection, self.vt_result, path)
        except Exception as exc:
            QMessageBox.critical(self, tr("detail.vt_export"), str(exc))
            return
        QMessageBox.information(self, tr("detail.vt_export"), tr("export.saved", path=written))

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
        title = QLabel(tr("findings.title"))
        title.setStyleSheet(f"color: {t['ink']}; font-size: 30px; font-weight: 700;")
        header.addWidget(title)
        header.addStretch(1)
        self.filter = QComboBox()
        for label, value in (
            (tr("findings.filter_all"), ""),
            (tr("findings.filter_critical"), "critical"),
            (tr("findings.filter_high"), "high"),
            (tr("findings.filter_medium"), "medium"),
            (tr("findings.filter_low"), "low"),
        ):
            self.filter.addItem(label, value)
        self.filter.currentIndexChanged.connect(self.refresh)
        header.addWidget(self.filter)
        layout.addLayout(header)

        self.subtitle = QLabel(tr("findings.empty"))
        self.subtitle.setStyleSheet(f"color: {t['muted']};")
        layout.addWidget(self.subtitle)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            tr("col.risk"), tr("col.finding"), tr("vt.col_indicator"), tr("nav.scans")
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.doubleClicked.connect(self._open_selected)
        layout.addWidget(self.table, 1)

        self.detail_btn = QPushButton(tr("findings.view"))
        self.detail_btn.setObjectName("primary")
        self.detail_btn.clicked.connect(self._open_selected)
        row = QHBoxLayout()
        row.addWidget(self.detail_btn)
        self.export_btn = QPushButton(tr("findings.export_all"))
        self.export_btn.clicked.connect(self._export)
        row.addWidget(self.export_btn)
        row.addStretch(1)
        layout.addLayout(row)

    def set_detections(self, detections: List):
        self.detections = list(detections)
        self.refresh()

    def refresh(self, *_):
        wanted = self.filter.currentData() or ""
        rows = [
            (scan_type, detection)
            for scan_type, detection in self.detections
            if not wanted or wanted == detection.risk_level.value
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
            tr("findings.count", count=len(rows)) if rows else tr("findings.empty")
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
        wanted = self.filter.currentData() or ""
        visible = [
            (scan_type, detection)
            for scan_type, detection in self.detections
            if not wanted or wanted == detection.risk_level.value
        ]
        if row < len(visible):
            FindingDialog(self.t, visible[row][1], self).exec_()
