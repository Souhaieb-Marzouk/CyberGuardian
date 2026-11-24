"""
Live traffic page — a guided, Sniffnet-inspired network monitor.

Shows active connections, throughput, process attribution and risk hints in plain
language, with per-direction firewall toggles and one-click VirusTotal / AI
triage for external endpoints.
"""

from __future__ import annotations

import csv
import json
import time
from datetime import datetime
from typing import Dict, List, Optional

from PyQt5.QtCore import QSettings, Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PyQt5.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QFrame, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from core.firewall import get_firewall_manager, is_admin
from core.ip_lookup import lookup_ip
from core.live_traffic import ConnectionView, TrafficMonitor, TrafficSnapshot
from scanners.base_scanner import Detection, RiskLevel
from ui.design_common import micro
from ui.findings import FindingDialog
from utils.i18n import tr

RISK_ORDER = {"high": 0, "medium": 1, "info": 2}
RISK_LABELS = {"high": "traffic.risk.high", "medium": "traffic.risk.medium", "info": "traffic.risk.info"}
STATE_KEYS = {
    "ESTABLISHED": "traffic.state.established",
    "LISTEN": "traffic.state.listen",
    "TIME_WAIT": "traffic.state.closing",
    "CLOSE_WAIT": "traffic.state.closing",
    "FIN_WAIT1": "traffic.state.closing",
    "FIN_WAIT2": "traffic.state.closing",
    "SYN_SENT": "traffic.state.connecting",
    "SYN_RECV": "traffic.state.connecting",
    "NONE": "traffic.state.none",
}


def _fmt_rate(value: float) -> str:
    if value >= 1024 * 1024:
        return f"{value / (1024 * 1024):.1f} MB/s"
    if value >= 1024:
        return f"{value / 1024:.1f} KB/s"
    return f"{value:.0f} B/s"


def _fmt_bytes(value: int) -> str:
    if value >= 1024 ** 3:
        return f"{value / (1024 ** 3):.1f} GB"
    if value >= 1024 ** 2:
        return f"{value / (1024 ** 2):.1f} MB"
    if value >= 1024:
        return f"{value / 1024:.1f} KB"
    return f"{value} B"


def _fmt_age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m {seconds % 60:02d}s"
    return f"{seconds // 3600}h {(seconds % 3600) // 60:02d}m"


def app_label(conn: ConnectionView) -> str:
    if conn.app == "System":
        return tr("traffic.app.system")
    if conn.app == "Unknown":
        return tr("traffic.app.unknown")
    return conn.app


def _state_label(state: str) -> str:
    key = STATE_KEYS.get((state or "").upper())
    return tr(key) if key else (state or "—")


class Sparkline(QWidget):
    """Two-series throughput sparkline (download / upload)."""

    def __init__(self, t: dict, parent=None):
        super().__init__(parent)
        self.t = t
        self.down: List[float] = []
        self.up: List[float] = []
        self.setMinimumHeight(92)

    def add(self, down: float, up: float):
        self.down.append(max(0.0, down))
        self.up.append(max(0.0, up))
        self.down = self.down[-60:]
        self.up = self.up[-60:]
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width, height = self.width(), self.height()
        painter.fillRect(self.rect(), QColor(self.t["surface"]))
        painter.setPen(QPen(QColor(self.t["line"]), 1))
        for fraction in (0.25, 0.5, 0.75):
            painter.drawLine(0, int(height * fraction), width, int(height * fraction))

        if len(self.down) < 2:
            painter.setPen(QColor(self.t["muted"]))
            painter.setFont(QFont("", 9))
            painter.drawText(self.rect(), Qt.AlignCenter, tr("traffic.chart.waiting"))
            return

        peak = max(max(self.down), max(self.up), 1.0)
        step = width / max(1, len(self.down) - 1)

        def polyline(values, colour):
            path = QPainterPath()
            points = []
            for index, value in enumerate(values):
                x = index * step
                y = height - 6 - (value / peak) * (height - 14)
                points.append((x, y))
            path.moveTo(*points[0])
            for point in points[1:]:
                path.lineTo(*point)
            painter.setPen(QPen(QColor(colour), 2))
            painter.drawPath(path)

        polyline(self.up, self.t["medium"])
        polyline(self.down, self.t["accent"])


class IpLookupWorker(QThread):
    done = pyqtSignal(dict)
    failed = pyqtSignal(str)

    def __init__(self, ip: str):
        super().__init__()
        self.ip = ip

    def run(self):
        try:
            self.done.emit(lookup_ip(self.ip))
        except Exception as exc:
            self.failed.emit(str(exc))


class TrafficGuideDialog(QDialog):
    def __init__(self, t: dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle(tr("traffic.guide.title"))
        self.setMinimumSize(760, 600)
        self.setStyleSheet(
            f"QDialog {{ background: {t['bg']}; color: {t['ink']}; }}"
            f"QLabel {{ color: {t['ink']}; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 22, 26, 18)
        layout.setSpacing(12)

        title = QLabel(tr("traffic.guide.title"))
        title.setStyleSheet("font-size: 24px; font-weight: 700;")
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        body = QVBoxLayout(inner)
        body.setContentsMargins(6, 6, 6, 6)
        body.setSpacing(14)
        for step in range(1, 5):
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background: {t['surface']}; border: 1px solid {t['line']};"
                " border-radius: 14px; }"
            )
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(18, 14, 18, 14)
            card_layout.setSpacing(5)
            heading = QLabel(tr(f"traffic.guide.step{step}.title"))
            heading.setStyleSheet("font-size: 15px; font-weight: 700;")
            card_layout.addWidget(heading)
            text = QLabel(tr(f"traffic.guide.step{step}.text"))
            text.setWordWrap(True)
            text.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
            card_layout.addWidget(text)
            body.addWidget(card)
        body.addStretch(1)
        scroll.setWidget(inner)
        layout.addWidget(scroll, 1)

        close = QPushButton(tr("traffic.guide.close"))
        close.setStyleSheet(
            f"QPushButton {{ background: {t['accent']}; color: white; border: none;"
            " border-radius: 9px; padding: 8px 16px; font-weight: 700; }}"
        )
        close.clicked.connect(self.accept)
        row = QHBoxLayout()
        row.addStretch(1)
        row.addWidget(close)
        layout.addLayout(row)


class ConnectionDetailDialog(QDialog):
    def __init__(self, t: dict, conn: ConnectionView, page: "TrafficPage"):
        super().__init__(page)
        self.t = t
        self.conn = conn
        self.page = page
        self._worker: Optional[IpLookupWorker] = None
        self.setWindowTitle(tr("traffic.detail.title"))
        self.setMinimumSize(720, 620)
        self.setStyleSheet(
            f"QDialog {{ background: {t['bg']}; color: {t['ink']}; }}"
            f"QLabel {{ color: {t['ink']}; }}"
            f"QFrame#box {{ background: {t['surface']}; border: 1px solid {t['line']};"
            " border-radius: 12px; }"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 16)
        layout.setSpacing(10)

        head = QHBoxLayout()
        title = QLabel(app_label(conn))
        title.setStyleSheet("font-size: 22px; font-weight: 700;")
        head.addWidget(title)
        risk = QLabel(tr(RISK_LABELS.get(conn.risk, "traffic.risk.info")))
        colour = {"high": t["critical"], "medium": t["medium"], "info": t["accent"]}[conn.risk]
        risk.setStyleSheet(
            f"background: {colour}22; color: {colour}; border-radius: 9px;"
            " padding: 3px 10px; font-size: 11px; font-weight: 800;"
        )
        head.addWidget(risk)
        head.addStretch(1)
        layout.addLayout(head)

        self.country_label = QLabel("")
        self.country_label.setStyleSheet(f"color: {t['muted']}; font-size: 11px;")
        layout.addWidget(self.country_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        inner = QWidget()
        inner_layout = QVBoxLayout(inner)
        inner_layout.setContentsMargins(0, 0, 6, 0)
        inner_layout.setSpacing(10)

        inner_layout.addWidget(self._box(tr("traffic.detail.who"), [
            (tr("traffic.col.app"), app_label(conn)),
            ("PID", str(conn.pid)),
            ("PPID", str(conn.ppid)),
            (tr("col.parent"), conn.parent or "—"),
            (tr("col.user"), conn.username or "—"),
            (tr("col.path"), conn.exe or "—"),
        ]))
        where_rows = [
            (tr("traffic.col.destination"), conn.remote_label),
            (tr("traffic.domain"), conn.domain or "—"),
            (tr("traffic.col.service"), conn.service or "—"),
            ("Port", str(conn.remote_port or "—")),
            ("Local", conn.local_label),
        ]
        inner_layout.addWidget(self._box(tr("traffic.detail.where"), where_rows))
        inner_layout.addWidget(self._box(tr("traffic.detail.how"), [
            (tr("traffic.col.protocol"), conn.protocol),
            (tr("traffic.col.state"), _state_label(conn.state)),
            (tr("traffic.col.age"), _fmt_age(conn.age)),
        ]))

        reasons = [tr("traffic.reason." + reason) for reason in conn.reasons] or [tr("traffic.risk.info")]
        inner_layout.addWidget(self._box(tr("traffic.detail.why"), [("•", r) for r in reasons]))
        normal = QLabel(tr("traffic.detail.normal_text"))
        normal.setWordWrap(True)
        normal.setStyleSheet(f"color: {t['muted']}; font-size: 11px;")
        inner_layout.addWidget(normal)
        inner_layout.addStretch(1)
        scroll.setWidget(inner)
        layout.addWidget(scroll, 1)

        actions = QHBoxLayout()
        self.enrich_btn = QPushButton(tr("traffic.detail.enrich"))
        self.enrich_btn.setEnabled(conn.is_public)
        self.enrich_btn.setToolTip(
            tr("traffic.detail.enrich_note") if conn.is_public else ""
        )
        self.enrich_btn.clicked.connect(self._enrich)
        actions.addWidget(self.enrich_btn)
        note = QLabel(tr("traffic.detail.enrich_note"))
        note.setStyleSheet(f"color: {t['muted']}; font-size: 10px;")
        actions.addWidget(note)
        actions.addStretch(1)
        layout.addLayout(actions)

        buttons = QHBoxLayout()
        vt = QPushButton(tr("traffic.detail.vt"))
        vt.setEnabled(conn.is_public)
        vt.clicked.connect(lambda: self.page.open_finding(conn, "vt"))
        buttons.addWidget(vt)
        ai = QPushButton(tr("traffic.detail.ai"))
        ai.clicked.connect(lambda: self.page.open_finding(conn, "ai"))
        buttons.addWidget(ai)
        self.down_btn = QPushButton()
        self.down_btn.clicked.connect(lambda: self._block("in"))
        buttons.addWidget(self.down_btn)
        self.up_btn = QPushButton()
        self.up_btn.clicked.connect(lambda: self._block("out"))
        buttons.addWidget(self.up_btn)
        buttons.addStretch(1)
        close = QPushButton(tr("traffic.detail.close"))
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self._refresh_blocks()

    def _box(self, title: str, rows) -> QFrame:
        frame = QFrame()
        frame.setObjectName("box")
        box = QVBoxLayout(frame)
        box.setContentsMargins(16, 10, 16, 10)
        box.setSpacing(3)
        box.addWidget(micro(title, self.t["muted"]))
        for label, value in rows:
            line = QHBoxLayout()
            name = QLabel(str(label))
            name.setStyleSheet(f"color: {self.t['muted']}; font-size: 11px;")
            name.setFixedWidth(140)
            text = QLabel(str(value))
            text.setWordWrap(True)
            text.setTextInteractionFlags(Qt.TextSelectableByMouse)
            text.setStyleSheet("font-size: 12px;")
            line.addWidget(name)
            line.addWidget(text, 1)
            box.addLayout(line)
        return frame

    def _refresh_blocks(self):
        for direction, button, down in (("in", self.down_btn, True), ("out", self.up_btn, False)):
            if not self.conn.blockable:
                button.setText("—")
                button.setEnabled(False)
                continue
            blocked = self.page.firewall.is_blocked(
                self.conn.remote_ip, self.conn.remote_port, direction, self.conn.protocol
            )
            if down:
                button.setText(tr("traffic.unblock.down") if blocked else tr("traffic.block.down"))
            else:
                button.setText(tr("traffic.unblock.up") if blocked else tr("traffic.block.up"))
            button.setStyleSheet(
                f"background: {self.t['critical']}; color: white; border: none;"
                " border-radius: 8px; padding: 6px 10px; font-weight: 700;"
                if blocked else
                f"background: transparent; color: {self.t['ink']};"
                f" border: 1px solid {self.t['line']}; border-radius: 8px; padding: 6px 10px;"
            )

    def _block(self, direction: str):
        self.page.toggle_block(self.conn, direction)
        self._refresh_blocks()

    def _enrich(self):
        if self._worker is not None:
            return
        self.enrich_btn.setEnabled(False)
        self.enrich_btn.setText(tr("traffic.detail.enriching"))
        self._worker = IpLookupWorker(self.conn.remote_ip)
        self._worker.done.connect(self._enriched)
        self._worker.failed.connect(self._failed)
        self._worker.start()

    def _enriched(self, data: dict):
        self.enrich_btn.setEnabled(False)
        self.enrich_btn.setText(tr("traffic.detail.enrich"))
        pieces = [data.get("country", ""), data.get("city", ""), data.get("org", "")]
        self.country_label.setText(" · ".join(piece for piece in pieces if piece))

    def _failed(self, message: str):
        self.enrich_btn.setEnabled(True)
        self.enrich_btn.setText(tr("traffic.detail.enrich"))
        QMessageBox.warning(self, tr("traffic.detail.enrich"), tr("traffic.detail.enrich_failed", message=message))


class FirewallRulesDialog(QDialog):
    """Review and remove the blocking rules created by the traffic page."""

    def __init__(self, t: dict, page: "TrafficPage"):
        super().__init__(page)
        self.t = t
        self.page = page
        self.setWindowTitle(tr("traffic.rules.title"))
        self.setMinimumSize(680, 420)
        self.setStyleSheet(
            f"QDialog {{ background: {t['bg']}; color: {t['ink']}; }}"
            f"QLabel {{ color: {t['ink']}; }}"
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(22, 18, 22, 16)
        layout.setSpacing(10)

        title = QLabel(tr("traffic.rules.title"))
        title.setStyleSheet("font-size: 20px; font-weight: 700;")
        layout.addWidget(title)
        hint = QLabel(tr("traffic.rules.hint"))
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {t['muted']}; font-size: 11px;")
        layout.addWidget(hint)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([
            tr("traffic.rules.col.direction"), tr("traffic.rules.col.address"),
            tr("traffic.rules.col.port"), tr("traffic.rules.col.protocol"),
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        layout.addWidget(self.table, 1)

        self.empty = QLabel(tr("traffic.rules.empty"))
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
        layout.addWidget(self.empty)

        buttons = QHBoxLayout()
        remove = QPushButton(tr("traffic.rules.remove"))
        remove.clicked.connect(self._remove_selected)
        buttons.addWidget(remove)
        remove_all = QPushButton(tr("traffic.rules.remove_all"))
        remove_all.clicked.connect(self._remove_all)
        buttons.addWidget(remove_all)
        buttons.addStretch(1)
        close = QPushButton(tr("detail.close"))
        close.clicked.connect(self.accept)
        buttons.addWidget(close)
        layout.addLayout(buttons)
        self.refresh()

    def refresh(self):
        rules = list(self.page.firewall.blocked_map().values())
        self.table.setRowCount(0)
        for rule in rules:
            row = self.table.rowCount()
            self.table.insertRow(row)
            direction = tr("traffic.rules.direction.in" if rule.get("direction") == "in"
                           else "traffic.rules.direction.out")
            values = [direction, rule.get("ip", ""), rule.get("port", ""), rule.get("protocol", "")]
            for column, value in enumerate(values):
                self.table.setItem(row, column, QTableWidgetItem(str(value)))
        self.table.setVisible(bool(rules))
        self.empty.setVisible(not rules)

    def _selected(self):
        row = self.table.currentRow()
        if row < 0:
            return None
        rules = list(self.page.firewall.blocked_map().values())
        return rules[row] if row < len(rules) else None

    def _remove_selected(self):
        rule = self._selected()
        if not rule:
            return
        if QMessageBox.question(self, tr("traffic.rules.title"),
                                tr("traffic.rules.confirm")) != QMessageBox.Yes:
            return
        self._remove(rule)

    def _remove(self, rule):
        ok, message = self.page.firewall.set_blocked(
            rule["ip"], int(rule["port"]), rule["direction"], rule["protocol"], False
        )
        if not ok:
            QMessageBox.critical(self, tr("traffic.rules.title"),
                                 tr("traffic.rules.failed", message=message))
            return
        self.refresh()
        self.page._last_keys = None
        if self.page.snapshot_data:
            self.page._refresh_table(self.page.snapshot_data)

    def _remove_all(self):
        if not self.page.firewall.blocked_map():
            return
        if QMessageBox.question(self, tr("traffic.rules.title"),
                                tr("traffic.rules.confirm_all")) != QMessageBox.Yes:
            return
        self.page.firewall.remove_all()
        self.refresh()
        self.page._last_keys = None
        if self.page.snapshot_data:
            self.page._refresh_table(self.page.snapshot_data)


class TrafficPage(QWidget):
    """Live network visibility with per-direction blocking and one-click triage."""

    def __init__(self, t: dict, shell):
        super().__init__()
        self.t = t
        self.shell = shell
        self.monitor = TrafficMonitor()
        self.firewall = get_firewall_manager()
        self.snapshot_data: Optional[TrafficSnapshot] = None
        self.running = False
        self._started_once = False
        self._last_keys: Optional[tuple] = None
        self._row_meta: Dict[str, dict] = {}
        self._notified: Dict[str, float] = {}
        self._settings = QSettings("CyberGuardian", "CyberGuardian")

        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self._tick)

        self._build()
        self._update_empty()

    # ------------------------------------------------------------------ build
    def _build(self):
        t = self.t
        root = QVBoxLayout(self)
        root.setContentsMargins(30, 22, 30, 22)
        root.setSpacing(12)

        header = QHBoxLayout()
        copy = QVBoxLayout()
        copy.setSpacing(1)
        title = QLabel(tr("traffic.title"))
        title.setStyleSheet("font-size: 28px; font-weight: 700;")
        copy.addWidget(title)
        subtitle = QLabel(tr("traffic.subtitle"))
        subtitle.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
        copy.addWidget(subtitle)
        header.addLayout(copy, 1)

        self.adapter_box = QComboBox()
        for adapter in self.monitor.adapters():
            self.adapter_box.addItem(adapter)
        self.adapter_box.setMinimumWidth(170)
        self.adapter_box.currentTextChanged.connect(self._adapter_changed)
        header.addWidget(self.adapter_box)

        self.notify = QCheckBox(tr("traffic.notify"))
        self.notify.setChecked(True)
        self.notify.setStyleSheet("font-size: 11px;")
        header.addWidget(self.notify)

        rules = QPushButton(tr("traffic.rules"))
        rules.clicked.connect(self.open_rules)
        header.addWidget(rules)

        guide = QPushButton(tr("traffic.guide"))
        guide.clicked.connect(self.open_guide)
        header.addWidget(guide)

        self.start_btn = QPushButton(tr("traffic.start"))
        self.start_btn.setObjectName("primary")
        self.start_btn.setMinimumWidth(110)
        self.start_btn.clicked.connect(self.toggle_running)
        header.addWidget(self.start_btn)
        root.addLayout(header)

        stats = QHBoxLayout()
        stats.setSpacing(10)
        self.stat_values = {}
        for key, label in (
            ("down", tr("traffic.stat.down")), ("up", tr("traffic.stat.up")),
            ("connections", tr("traffic.stat.connections")),
            ("review", tr("traffic.stat.review")),
        ):
            card = QFrame()
            card.setStyleSheet(
                f"QFrame {{ background: {t['surface']}; border: 1px solid {t['line']};"
                " border-radius: 12px; }"
            )
            box = QVBoxLayout(card)
            box.setContentsMargins(14, 10, 14, 10)
            box.setSpacing(2)
            box.addWidget(micro(label, t["muted"]))
            value = QLabel("—")
            value.setStyleSheet("font-size: 21px; font-weight: 700;")
            box.addWidget(value)
            self.stat_values[key] = value
            stats.addWidget(card, 1)

        spark_card = QFrame()
        spark_card.setStyleSheet(
            f"QFrame {{ background: {t['surface']}; border: 1px solid {t['line']};"
            " border-radius: 12px; }"
        )
        spark_layout = QVBoxLayout(spark_card)
        spark_layout.setContentsMargins(10, 8, 10, 8)
        spark_layout.setSpacing(0)
        self.spark = Sparkline(t)
        spark_layout.addWidget(self.spark)
        stats.addWidget(spark_card, 3)
        root.addLayout(stats)

        self.first_run = QFrame()
        self.first_run.setStyleSheet(
            f"QFrame {{ background: {t['accent_soft']}; border: 1px solid {t['line']};"
            " border-radius: 12px; }"
        )
        first_layout = QHBoxLayout(self.first_run)
        first_layout.setContentsMargins(16, 10, 16, 10)
        text_box = QVBoxLayout()
        first_title = QLabel(tr("traffic.firstrun.title"))
        first_title.setStyleSheet("font-weight: 700; font-size: 12px;")
        first_text = QLabel(tr("traffic.firstrun.text"))
        first_text.setWordWrap(True)
        first_text.setStyleSheet(f"color: {t['muted']}; font-size: 11px;")
        text_box.addWidget(first_title)
        text_box.addWidget(first_text)
        first_layout.addLayout(text_box, 1)
        open_guide = QPushButton(tr("traffic.firstrun.open"))
        open_guide.clicked.connect(self._first_guide)
        first_layout.addWidget(open_guide)
        dismiss = QPushButton(tr("traffic.firstrun.dismiss"))
        dismiss.clicked.connect(self._dismiss_first)
        first_layout.addWidget(dismiss)
        root.addWidget(self.first_run)
        if self._settings.value("traffic/guide_seen", False, type=bool):
            self.first_run.setVisible(False)

        self.banner = QFrame()
        self.banner.setStyleSheet(
            "QFrame { background: #fdf5df; border: 1px solid #e7d39a; border-radius: 12px; }"
        )
        banner_layout = QHBoxLayout(self.banner)
        banner_layout.setContentsMargins(16, 10, 16, 10)
        banner_text = QVBoxLayout()
        self.banner_title = QLabel("")
        self.banner_title.setStyleSheet("color: #6b4d0f; font-weight: 700; font-size: 12px;")
        banner_sub = QLabel(tr("traffic.banner.text"))
        banner_sub.setWordWrap(True)
        banner_sub.setStyleSheet("color: #6b4d0f; font-size: 11px;")
        banner_text.addWidget(self.banner_title)
        banner_text.addWidget(banner_sub)
        banner_layout.addLayout(banner_text, 1)
        review = QPushButton(tr("traffic.banner.review"))
        review.clicked.connect(self._review_first)
        banner_layout.addWidget(review)
        understand = QPushButton(tr("traffic.banner.understand"))
        understand.clicked.connect(self.open_guide)
        banner_layout.addWidget(understand)
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText(tr("traffic.search"))
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filters_changed)
        filters.addWidget(self.search, 2)

        self.scope = QComboBox()
        self.scope.addItem(tr("traffic.scope.all"), "all")
        self.scope.addItem(tr("traffic.scope.external"), "external")
        self.scope.addItem(tr("traffic.scope.local"), "local")
        self.scope.addItem(tr("traffic.scope.listening"), "listening")
        self.scope.currentIndexChanged.connect(self._filters_changed)
        filters.addWidget(self.scope)

        self.risk_filter = QComboBox()
        self.risk_filter.addItem(tr("traffic.risk.all"), "all")
        self.risk_filter.addItem(tr("traffic.risk.review"), "review")
        self.risk_filter.currentIndexChanged.connect(self._filters_changed)
        filters.addWidget(self.risk_filter)

        self.proto = QComboBox()
        self.proto.addItem(tr("traffic.proto.all"), "all")
        self.proto.addItem("TCP", "TCP")
        self.proto.addItem("UDP", "UDP")
        self.proto.currentIndexChanged.connect(self._filters_changed)
        filters.addWidget(self.proto)

        export = QPushButton(tr("traffic.export"))
        export.clicked.connect(self.export_snapshot)
        filters.addWidget(export)
        root.addLayout(filters)

        self.table = QTableWidget(0, 10)
        self.table.setHorizontalHeaderLabels([
            tr("traffic.col.risk"), tr("traffic.col.app"), tr("traffic.col.destination"),
            tr("traffic.col.service"), tr("traffic.col.protocol"),
            tr("traffic.col.state"), tr("traffic.col.age"),
            tr("traffic.col.block_down"), tr("traffic.col.block_up"), tr("traffic.col.actions"),
        ])
        header_view = self.table.horizontalHeader()
        header_view.setSectionResizeMode(QHeaderView.Fixed)
        header_view.setSectionResizeMode(2, QHeaderView.Stretch)
        for column, width in {
            0: 72, 1: 160, 3: 90, 4: 95, 5: 95, 6: 64,
            7: 150, 8: 150, 9: 164,
        }.items():
            self.table.setColumnWidth(column, width)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setShowGrid(False)
        self.table.doubleClicked.connect(self._open_selected)
        root.addWidget(self.table, 1)

        self.empty = QLabel("")
        self.empty.setAlignment(Qt.AlignCenter)
        self.empty.setWordWrap(True)
        self.empty.setStyleSheet(f"color: {t['muted']}; font-size: 13px;")
        root.addWidget(self.empty)

        self.legend = QLabel(tr("traffic.legend"))
        self.legend.setWordWrap(True)
        self.legend.setStyleSheet(f"color: {t['muted']}; font-size: 10px;")
        root.addWidget(self.legend)
        self.status = QLabel(tr("traffic.status.paused"))
        self.status.setStyleSheet(f"color: {t['muted']}; font-size: 10px;")
        root.addWidget(self.status)

    # --------------------------------------------------------------- lifecycle
    def showEvent(self, event):
        super().showEvent(event)
        if not self._started_once:
            self._started_once = True
            self.start()

    def shutdown(self):
        self.timer.stop()

    def toggle_running(self):
        if self.running:
            self.pause()
        else:
            self.start()

    def start(self):
        self.running = True
        self.timer.start()
        self.start_btn.setText(tr("traffic.pause"))
        self.start_btn.setObjectName("")
        self.status.setText(tr("traffic.status.running"))
        self._tick()

    def pause(self):
        self.running = False
        self.timer.stop()
        self.start_btn.setText(tr("traffic.resume"))
        self.start_btn.setObjectName("primary")
        self.status.setText(tr("traffic.status.paused"))
        self._update_empty()

    def _adapter_changed(self, name: str):
        self.monitor.set_adapter(name)
        self.monitor._adapter_counters = None
        self._last_keys = None

    # ------------------------------------------------------------------- data
    def _tick(self):
        if not self.running:
            return
        self.snapshot_data = self.monitor.snapshot()
        snap = self.snapshot_data
        self.stat_values["down"].setText(_fmt_rate(snap.download_bps))
        self.stat_values["up"].setText(_fmt_rate(snap.upload_bps))
        self.stat_values["down"].setToolTip(f"{tr('traffic.total')}: {_fmt_bytes(snap.total_download)}")
        self.stat_values["up"].setToolTip(f"{tr('traffic.total')}: {_fmt_bytes(snap.total_upload)}")
        self.stat_values["connections"].setText(str(len(snap.connections)))
        self.stat_values["review"].setText(str(snap.suspicious))
        self.spark.add(snap.download_bps, snap.upload_bps)
        self._update_banner(snap)
        self._refresh_table(snap)
        self._notify(snap)

    def _filtered(self, connections: List[ConnectionView]):
        scope = self.scope.currentData()
        risk = self.risk_filter.currentData()
        protocol = self.proto.currentData()
        needle = self.search.text().strip().lower()
        result = []
        for conn in connections:
            if scope == "external" and not conn.is_public:
                continue
            if scope == "local" and not conn.is_lan:
                continue
            if scope == "listening" and conn.state != "LISTEN":
                continue
            if risk == "review" and conn.risk == "info":
                continue
            if protocol != "all" and conn.protocol != protocol:
                continue
            if needle:
                haystack = " ".join((
                    conn.app, conn.exe, conn.remote_ip, conn.domain,
                    conn.service, str(conn.remote_port), conn.username,
                )).lower()
                if needle not in haystack:
                    continue
            result.append(conn)
        return result

    def _update_banner(self, snap: TrafficSnapshot):
        show = snap.suspicious > 0 and self.running
        self.banner.setVisible(show)
        if show:
            self.banner_title.setText(tr("traffic.banner.title", count=snap.suspicious))

    def _refresh_table(self, snap: TrafficSnapshot):
        connections = self._filtered(snap.connections)
        keys = tuple(conn.key for conn in connections)
        if keys == self._last_keys:
            for conn in connections:
                meta = self._row_meta.get(conn.key)
                if not meta:
                    continue
                meta["conn"] = conn
                meta["age"].setText(_fmt_age(conn.age))
                if "dest" in meta:
                    meta["dest"].setText(conn.remote_label)
                self._apply_risk(meta["risk"], conn)
            self._update_empty()
            return

        self._last_keys = keys
        selected = self.table.currentRow()
        selected_key = None
        if 0 <= selected < self.table.rowCount():
            item = self.table.item(selected, 2)
            selected_key = item.data(Qt.UserRole) if item else None

        self.table.setUpdatesEnabled(False)
        self.table.setRowCount(0)
        self._row_meta = {}
        for conn in connections:
            row = self.table.rowCount()
            self.table.insertRow(row)
            risk_item = QTableWidgetItem("")
            risk_item.setForeground(QColor(
                self.t["critical"] if conn.risk == "high"
                else self.t["medium"] if conn.risk == "medium" else self.t["accent"]
            ))
            self.table.setItem(row, 0, risk_item)
            self._apply_risk(risk_item, conn)

            app = QTableWidgetItem(app_label(conn))
            app.setToolTip(conn.exe or conn.cmdline)
            self.table.setItem(row, 1, app)

            destination = QTableWidgetItem(conn.remote_label)
            destination.setData(Qt.UserRole, conn.key)
            network = "LAN" if conn.is_lan else ("Internet" if conn.is_public else "Local")
            destination.setToolTip(f"{conn.local_label} → {conn.remote_label} ({network})")
            self.table.setItem(row, 2, destination)

            service = QTableWidgetItem(conn.service or "—")
            service.setToolTip(f"Port {conn.remote_port or conn.local_port}")
            self.table.setItem(row, 3, service)

            self.table.setItem(row, 4, QTableWidgetItem(conn.protocol))
            self.table.setItem(row, 5, QTableWidgetItem(_state_label(conn.state)))
            age = QTableWidgetItem(_fmt_age(conn.age))
            self.table.setItem(row, 6, age)

            down_btn = self._block_button(conn, "in")
            self.table.setCellWidget(row, 7, down_btn)
            up_btn = self._block_button(conn, "out")
            self.table.setCellWidget(row, 8, up_btn)

            actions = QWidget()
            action_layout = QHBoxLayout(actions)
            action_layout.setContentsMargins(2, 2, 2, 2)
            action_layout.setSpacing(3)
            for text, callback in (
                (tr("traffic.action.vt"), lambda _=False, c=conn: self.open_finding(c, "vt")),
                (tr("traffic.action.ai"), lambda _=False, c=conn: self.open_finding(c, "ai")),
                (tr("traffic.action.details"), lambda _=False, c=conn: self.open_details(c)),
            ):
                button = QPushButton(text)
                button.setFixedHeight(24)
                button.setStyleSheet(
                    f"QPushButton {{ background: transparent; color: {self.t['ink']};"
                    f" border: 1px solid {self.t['line']}; border-radius: 6px;"
                    " padding: 1px 6px; font-size: 10px; }"
                    f"QPushButton:hover {{ border-color: {self.t['accent']}; }}"
                    f"QPushButton:disabled {{ color: {self.t['muted']}; border-color: {self.t['line']}; }}"
                )
                button.clicked.connect(callback)
                if text == tr("traffic.action.vt"):
                    button.setEnabled(conn.is_public)
                action_layout.addWidget(button)
            self.table.setCellWidget(row, 9, actions)
            self.table.setRowHeight(row, 34)

            self._row_meta[conn.key] = {
                "conn": conn, "risk": risk_item, "age": age, "dest": destination,
                "down": down_btn, "up": up_btn,
            }

        if selected_key:
            for row in range(self.table.rowCount()):
                item = self.table.item(row, 2)
                if item and item.data(Qt.UserRole) == selected_key:
                    self.table.selectRow(row)
                    break
        self.table.setUpdatesEnabled(True)
        self._update_empty()

    def _apply_risk(self, item: QTableWidgetItem, conn: ConnectionView):
        item.setText(tr(RISK_LABELS.get(conn.risk, "traffic.risk.info")))
        item.setToolTip("\n".join(tr("traffic.reason." + reason) for reason in conn.reasons))

    def _block_button(self, conn: ConnectionView, direction: str) -> QPushButton:
        blocked = self.firewall.is_blocked(
            conn.remote_ip, conn.remote_port, direction, conn.protocol
        ) if conn.blockable else False
        label = (
            tr("traffic.unblock.down") if direction == "in" else tr("traffic.unblock.up")
        ) if blocked else (
            tr("traffic.block.down") if direction == "in" else tr("traffic.block.up")
        )
        if not conn.blockable:
            label = "—"
        button = QPushButton(label)
        button.setFixedHeight(24)
        button.setEnabled(conn.blockable)
        button.setStyleSheet(
            f"QPushButton {{ background: {self.t['critical']}; color: white; border: none;"
            " border-radius: 6px; padding: 1px 6px; font-size: 10px; font-weight: 700; }"
            if blocked else
            f"QPushButton {{ background: transparent; color: {self.t['ink']};"
            f" border: 1px solid {self.t['line']}; border-radius: 6px;"
            " padding: 1px 6px; font-size: 10px; }"
        )
        button.clicked.connect(lambda _=False: self.toggle_block(conn, direction))
        button.setToolTip(tr("traffic.block.tooltip", remote=conn.remote_label))
        return button

    def _update_empty(self):
        has_rows = self.table.rowCount() > 0
        self.table.setVisible(has_rows)
        self.empty.setVisible(not has_rows)
        if not self.running:
            self.empty.setText(tr("traffic.empty.stopped"))
        else:
            self.empty.setText(tr("traffic.empty.filtered"))

    def _filters_changed(self, *_):
        self._last_keys = None
        if self.snapshot_data:
            self._refresh_table(self.snapshot_data)

    # ------------------------------------------------------------------ actions
    def _selected_connection(self) -> Optional[ConnectionView]:
        row = self.table.currentRow()
        if row < 0:
            return None
        item = self.table.item(row, 2)
        key = item.data(Qt.UserRole) if item else None
        meta = self._row_meta.get(key)
        return meta["conn"] if meta else None

    def _open_selected(self, *_):
        conn = self._selected_connection()
        if conn:
            self.open_details(conn)

    def open_details(self, conn: ConnectionView):
        ConnectionDetailDialog(self.t, conn, self).exec_()

    def open_finding(self, conn: ConnectionView, tab: str):
        detection = self._detection(conn)
        FindingDialog(self.t, detection, self, initial_tab=tab, auto_start=True).exec_()

    def _detection(self, conn: ConnectionView) -> Detection:
        risk = {"high": RiskLevel.HIGH, "medium": RiskLevel.MEDIUM}.get(conn.risk, RiskLevel.LOW)
        reasons = ", ".join(tr("traffic.reason." + reason) for reason in conn.reasons) or tr("traffic.risk.info")
        connection = {
            "local": conn.local_label, "remote": conn.remote_label,
            "remote_ip": conn.remote_ip, "remote_port": conn.remote_port,
            "local_ip": conn.local_ip, "local_port": conn.local_port,
            "remote_hostname": conn.domain, "protocol": conn.protocol,
            "status": conn.state, "pid": conn.pid, "process_name": conn.app,
            "process_path": conn.exe, "process_owner": conn.username,
            "process_cmdline": conn.cmdline, "age_seconds": round(conn.age, 1),
            "bytes_sent": 0, "bytes_recv": 0,
        }
        process = {
            "name": conn.app, "pid": conn.pid, "ppid": conn.ppid,
            "parent": conn.parent, "path": conn.exe,
            "directory": str(__import__("pathlib").Path(conn.exe).parent) if conn.exe else "",
            "command_line": conn.cmdline, "user": conn.username,
            "started": conn.started,
        }
        return Detection(
            detection_id=f"LIVE-{abs(hash(conn.key)) % 10**10}",
            detection_type="live_connection",
            indicator=conn.remote_label,
            indicator_type="network",
            risk_level=risk,
            confidence=0.6 if conn.risk != "info" else 0.3,
            description=f"{conn.app} → {conn.remote_label}",
            detection_reason=reasons,
            remediation=[
                tr("traffic.detail.normal_text"),
            ],
            process_name=conn.app,
            process_id=conn.pid,
            file_path=conn.exe,
            command_line=conn.cmdline,
            user=conn.username,
            evidence={"connection": connection, "process": process},
        )

    def toggle_block(self, conn: ConnectionView, direction: str):
        if not conn.blockable:
            return
        blocked = self.firewall.is_blocked(
            conn.remote_ip, conn.remote_port, direction, conn.protocol
        )
        if not blocked:
            confirm = QMessageBox.question(
                self, tr("traffic.confirm_block_title"),
                tr("traffic.confirm_block", remote=conn.remote_label),
                QMessageBox.Yes | QMessageBox.No,
            )
            if confirm != QMessageBox.Yes:
                return
        ok, message = self.firewall.set_blocked(
            conn.remote_ip, conn.remote_port, direction, conn.protocol, not blocked
        )
        if not ok:
            if message == "admin":
                QMessageBox.information(self, tr("traffic.confirm_block_title"),
                                        tr("traffic.admin_required"))
            else:
                QMessageBox.critical(self, tr("traffic.confirm_block_title"),
                                     tr("traffic.block_failed", message=message))
            return
        self._last_keys = None
        if self.snapshot_data:
            self._refresh_table(self.snapshot_data)

    def _review_first(self):
        if self.snapshot_data:
            for conn in self.snapshot_data.connections:
                if conn.risk != "info":
                    self.open_details(conn)
                    return

    def _first_guide(self):
        self._settings.setValue("traffic/guide_seen", True)
        self.first_run.setVisible(False)
        self.open_guide()

    def _dismiss_first(self):
        self._settings.setValue("traffic/guide_seen", True)
        self.first_run.setVisible(False)

    def open_rules(self):
        FirewallRulesDialog(self.t, self).exec_()

    def open_guide(self):
        TrafficGuideDialog(self.t, self).exec_()

    def _notify(self, snap: TrafficSnapshot):
        if not self.notify.isChecked() or not getattr(self.shell, "tray", None):
            return
        now = time.time()
        for conn in snap.connections:
            if conn.risk != "high":
                continue
            last = self._notified.get(conn.key, 0)
            if now - last < 1800:
                continue
            self._notified[conn.key] = now
            try:
                self.shell.tray.showMessage(
                    tr("traffic.banner.title", count=1),
                    f"{conn.app} → {conn.remote_label}",
                    self.shell.tray.Warning, 8000,
                )
            except Exception:
                pass

    def export_snapshot(self):
        if not self.snapshot_data:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, tr("traffic.export_title"),
            f"traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            "CSV (*.csv);;JSON (*.json)",
        )
        if not path:
            return
        connections = self._filtered(self.snapshot_data.connections)
        try:
            if path.lower().endswith(".json"):
                payload = [
                    {**conn.__dict__, "remote_label": conn.remote_label,
                     "local_label": conn.local_label}
                    for conn in connections
                ]
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(payload, handle, indent=2, default=str)
            else:
                fields = [
                    "app", "pid", "ppid", "parent", "exe", "username", "state",
                    "protocol", "local_ip", "local_port", "remote_ip",
                    "remote_port", "domain", "service", "risk", "reasons",
                    "down_rate", "up_rate", "age",
                ]
                with open(path, "w", encoding="utf-8-sig", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=fields)
                    writer.writeheader()
                    for conn in connections:
                        row = {field: getattr(conn, field, "") for field in fields}
                        row["reasons"] = ", ".join(conn.reasons)
                        writer.writerow(row)
        except OSError as exc:
            QMessageBox.critical(self, tr("traffic.export"), str(exc))
            return
        QMessageBox.information(self, tr("traffic.export"), tr("traffic.export_saved", path=path))
