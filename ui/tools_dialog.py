"""
CyberGuardian Tools Dialog
==========================

One window for the everyday tools: startup impact, installed software, a
file/link reputation check, ransomware canaries and the quarantine vault.

Kept self-contained so it can be opened from the main window with a single
button; all business logic lives in ``core/``.
"""

from __future__ import annotations

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

from core.canary import get_canary_manager
from core.quarantine import QuarantineError, get_vault
from core.reputation import check_target
from core.software import audit, get_installed_software
from core.startup import enumerate_startup, set_enabled
from utils.logging_utils import get_logger

logger = get_logger("ui.tools_dialog")

COLORS = {
    "bg": "#070b14", "card": "#121b2c", "border": "#22304a",
    "text": "#e6edf7", "muted": "#8b9bb4", "primary": "#00e5a0",
    "medium": "#ffd166", "high": "#ff8a3d", "critical": "#ff4d6d",
}

IMPACT_COLORS = {"high": COLORS["critical"], "medium": COLORS["high"], "low": COLORS["primary"]}


def _button(text: str, handler=None, primary: bool = False) -> QPushButton:
    button = QPushButton(text)
    if primary:
        button.setStyleSheet(
            f"background: {COLORS['primary']}; color: #04120c; font-weight: bold;"
            "padding: 6px 14px; border-radius: 6px;"
        )
    if handler is not None:
        button.clicked.connect(handler)
    return button


def _table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
    table.setSelectionBehavior(QTableWidget.SelectRows)
    table.setEditTriggers(QTableWidget.NoEditTriggers)
    table.setStyleSheet(
        f"background: {COLORS['card']}; color: {COLORS['text']};"
        f"gridline-color: {COLORS['border']}; border: 1px solid {COLORS['border']};"
    )
    return table


class ToolsDialog(QDialog):
    """Tabbed toolbox for startup, software, reputation, canaries and quarantine."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CyberGuardian Tools")
        self.setMinimumSize(900, 620)
        self._startup_entries = []
        self._software_entries = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Tools")
        title.setStyleSheet(f"color: {COLORS['primary']}; font-size: 22px; font-weight: 900;")
        layout.addWidget(title)

        tabs = QTabWidget()
        tabs.addTab(self._build_startup_tab(), "Startup")
        tabs.addTab(self._build_software_tab(), "Software")
        tabs.addTab(self._build_check_tab(), "Check a file or link")
        tabs.addTab(self._build_canary_tab(), "Ransomware canaries")
        tabs.addTab(self._build_quarantine_tab(), "Quarantine")
        layout.addWidget(tabs, 1)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # ------------------------------------------------------------------ startup
    def _build_startup_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        self.startup_table = _table(["Name", "Impact", "Source", "State", "Publisher"])
        layout.addWidget(self.startup_table, 1)

        row = QHBoxLayout()
        row.addWidget(_button("Refresh", self.refresh_startup))
        row.addWidget(_button("Disable selected", lambda: self._toggle_startup(False)))
        row.addWidget(_button("Enable selected", lambda: self._toggle_startup(True)))
        row.addStretch(1)
        layout.addLayout(row)
        self.refresh_startup()
        return page

    def refresh_startup(self):
        self.startup_table.setRowCount(0)
        try:
            self._startup_entries = enumerate_startup(include_tasks=False)
        except Exception as exc:  # pragma: no cover - defensive
            QMessageBox.warning(self, "Startup", f"Could not enumerate startup items: {exc}")
            return
        for entry in self._startup_entries:
            row = self.startup_table.rowCount()
            self.startup_table.insertRow(row)
            values = [entry.name, entry.impact.upper(), entry.source,
                      "enabled" if entry.enabled else "disabled", entry.publisher or "—"]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 1:
                    item.setForeground(Qt.GlobalColor.white)
                    item.setBackground(Qt.GlobalColor.transparent)
                self.startup_table.setItem(row, column, item)

    def _toggle_startup(self, enabled: bool):
        row = self.startup_table.currentRow()
        if row < 0 or row >= len(self._startup_entries):
            QMessageBox.information(self, "Startup", "Select an entry first.")
            return
        entry = self._startup_entries[row]
        try:
            changed = set_enabled(entry, enabled)
        except Exception as exc:
            logger.warning(f"Startup change failed: {exc}")
            changed = False
        if changed:
            self.refresh_startup()
        elif entry.source == "service":
            QMessageBox.warning(
                self, "Startup",
                "Could not change this service. Administrator privileges are required.",
            )
        else:
            QMessageBox.warning(
                self, "Startup",
                "This startup item cannot be changed here. "
                "Use Task Manager > Startup apps instead.",
            )

    # ----------------------------------------------------------------- software
    def _build_software_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.software_table = _table(["Application", "Installed", "Safe from", "Status"])
        layout.addWidget(self.software_table, 1)
        row = QHBoxLayout()
        row.addWidget(_button("Refresh", self.refresh_software))
        row.addStretch(1)
        layout.addLayout(row)
        self.refresh_software()
        return page

    def refresh_software(self):
        self.software_table.setRowCount(0)
        try:
            self._software_entries = audit(get_installed_software())
        except Exception as exc:  # pragma: no cover
            QMessageBox.warning(self, "Software", f"Could not read installed software: {exc}")
            return
        for entry in self._software_entries:
            row = self.software_table.rowCount()
            self.software_table.insertRow(row)
            values = [entry.name, entry.version or "—", entry.min_version or "—",
                      entry.status.replace("_", " ")]
            for column, value in enumerate(values):
                self.software_table.setItem(row, column, QTableWidgetItem(str(value)))

    # -------------------------------------------------------------------- check
    def _build_check_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        hint = QLabel("Paste a link, or choose a file. Nothing is uploaded except a hash or URL to VirusTotal (if configured).")
        hint.setWordWrap(True)
        hint.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(hint)

        row = QHBoxLayout()
        self.check_input = QLineEdit()
        self.check_input.setPlaceholderText("https://example.com or C:\\Downloads\\file.exe")
        row.addWidget(self.check_input, 1)
        row.addWidget(_button("Browse…", self._browse_file))
        row.addWidget(_button("Check", self.run_check, primary=True))
        layout.addLayout(row)

        self.check_result = QTextEdit()
        self.check_result.setReadOnly(True)
        self.check_result.setStyleSheet(
            f"background: {COLORS['card']}; color: {COLORS['text']};"
            f"border: 1px solid {COLORS['border']}; padding: 10px;"
        )
        layout.addWidget(self.check_result, 1)
        return page

    def _browse_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a file to check")
        if path:
            self.check_input.setText(path)

    def run_check(self):
        target = self.check_input.text().strip()
        if not target:
            return
        try:
            verdict = check_target(target)
        except Exception as exc:
            self.check_result.setPlainText(f"Could not check this item:\n{exc}")
            return
        lines = [
            f"Verdict: {verdict.verdict.upper()}  (score {verdict.score}/100)",
            "",
            verdict.summary,
            "",
            "Why:",
        ]
        lines += [f"  • {reason}" for reason in verdict.reasons]
        details = verdict.details
        if details.get("vt_ratio"):
            lines += ["", f"VirusTotal: {details['vt_ratio']}"]
        self.check_result.setPlainText("\n".join(lines))

    # ------------------------------------------------------------------ canaries
    def _build_canary_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        text = QLabel(
            "Canary files look like important documents. If ransomware encrypts "
            "them, CyberGuardian can tell you immediately — before the rest of "
            "your files are affected."
        )
        text.setWordWrap(True)
        text.setStyleSheet(f"color: {COLORS['muted']};")
        layout.addWidget(text)

        row = QHBoxLayout()
        row.addWidget(_button("Install canaries", self._install_canaries, primary=True))
        row.addWidget(_button("Check now", self._check_canaries))
        row.addWidget(_button("Remove", self._remove_canaries))
        row.addStretch(1)
        layout.addLayout(row)

        self.canary_status = QLabel()
        self.canary_status.setWordWrap(True)
        layout.addWidget(self.canary_status)
        layout.addStretch(1)
        self._refresh_canary_status()
        return page

    def _refresh_canary_status(self):
        manager = get_canary_manager()
        if manager.is_installed():
            self.canary_status.setText(f"{len(manager.canaries)} canary file(s) active.")
        else:
            self.canary_status.setText("No canaries installed.")

    def _install_canaries(self):
        try:
            created = get_canary_manager().install()
        except Exception as exc:
            logger.warning(f"Canary install failed: {exc}")
            QMessageBox.critical(self, "Canaries", f"Could not create canary files:\n{exc}")
            return
        self._refresh_canary_status()
        QMessageBox.information(self, "Canaries", f"Created {len(created)} canary file(s).")

    def _remove_canaries(self):
        try:
            removed = get_canary_manager().remove()
        except Exception as exc:
            logger.warning(f"Canary removal failed: {exc}")
            QMessageBox.critical(self, "Canaries", f"Could not remove canary files:\n{exc}")
            return
        self._refresh_canary_status()
        QMessageBox.information(self, "Canaries", f"Removed {removed} canary file(s).")

    def _check_canaries(self):
        try:
            triggered = get_canary_manager().check()
        except Exception as exc:
            logger.warning(f"Canary check failed: {exc}")
            QMessageBox.critical(self, "Canaries", f"Could not check canary files:\n{exc}")
            return
        if triggered:
            QMessageBox.critical(
                self, "Possible ransomware",
                "A canary file was changed or deleted!\n\n"
                "Disconnect from the network now and do not reboot.\n"
                "Changed files:\n" + "\n".join(c.path for c in triggered[:5]),
            )
        else:
            QMessageBox.information(self, "Canaries", "All canary files are intact.")

    # ---------------------------------------------------------------- quarantine
    def _build_quarantine_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.quarantine_table = _table(["File", "Original path", "Size", "Quarantined"])
        layout.addWidget(self.quarantine_table, 1)

        row = QHBoxLayout()
        row.addWidget(_button("Refresh", self.refresh_quarantine))
        row.addWidget(_button("Restore selected", self._restore_selected, primary=True))
        row.addWidget(_button("Delete permanently", self._delete_selected))
        row.addStretch(1)
        layout.addLayout(row)
        self.refresh_quarantine()
        return page

    def refresh_quarantine(self):
        self.quarantine_table.setRowCount(0)
        try:
            self._quarantine_entries = get_vault().list_entries()
        except Exception as exc:
            logger.warning(f"Could not list quarantine: {exc}")
            self._quarantine_entries = []
            QMessageBox.warning(self, "Quarantine", f"Could not read the quarantine vault:\n{exc}")
            return
        for entry in self._quarantine_entries:
            row = self.quarantine_table.rowCount()
            self.quarantine_table.insertRow(row)
            values = [entry.name, entry.original_path, f"{entry.size/1024:.1f} KB",
                      entry.quarantined_at[:19].replace("T", " ")]
            for column, value in enumerate(values):
                self.quarantine_table.setItem(row, column, QTableWidgetItem(str(value)))

    def _selected_entry(self):
        row = self.quarantine_table.currentRow()
        if row < 0 or row >= len(getattr(self, "_quarantine_entries", [])):
            return None
        return self._quarantine_entries[row]

    def _restore_selected(self):
        entry = self._selected_entry()
        if entry is None:
            QMessageBox.information(self, "Quarantine", "Select an entry first.")
            return
        try:
            restored = get_vault().restore(entry.entry_id)
        except QuarantineError as exc:
            QMessageBox.critical(self, "Quarantine", str(exc))
        except Exception as exc:
            logger.warning(f"Restore failed: {exc}")
            QMessageBox.critical(self, "Quarantine", f"Could not restore the file:\n{exc}")
        else:
            QMessageBox.information(self, "Quarantine", f"Restored to:\n{restored}")
        self.refresh_quarantine()

    def _delete_selected(self):
        entry = self._selected_entry()
        if entry is None:
            QMessageBox.information(self, "Quarantine", "Select an entry first.")
            return
        if QMessageBox.question(
            self, "Delete permanently",
            f"Delete {entry.name} permanently? This cannot be undone.",
        ) == QMessageBox.Yes:
            try:
                get_vault().delete(entry.entry_id)
            except Exception as exc:
                logger.warning(f"Delete failed: {exc}")
                QMessageBox.critical(self, "Quarantine", f"Could not delete the file:\n{exc}")
            self.refresh_quarantine()
