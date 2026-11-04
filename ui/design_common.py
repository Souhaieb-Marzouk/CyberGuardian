"""
Shared visual kit for the v3/v4 design studies.

Deliberately small and opinionated: typographic scale, surfaces, a gauge and a
bar chart.  Each design supplies its own palette and QSS, so the two shells stay
visually independent while sharing the same primitives.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from PyQt5.QtCore import QRectF, Qt
from PyQt5.QtGui import QColor, QFont, QFontDatabase, QPainter, QPen
from PyQt5.QtWidgets import QFrame, QHBoxLayout, QLabel, QVBoxLayout, QWidget

FONT_CANDIDATES = (
    "Inter", "Segoe UI Variable Text", "Segoe UI", "Bahnschrift", "Arial",
)


def load_fonts() -> str:
    """Register a bundled font when present; return the family to use."""
    path = Path(__file__).resolve().parent.parent / "assets" / "fonts" / "Inter.ttf"
    if path.exists():
        font_id = QFontDatabase.addApplicationFont(str(path))
        if font_id >= 0:
            families = QFontDatabase.applicationFontFamilies(font_id)
            if families:
                return families[0]
    return "Segoe UI"


def micro(text: str, color: str, spacing: float = 1.6) -> QLabel:
    """Small uppercase section label."""
    item = QLabel(text.upper())
    font = QFont(item.font())
    font.setPointSize(8)
    font.setBold(True)
    font.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    item.setFont(font)
    item.setStyleSheet(f"color: {color}; background: transparent;")
    return item


class Card(QFrame):
    """Rounded surface with a subtle border and generous padding."""

    def __init__(self, bg: str, border: str, radius: int = 18, padding: int = 22, parent=None):
        super().__init__(parent)
        self.setObjectName("surfaceCard")
        self.setStyleSheet(
            f"QFrame#surfaceCard {{ background: {bg}; border: 1px solid {border};"
            f" border-radius: {radius}px; }}"
        )
        self.body = QVBoxLayout(self)
        self.body.setContentsMargins(padding, padding, padding, padding)
        self.body.setSpacing(12)


class Chip(QLabel):
    def __init__(self, text: str, fg: str, bg: str, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet(
            f"background: {bg}; color: {fg}; border-radius: 10px;"
            " padding: 3px 10px; font-size: 11px; font-weight: 600;"
        )
        self.setAlignment(Qt.AlignCenter)


class Gauge(QWidget):
    """Semi-circular score gauge with tick marks and a caption."""

    def __init__(self, accent: str, track: str, text: str, muted: str,
                 caption: str = "health", parent=None):
        super().__init__(parent)
        self.accent = QColor(accent)
        self.track = QColor(track)
        self.text_color = QColor(text)
        self.muted = QColor(muted)
        self.caption = caption
        self.value = 86
        self.setMinimumSize(260, 190)

    def set_value(self, value: int):
        self.value = max(0, min(100, value))
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width, height = self.width(), self.height()
        radius = min(width - 40, (height - 40) * 2) / 2
        rect = QRectF(width / 2 - radius, height - 55 - radius, radius * 2, radius * 2)

        # ticks
        painter.save()
        painter.translate(width / 2, height - 55)
        for index in range(41):
            angle = 180 - index * 4.5
            painter.save()
            painter.rotate(-angle)
            long_tick = index % 5 == 0
            painter.setPen(QPen(self.muted.lighter(120), 1.4 if long_tick else 1))
            length = 10 if long_tick else 5
            painter.drawLine(0, -int(radius) - 12, 0, -int(radius) - 12 - length)
            painter.restore()
        painter.restore()

        pen = QPen(self.track, 16, Qt.SolidLine, Qt.RoundCap)
        painter.setPen(pen)
        painter.drawArc(rect, 180 * 16, -180 * 16)

        pen.setColor(self.accent)
        painter.setPen(pen)
        painter.drawArc(rect, 180 * 16, -int(180 * 16 * self.value / 100))

        painter.setPen(self.text_color)
        font = QFont(self.font())
        font.setPointSize(42)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(QRectF(0, height - 150, width, 70), Qt.AlignCenter, str(self.value))

        painter.setPen(self.muted)
        font.setPointSize(10)
        font.setBold(False)
        painter.setFont(font)
        painter.drawText(QRectF(0, height - 78, width, 30), Qt.AlignCenter, self.caption)


class Bars(QWidget):
    """Compact horizontal bar chart for finding counts."""

    def __init__(self, accent: str, track: str, text: str, muted: str, parent=None):
        super().__init__(parent)
        self.accent = QColor(accent)
        self.track = QColor(track)
        self.text = QColor(text)
        self.muted = QColor(muted)
        self.items: List[Tuple[str, int]] = []
        self.setMinimumHeight(150)

    def set_items(self, items: List[Tuple[str, int]]):
        self.items = items or []
        self.update()

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        if not self.items:
            painter.setPen(self.muted)
            painter.drawText(self.rect(), Qt.AlignCenter, "No findings yet")
            return

        peak = max(value for _, value in self.items) or 1
        row_height = self.height() / max(len(self.items), 1)
        for index, (name, value) in enumerate(self.items):
            top = index * row_height + 6
            painter.setPen(self.muted)
            font = QFont(self.font())
            font.setPointSize(9)
            painter.setFont(font)
            painter.drawText(QRectF(0, top, self.width() * 0.32, 18), Qt.AlignLeft | Qt.AlignVCenter, name)

            bar_left = self.width() * 0.34
            bar_width = self.width() * 0.52
            painter.setPen(Qt.NoPen)
            painter.setBrush(self.track)
            painter.drawRoundedRect(QRectF(bar_left, top + 3, bar_width, 9), 4.5, 4.5)
            painter.setBrush(self.accent)
            painter.drawRoundedRect(
                QRectF(bar_left, top + 3, bar_width * (value / peak if peak else 0), 9), 4.5, 4.5
            )

            painter.setPen(self.text)
            painter.drawText(
                QRectF(self.width() * 0.88, top, self.width() * 0.12, 18),
                Qt.AlignRight | Qt.AlignVCenter, str(value),
            )


class Stat(QWidget):
    """Large number with a quiet label."""

    def __init__(self, value: str, label: str, text: str, muted: str, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(2)
        number = QLabel(value)
        number.setStyleSheet(f"color: {text}; font-size: 30px; font-weight: 700;")
        caption = QLabel(label)
        caption.setStyleSheet(f"color: {muted}; font-size: 11px;")
        layout.addWidget(number)
        layout.addWidget(caption)
