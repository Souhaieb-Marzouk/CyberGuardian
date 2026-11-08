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
    """Semi-circular score gauge with a status word and a caption."""

    def __init__(self, accent: str, track: str, text: str, muted: str,
                 caption: str = "health", parent=None):
        super().__init__(parent)
        self.accent = QColor(accent)
        self.track = QColor(track)
        self.text_color = QColor(text)
        self.muted = QColor(muted)
        self.caption = caption
        self.value = None
        self._family = load_fonts()
        self.setMinimumSize(280, 215)

    def set_value(self, value):
        if value is None:
            self.value = None
        else:
            self.value = max(0, min(100, int(value)))
        self.update()

    def _status(self):
        from utils.i18n import tr

        if self.value is None:
            return tr("gauge.no_data"), self.muted
        if self.value >= 85:
            return tr("gauge.excellent"), self.accent
        if self.value >= 70:
            return tr("gauge.good"), self.accent
        if self.value >= 50:
            return tr("gauge.fair"), QColor("#c56a1b")
        return tr("gauge.poor"), QColor("#c71f37")

    def paintEvent(self, _event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        width, height = self.width(), self.height()

        margin = 18
        stroke = 14
        radius = min((width - 2 * margin) / 2, height - 62)
        cx = width / 2
        cy = margin + radius + 6
        rect = QRectF(cx - radius, cy - radius, radius * 2, radius * 2)

        painter.setPen(QPen(self.track, stroke, Qt.SolidLine, Qt.RoundCap))
        painter.drawArc(rect, 180 * 16, -180 * 16)

        if self.value is not None:
            painter.setPen(QPen(self.accent, stroke, Qt.SolidLine, Qt.RoundCap))
            painter.drawArc(rect, 180 * 16, -int(180 * 16 * self.value / 100))

        # tick marks just outside the arc
        painter.save()
        painter.translate(cx, cy)
        for index in range(11):
            angle = 180 - index * 18
            painter.save()
            painter.rotate(-angle)
            painter.setPen(QPen(self.muted, 1))
            inner = int(radius) + stroke + 3
            outer = inner + (8 if index % 5 == 0 else 4)
            painter.drawLine(0, -inner, 0, -outer)
            painter.restore()
        painter.restore()

        font = QFont(self._family)
        font.setBold(True)
        font.setPointSizeF(max(24, min(40, width * 0.145)))
        painter.setFont(font)
        painter.setPen(self.text_color)
        score = "?" if self.value is None else str(self.value)
        painter.drawText(
            QRectF(cx - radius * 0.8, cy - radius * 0.78, radius * 1.6, radius * 0.62),
            Qt.AlignCenter, score,
        )

        label, colour = self._status()
        font.setPointSizeF(max(9, min(12, width * 0.043)))
        painter.setFont(font)
        painter.setPen(colour)
        painter.drawText(
            QRectF(cx - radius, cy + radius * 0.06, radius * 2, 20),
            Qt.AlignCenter, label,
        )

        font.setBold(False)
        font.setPointSizeF(8.5)
        painter.setFont(font)
        painter.setPen(self.muted)
        painter.drawText(QRectF(0, height - 20, width, 16), Qt.AlignCenter, self.caption)


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
