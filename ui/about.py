"""
About CyberGuardian — identity, author and legal information.

The dialog is theme-aware and deliberately reads like a product page: a hero
with the monogram, the architect's name, project links and the legal notice,
plus a short privacy statement.
"""

from __future__ import annotations

from PyQt5.QtCore import Qt, QUrl
from PyQt5.QtGui import QDesktopServices, QFont
from PyQt5.QtWidgets import (
    QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget,
)

from core import branding
from ui.design_common import load_fonts, micro
from utils.i18n import tr


def _open(url: str):
    QDesktopServices.openUrl(QUrl(url))


class AboutDialog(QDialog):
    def __init__(self, t: dict, parent=None):
        super().__init__(parent)
        self.t = t
        self.setWindowTitle(f"{branding.APP_NAME} — {branding.APP_VERSION}")
        self.setMinimumSize(780, 660)
        family = load_fonts()

        self.setStyleSheet(f"""
            QDialog {{ background: {t['bg']}; color: {t['ink']}; }}
            QLabel {{ color: {t['ink']}; }}
            QPushButton {{
                background: {t['surface']}; color: {t['ink']};
                border: 1px solid {t['line']}; border-radius: 10px;
                padding: 8px 14px; font-weight: 600;
            }}
            QPushButton:hover {{ border-color: {t['accent']}; }}
            QPushButton#primary {{
                background: {t['accent']}; color: white; border: none;
            }}
            QFrame#card {{
                background: {t['surface']}; border: 1px solid {t['line']};
                border-radius: 16px;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(26, 24, 26, 20)
        layout.setSpacing(14)

        # ------------------------------------------------------------- hero
        hero = QFrame()
        hero.setObjectName("card")
        hero.setStyleSheet(
            f"QFrame#card {{ background: qlineargradient(x1:0, y1:0, x2:1, y2:1,"
            f" stop:0 {t['hero_a']}, stop:1 {t['hero_b']});"
            f" border: 1px solid {t['line']}; border-radius: 20px; }}"
        )
        hero_row = QHBoxLayout(hero)
        hero_row.setContentsMargins(26, 24, 26, 24)
        hero_row.setSpacing(22)

        monogram = QLabel("CG")
        monogram.setFixedSize(86, 86)
        monogram.setAlignment(Qt.AlignCenter)
        monogram.setFont(QFont(family, 30, QFont.Black))
        monogram.setStyleSheet(
            f"background: {t['accent']}; color: white; border-radius: 24px;"
        )
        hero_row.addWidget(monogram, 0, Qt.AlignTop)

        copy = QVBoxLayout()
        copy.setSpacing(4)
        name = QLabel(branding.APP_NAME)
        name.setFont(QFont(family, 28, QFont.Bold))
        copy.addWidget(name)

        version = QLabel(tr("about.version", version=branding.APP_VERSION))
        version.setStyleSheet(
            f"color: {t['accent']}; font-size: 12px; font-weight: 700;"
        )
        copy.addWidget(version)

        tagline = QLabel(tr("about.tagline"))
        tagline.setWordWrap(True)
        tagline.setStyleSheet(f"color: {t['muted']}; font-size: 13px;")
        copy.addWidget(tagline)

        privacy = QLabel(tr("about.privacy_note"))
        privacy.setWordWrap(True)
        privacy.setStyleSheet(f"color: {t['ink']}; font-size: 11px; opacity: 0.8;")
        copy.addSpacing(6)
        copy.addWidget(privacy)
        hero_row.addLayout(copy, 1)
        layout.addWidget(hero)

        # ----------------------------------------------------------- author
        author_card = QFrame()
        author_card.setObjectName("card")
        author_layout = QVBoxLayout(author_card)
        author_layout.setContentsMargins(24, 18, 24, 18)
        author_layout.setSpacing(3)
        author_layout.addWidget(micro(tr("about.role"), t["muted"]))
        author = QLabel(branding.AUTHOR)
        author.setFont(QFont(family, 24, QFont.Bold))
        author_layout.addWidget(author)
        role = QLabel(f"CyberGuardian · © {branding.YEAR} {branding.AUTHOR} · {tr('about.rights')}")
        role.setStyleSheet(f"color: {t['muted']}; font-size: 11px;")
        author_layout.addWidget(role)
        layout.addWidget(author_card)

        # ---------------------------------------------------------- columns
        columns = QHBoxLayout()
        columns.setSpacing(14)

        project = QFrame()
        project.setObjectName("card")
        project_layout = QVBoxLayout(project)
        project_layout.setContentsMargins(20, 16, 20, 16)
        project_layout.setSpacing(7)
        project_layout.addWidget(micro(tr("about.project"), t["muted"]))
        for label, url in (
            (tr("about.github"), branding.GITHUB_URL),
            (tr("about.releases"), branding.RELEASES_URL),
            (tr("about.issues"), branding.ISSUES_URL),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _=False, link=url: _open(link))
            project_layout.addWidget(button)
        project_layout.addStretch(1)
        columns.addWidget(project, 1)

        legal = QFrame()
        legal.setObjectName("card")
        legal_layout = QVBoxLayout(legal)
        legal_layout.setContentsMargins(20, 16, 20, 16)
        legal_layout.setSpacing(6)
        legal_layout.addWidget(micro(tr("about.legal"), t["muted"]))

        copyright_label = QLabel(f"© {branding.YEAR} {branding.AUTHOR}. {tr('about.rights')}")
        copyright_label.setWordWrap(True)
        copyright_label.setStyleSheet(f"color: {t['ink']}; font-size: 12px; font-weight: 600;")
        legal_layout.addWidget(copyright_label)

        license_label = QLabel(f"{tr('about.license')}: {branding.LICENSE_NAME}")
        license_label.setStyleSheet(f"color: {t['muted']}; font-size: 12px;")
        legal_layout.addWidget(license_label)

        legal_layout.addSpacing(4)
        legal_layout.addWidget(micro(tr("about.third_party"), t["muted"]))
        notices = QLabel(branding.THIRD_PARTY_NOTICES)
        notices.setWordWrap(True)
        notices.setStyleSheet(f"color: {t['muted']}; font-size: 10px;")
        legal_layout.addWidget(notices)
        legal_layout.addStretch(1)
        columns.addWidget(legal, 1)
        layout.addLayout(columns)

        # ---------------------------------------------------------- built with
        built = QFrame()
        built.setObjectName("card")
        built_row = QHBoxLayout(built)
        built_row.setContentsMargins(20, 12, 20, 12)
        built_row.setSpacing(10)
        built_row.addWidget(micro(tr("about.built"), t["muted"]))
        for name, role_text in branding.BUILT_WITH:
            chip = QLabel(f"{name} · {role_text}")
            chip.setStyleSheet(
                f"background: {t['chip_bg']}; color: {t['ink']};"
                " border-radius: 9px; padding: 3px 9px; font-size: 10px; font-weight: 600;"
            )
            built_row.addWidget(chip)
        built_row.addStretch(1)
        layout.addWidget(built)

        # ------------------------------------------------------------ footer
        footer = QHBoxLayout()
        link = QLabel(
            f'<a href="{branding.GITHUB_URL}" style="color:{t["accent"]};'
            f' text-decoration:none;">{branding.GITHUB_URL.replace("https://", "")}</a>'
        )
        link.setOpenExternalLinks(True)
        link.setStyleSheet("font-size: 11px;")
        footer.addWidget(link)
        footer.addStretch(1)

        github = QPushButton(tr("about.github"))
        github.setObjectName("primary")
        github.clicked.connect(lambda: _open(branding.GITHUB_URL))
        footer.addWidget(github)

        close = QPushButton(tr("about.close"))
        close.clicked.connect(self.reject)
        footer.addWidget(close)
        layout.addLayout(footer)
