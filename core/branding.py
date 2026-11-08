"""
Application identity and attribution.

One source of truth for the author, version, repository links and legal notice,
used by the Studio header, the About dialog, the status bar, exported reports
and the README.
"""

from __future__ import annotations

from datetime import datetime

APP_NAME = "CyberGuardian"
APP_VERSION = "1.5.0"
TAGLINE = "Local-first malware detection and threat hunting for Windows."

AUTHOR = "Souhaieb Marzouk"
AUTHOR_ROLE = "Designed & architected by"
GITHUB_URL = "https://github.com/Souhaieb-Marzouk/CyberGuardian"
RELEASES_URL = f"{GITHUB_URL}/releases"
ISSUES_URL = f"{GITHUB_URL}/issues"
LICENSE_NAME = "MIT License"

YEAR = datetime.now().year
COPYRIGHT = f"© {YEAR} {AUTHOR}. All rights reserved."
COPYRIGHT_SHORT = f"© {YEAR} {AUTHOR} · All rights reserved"

PRIVACY_NOTE = (
    "CyberGuardian runs entirely on this machine. Scans and evidence are never "
    "uploaded; only the AI analysis and VirusTotal checks you explicitly start "
    "send the selected finding."
)

BUILT_WITH = [
    ("Python", "3.9+"),
    ("PyQt5", "desktop UI"),
    ("yara-python", "signatures"),
    ("Inter", "SIL OFL font"),
]

THIRD_PARTY_NOTICES = (
    "Inter font © The Inter Project Authors, licensed under the SIL Open Font "
    "License 1.1. PyQt5 is licensed under the GPL v3. yara-python and YARA are "
    "licensed under the Apache 2.0 / BSD 3-Clause licenses."
)
