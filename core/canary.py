"""
CyberGuardian Ransomware Canaries
=================================

Decoy files that look like ordinary business documents, placed where ransomware
actually hunts (Documents, Desktop, Downloads, OneDrive, Public).  Each canary is
a valid DOCX/XLSX/CSV/TXT with plausible content, a realistic size and a
back-dated modification time, so it does not stand out in a directory listing.

The manager records every canary (hash, size, entropy, timestamps) and reports:

* modified / re-saved
* encrypted (entropy jump)
* deleted
* renamed or moved (same content found under another name)
* touched (timestamp changed, content intact)

Events keep a full modification history so the UI can show a timeline and a
step-by-step response guide.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import math
import os
import uuid
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from utils.config import CACHE_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.canary")

STATE_FILE = Path(CACHE_DIR) / "canaries.json"
ENCRYPTED_ENTROPY = 7.4


# ---------------------------------------------------------------------------
# Document builders — small, valid, and boring on purpose
# ---------------------------------------------------------------------------

def _docx_bytes(title: str, paragraphs: List[str]) -> bytes:
    body = "".join(
        f'<w:p><w:r><w:t xml:space="preserve">{text}</w:t></w:r></w:p>' for text in paragraphs
    )
    document = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body><w:p><w:r><w:t>{title}</w:t></w:r></w:p>{body}</w:body>
</w:document>"""
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>"""
    rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("word/document.xml", document)
    return buffer.getvalue()


def _xlsx_bytes(sheet: str, rows: List[List[str]]) -> bytes:
    def cell(ref: str, value: str) -> str:
        return f'<c r="{ref}" t="inlineStr"><is><t>{value}</t></is></c>'

    sheet_rows = []
    for index, row in enumerate(rows, 1):
        cells = "".join(cell(f"{chr(65 + col)}{index}", str(value)) for col, value in enumerate(row))
        sheet_rows.append(f'<row r="{index}">{cells}</row>')

    worksheet = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<sheetData>{''.join(sheet_rows)}</sheetData></worksheet>"""
    workbook = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"
 xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets><sheet name="{sheet}" sheetId="1" r:id="rId1"/></sheets></workbook>"""
    content_types = """<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"""
    rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>"""
    workbook_rels = """<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
</Relationships>"""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("_rels/.rels", rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", workbook_rels)
        archive.writestr("xl/worksheets/sheet1.xml", worksheet)
    return buffer.getvalue()


def _csv_bytes(header: List[str], rows: List[List[str]]) -> bytes:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return buffer.getvalue().encode("utf-8")


# ---------------------------------------------------------------------------
# Canary catalogue — names and content a ransomware operator would target
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CanarySpec:
    key: str
    filename: str
    location: str          # documents | desktop | downloads | onedrive | public
    subtitle: str
    age_days: int


CANARY_SPECS: List[CanarySpec] = [
    CanarySpec("tax", "2026_Tax_Return_Draft.docx", "documents", "Tax return working copy", 41),
    CanarySpec("payroll", "Payroll_Summary_Q4.xlsx", "documents", "Quarterly payroll summary", 12),
    CanarySpec("contracts", "Client_Contracts_2026.docx", "onedrive", "Signed client agreements", 67),
    CanarySpec("invoices", "Invoices_November.csv", "downloads", "Supplier invoices", 8),
    CanarySpec("recovery", "RecoveryCodes.txt", "desktop", "Account recovery codes", 130),
    CanarySpec("handbook", "Employee_Handbook.docx", "public", "HR handbook", 210),
]

LOCATION_BUILDERS = {
    "documents": lambda: Path(os.path.expanduser("~")) / "Documents",
    "desktop": lambda: Path(os.path.expanduser("~")) / "Desktop",
    "downloads": lambda: Path(os.path.expanduser("~")) / "Downloads",
    "onedrive": lambda: Path(os.path.expanduser("~")) / "OneDrive" / "Documents",
    "public": lambda: Path(os.environ.get("PUBLIC", r"C:\Users\Public")) / "Documents",
}


def _content_for(spec: CanarySpec) -> bytes:
    if spec.key == "tax":
        return _docx_bytes("2026 Tax Return - Working Draft", [
            "Prepared for the 2026 filing season. Figures are provisional.",
            "Gross income: 94,280.00    Deductions: 18,940.00",
            "Estimated balance due: 6,112.00 (see schedule B).",
            "Review with the accountant before submitting.",
        ])
    if spec.key == "payroll":
        return _xlsx_bytes("Q4", [
            ["Employee", "Department", "Gross", "Tax", "Net"],
            ["A. Bennett", "Operations", "5,240.00", "1,048.00", "4,192.00"],
            ["M. Haddad", "Engineering", "6,180.00", "1,236.00", "4,944.00"],
            ["S. Novak", "Finance", "5,760.00", "1,152.00", "4,608.00"],
        ])
    if spec.key == "contracts":
        return _docx_bytes("Client Services Agreement", [
            "This agreement is entered into between the parties named below.",
            "Term: 12 months, renewable. Notice period: 30 days.",
            "Payment terms: net 30 from invoice date.",
            "Confidentiality obligations survive termination.",
        ])
    if spec.key == "invoices":
        return _csv_bytes(
            ["Invoice", "Supplier", "Date", "Amount", "Status"],
            [["INV-2026-0141", "Northwind Ltd", "2026-10-02", "1,240.00", "paid"],
             ["INV-2026-0142", "Contoso GmbH", "2026-10-11", "3,980.00", "open"],
             ["INV-2026-0143", "Fabrikam SA", "2026-10-19", "760.50", "open"]],
        )
    if spec.key == "recovery":
        return (
            "Account recovery codes\n"
            "Keep these offline. Each code can be used once.\n\n"
            "MAIL-4471-9920\nBANK-1180-3345\nVPN-7724-1098\n"
            "MAIL-5528-7741\nBANK-9902-4417\n"
        ).encode("utf-8")
    return _docx_bytes("Employee Handbook", [
        "Section 1 - Working hours and remote work policy.",
        "Section 2 - Expense reimbursement and approvals.",
        "Section 3 - Information security responsibilities.",
    ])


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Canary:
    key: str
    path: str
    sha256: str
    size: int
    created_at: str
    first_seen: str
    modified_at: str
    entropy: float = 0.0
    history: List[str] = field(default_factory=list)
    missing_since: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CanaryEvent:
    event_id: str
    canary_key: str
    name: str
    path: str
    kind: str                  # modified | encrypted | deleted | renamed | touched
    detected_at: str
    first_seen: str
    modification_count: int
    timestamps: List[str]
    previous_size: int
    current_size: int
    previous_hash: str
    current_hash: str
    renamed_to: str = ""
    entropy: float = 0.0
    guidance: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


GUIDANCE = {
    "encrypted": [
        "Disconnect this PC from the network and Wi-Fi immediately; do not shut it down or reboot.",
        "Do not delete the canary file - it is evidence of the encryption routine and its timing.",
        "Note the exact time shown here; it marks when encryption started.",
        "Check whether other files in the same folder have new extensions or unreadable content.",
        "Identify the process writing to the file: Task Manager > Details, then check publisher and path.",
        "Restore affected files from an offline or cloud backup after the machine is cleaned.",
        "Report the incident to IT/security; preserve Security, Defender and PowerShell logs.",
    ],
    "modified": [
        "Note the time: something wrote to a file that no legitimate process should touch.",
        "Check the folder for a ransom note (README, DECRYPT, HOW_TO_RECOVER).",
        "Review Startup apps, scheduled tasks and services created recently.",
        "Run a full Windows Defender scan plus CyberGuardian process, registry and event-log scans.",
        "If the change was not made by you or an approved tool, treat the machine as compromised.",
    ],
    "deleted": [
        "A deleted canary can mean an automated cleaner or ransomware preparing files.",
        "Check the Recycle Bin; if empty, avoid writing more data and use file recovery tools.",
        "Review recent process activity and event logs for deletion or security-tool tampering.",
    ],
    "renamed": [
        "The file still exists under a different name - ransomware often renames before encrypting.",
        "Copy the new file aside before opening it; do not execute anything it contains.",
        "Compare its hash with the original recorded here to confirm it is the same file.",
    ],
    "touched": [
        "The timestamp changed but the content did not - typical of backup or sync tools.",
        "Confirm whether OneDrive or backup software was running; if not, investigate the process.",
    ],
}


# ---------------------------------------------------------------------------
# Manager
# ---------------------------------------------------------------------------

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    value = 0.0
    for count in counts:
        if count:
            probability = count / length
            value -= probability * math.log2(probability)
    return value


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class CanaryManager:
    def __init__(self, state_file: Path = STATE_FILE, roots: Optional[Dict[str, Path]] = None):
        self.state_file = Path(state_file)
        self.roots = roots
        self.canaries: List[Canary] = []
        self.events: List[CanaryEvent] = []
        self._load()

    # ------------------------------------------------------------------ state
    def _load(self) -> None:
        try:
            if self.state_file.exists():
                data = json.loads(self.state_file.read_text(encoding="utf-8"))
                self.canaries = [Canary(**item) for item in data.get("canaries", [])]
                self.events = [CanaryEvent(**item) for item in data.get("events", [])]
        except Exception as exc:
            logger.debug(f"Could not load canary state: {exc}")

    def _save(self) -> None:
        try:
            self.state_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "canaries": [canary.to_dict() for canary in self.canaries],
                "events": [event.to_dict() for event in self.events[-100:]],
            }
            temp = Path(str(self.state_file) + ".tmp")
            temp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            os.replace(temp, self.state_file)
        except Exception as exc:
            logger.warning(f"Could not save canary state: {exc}")

    def _root(self, name: str) -> Optional[Path]:
        if self.roots is not None:
            return self.roots.get(name)
        try:
            return LOCATION_BUILDERS[name]()
        except KeyError:
            return None

    # ------------------------------------------------------------------ install
    def install(self) -> List[Canary]:
        created: List[Canary] = []
        existing = {canary.path.lower() for canary in self.canaries}

        for spec in CANARY_SPECS:
            root = self._root(spec.location)
            if root is None:
                continue
            try:
                root.mkdir(parents=True, exist_ok=True)
            except OSError:
                continue

            target = root / spec.filename
            if str(target).lower() in existing or target.exists():
                continue

            data = _content_for(spec)
            try:
                target.write_bytes(data)
                # Back-date so a new canary does not look freshly planted.
                stamp = (datetime.now() - timedelta(days=spec.age_days)).timestamp()
                os.utime(target, (stamp, stamp))
            except OSError as exc:
                logger.debug(f"Could not create canary {target}: {exc}")
                continue

            now = datetime.utcnow().isoformat()
            canary = Canary(
                key=spec.key,
                path=str(target),
                sha256=_sha256(data),
                size=len(data),
                created_at=now,
                first_seen=now,
                modified_at=datetime.fromtimestamp(stamp).isoformat(),
                entropy=round(_entropy(data), 2),
                history=[now],
            )
            self.canaries.append(canary)
            created.append(canary)

        if created:
            self._save()
            logger.info(f"Armed {len(created)} ransomware canaries")
        return created

    # -------------------------------------------------------------------- check
    def check(self) -> List[CanaryEvent]:
        events: List[CanaryEvent] = []
        for canary in list(self.canaries):
            event = self._inspect(canary)
            if event is not None:
                events.append(event)
                self.events.append(event)
        if events:
            self._save()
        return events

    def _inspect(self, canary: Canary) -> Optional[CanaryEvent]:
        path = Path(canary.path)
        now = datetime.utcnow().isoformat()

        if not path.exists():
            # One alert per disappearance: without this the 3-second poll kept
            # re-emitting "deleted" forever and the popup reopened every tick.
            if canary.missing_since:
                return None
            canary.missing_since = now
            canary.history.append(now)
            renamed_to = self._find_by_hash(Path(canary.path).parent, canary.sha256)
            kind = "renamed" if renamed_to else "deleted"
            return self._event(
                canary, kind, now, current_size=0, current_hash="",
                renamed_to=renamed_to or "", previous_size=canary.size,
                previous_hash=canary.sha256,
            )

        if canary.missing_since:
            canary.missing_since = ""

        try:
            stat = path.stat()
            data = path.read_bytes()
        except OSError:
            return None

        digest = _sha256(data)
        entropy = round(_entropy(data), 2)
        modified = datetime.fromtimestamp(stat.st_mtime).isoformat()

        if digest != canary.sha256 or stat.st_size != canary.size:
            previous_size, previous_hash, previous_entropy = canary.size, canary.sha256, canary.entropy
            kind = (
                "encrypted"
                if digest != canary.sha256 and entropy > ENCRYPTED_ENTROPY and previous_entropy < 7.0
                else "modified"
            )
            canary.history.append(now)
            event = self._event(
                canary, kind, now, current_size=len(data), current_hash=digest,
                entropy=entropy, previous_size=previous_size, previous_hash=previous_hash,
            )
            # Re-baseline so the same tamper is reported exactly once.
            canary.sha256, canary.size = digest, len(data)
            canary.entropy, canary.modified_at = entropy, modified
            return event

        if modified != canary.modified_at:
            previous_size, previous_hash = canary.size, canary.sha256
            canary.modified_at = modified
            canary.history.append(now)
            return self._event(
                canary, "touched", now, current_size=stat.st_size,
                current_hash=digest, entropy=entropy,
                previous_size=previous_size, previous_hash=previous_hash,
            )

        return None

    def _find_by_hash(self, folder: Path, digest: str) -> Optional[str]:
        """A renamed canary keeps its bytes; look for them next to the old path."""
        try:
            for candidate in folder.iterdir():
                if not candidate.is_file():
                    continue
                try:
                    if candidate.stat().st_size > 2_000_000:
                        continue
                    if _sha256(candidate.read_bytes()) == digest:
                        return str(candidate)
                except OSError:
                    continue
        except OSError:
            return None
        return None

    def _event(self, canary: Canary, kind: str, when: str, current_size: int,
               current_hash: str, renamed_to: str = "", entropy: float = 0.0,
               previous_size: Optional[int] = None,
               previous_hash: Optional[str] = None) -> CanaryEvent:
        return CanaryEvent(
            event_id=uuid.uuid4().hex[:12],
            canary_key=canary.key,
            name=Path(canary.path).name,
            path=canary.path,
            kind=kind,
            detected_at=when,
            first_seen=canary.first_seen,
            modification_count=len(canary.history),
            timestamps=list(canary.history),
            previous_size=canary.size if previous_size is None else previous_size,
            current_size=current_size,
            previous_hash=canary.sha256 if previous_hash is None else previous_hash,
            current_hash=current_hash,
            renamed_to=renamed_to,
            entropy=entropy,
            guidance=list(GUIDANCE.get(kind, GUIDANCE["modified"])),
        )

    # ------------------------------------------------------------------- query
    def is_installed(self) -> bool:
        return bool(self.canaries)

    def armed(self) -> List[Canary]:
        return [canary for canary in self.canaries if Path(canary.path).exists()]

    def summary(self) -> Dict:
        return {
            "armed": len(self.armed()),
            "total": len(self.canaries),
            "events": len(self.events),
            "last_event": self.events[-1].detected_at if self.events else "",
        }

    # ------------------------------------------------------------------ remove
    def remove(self) -> int:
        removed = 0
        for canary in self.canaries:
            try:
                Path(canary.path).unlink(missing_ok=True)
                removed += 1
            except OSError as exc:
                logger.debug(f"Could not remove canary {canary.path}: {exc}")
        self.canaries = []
        self.events = []
        self._save()
        return removed

    def clear_events(self) -> None:
        self.events = []
        self._save()


_manager: Optional[CanaryManager] = None


def get_canary_manager() -> CanaryManager:
    global _manager
    if _manager is None:
        _manager = CanaryManager()
    return _manager
