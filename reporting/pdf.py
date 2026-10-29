"""
CyberGuardian PDF Export
========================

Renders the HTML report to PDF with WeasyPrint when available, falling back to
ReportLab.  Both are optional: the module raises a clear error instead of
returning ``None`` so the CLI/UI can tell the user what to install.
"""

from __future__ import annotations

import html as html_module
from pathlib import Path
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

from reporting.generator import ReportGenerator
from utils.config import REPORTS_DIR
from utils.logging_utils import get_logger

logger = get_logger("reporting.pdf")


class PdfExportError(RuntimeError):
    """Raised when no PDF backend is available or rendering fails."""


def _stamp() -> str:
    from datetime import datetime
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _playbook_html(analysis: Dict[str, Any]) -> str:
    """Render the AI verification/containment/remediation sections."""
    if not analysis:
        return ""

    sections = (
        ("How to verify", analysis.get("verification_steps") or []),
        ("Containment", analysis.get("containment_steps") or []),
        ("Remediation", analysis.get("remediation_steps") or []),
        ("Validation", analysis.get("validation_steps") or []),
    )
    if not any(items for _, items in sections):
        return ""

    parts = ['<div class="playbook"><h2>Guided response plan</h2>']
    for title, items in sections:
        if not items:
            continue
        parts.append(f"<h3>{html_module.escape(title)}</h3><ol>")
        parts.extend(f"<li>{html_module.escape(str(item))}</li>" for item in items)
        parts.append("</ol>")
    parts.append("</div>")
    return "".join(parts)


def export_pdf(
    results: List,
    title: str = "CyberGuardian Security Report",
    output: Optional[Path] = None,
    ai_analysis: Optional[Dict[str, Any]] = None,
) -> Path:
    """Write a PDF report and return its path."""
    generator = ReportGenerator()
    html = generator._build_html(results, title, include_summary=True)
    playbook = _playbook_html(ai_analysis or {})
    if playbook:
        html = html.replace("</body>", f"{playbook}</body>")

    target = Path(output) if output else Path(REPORTS_DIR) / f"cyberguardian_report_{_stamp()}.pdf"
    target.parent.mkdir(parents=True, exist_ok=True)

    try:
        from weasyprint import HTML  # type: ignore
        HTML(string=html).write_pdf(str(target))
        logger.info(f"Generated PDF report: {target}")
        return target
    except ImportError:
        pass
    except Exception as exc:
        raise PdfExportError(f"PDF rendering failed: {exc}") from exc

    try:
        from reportlab.lib.pagesizes import A4  # type: ignore
        from reportlab.lib.styles import getSampleStyleSheet  # type: ignore
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer  # type: ignore
    except ImportError as exc:
        raise PdfExportError(
            "PDF export requires the optional 'weasyprint' or 'reportlab' package "
            "(pip install weasyprint)"
        ) from exc

    try:
        styles = getSampleStyleSheet()
        doc = SimpleDocTemplate(str(target), pagesize=A4, title=title)
        story = [Paragraph(xml_escape(title), styles["Title"]), Spacer(1, 12)]

        for result in results:
            story.append(Paragraph(
                xml_escape(f"{result.scan_type.title()} scan"), styles["Heading2"]
            ))
            story.append(Paragraph(
                xml_escape(
                    f"{result.total_items} items, {len(result.detections)} detections, "
                    f"status {result.status.value}"
                ),
                styles["Normal"],
            ))
            for detection in result.detections:
                # ReportLab's Paragraph parses a small XML dialect: a raw '&' or
                # '<' in a file name/command line aborted the whole export.
                story.append(Paragraph(
                    xml_escape(
                        f"[{detection.risk_level.value.upper()}] "
                        f"{detection.detection_type}: {detection.indicator}"
                    ),
                    styles["Heading3"],
                ))
                story.append(Paragraph(xml_escape(detection.description or ""), styles["Normal"]))
                story.append(Spacer(1, 6))
            story.append(Spacer(1, 12))

        for heading, key in (
            ("How to verify", "verification_steps"),
            ("Containment", "containment_steps"),
            ("Remediation", "remediation_steps"),
            ("Validation", "validation_steps"),
        ):
            items = (ai_analysis or {}).get(key) or []
            if items:
                story.append(Paragraph(heading, styles["Heading2"]))
                for index, item in enumerate(items, 1):
                    story.append(Paragraph(
                        xml_escape(f"{index}. {item}"), styles["Normal"]
                    ))
                story.append(Spacer(1, 8))

        doc.build(story)
        logger.info(f"Generated PDF report with ReportLab: {target}")
        return target
    except Exception as exc:
        raise PdfExportError(f"PDF rendering failed: {exc}") from exc
