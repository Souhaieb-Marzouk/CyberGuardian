"""
Standalone HTML reports for AI analyses and VirusTotal checks.

The files are self-contained (inline CSS), safe to archive or send to a
colleague, and every interpolated value is HTML-escaped.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional

from core import branding
from utils.i18n import tr


def _escape(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _page(title: str, body: str) -> str:
    from core import branding as _branding
    version = _branding.APP_VERSION
    github = _branding.GITHUB_URL
    author = _branding.AUTHOR
    copyright = _branding.COPYRIGHT
    license = _branding.LICENSE_NAME
    when = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_escape(title)}</title>
<style>
  :root {{ color-scheme: light; }}
  body {{ font-family: "Segoe UI", system-ui, sans-serif; margin: 0;
         background: #f4f6f8; color: #1b2430; }}
  main {{ max-width: 900px; margin: 32px auto; background: #fff;
          border: 1px solid #e2e6eb; border-radius: 14px; padding: 34px 38px; }}
  h1 {{ font-size: 24px; margin: 0 0 4px; }}
  h2 {{ font-size: 16px; margin: 26px 0 8px; color: #2f4a5a; }}
  .muted {{ color: #6b7785; font-size: 12px; }}
  .badge {{ display: inline-block; padding: 3px 10px; border-radius: 10px;
            font-weight: 700; font-size: 12px; }}
  .risk-critical {{ background: #fbe7eb; color: #a11d36; }}
  .risk-high {{ background: #fdeee5; color: #a84b1f; }}
  .risk-medium {{ background: #fdf5df; color: #8a6210; }}
  .risk-low {{ background: #e7f4ef; color: #1c6b52; }}
  .grid {{ display: grid; grid-template-columns: 160px 1fr; gap: 6px 14px;
           margin: 16px 0; font-size: 13px; }}
  .grid dt {{ color: #6b7785; }}
  .grid dd {{ margin: 0; word-break: break-word; }}
  pre {{ background: #f6f8fa; border: 1px solid #e2e6eb; border-radius: 8px;
         padding: 14px; white-space: pre-wrap; word-break: break-word;
         font-size: 12.5px; line-height: 1.5; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 12.5px; margin: 10px 0; }}
  th, td {{ border: 1px solid #e2e6eb; padding: 7px 9px; text-align: left; }}
  th {{ background: #f2f5f8; }}
  .malicious {{ color: #a11d36; font-weight: 700; }}
  ol, ul {{ padding-left: 22px; }}
  li {{ margin: 5px 0; }}
  footer {{ margin-top: 30px; border-top: 1px solid #e2e6eb; padding-top: 10px;
            color: #6b7785; font-size: 11px; }}
</style>
</head>
<body><main>
{body}
<footer>CyberGuardian {version} · Designed &amp; architected by <a href="{github}" style="color:#2f7f6f;">{author}</a> · {copyright} · {license} · generated {when}</footer>
</main></body></html>
"""


def _meta_block(detection) -> str:
    rows = [
        ("Risk", getattr(getattr(detection, "risk_level", None), "value", "").upper()),
        ("Finding", getattr(detection, "detection_type", "")),
        ("Indicator", getattr(detection, "indicator", "")),
        ("Process", getattr(detection, "process_name", "") or ""),
        ("PID", getattr(detection, "process_id", "") or ""),
        ("File", getattr(detection, "file_path", "") or ""),
        ("Command line", getattr(detection, "command_line", "") or ""),
        ("Detected", getattr(detection, "timestamp", "") or ""),
    ]
    items = "".join(
        f"<dt>{_escape(name)}</dt><dd>{_escape(value)}</dd>"
        for name, value in rows if value not in ("", None)
    )
    return f'<dl class="grid">{items}</dl>'


def _list_section(title: str, values: Optional[List]) -> str:
    values = [str(value) for value in (values or []) if str(value).strip()]
    if not values:
        return ""
    items = "".join(f"<li>{_escape(value)}</li>" for value in values)
    return f"<h2>{_escape(title)}</h2><ol>{items}</ol>"


def export_ai_html(detection, result, path: Path, vt=None) -> Path:
    """Write a standalone HTML report for one AI analysis."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    risk = getattr(getattr(detection, "risk_level", None), "value", "unknown")
    verdict = getattr(getattr(result, "verdict", None), "value", "unknown").replace("_", " ").upper()
    confidence = getattr(result, "confidence", 0) or 0
    score = getattr(result, "risk_score", 0) or 0

    parts = [
        "<h1>CyberGuardian — AI analysis</h1>",
        f'<div class="muted">{_escape(getattr(detection, "description", ""))}</div>',
        f'<p><span class="badge risk-{_escape(risk)}">{_escape(risk.upper())}</span></p>',
        _meta_block(detection),
        f'<h2>{_escape(tr("detail.ai_verdict", verdict=verdict))}</h2>',
        f'<p>{_escape(tr("detail.ai_confidence", confidence=f"{confidence:.0%}", score=score))}</p>',
        f"<h2>Summary</h2><p>{_escape(getattr(result, 'summary', ''))}</p>",
        f"<h2>{_escape(tr('detail.ai_detailed'))}</h2>",
        f"<pre>{_escape(getattr(result, 'detailed_analysis', ''))}</pre>",
    ]

    parts.append(_list_section(tr("detail.ai_verify"), getattr(result, "verification_steps", [])))
    parts.append(_list_section(tr("detail.ai_contain"), getattr(result, "containment_steps", [])))
    parts.append(_list_section(tr("detail.ai_remediate"), getattr(result, "remediation_steps", [])))
    parts.append(_list_section(tr("detail.ai_validate"), getattr(result, "validation_steps", [])))
    parts.append(_list_section("Recommendations", getattr(result, "recommendations", [])))
    parts.append(_list_section("Indicators", getattr(result, "indicators", [])))

    severity = getattr(result, "severity_justification", "")
    if severity:
        parts.append(f"<h2>Severity justification</h2><p>{_escape(severity)}</p>")

    mitre = getattr(result, "mitre_techniques", [])
    if mitre:
        parts.append(f"<h2>{_escape(tr('detail.ai_mitre'))}</h2><p>{_escape(', '.join(map(str, mitre)))}</p>")

    if vt is not None:
        try:
            data = vt.to_dict()
            parts.append(
                f"<h2>VirusTotal</h2><p>{_escape(data.get('vt_summary', ''))}</p>"
                f"<p class=\"muted\">{_escape(data.get('iocs_malicious', 0))} / "
                f"{_escape(data.get('iocs_checked', 0))} IoC</p>"
            )
        except Exception:
            pass

    parts.append(
        f'<h2>Raw evidence</h2><pre>{_escape(_json(getattr(detection, "evidence", {})))}</pre>'
    )

    target.write_text(_page("CyberGuardian AI report", "".join(parts)), encoding="utf-8")
    return target


def _verdict_for(item) -> str:
    if getattr(item, "error", None):
        return tr("vt.error")
    if getattr(item, "is_malicious", False):
        return tr("vt.malicious")
    if getattr(item, "detection_ratio", ""):
        return tr("vt.clean")
    return tr("vt.unknown")


def export_vt_html(detection, vt, path: Path) -> Path:
    """Write a standalone HTML report for one VirusTotal check."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    rows = []
    for label, items in (
        (tr("vt.hash"), getattr(vt, "hash_results", [])),
        (tr("vt.ip"), getattr(vt, "ip_results", [])),
        (tr("vt.domain"), getattr(vt, "domain_results", [])),
        (tr("vt.url"), getattr(vt, "url_results", [])),
    ):
        for item in items:
            value = (
                getattr(item, "hash_value", "")
                or getattr(item, "ip_address", "")
                or getattr(item, "domain", "")
                or getattr(item, "url", "")
            )
            details = []
            for attribute in ("threat_names", "categories"):
                values = getattr(item, attribute, None)
                if values:
                    details.append(", ".join(map(str, values[:4])))
            for attribute in ("country", "as_owner", "file_type", "final_url"):
                value_text = getattr(item, attribute, "")
                if value_text:
                    details.append(str(value_text))
            verdict = _verdict_for(item)
            css = " class=\"malicious\"" if verdict == tr("vt.malicious") else ""
            rows.append(
                "<tr>"
                f"<td>{_escape(label)}</td><td>{_escape(value)}</td>"
                f"<td{css}>{_escape(verdict)}</td>"
                f"<td>{_escape(getattr(item, 'detection_ratio', '') or '—')}</td>"
                f"<td>{_escape('; '.join(details) or '—')}</td>"
                "</tr>"
            )

    table = (
        "<table><thead><tr>"
        f"<th>{_escape(tr('vt.col_type'))}</th><th>{_escape(tr('vt.col_indicator'))}</th>"
        f"<th>{_escape(tr('vt.col_verdict'))}</th><th>{_escape(tr('vt.col_detections'))}</th>"
        f"<th>{_escape(tr('vt.col_details'))}</th>"
        "</tr></thead><tbody>" + "".join(rows) + "</tbody></table>"
    )

    summary = getattr(vt, "vt_summary", "") or tr(
        "vt.summary",
        summary=f"{getattr(vt, 'iocs_malicious', 0)} / {getattr(vt, 'iocs_checked', 0)}",
        risk=getattr(vt, "highest_risk_level", "unknown"),
    )

    body = "".join([
        "<h1>CyberGuardian — VirusTotal report</h1>",
        f'<div class="muted">{_escape(getattr(detection, "description", ""))}</div>',
        _meta_block(detection),
        f"<h2>Summary</h2><p>{_escape(summary)}</p>",
        table,
    ])

    target.write_text(_page("CyberGuardian VirusTotal report", body), encoding="utf-8")
    return target


def _json(value: Any) -> str:
    import json
    try:
        return json.dumps(value, indent=2, default=str)
    except Exception:
        return str(value)
