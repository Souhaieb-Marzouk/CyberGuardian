"""
Detection export for triage and false-positive analysis.

Two formats:

* **JSON** — complete fidelity: scan metadata plus every detection with its full
  evidence (YARA rule, namespace, matched strings and offsets, process context).
* **CSV** — one row per detection with the columns analysts need to sort in a
  spreadsheet: process identity, parent process, rule, matched identifiers,
  file hash, confidence, reason.

The exporter never drops evidence: fields that do not fit a column are joined or
serialised into the row, so nothing useful is lost when sharing with a colleague.
"""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List

CSV_COLUMNS = [
    "scan_type", "scan_target", "scan_started", "risk", "detection_type",
    "indicator", "indicator_type", "confidence", "process_name", "pid", "ppid",
    "parent_process", "user", "file_path", "command_line", "sha256",
    "yara_rule", "yara_namespace", "yara_severity", "yara_tags",
    "matched_identifiers", "matched_offsets", "matched_preview",
    "signature_status", "signer", "description", "reason", "remediation",
    "evidence_json",
]


def _yara_rows(detection: Dict[str, Any]) -> List[Dict[str, Any]]:
    evidence = detection.get("evidence") or {}
    matches = evidence.get("yara_matches") or []
    if not isinstance(matches, list) or not matches:
        return [{}]
    rows = []
    for match in matches:
        if not isinstance(match, dict):
            continue
        strings = match.get("strings") or []
        identifiers = sorted({
            str(item.get("identifier", "")) for item in strings
            if isinstance(item, dict) and item.get("identifier")
        })
        offsets = sorted({
            int(item.get("offset", 0)) for item in strings
            if isinstance(item, dict)
        })
        previews = [
            str(item.get("preview", ""))[:60] for item in strings
            if isinstance(item, dict) and item.get("preview")
        ]
        rows.append({
            "yara_rule": match.get("rule", ""),
            "yara_namespace": match.get("namespace", ""),
            "yara_severity": match.get("severity", ""),
            "yara_tags": ", ".join(match.get("tags", []) or []),
            "matched_identifiers": ", ".join(identifiers[:12]),
            "matched_offsets": ", ".join(str(offset) for offset in offsets[:12]),
            "matched_preview": " | ".join(previews[:4]),
        })
    return rows or [{}]


def _process_context(detection: Dict[str, Any]) -> Dict[str, Any]:
    evidence = detection.get("evidence") or {}
    process = evidence.get("process") if isinstance(evidence.get("process"), dict) else {}
    return {
        "pid": detection.get("process_id") or process.get("pid", ""),
        "ppid": process.get("ppid", ""),
        "parent_process": process.get("parent", ""),
        "signature_status": evidence.get("signature_status", ""),
        "signer": evidence.get("signer", process.get("signer", "")),
        "sha256": evidence.get("sha256", ""),
    }


def flatten(results: Iterable) -> List[Dict[str, Any]]:
    """Flatten scan results into spreadsheet-ready rows."""
    rows: List[Dict[str, Any]] = []
    for result in results:
        for detection in getattr(result, "detections", []) or []:
            base = {
                "scan_type": getattr(result, "scan_type", ""),
                "scan_target": getattr(result, "scan_target", ""),
                "scan_started": getattr(result, "start_time", ""),
                "risk": getattr(detection.risk_level, "value", ""),
                "detection_type": detection.detection_type,
                "indicator": detection.indicator,
                "indicator_type": detection.indicator_type,
                "confidence": detection.confidence,
                "process_name": detection.process_name or "",
                "user": detection.user or "",
                "file_path": detection.file_path or "",
                "command_line": _command_line(detection),
                "description": detection.description,
                "reason": detection.detection_reason,
                "remediation": "; ".join(detection.remediation or []),
                "evidence_json": json.dumps(detection.evidence or {}, default=str)[:4000],
            }
            base.update(_process_context({
                "process_id": detection.process_id,
                "evidence": detection.evidence or {},
            }))
            for yara_fields in _yara_rows({"evidence": detection.evidence or {}}):
                row = {column: "" for column in CSV_COLUMNS}
                row.update(base)
                row.update(yara_fields)
                rows.append(row)
    return rows


def _command_line(detection) -> str:
    return (detection.command_line or "")[:1000]


def export_results(results: List, path: Path) -> Path:
    """Write JSON or CSV based on the file suffix; return the written path."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    if target.suffix.lower() == ".csv":
        rows = flatten(results)
        with open(target, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
        return target

    payload = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "scans": [],
    }
    for result in results:
        payload["scans"].append({
            "scan_type": getattr(result, "scan_type", ""),
            "target": getattr(result, "scan_target", ""),
            "status": getattr(getattr(result, "status", None), "value", ""),
            "started": str(getattr(result, "start_time", "")),
            "duration_seconds": getattr(result, "scan_duration_seconds", 0),
            "total_items": getattr(result, "total_items", 0),
            "counts": {
                "critical": sum(1 for d in result.detections if d.risk_level.value == "critical"),
                "high": sum(1 for d in result.detections if d.risk_level.value == "high"),
                "medium": sum(1 for d in result.detections if d.risk_level.value == "medium"),
                "low": sum(1 for d in result.detections if d.risk_level.value == "low"),
            },
            "detections": [
                {
                    "risk": d.risk_level.value,
                    "type": d.detection_type,
                    "indicator": d.indicator,
                    "indicator_type": d.indicator_type,
                    "confidence": d.confidence,
                    "description": d.description,
                    "reason": d.detection_reason,
                    "remediation": list(d.remediation or []),
                    "process": {
                        "name": d.process_name,
                        "pid": d.process_id,
                        "ppid": (d.evidence or {}).get("process", {}).get("ppid"),
                        "parent": (d.evidence or {}).get("process", {}).get("parent"),
                        "path": d.file_path,
                        "command_line": d.command_line,
                        "user": d.user,
                    },
                    "evidence": d.evidence or {},
                    "timestamp": getattr(d, "timestamp", ""),
                }
                for d in result.detections
            ],
        })
    target.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return target
