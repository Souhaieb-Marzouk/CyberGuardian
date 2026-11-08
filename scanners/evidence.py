"""
Rich evidence attached to detections.

Every scanner contributes the context that an analyst (or the AI) needs to judge
a finding: the process tree for runtime detections, file metadata for file
detections, the five-tuple for network events, the hive/key/value for registry
persistence, and the event identity for log detections.

The UI renders these fields as an event table; the exporter serialises them and
the AI prompt receives them, so nothing valuable is lost between scan and triage.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


def merge_evidence(detection, key: str, payload: Dict[str, Any]) -> None:
    """Attach ``payload`` under ``key`` without discarding existing evidence."""
    evidence = detection.evidence if isinstance(detection.evidence, dict) else {}
    existing = evidence.get(key)
    if isinstance(existing, dict):
        merged = dict(payload)
        merged.update({k: v for k, v in existing.items() if v not in (None, "", [], {})})
        evidence[key] = merged
    else:
        evidence[key] = payload
    detection.evidence = evidence


def _iso(timestamp: Optional[float]) -> str:
    try:
        return datetime.fromtimestamp(float(timestamp)).isoformat(timespec="seconds")
    except Exception:
        return ""


def process_payload(proc) -> Dict[str, Any]:
    return {
        "name": proc.name,
        "pid": proc.pid,
        "ppid": proc.parent_pid,
        "parent": proc.parent_name,
        "path": proc.path,
        "directory": str(Path(proc.path).parent) if proc.path else "",
        "command_line": (proc.command_line or "")[:1200],
        "user": proc.username,
        "started": _iso(proc.create_time),
        "status": proc.status,
        "threads": proc.num_threads,
        "handles": proc.num_handles,
        "memory_mb": round((proc.memory_bytes or 0) / (1024 * 1024), 1),
        "signed": proc.is_signed,
        "signer": proc.signer,
        "sha256": proc.sha256,
    }


def file_payload(info) -> Dict[str, Any]:
    stat = None
    try:
        stat = info.path.stat()
    except OSError:
        pass
    return {
        "name": info.name,
        "path": str(info.path),
        "directory": str(info.path.parent),
        "size": info.size,
        "extension": info.extension,
        "mime": info.mime_type,
        "entropy": round(info.entropy, 2),
        "sha256": info.sha256,
        "md5": info.md5,
        "is_pe": info.is_pe,
        "is_office": info.is_office,
        "is_archive": info.is_archive,
        "created": _iso(stat.st_ctime) if stat else "",
        "modified": _iso(stat.st_mtime) if stat else "",
        "pe": info.pe_info if isinstance(info.pe_info, dict) else {},
    }


def connection_payload(conn) -> Dict[str, Any]:
    return {
        "local": f"{conn.local_ip}:{conn.local_port}",
        "remote": f"{conn.remote_ip}:{conn.remote_port}" if conn.remote_ip else "",
        "remote_hostname": conn.remote_hostname,
        "remote_ip": conn.remote_ip,
        "remote_port": conn.remote_port,
        "local_ip": conn.local_ip,
        "local_port": conn.local_port,
        "protocol": conn.protocol,
        "status": conn.status,
        "pid": conn.pid,
        "process_name": conn.process_name,
        "process_path": conn.process_path,
        "process_owner": conn.process_owner,
        "process_cmdline": (conn.process_cmdline or "")[:1000],
        "age_seconds": round(conn.connection_age, 1),
        "bytes_sent": conn.bytes_sent,
        "bytes_recv": conn.bytes_recv,
    }


def registry_payload(entry) -> Dict[str, Any]:
    return {
        "hive": entry.hive,
        "key": entry.key_path,
        "value_name": entry.value_name,
        "value_type": entry.value_type,
        "value_data": (entry.value_data or "")[:1200],
    }


def event_payload(record) -> Dict[str, Any]:
    return {
        "channel": record.channel,
        "label": record.label,
        "event_id": record.event_id,
        "record_id": record.record_id,
        "timestamp": record.timestamp,
        "provider": record.provider,
        "computer": record.computer,
        "level": record.level,
        "fields": dict(record.fields or {}),
    }
