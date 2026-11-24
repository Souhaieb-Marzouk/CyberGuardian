"""Opt-in IP enrichment (country / ASN / organisation) for the traffic page."""

from __future__ import annotations

import ipaddress
import json
import time
from pathlib import Path
from typing import Dict, Optional

import requests

from utils.config import CACHE_DIR
from utils.logging_utils import get_logger

logger = get_logger("core.ip_lookup")

CACHE_FILE = Path(CACHE_DIR) / "ip_lookup.json"
CACHE_TTL = 7 * 24 * 3600
ENDPOINT = "https://ipapi.co/{ip}/json/"


def _load_cache() -> Dict[str, dict]:
    try:
        if CACHE_FILE.exists():
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


def _save_cache(cache: Dict[str, dict]):
    try:
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except OSError:
        pass


def lookup_ip(ip: str, timeout: int = 8) -> Dict[str, str]:
    """Return country/ASN information for a public IP.

    This performs an explicit external request to ipapi.co; the caller must ask
    the user first.  Results are cached for a week.
    """
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError("invalid IP address") from exc
    if address.is_private or address.is_loopback or address.is_link_local:
        raise ValueError("private address")

    cache = _load_cache()
    entry = cache.get(ip)
    if entry and time.time() - entry.get("_ts", 0) < CACHE_TTL:
        return {key: value for key, value in entry.items() if key != "_ts"}

    response = requests.get(
        ENDPOINT.format(ip=ip),
        timeout=timeout,
        headers={"User-Agent": "CyberGuardian/1.5"},
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("error"):
        raise RuntimeError(payload.get("reason") or "lookup failed")

    result = {
        "ip": ip,
        "country": payload.get("country_name", ""),
        "region": payload.get("region", ""),
        "city": payload.get("city", ""),
        "org": payload.get("org", ""),
        "asn": payload.get("asn", ""),
        "timezone": payload.get("timezone", ""),
        "cached": "no",
    }
    entry = dict(result)
    entry["_ts"] = time.time()
    cache[ip] = entry
    _save_cache(cache)
    return result
