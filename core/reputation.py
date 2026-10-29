"""
CyberGuardian Reputation Checker
================================

Answers the everyday question "is this file or link safe?" with a verdict the
user can act on, plus the evidence behind it.

File checks are local first (signature, location, size) and optionally consult
VirusTotal through the existing checker.  URL checks never download the page:
they use parsing heuristics and, when enabled, a VirusTotal URL report.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from utils.logging_utils import get_logger
from utils.signature_check import verify_file

logger = get_logger("core.reputation")

USER_WRITABLE = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\users\\public\\", "\\desktop\\")
SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "work", "loan",
    "review", "country", "kim", "cricket", "science", "party", "date",
}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}


@dataclass
class Verdict:
    """Outcome of a reputation check."""

    target: str
    kind: str                    # file | url
    verdict: str                 # safe | unknown | suspicious | malicious
    score: int = 0               # 0 (bad) .. 100 (good)
    summary: str = ""
    reasons: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_bad(self) -> bool:
        return self.verdict in ("suspicious", "malicious")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target, "kind": self.kind, "verdict": self.verdict,
            "score": self.score, "summary": self.summary,
            "reasons": list(self.reasons), "details": dict(self.details),
        }


def _finalize(verdict: Verdict) -> Verdict:
    if verdict.verdict == "malicious":
        verdict.score = min(verdict.score, 15)
    elif verdict.verdict == "suspicious":
        verdict.score = min(verdict.score, 45)
    elif verdict.verdict == "safe":
        verdict.score = max(verdict.score, 85)
    else:
        verdict.score = 60
    return verdict


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

def check_file(path: str, use_online: bool = True) -> Verdict:
    """Assess a file locally and (optionally) via VirusTotal."""
    target = str(path)
    file_path = Path(target)

    if not file_path.is_file():
        raise FileNotFoundError(target)

    reasons: List[str] = []
    details: Dict[str, Any] = {}
    score = 80
    verdict = "unknown"

    info = None
    try:
        info = verify_file(target)
    except Exception as exc:  # signature verification must not abort the check
        logger.debug(f"Signature verification failed for {target}: {exc}")

    if info is not None:
        details["signature"] = info.status
        details["publisher"] = info.signer
    else:
        details["signature"] = "verification_error"
        details["publisher"] = ""
    details["size"] = file_path.stat().st_size
    details["sha256"] = _sha256(file_path)

    if info is not None and info.is_valid:
        reasons.append(
            f"Digitally signed by {info.signer or 'a trusted publisher'}"
        )
        score = max(score, 90)
        verdict = "safe"
    else:
        status = info.status if info is not None else "verification failed"
        reasons.append(f"No valid digital signature ({status})")
        score -= 20

    lowered = target.lower()
    if any(marker in lowered for marker in USER_WRITABLE):
        reasons.append("Located in a folder that malware commonly uses")
        score -= 25
        if verdict != "safe":
            verdict = "suspicious"

    if file_path.stat().st_size == 0:
        reasons.append("File is empty")
        score -= 5

    if use_online:
        try:
            from threat_intel.virustotal_checker import (
                get_virustotal_checker, is_virustotal_available,
            )
            if is_virustotal_available():
                result = get_virustotal_checker().lookup_hash(details["sha256"])
                if result is not None:
                    details["vt_ratio"] = result.detection_ratio
                    details["vt_threats"] = result.threat_names[:5]
                    if result.is_malicious:
                        verdict = "malicious"
                        score = 5
                        reasons.insert(0, f"VirusTotal detections: {result.detection_ratio}")
                        if result.threat_names:
                            reasons.append("Detected as: " + ", ".join(result.threat_names[:3]))
                    elif result.detection_ratio not in ("", "0/0"):
                        reasons.append("No antivirus engine flagged this file")
                        score = max(score, 85)
                        if verdict == "unknown":
                            verdict = "safe"
                else:
                    reasons.append("VirusTotal lookup unavailable (rate limit or error)")
        except Exception as exc:
            logger.debug(f"Online file lookup failed: {exc}")
            reasons.append("Online check could not be completed")

    if verdict == "unknown" and score >= 70:
        verdict = "safe"
    if verdict == "safe" and score < 60:
        verdict = "suspicious"

    summary = {
        "safe": "This file looks safe, but stay cautious with unknown downloads.",
        "unknown": "There is not enough information to judge this file.",
        "suspicious": "This file has suspicious characteristics. Do not run it.",
        "malicious": "This file is malicious. Quarantine it and scan the machine.",
    }[verdict]

    return _finalize(Verdict(target, "file", verdict, score, summary, reasons, details))


def _sha256(path: Path) -> str:
    import hashlib
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------

def check_url(url: str, use_online: bool = True) -> Verdict:
    """Assess a URL using parsing heuristics and, optionally, VirusTotal."""
    target = (url or "").strip()
    try:
        parsed = urlparse(target)
        scheme = parsed.scheme
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError as exc:
        # urlparse()/`.port` raise for malformed IPv6 literals and ports outside
        # 0-65535; a user pasting a bad link must get a verdict, not a traceback.
        return _finalize(Verdict(
            target, "url", "suspicious", 25,
            "This link is malformed and cannot be trusted.",
            [f"Invalid URL: {exc}"], {"scheme": "", "host": "", "error": str(exc)},
        ))

    reasons: List[str] = []
    details: Dict[str, Any] = {"scheme": scheme, "host": host}
    score = 85
    verdict = "safe"

    if scheme not in ("http", "https"):
        return _finalize(Verdict(
            target, "url", "suspicious", 30,
            "Only http and https links can be checked.",
            [f"Unsupported scheme: {scheme or 'none'}"], details,
        ))

    if scheme == "http":
        reasons.append("Link does not use HTTPS")
        score -= 15
        verdict = "suspicious"

    if not host:
        return _finalize(Verdict(target, "url", "suspicious", 25,
                                 "The link has no valid host name.", reasons, details))

    if re.search(r"[\s\x00-\x1f\x7f]", host) or host.startswith(".") or host.endswith("."):
        reasons.append("Host name contains invalid characters")
        score -= 30
        verdict = "suspicious"

    try:
        ipaddress.ip_address(host)
        reasons.append("Link uses a raw IP address instead of a domain")
        score -= 25
        verdict = "suspicious"
    except ValueError:
        pass

    if "xn--" in host:
        reasons.append("Domain uses punycode and may imitate another site")
        score -= 30
        verdict = "suspicious"

    if "@" in parsed.netloc:
        reasons.append("Link hides the real destination with '@'")
        score -= 30
        verdict = "suspicious"

    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        reasons.append(f"'.{tld}' domains are frequently used for scams")
        score -= 20
        verdict = "suspicious"

    if host in SHORTENERS:
        reasons.append("Shortened link hides its final destination")
        score -= 10
        if verdict == "safe":
            verdict = "unknown"

    if port and port not in (80, 443):
        reasons.append(f"Non-standard port {port}")
        score -= 10

    if not reasons:
        reasons.append("No suspicious patterns in the link itself")

    if use_online:
        try:
            from threat_intel.virustotal_checker import (
                get_virustotal_checker, is_virustotal_available,
            )
            if is_virustotal_available():
                result = get_virustotal_checker().lookup_url(target)
                if result is not None:
                    details["vt_ratio"] = result.detection_ratio
                    if result.is_malicious:
                        verdict = "malicious"
                        score = 5
                        reasons.insert(0, f"VirusTotal detections: {result.detection_ratio}")
                else:
                    reasons.append("VirusTotal lookup unavailable")
        except Exception as exc:
            logger.debug(f"Online URL lookup failed: {exc}")

    summary = {
        "safe": "No red flags found. Still avoid entering credentials on unfamiliar sites.",
        "unknown": "Limited information. Open it only if you trust the sender.",
        "suspicious": "This link looks risky. Do not open it or enter any data.",
        "malicious": "This link is malicious. Do not open it.",
    }[verdict]

    return _finalize(Verdict(target, "url", verdict, score, summary, reasons, details))


def check_target(value: str, use_online: bool = True) -> Verdict:
    """Check a file path if it exists, otherwise treat the value as a URL."""
    try:
        if Path(value).is_file():
            return check_file(value, use_online=use_online)
    except OSError:
        pass
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value or ""):
        return check_url(value, use_online=use_online)
    raise ValueError("Enter an existing file path or an http(s) link")
