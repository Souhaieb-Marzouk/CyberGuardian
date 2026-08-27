"""
CyberGuardian VirusTotal IOC Checker Module
============================================
Comprehensive VirusTotal integration for checking Indicators of Compromise.
Supports IP addresses, hash values, domain names, and URLs.
Properly integrates with AI analysis for accurate threat assessment.
"""

import re
import json
import logging
import time
import ipaddress
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading
from urllib.parse import urlparse
import hashlib

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from utils.config import get_config, CACHE_DIR
from utils.logging_utils import get_logger
from utils.secure_storage import get_secure_storage

logger = get_logger('threat_intel.virustotal')


class VTAnalysisDepth(Enum):
    """VirusTotal analysis depth levels."""
    DISABLED = "disabled"
    QUICK = "quick"          # Hashes only
    STANDARD = "standard"    # Hashes, IPs, Domains, URLs
    DEEP = "deep"            # All IOCs + Relations
    FULL = "full"            # All IOCs + Relations + Community


@dataclass
class VTHashResult:
    """Result of a VirusTotal hash lookup."""
    hash_value: str
    hash_type: str
    is_malicious: bool
    detection_ratio: str = ""
    malicious_count: int = 0
    total_engines: int = 0
    threat_names: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    file_type: str = ""
    file_size: int = 0
    reputation: int = 0
    source: str = "virustotal"
    confidence: str = "low"
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VTIPResult:
    """Result of a VirusTotal IP address lookup."""
    ip_address: str
    is_malicious: bool
    detection_ratio: str = ""
    malicious_count: int = 0
    total_engines: int = 0
    threat_names: List[str] = field(default_factory=list)
    country: str = ""
    asn: int = 0
    as_owner: str = ""
    reputation: int = 0
    detected_urls: int = 0
    detected_downloaded_files: int = 0
    detected_communicating_samples: int = 0
    source: str = "virustotal"
    confidence: str = "low"
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VTDomainResult:
    """Result of a VirusTotal domain lookup."""
    domain: str
    is_malicious: bool
    detection_ratio: str = ""
    malicious_count: int = 0
    total_engines: int = 0
    threat_names: List[str] = field(default_factory=list)
    reputation: int = 0
    creation_date: Optional[str] = None
    whois_info: Dict[str, str] = field(default_factory=dict)
    detected_urls: int = 0
    detected_downloaded_files: int = 0
    detected_communicating_samples: int = 0
    categories: List[str] = field(default_factory=list)
    source: str = "virustotal"
    confidence: str = "low"
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VTURLResult:
    """Result of a VirusTotal URL lookup."""
    url: str
    is_malicious: bool
    detection_ratio: str = ""
    malicious_count: int = 0
    total_engines: int = 0
    threat_names: List[str] = field(default_factory=list)
    final_url: str = ""
    status_code: int = 0
    source: str = "virustotal"
    confidence: str = "low"
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IOCResult:
    """Result of comprehensive IOC checking."""
    iocs_checked: int = 0
    iocs_malicious: int = 0
    iocs_suspicious: int = 0
    iocs_clean: int = 0
    iocs_unknown: int = 0
    
    hash_results: List[VTHashResult] = field(default_factory=list)
    ip_results: List[VTIPResult] = field(default_factory=list)
    domain_results: List[VTDomainResult] = field(default_factory=list)
    url_results: List[VTURLResult] = field(default_factory=list)
    
    overall_risk_adjustment: float = 0.0
    highest_risk_level: str = "unknown"
    
    all_iocs: Dict[str, List[str]] = field(default_factory=dict)
    vt_summary: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'iocs_checked': self.iocs_checked,
            'iocs_malicious': self.iocs_malicious,
            'iocs_clean': self.iocs_clean,
            'overall_risk_adjustment': self.overall_risk_adjustment,
            'highest_risk_level': self.highest_risk_level,
            'all_iocs': self.all_iocs,
            'vt_summary': self.vt_summary,
            'hash_results': [
                {
                    'hash_value': r.hash_value[:16] + '...',
                    'is_malicious': r.is_malicious,
                    'detection_ratio': r.detection_ratio,
                    'threat_names': r.threat_names[:5],
                    'file_type': r.file_type
                } for r in self.hash_results if r.is_malicious
            ],
            'ip_results': [
                {
                    'ip_address': r.ip_address,
                    'is_malicious': r.is_malicious,
                    'detection_ratio': r.detection_ratio,
                    'malicious_count': r.malicious_count,
                    'total_engines': r.total_engines,
                    'country': r.country,
                    'as_owner': r.as_owner,
                    'threat_names': r.threat_names[:5]
                } for r in self.ip_results
            ],
            'domain_results': [
                {
                    'domain': r.domain,
                    'is_malicious': r.is_malicious,
                    'detection_ratio': r.detection_ratio,
                    'categories': r.categories
                } for r in self.domain_results if r.is_malicious
            ],
            'url_results': [
                {
                    'url': r.url[:50] + '...' if len(r.url) > 50 else r.url,
                    'is_malicious': r.is_malicious,
                    'detection_ratio': r.detection_ratio
                } for r in self.url_results if r.is_malicious
            ]
        }


class VirusTotalCache:
    """Manages local caching of VirusTotal results."""
    
    def __init__(self, cache_dir: Path = CACHE_DIR, ttl_hours: int = 24):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self._lock = threading.RLock()
        
        self.hash_cache_file = cache_dir / "vt_hash_cache.json"
        self.ip_cache_file = cache_dir / "vt_ip_cache.json"
        self.domain_cache_file = cache_dir / "vt_domain_cache.json"
        self.url_cache_file = cache_dir / "vt_url_cache.json"
        
        self.hash_cache: Dict[str, Dict] = self._load_cache(self.hash_cache_file)
        self.ip_cache: Dict[str, Dict] = self._load_cache(self.ip_cache_file)
        self.domain_cache: Dict[str, Dict] = self._load_cache(self.domain_cache_file)
        self.url_cache: Dict[str, Dict] = self._load_cache(self.url_cache_file)
    
    def _load_cache(self, filepath: Path) -> Dict:
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.debug(f"Failed to load cache {filepath}: {e}")
        return {}
    
    def _save_cache(self, filepath: Path, data: Dict) -> None:
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache {filepath}: {e}")
    
    def _is_expired(self, entry: Dict) -> bool:
        if 'timestamp' not in entry:
            return True
        try:
            cached_time = datetime.fromisoformat(entry['timestamp'])
            return datetime.utcnow() - cached_time > timedelta(hours=self.ttl_hours)
        except:
            return True
    
    def get_hash(self, hash_value: str) -> Optional[Dict]:
        with self._lock:
            entry = self.hash_cache.get(hash_value.lower())
            if entry and not self._is_expired(entry):
                return {k: v for k, v in entry.items() if k != 'timestamp'}
        return None
    
    def set_hash(self, hash_value: str, result: Dict) -> None:
        with self._lock:
            self.hash_cache[hash_value.lower()] = {
                **result,
                'timestamp': datetime.utcnow().isoformat()
            }
            self._save_cache(self.hash_cache_file, self.hash_cache)
    
    def get_ip(self, ip: str) -> Optional[Dict]:
        with self._lock:
            entry = self.ip_cache.get(ip)
            if entry and not self._is_expired(entry):
                return {k: v for k, v in entry.items() if k != 'timestamp'}
        return None
    
    def set_ip(self, ip: str, result: Dict) -> None:
        with self._lock:
            self.ip_cache[ip] = {
                **result,
                'timestamp': datetime.utcnow().isoformat()
            }
            self._save_cache(self.ip_cache_file, self.ip_cache)
    
    def get_domain(self, domain: str) -> Optional[Dict]:
        with self._lock:
            entry = self.domain_cache.get(domain.lower())
            if entry and not self._is_expired(entry):
                return {k: v for k, v in entry.items() if k != 'timestamp'}
        return None
    
    def set_domain(self, domain: str, result: Dict) -> None:
        with self._lock:
            self.domain_cache[domain.lower()] = {
                **result,
                'timestamp': datetime.utcnow().isoformat()
            }
            self._save_cache(self.domain_cache_file, self.domain_cache)
    
    def get_url(self, url: str) -> Optional[Dict]:
        url_key = hashlib.sha256(url.encode()).hexdigest()[:16]
        with self._lock:
            entry = self.url_cache.get(url_key)
            if entry and not self._is_expired(entry):
                return {k: v for k, v in entry.items() if k != 'timestamp'}
        return None
    
    def set_url(self, url: str, result: Dict) -> None:
        url_key = hashlib.sha256(url.encode()).hexdigest()[:16]
        with self._lock:
            self.url_cache[url_key] = {
                **result,
                'url': url,
                'timestamp': datetime.utcnow().isoformat()
            }
            self._save_cache(self.url_cache_file, self.url_cache)


class VirusTotalChecker:
    """
    Comprehensive VirusTotal API integration for IOC checking.
    
    Supports:
    - File hashes (MD5, SHA1, SHA256)
    - IP addresses
    - Domain names
    - URLs
    """
    
    API_BASE_URL = "https://www.virustotal.com/api/v3"
    RATE_LIMIT_REQUESTS = 4
    RATE_LIMIT_PERIOD = 60
    
    def __init__(self):
        self.config = get_config()
        self.cache = VirusTotalCache()
        self._api_key: Optional[str] = None
        self._session: Optional[requests.Session] = None
        self._last_request_time = 0
        self._request_count = 0
        self._rate_limit_lock = threading.Lock()
        
        self._load_api_key()
        
        if REQUESTS_AVAILABLE and self._api_key:
            self._session = self._create_session()
            logger.info("VirusTotal checker initialized with API key")
        else:
            logger.info("VirusTotal checker initialized without API key - limited functionality")
    
    def _load_api_key(self):
        """Load VirusTotal API key from secure storage or config."""
        # Try secure storage first
        try:
            secure_storage = get_secure_storage()
            self._api_key = secure_storage.get_api_key('virustotal_api_key')
            if self._api_key:
                logger.debug("Loaded VT API key from secure storage")
                return
        except Exception as e:
            logger.debug(f"Could not load VT API key from secure storage: {e}")
        
        # Try config file
        try:
            self._api_key = self.config.config.api.virustotal_api_key
            if self._api_key:
                logger.debug("Loaded VT API key from config")
                return
        except Exception as e:
            logger.debug(f"Could not load VT API key from config: {e}")
        
        # Try environment variable
        import os
        self._api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
    
    def _rate_limit(self) -> None:
        """Apply rate limiting for API calls."""
        with self._rate_limit_lock:
            current_time = time.time()
            elapsed = current_time - self._last_request_time
            
            if elapsed >= self.RATE_LIMIT_PERIOD:
                self._request_count = 0
                self._last_request_time = current_time
            
            if self._request_count >= self.RATE_LIMIT_REQUESTS:
                wait_time = self.RATE_LIMIT_PERIOD - elapsed
                if wait_time > 0:
                    logger.debug(f"Rate limiting: waiting {wait_time:.1f} seconds")
                    time.sleep(wait_time)
                self._request_count = 0
                self._last_request_time = time.time()
            
            self._request_count += 1
    
    def _make_request(self, endpoint: str) -> Optional[Dict]:
        """Make an authenticated request to VirusTotal API."""
        if not REQUESTS_AVAILABLE:
            logger.warning("Requests module not available")
            return None
        
        if not self._api_key:
            logger.debug("No VirusTotal API key configured")
            return None
        
        if not self._session:
            self._session = self._create_session()
        
        self._rate_limit()
        
        url = f"{self.API_BASE_URL}/{endpoint}"
        headers = {
            'x-apikey': self._api_key,
            'Accept': 'application/json'
        }
        
        try:
            response = self._session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                logger.error("VirusTotal API key is invalid")
                return None
            elif response.status_code == 404:
                logger.debug(f"Resource not found: {endpoint}")
                return None
            elif response.status_code == 429:
                logger.warning("VirusTotal rate limit exceeded")
                time.sleep(60)
                return None
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return None
                
        except requests.exceptions.Timeout:
            logger.error("VirusTotal API request timed out")
            return None
        except requests.exceptions.RequestException as e:
            logger.error(f"VirusTotal API request error: {e}")
            return None
    
    def is_api_key_configured(self) -> bool:
        """Check if VirusTotal API key is configured."""
        return bool(self._api_key)
    
    # ================== HASH LOOKUP ==================
    
    def lookup_hash(self, hash_value: str) -> VTHashResult:
        """Look up a file hash in VirusTotal."""
        hash_value = hash_value.lower().strip()
        
        hash_type = self._get_hash_type(hash_value)
        if not hash_type:
            return VTHashResult(
                hash_value=hash_value,
                hash_type='unknown',
                is_malicious=False,
                error="Invalid hash format"
            )
        
        # Check cache
        cached = self.cache.get_hash(hash_value)
        if cached:
            logger.debug(f"[VT] Cache hit for hash: {hash_value[:16]}...")
            return VTHashResult(**cached)
        
        if not self._api_key:
            return VTHashResult(
                hash_value=hash_value,
                hash_type=hash_type,
                is_malicious=False,
                source='virustotal',
                error="No API key configured"
            )
        
        logger.info(f"[VT] Checking hash: {hash_value[:16]}...")
        
        data = self._make_request(f"files/{hash_value}")
        
        if not data:
            result = VTHashResult(
                hash_value=hash_value,
                hash_type=hash_type,
                is_malicious=False,
                source='virustotal',
                confidence='medium'
            )
        else:
            result = self._parse_hash_response(hash_value, hash_type, data)
        
        # Cache the result
        result_dict = {
            'hash_value': result.hash_value,
            'hash_type': result.hash_type,
            'is_malicious': result.is_malicious,
            'detection_ratio': result.detection_ratio,
            'malicious_count': result.malicious_count,
            'total_engines': result.total_engines,
            'threat_names': result.threat_names,
            'first_seen': result.first_seen,
            'last_seen': result.last_seen,
            'file_type': result.file_type,
            'file_size': result.file_size,
            'reputation': result.reputation,
            'source': result.source,
            'confidence': result.confidence,
            'details': result.details
        }
        self.cache.set_hash(hash_value, result_dict)
        
        return result
    
    def _parse_hash_response(self, hash_value: str, hash_type: str, data: Dict) -> VTHashResult:
        """Parse VirusTotal file report response."""
        attributes = data.get('data', {}).get('attributes', {})
        
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious = last_analysis.get('malicious', 0)
        suspicious = last_analysis.get('suspicious', 0)
        total = sum(last_analysis.values())
        
        threat_names = []
        analysis_results = attributes.get('last_analysis_results', {})
        for engine, result in analysis_results.items():
            if result.get('result') and result.get('category') in ['malicious', 'suspicious']:
                threat_name = result.get('result', '')
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        if malicious >= 10:
            confidence = 'high'
        elif malicious >= 3:
            confidence = 'medium'
        elif malicious > 0 or suspicious > 0:
            confidence = 'low'
        else:
            confidence = 'high'
        
        first_seen = None
        last_seen = None
        if attributes.get('first_submission_date'):
            first_seen = datetime.fromtimestamp(attributes['first_submission_date']).isoformat()
        if attributes.get('last_analysis_date'):
            last_seen = datetime.fromtimestamp(attributes['last_analysis_date']).isoformat()
        
        return VTHashResult(
            hash_value=hash_value,
            hash_type=hash_type,
            is_malicious=malicious > 0,
            detection_ratio=f"{malicious}/{total}",
            malicious_count=malicious,
            total_engines=total,
            threat_names=threat_names[:10],
            first_seen=first_seen,
            last_seen=last_seen,
            file_type=attributes.get('type_description', ''),
            file_size=attributes.get('size', 0),
            reputation=attributes.get('reputation', 0),
            source='virustotal',
            confidence=confidence,
            details={
                'suspicious_count': suspicious,
                'undetected_count': last_analysis.get('undetected', 0),
                'harmless_count': last_analysis.get('harmless', 0),
                'type_tags': attributes.get('type_tags', [])[:5],
                'names': attributes.get('names', [])[:5],
                'magic': attributes.get('magic', '')
            }
        )
    
    # ================== IP LOOKUP ==================
    
    def lookup_ip(self, ip_address: str) -> VTIPResult:
        """Look up an IP address in VirusTotal."""
        ip_address = ip_address.strip()
        
        logger.info(f"[VT] lookup_ip called for: {ip_address}")
        
        # Validate IP
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.is_private or ip_obj.is_loopback:
                logger.info(f"[VT] IP {ip_address} is private/loopback - skipping")
                return VTIPResult(
                    ip_address=ip_address,
                    is_malicious=False,
                    confidence='high',
                    details={'note': 'Private/internal IP address'}
                )
        except ValueError as e:
            logger.warning(f"[VT] Invalid IP format: {ip_address} - {e}")
            return VTIPResult(
                ip_address=ip_address,
                is_malicious=False,
                error="Invalid IP address format"
            )
        
        # Check cache
        cached = self.cache.get_ip(ip_address)
        if cached:
            logger.info(f"[VT] Cache hit for IP: {ip_address}, cached result: is_malicious={cached.get('is_malicious', False)}")
            return VTIPResult(**cached)
        
        if not self._api_key:
            logger.warning(f"[VT] No API key configured - cannot check IP {ip_address}")
            return VTIPResult(
                ip_address=ip_address,
                is_malicious=False,
                source='virustotal',
                error="No API key configured"
            )
        
        logger.info(f"[VT] Making API request for IP: {ip_address}")
        
        data = self._make_request(f"ip_addresses/{ip_address}")
        
        if not data:
            logger.warning(f"[VT] No data returned for IP: {ip_address}")
            result = VTIPResult(
                ip_address=ip_address,
                is_malicious=False,
                source='virustotal',
                confidence='medium'
            )
        else:
            result = self._parse_ip_response(ip_address, data)
            logger.info(f"[VT] IP {ip_address} result: is_malicious={result.is_malicious}, ratio={result.detection_ratio}, malicious_count={result.malicious_count}")
        
        # Cache the result
        result_dict = {
            'ip_address': result.ip_address,
            'is_malicious': result.is_malicious,
            'detection_ratio': result.detection_ratio,
            'malicious_count': result.malicious_count,
            'total_engines': result.total_engines,
            'threat_names': result.threat_names,
            'country': result.country,
            'asn': result.asn,
            'as_owner': result.as_owner,
            'reputation': result.reputation,
            'detected_urls': result.detected_urls,
            'detected_downloaded_files': result.detected_downloaded_files,
            'detected_communicating_samples': result.detected_communicating_samples,
            'source': result.source,
            'confidence': result.confidence,
            'details': result.details
        }
        self.cache.set_ip(ip_address, result_dict)
        
        return result
    
    def _parse_ip_response(self, ip_address: str, data: Dict) -> VTIPResult:
        """Parse VirusTotal IP report response."""
        attributes = data.get('data', {}).get('attributes', {})
        
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious = last_analysis.get('malicious', 0)
        suspicious = last_analysis.get('suspicious', 0)
        total = sum(last_analysis.values())
        
        threat_names = []
        analysis_results = attributes.get('last_analysis_results', {})
        for engine, result in analysis_results.items():
            if result.get('result') and result.get('category') in ['malicious', 'suspicious']:
                threat_name = result.get('result', '')
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        # Determine confidence based on detection count
        if malicious >= 10:
            confidence = 'high'
        elif malicious >= 3:
            confidence = 'medium'
        elif malicious > 0 or suspicious > 0:
            confidence = 'low'
        else:
            confidence = 'high'
        
        return VTIPResult(
            ip_address=ip_address,
            is_malicious=malicious > 0,
            detection_ratio=f"{malicious}/{total}",
            malicious_count=malicious,
            total_engines=total,
            threat_names=threat_names[:10],
            country=attributes.get('country', ''),
            asn=attributes.get('asn', 0),
            as_owner=attributes.get('as_owner', ''),
            reputation=attributes.get('reputation', 0),
            detected_urls=attributes.get('detected_urls', 0),
            detected_downloaded_files=attributes.get('detected_downloaded_files', 0),
            detected_communicating_samples=attributes.get('detected_communicating_samples', 0),
            source='virustotal',
            confidence=confidence,
            details={
                'suspicious_count': suspicious,
                'undetected_count': last_analysis.get('undetected', 0),
                'harmless_count': last_analysis.get('harmless', 0),
                'network': attributes.get('network', ''),
                'continent': attributes.get('continent', '')
            }
        )
    
    # ================== DOMAIN LOOKUP ==================
    
    def lookup_domain(self, domain: str) -> VTDomainResult:
        """Look up a domain in VirusTotal."""
        domain = domain.lower().strip()
        
        # Check cache
        cached = self.cache.get_domain(domain)
        if cached:
            logger.debug(f"[VT] Cache hit for domain: {domain}")
            return VTDomainResult(**cached)
        
        if not self._api_key:
            return VTDomainResult(
                domain=domain,
                is_malicious=False,
                source='virustotal',
                error="No API key configured"
            )
        
        logger.info(f"[VT] Checking domain: {domain}")
        
        data = self._make_request(f"domains/{domain}")
        
        if not data:
            result = VTDomainResult(
                domain=domain,
                is_malicious=False,
                source='virustotal',
                confidence='medium'
            )
        else:
            result = self._parse_domain_response(domain, data)
        
        # Cache the result
        result_dict = {
            'domain': result.domain,
            'is_malicious': result.is_malicious,
            'detection_ratio': result.detection_ratio,
            'malicious_count': result.malicious_count,
            'total_engines': result.total_engines,
            'threat_names': result.threat_names,
            'reputation': result.reputation,
            'creation_date': result.creation_date,
            'whois_info': result.whois_info,
            'detected_urls': result.detected_urls,
            'detected_downloaded_files': result.detected_downloaded_files,
            'detected_communicating_samples': result.detected_communicating_samples,
            'categories': result.categories,
            'source': result.source,
            'confidence': result.confidence,
            'details': result.details
        }
        self.cache.set_domain(domain, result_dict)
        
        return result
    
    def _parse_domain_response(self, domain: str, data: Dict) -> VTDomainResult:
        """Parse VirusTotal domain report response."""
        attributes = data.get('data', {}).get('attributes', {})
        
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious = last_analysis.get('malicious', 0)
        suspicious = last_analysis.get('suspicious', 0)
        total = sum(last_analysis.values())
        
        threat_names = []
        analysis_results = attributes.get('last_analysis_results', {})
        for engine, result in analysis_results.items():
            if result.get('result') and result.get('category') in ['malicious', 'suspicious']:
                threat_name = result.get('result', '')
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        if malicious >= 10:
            confidence = 'high'
        elif malicious >= 3:
            confidence = 'medium'
        elif malicious > 0 or suspicious > 0:
            confidence = 'low'
        else:
            confidence = 'high'
        
        creation_date = None
        if attributes.get('creation_date'):
            try:
                creation_date = datetime.fromtimestamp(attributes['creation_date']).isoformat()
            except:
                pass
        
        return VTDomainResult(
            domain=domain,
            is_malicious=malicious > 0,
            detection_ratio=f"{malicious}/{total}",
            malicious_count=malicious,
            total_engines=total,
            threat_names=threat_names[:10],
            reputation=attributes.get('reputation', 0),
            creation_date=creation_date,
            whois_info=attributes.get('whois', {}),
            detected_urls=attributes.get('detected_urls', 0),
            detected_downloaded_files=attributes.get('detected_downloaded_files', 0),
            detected_communicating_samples=attributes.get('detected_communicating_samples', 0),
            categories=attributes.get('categories', []),
            source='virustotal',
            confidence=confidence,
            details={
                'suspicious_count': suspicious,
                'undetected_count': last_analysis.get('undetected', 0),
                'harmless_count': last_analysis.get('harmless', 0),
                'last_dns_records': attributes.get('last_dns_records', {})
            }
        )
    
    # ================== URL LOOKUP ==================
    
    def lookup_url(self, url: str) -> VTURLResult:
        """Look up a URL in VirusTotal."""
        url = url.strip()
        
        # Check cache
        cached = self.cache.get_url(url)
        if cached:
            logger.debug(f"[VT] Cache hit for URL")
            return VTURLResult(**cached)
        
        if not self._api_key:
            return VTURLResult(
                url=url,
                is_malicious=False,
                source='virustotal',
                error="No API key configured"
            )
        
        logger.info(f"[VT] Checking URL: {url[:50]}...")
        
        # URL needs to be base64 encoded for VT API
        url_id = self._get_url_id(url)
        data = self._make_request(f"urls/{url_id}")
        
        if not data:
            result = VTURLResult(
                url=url,
                is_malicious=False,
                source='virustotal',
                confidence='medium'
            )
        else:
            result = self._parse_url_response(url, data)
        
        # Cache the result
        result_dict = {
            'url': result.url,
            'is_malicious': result.is_malicious,
            'detection_ratio': result.detection_ratio,
            'malicious_count': result.malicious_count,
            'total_engines': result.total_engines,
            'threat_names': result.threat_names,
            'final_url': result.final_url,
            'status_code': result.status_code,
            'source': result.source,
            'confidence': result.confidence,
            'details': result.details
        }
        self.cache.set_url(url, result_dict)
        
        return result
    
    def _get_url_id(self, url: str) -> str:
        """Get VirusTotal URL ID (base64 encoded without padding)."""
        import base64
        return base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    
    def _parse_url_response(self, url: str, data: Dict) -> VTURLResult:
        """Parse VirusTotal URL report response."""
        attributes = data.get('data', {}).get('attributes', {})
        
        last_analysis = attributes.get('last_analysis_stats', {})
        malicious = last_analysis.get('malicious', 0)
        suspicious = last_analysis.get('suspicious', 0)
        total = sum(last_analysis.values())
        
        threat_names = []
        analysis_results = attributes.get('last_analysis_results', {})
        for engine, result in analysis_results.items():
            if result.get('result') and result.get('category') in ['malicious', 'suspicious']:
                threat_name = result.get('result', '')
                if threat_name and threat_name not in threat_names:
                    threat_names.append(threat_name)
        
        if malicious >= 10:
            confidence = 'high'
        elif malicious >= 3:
            confidence = 'medium'
        elif malicious > 0 or suspicious > 0:
            confidence = 'low'
        else:
            confidence = 'high'
        
        return VTURLResult(
            url=url,
            is_malicious=malicious > 0,
            detection_ratio=f"{malicious}/{total}",
            malicious_count=malicious,
            total_engines=total,
            threat_names=threat_names[:10],
            final_url=attributes.get('last_final_url', ''),
            status_code=attributes.get('last_http_response_code', 0),
            source='virustotal',
            confidence=confidence,
            details={
                'suspicious_count': suspicious,
                'undetected_count': last_analysis.get('undetected', 0),
                'harmless_count': last_analysis.get('harmless', 0),
                'redirection_chain': attributes.get('redirection_chain', [])
            }
        )
    
    # ================== HELPER METHODS ==================
    
    def _get_hash_type(self, hash_value: str) -> Optional[str]:
        """Determine hash type from length."""
        length = len(hash_value)
        if length == 32:
            return 'md5'
        elif length == 40:
            return 'sha1'
        elif length == 64:
            return 'sha256'
        return None
    
    def _is_valid_ip(self, value: str) -> bool:
        """Check if value is a valid IP address."""
        try:
            ip = ipaddress.ip_address(value.strip())
            return not (ip.is_private or ip.is_loopback or ip.is_link_local)
        except ValueError:
            return False
    
    def _is_valid_domain(self, value: str) -> bool:
        """Check if value looks like a valid domain."""
        value = value.strip().lower()
        if not value or len(value) < 3 or len(value) > 253:
            return False
        # Basic domain pattern
        pattern = r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$'
        if not re.match(pattern, value):
            return False
        # Exclude common false positives
        false_positives = {'exe', 'dll', 'sys', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'hta', 'js', 'html', 'txt'}
        parts = value.split('.')
        if len(parts) == 2 and parts[-1] in false_positives:
            return False
        return True
    
    def _is_valid_url(self, value: str) -> bool:
        """Check if value is a valid URL."""
        try:
            result = urlparse(value.strip())
            return all([result.scheme, result.netloc])
        except:
            return False
    
    def _extract_iocs_from_evidence(self, evidence: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract all IOCs from evidence dictionary."""
        iocs = {
            'hashes': set(),
            'ips': set(),
            'domains': set(),
            'urls': set()
        }
        
        def extract_from_value(value: Any):
            """Recursively extract IOCs from any value."""
            if isinstance(value, str):
                # Extract hashes (MD5, SHA1, SHA256)
                hash_patterns = [
                    r'\b[a-fA-F0-9]{32}\b',  # MD5
                    r'\b[a-fA-F0-9]{40}\b',  # SHA1
                    r'\b[a-fA-F0-9]{64}\b',  # SHA256
                ]
                for pattern in hash_patterns:
                    for match in re.findall(pattern, value):
                        iocs['hashes'].add(match.lower())
                
                # Extract IPs
                ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                for match in re.findall(ip_pattern, value):
                    if self._is_valid_ip(match):
                        iocs['ips'].add(match)
                
                # Extract URLs
                url_pattern = r'https?://[^\s<>"\'\)\]\}]+'
                for match in re.findall(url_pattern, value):
                    if self._is_valid_url(match):
                        iocs['urls'].add(match)
                
                # Extract domains (basic pattern)
                domain_pattern = r'\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}\b'
                for match in re.findall(domain_pattern, value):
                    if self._is_valid_domain(match):
                        iocs['domains'].add(match.lower())
            
            elif isinstance(value, dict):
                for v in value.values():
                    extract_from_value(v)
            
            elif isinstance(value, (list, tuple)):
                for item in value:
                    extract_from_value(item)
        
        extract_from_value(evidence)
        
        return {k: list(v) for k, v in iocs.items()}
    
    # ================== COMPREHENSIVE IOC CHECKING ==================
    
    def check_iocs_from_detection(
        self,
        indicator: str,
        detection_type: str,
        evidence: Dict[str, Any]
    ) -> IOCResult:
        """
        Check all IOCs from a detection against VirusTotal.
        
        This method checks:
        1. The main indicator (IP/domain/hash/URL)
        2. All IOCs extracted from evidence
        
        Args:
            indicator: The main detection indicator
            detection_type: Type of detection (process, network, file, etc.)
            evidence: Additional evidence dictionary
        
        Returns:
            IOCResult with all VT lookup results
        """
        result = IOCResult()
        
        logger.info(f"[VT] check_iocs_from_detection called - indicator: '{indicator}', type: {detection_type}")
        
        if not self._api_key:
            result.vt_summary = "VirusTotal API key not configured"
            logger.warning("[VT] No API key configured")
            return result
        
        # Collect all IOCs
        all_iocs = {
            'hashes': set(),
            'ips': set(),
            'domains': set(),
            'urls': set()
        }
        
        # 1. Check the main indicator first
        indicator = indicator.strip()
        logger.info(f"[VT] Processing main indicator: '{indicator}'")
        
        # Determine indicator type and check it
        if self._is_valid_ip(indicator):
            all_iocs['ips'].add(indicator)
            logger.info(f"[VT] Main indicator is a valid IP: {indicator}")
        elif self._get_hash_type(indicator):
            all_iocs['hashes'].add(indicator.lower())
            logger.info(f"[VT] Main indicator is a hash: {indicator[:16]}...")
        elif self._is_valid_url(indicator):
            all_iocs['urls'].add(indicator)
            logger.info(f"[VT] Main indicator is a URL")
        elif self._is_valid_domain(indicator):
            all_iocs['domains'].add(indicator.lower())
            logger.info(f"[VT] Main indicator is a domain: {indicator}")
        else:
            logger.info(f"[VT] Main indicator '{indicator}' type could not be determined (may be text/path)")
        
        # 2. Extract IOCs from evidence
        evidence_iocs = self._extract_iocs_from_evidence(evidence)
        logger.info(f"[VT] IOCs extracted from evidence: hashes={len(evidence_iocs.get('hashes', []))}, ips={len(evidence_iocs.get('ips', []))}, domains={len(evidence_iocs.get('domains', []))}, urls={len(evidence_iocs.get('urls', []))}")
        
        for ioc_type, ioc_list in evidence_iocs.items():
            all_iocs[ioc_type].update(ioc_list)
        
        # Convert sets to lists
        all_iocs = {k: list(v) for k, v in all_iocs.items()}
        result.all_iocs = all_iocs
        
        # 3. Check hashes
        for hash_value in all_iocs['hashes'][:10]:  # Limit to 10
            try:
                hash_result = self.lookup_hash(hash_value)
                result.hash_results.append(hash_result)
                result.iocs_checked += 1
                if hash_result.is_malicious:
                    result.iocs_malicious += 1
                elif hash_result.confidence in ['high', 'medium']:
                    result.iocs_clean += 1
                else:
                    result.iocs_unknown += 1
            except Exception as e:
                logger.error(f"Error checking hash {hash_value[:16]}...: {e}")
        
        # 4. Check IPs
        for ip in all_iocs['ips'][:10]:  # Limit to 10
            try:
                ip_result = self.lookup_ip(ip)
                result.ip_results.append(ip_result)
                result.iocs_checked += 1
                if ip_result.is_malicious:
                    result.iocs_malicious += 1
                elif ip_result.confidence in ['high', 'medium']:
                    result.iocs_clean += 1
                else:
                    result.iocs_unknown += 1
            except Exception as e:
                logger.error(f"Error checking IP {ip}: {e}")
        
        # 5. Check domains
        for domain in all_iocs['domains'][:10]:  # Limit to 10
            try:
                domain_result = self.lookup_domain(domain)
                result.domain_results.append(domain_result)
                result.iocs_checked += 1
                if domain_result.is_malicious:
                    result.iocs_malicious += 1
                elif domain_result.confidence in ['high', 'medium']:
                    result.iocs_clean += 1
                else:
                    result.iocs_unknown += 1
            except Exception as e:
                logger.error(f"Error checking domain {domain}: {e}")
        
        # 6. Check URLs
        for url in all_iocs['urls'][:5]:  # Limit to 5 URLs
            try:
                url_result = self.lookup_url(url)
                result.url_results.append(url_result)
                result.iocs_checked += 1
                if url_result.is_malicious:
                    result.iocs_malicious += 1
                elif url_result.confidence in ['high', 'medium']:
                    result.iocs_clean += 1
                else:
                    result.iocs_unknown += 1
            except Exception as e:
                logger.error(f"Error checking URL: {e}")
        
        # 7. Calculate risk adjustment and determine highest risk
        result.overall_risk_adjustment = self._calculate_risk_adjustment(result)
        result.highest_risk_level = self._determine_highest_risk(result)
        result.vt_summary = self._generate_vt_summary(result)
        
        logger.info(f"[VT] IOC check complete: {result.iocs_checked} checked, {result.iocs_malicious} malicious, highest risk: {result.highest_risk_level}")
        
        return result
    
    def _calculate_risk_adjustment(self, result: IOCResult) -> float:
        """Calculate overall risk adjustment based on VT results."""
        if result.iocs_checked == 0:
            return 0.0
        
        adjustment = 0.0
        
        # Weight based on detection count
        for hash_result in result.hash_results:
            if hash_result.is_malicious:
                if hash_result.malicious_count >= 20:
                    adjustment += 0.5
                elif hash_result.malicious_count >= 10:
                    adjustment += 0.3
                else:
                    adjustment += 0.2
        
        for ip_result in result.ip_results:
            if ip_result.is_malicious:
                if ip_result.malicious_count >= 10:
                    adjustment += 0.4
                elif ip_result.malicious_count >= 5:
                    adjustment += 0.3
                else:
                    adjustment += 0.25
        
        for domain_result in result.domain_results:
            if domain_result.is_malicious:
                if domain_result.malicious_count >= 10:
                    adjustment += 0.35
                else:
                    adjustment += 0.25
        
        for url_result in result.url_results:
            if url_result.is_malicious:
                adjustment += 0.25
        
        # Reduce risk if IOCs are confirmed clean
        if result.iocs_clean > 0 and result.iocs_malicious == 0:
            adjustment -= 0.1 * min(result.iocs_clean, 3)
        
        return max(-1.0, min(1.0, adjustment))
    
    def _determine_highest_risk(self, result: IOCResult) -> str:
        """Determine the highest risk level based on VT results."""
        if result.iocs_malicious == 0:
            if result.iocs_clean > 0:
                return "clean"
            return "unknown"
        
        # Check for critical risk (high detection count)
        for hash_result in result.hash_results:
            if hash_result.is_malicious and hash_result.malicious_count >= 20:
                return "critical"
        
        for ip_result in result.ip_results:
            if ip_result.is_malicious and ip_result.malicious_count >= 10:
                return "critical"
        
        # Multiple malicious IOCs = high risk
        if result.iocs_malicious >= 3:
            return "high"
        
        # Moderate detection counts = high risk
        for r in result.hash_results + result.ip_results + result.domain_results:
            if r.is_malicious and r.malicious_count >= 5:
                return "high"
        
        # Single or few malicious IOCs with lower detection = medium
        if result.iocs_malicious >= 1:
            return "medium"
        
        return "low"
    
    def _generate_vt_summary(self, result: IOCResult) -> str:
        """Generate a human-readable summary of VT results."""
        parts = []
        
        if result.iocs_checked == 0:
            return "No IOCs found to check against VirusTotal"
        
        parts.append(f"Checked {result.iocs_checked} IOC(s) against VirusTotal")
        
        if result.iocs_malicious > 0:
            parts.append(f"{result.iocs_malicious} flagged as MALICIOUS")
            
            details = []
            for hr in result.hash_results:
                if hr.is_malicious:
                    details.append(f"Hash {hr.hash_value[:16]}... ({hr.detection_ratio}, {hr.file_type})")
            for ir in result.ip_results:
                if ir.is_malicious:
                    details.append(f"IP {ir.ip_address} ({ir.detection_ratio}, {ir.country or 'Unknown'})")
            for dr in result.domain_results:
                if dr.is_malicious:
                    details.append(f"Domain {dr.domain} ({dr.detection_ratio})")
            
            if details:
                parts.append("Malicious: " + "; ".join(details[:5]))
        else:
            parts.append("No malicious detections found")
        
        if result.iocs_clean > 0:
            parts.append(f"{result.iocs_clean} confirmed clean")
        
        return ". ".join(parts)


# Global instance
_vt_checker_instance: Optional[VirusTotalChecker] = None


def get_virustotal_checker() -> VirusTotalChecker:
    """Get the global VirusTotal checker instance."""
    global _vt_checker_instance
    if _vt_checker_instance is None:
        _vt_checker_instance = VirusTotalChecker()
    return _vt_checker_instance


def is_virustotal_available() -> bool:
    """Check if VirusTotal checking is available (API key configured)."""
    checker = get_virustotal_checker()
    return checker.is_api_key_configured()
