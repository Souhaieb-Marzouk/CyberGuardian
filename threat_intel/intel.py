"""
CyberGuardian Threat Intelligence Module
========================================
Handles hash lookups, IP reputation checking, and
threat intelligence feed management.
"""

import os
import json
import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import threading
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from utils.config import CACHE_DIR, get_config
from utils.logging_utils import get_logger

logger = get_logger('threat_intel.intel')


@dataclass
class HashLookupResult:
    """Result of a hash lookup."""
    hash_value: str
    hash_type: str
    is_malicious: bool
    detection_ratio: str = ""
    threat_names: List[str] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source: str = ""
    confidence: str = "low"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IPReputationResult:
    """Result of an IP reputation check."""
    ip_address: str
    is_malicious: bool
    abuse_score: int = 0
    threat_types: List[str] = field(default_factory=list)
    country: str = ""
    asn: str = ""
    domain: str = ""
    reports_count: int = 0
    last_reported: Optional[str] = None
    source: str = ""
    confidence: str = "low"
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainReputationResult:
    """Result of a domain reputation check."""
    domain: str
    is_malicious: bool
    threat_types: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    reputation_score: int = 0
    creation_date: Optional[str] = None
    source: str = ""
    confidence: str = "low"
    details: Dict[str, Any] = field(default_factory=dict)


class CacheManager:
    """
    Manages local caching of threat intelligence results.
    """
    
    def __init__(self, cache_dir: Path = CACHE_DIR, ttl_hours: int = 24):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl_hours = ttl_hours
        self._lock = threading.RLock()
        
        # Cache files
        self.hash_cache_file = cache_dir / "hash_cache.json"
        self.ip_cache_file = cache_dir / "ip_cache.json"
        self.domain_cache_file = cache_dir / "domain_cache.json"
        
        # In-memory caches
        self.hash_cache: Dict[str, Dict] = self._load_cache(self.hash_cache_file)
        self.ip_cache: Dict[str, Dict] = self._load_cache(self.ip_cache_file)
        self.domain_cache: Dict[str, Dict] = self._load_cache(self.domain_cache_file)
    
    def _load_cache(self, filepath: Path) -> Dict:
        """Load cache from file."""
        if filepath.exists():
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.debug(f"Failed to load cache {filepath}: {e}")
        return {}
    
    def _save_cache(self, filepath: Path, data: Dict) -> None:
        """Save cache to file."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save cache {filepath}: {e}")
    
    def _is_expired(self, entry: Dict) -> bool:
        """Check if cache entry is expired."""
        if 'timestamp' not in entry:
            return True
        
        cached_time = datetime.fromisoformat(entry['timestamp'])
        return datetime.utcnow() - cached_time > timedelta(hours=self.ttl_hours)
    
    def get_hash(self, hash_value: str) -> Optional[HashLookupResult]:
        """Get cached hash lookup result."""
        with self._lock:
            entry = self.hash_cache.get(hash_value.lower())
            if entry and not self._is_expired(entry):
                return HashLookupResult(**entry)
        return None
    
    def set_hash(self, result: HashLookupResult) -> None:
        """Cache hash lookup result. Only cache positive (malicious) results."""
        # Only cache if malicious or if it's a verified clean result from VT
        # Don't cache errors, no_api_key, or unknown results
        if result.is_malicious or (result.source == 'virustotal' and result.confidence in ['high', 'medium']):
            with self._lock:
                self.hash_cache[result.hash_value.lower()] = {
                    'hash_value': result.hash_value,
                    'hash_type': result.hash_type,
                    'is_malicious': result.is_malicious,
                    'detection_ratio': result.detection_ratio,
                    'threat_names': result.threat_names,
                    'first_seen': result.first_seen,
                    'last_seen': result.last_seen,
                    'source': result.source,
                    'confidence': result.confidence,
                    'details': result.details,
                    'timestamp': datetime.utcnow().isoformat(),
                }
                self._save_cache(self.hash_cache_file, self.hash_cache)
    
    def get_ip(self, ip: str) -> Optional[IPReputationResult]:
        """Get cached IP reputation result."""
        with self._lock:
            entry = self.ip_cache.get(ip)
            if entry and not self._is_expired(entry):
                return IPReputationResult(**{k: v for k, v in entry.items() if k != 'timestamp'})
        return None
    
    def set_ip(self, result: IPReputationResult) -> None:
        """Cache IP reputation result."""
        with self._lock:
            self.ip_cache[result.ip_address] = {
                'ip_address': result.ip_address,
                'is_malicious': result.is_malicious,
                'abuse_score': result.abuse_score,
                'threat_types': result.threat_types,
                'country': result.country,
                'asn': result.asn,
                'domain': result.domain,
                'reports_count': result.reports_count,
                'last_reported': result.last_reported,
                'source': result.source,
                'confidence': result.confidence,
                'details': result.details,
                'timestamp': datetime.utcnow().isoformat(),
            }
            self._save_cache(self.ip_cache_file, self.ip_cache)
    
    def get_domain(self, domain: str) -> Optional[DomainReputationResult]:
        """Get cached domain reputation result."""
        with self._lock:
            entry = self.domain_cache.get(domain.lower())
            if entry and not self._is_expired(entry):
                return DomainReputationResult(**{k: v for k, v in entry.items() if k != 'timestamp'})
        return None
    
    def set_domain(self, result: DomainReputationResult) -> None:
        """Cache domain reputation result."""
        with self._lock:
            self.domain_cache[result.domain.lower()] = {
                'domain': result.domain,
                'is_malicious': result.is_malicious,
                'threat_types': result.threat_types,
                'categories': result.categories,
                'reputation_score': result.reputation_score,
                'creation_date': result.creation_date,
                'source': result.source,
                'confidence': result.confidence,
                'details': result.details,
                'timestamp': datetime.utcnow().isoformat(),
            }
            self._save_cache(self.domain_cache_file, self.domain_cache)
    
    def clear_expired(self) -> int:
        """Remove all expired entries from caches."""
        count = 0
        
        with self._lock:
            for cache, filepath in [
                (self.hash_cache, self.hash_cache_file),
                (self.ip_cache, self.ip_cache_file),
                (self.domain_cache, self.domain_cache_file),
            ]:
                expired = [k for k, v in cache.items() if self._is_expired(v)]
                for key in expired:
                    del cache[key]
                    count += 1
                if expired:
                    self._save_cache(filepath, cache)
        
        logger.info(f"Cleared {count} expired cache entries")
        return count


class ThreatIntelManager:
    """
    Central manager for threat intelligence lookups.
    Handles VirusTotal, AbuseIPDB, and other threat feeds.
    """
    
    # Known malicious hashes (sample data for offline detection)
    KNOWN_MALICIOUS_HASHES = {
        # WannaCry
        'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa': 'WannaCry Ransomware',
        # Emotet
        'a7e534d8e72d5c5a8c3c5a8b5c8a5c8a5c8a5c8a5c8a5c8a5c8a5c8a5c8a': 'Emotet Trojan',
        # Ryuk
        'b7e534d8e72d5c5a8c3c5a8b5c8a5c8a5c8a5c8a5c8a5c8a5c8a5c8a5c8a': 'Ryuk Ransomware',
        # TrickBot
        'c7e534d8e72d5c5a8c3c5a8b5c8a5c8a5c8a5c8a5c8a5c8a5c8a5c8a5c8a': 'TrickBot',
    }
    
    # Known malicious IPs (sample data)
    KNOWN_MALICIOUS_IPS = {
        '185.220.101.0': 'Tor Exit Node',
        '185.220.101.1': 'Tor Exit Node',
        '23.129.64.0': 'Malicious C2',
        '23.129.64.1': 'Malicious C2',
    }
    
    # Known malicious domains (sample data)
    KNOWN_MALICIOUS_DOMAINS = {
        'malware-test.com': 'Test Domain',
        'eicar.com': 'Test Domain',
    }
    
    def __init__(self):
        self.config = get_config()
        self.cache = CacheManager(ttl_hours=self.config.config.api.cache_ttl_hours)
        self._session = self._create_session()
        
        # Rate limiting
        self._last_vt_request = 0
        self._last_abuseipdb_request = 0
        self._rate_limit_lock = threading.Lock()
    
    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
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
    
    def _rate_limit(self, api: str) -> None:
        """Apply rate limiting for API calls."""
        with self._rate_limit_lock:
            if api == 'virustotal':
                # VirusTotal free tier: 4 requests per minute
                min_interval = 15  # seconds
                elapsed = time.time() - self._last_vt_request
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                self._last_vt_request = time.time()
            
            elif api == 'abuseipdb':
                # AbuseIPDB: 1000 requests per day = ~1 per 86 seconds
                # We'll be conservative with 1 per 10 seconds
                min_interval = 10
                elapsed = time.time() - self._last_abuseipdb_request
                if elapsed < min_interval:
                    time.sleep(min_interval - elapsed)
                self._last_abuseipdb_request = time.time()
    
    def lookup_hash(
        self,
        hash_value: str,
        use_online: bool = True
    ) -> HashLookupResult:
        """
        Look up a file hash in threat intelligence databases.
        
        Args:
            hash_value: SHA-256, MD5, or SHA-1 hash
            use_online: Whether to query online APIs
        
        Returns:
            HashLookupResult with lookup findings
        """
        # Normalize hash
        hash_value = hash_value.lower().strip()
        
        # Determine hash type
        hash_type = self._get_hash_type(hash_value)
        if not hash_type:
            return HashLookupResult(
                hash_value=hash_value,
                hash_type='unknown',
                is_malicious=False,
                confidence='low',
                source='invalid'
            )
        
        # Check cache first
        cached = self.cache.get_hash(hash_value)
        if cached:
            logger.debug(f"Hash cache hit: {hash_value[:16]}...")
            return cached
        
        # Check local known malicious hashes
        if hash_value in self.KNOWN_MALICIOUS_HASHES:
            result = HashLookupResult(
                hash_value=hash_value,
                hash_type=hash_type,
                is_malicious=True,
                threat_names=[self.KNOWN_MALICIOUS_HASHES[hash_value]],
                source='local',
                confidence='high'
            )
            self.cache.set_hash(result)
            return result
        
        # Query online API if enabled and key available
        if use_online and self.config.config.api.virustotal_api_key:
            return self._query_virustotal_hash(hash_value, hash_type)
        
        # No result found
        return HashLookupResult(
            hash_value=hash_value,
            hash_type=hash_type,
            is_malicious=False,
            confidence='low',
            source='local'
        )
    
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
    
    def _query_virustotal_hash(
        self,
        hash_value: str,
        hash_type: str
    ) -> HashLookupResult:
        """Query VirusTotal for hash information."""
        api_key = self.config.config.api.virustotal_api_key
        
        if not api_key:
            return HashLookupResult(
                hash_value=hash_value,
                hash_type=hash_type,
                is_malicious=False,
                confidence='low',
                source='no_api_key'
            )
        
        try:
            self._rate_limit('virustotal')
            
            url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
            headers = {'x-apikey': api_key}
            
            response = self._session.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                last_analysis = attributes.get('last_analysis_stats', {})
                malicious = last_analysis.get('malicious', 0)
                total = sum(last_analysis.values())
                
                # Get threat names
                threat_names = list(set(
                    result.get('result', '')
                    for result in attributes.get('last_analysis_results', {}).values()
                    if result.get('result')
                ))
                threat_names = [t for t in threat_names if t][:10]
                
                result = HashLookupResult(
                    hash_value=hash_value,
                    hash_type=hash_type,
                    is_malicious=malicious > 0,
                    detection_ratio=f"{malicious}/{total}",
                    threat_names=threat_names,
                    first_seen=attributes.get('first_submission_date'),
                    last_seen=attributes.get('last_analysis_date'),
                    source='virustotal',
                    confidence='high' if malicious > 5 else ('medium' if malicious > 0 else 'high')
                )
                
                self.cache.set_hash(result)
                return result
            
            elif response.status_code == 404:
                # Hash not found in VT database
                result = HashLookupResult(
                    hash_value=hash_value,
                    hash_type=hash_type,
                    is_malicious=False,
                    source='virustotal',
                    confidence='medium'
                )
                self.cache.set_hash(result)
                return result
            
            else:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"VirusTotal lookup error: {e}")
        
        return HashLookupResult(
            hash_value=hash_value,
            hash_type=hash_type,
            is_malicious=False,
            confidence='low',
            source='error'
        )
    
    def check_ip_reputation(
        self,
        ip_address: str,
        use_online: bool = True
    ) -> IPReputationResult:
        """
        Check IP address reputation.
        
        Args:
            ip_address: IP address to check
            use_online: Whether to query online APIs
        
        Returns:
            IPReputationResult with reputation data
        """
        ip_address = ip_address.strip()
        
        # Check cache
        cached = self.cache.get_ip(ip_address)
        if cached:
            logger.debug(f"IP cache hit: {ip_address}")
            return cached
        
        # Check local known malicious IPs
        if ip_address in self.KNOWN_MALICIOUS_IPS:
            result = IPReputationResult(
                ip_address=ip_address,
                is_malicious=True,
                threat_types=[self.KNOWN_MALICIOUS_IPS[ip_address]],
                source='local',
                confidence='high'
            )
            self.cache.set_ip(result)
            return result
        
        # Query online API
        if use_online and self.config.config.api.abuseipdb_api_key:
            return self._query_abuseipdb(ip_address)
        
        return IPReputationResult(
            ip_address=ip_address,
            is_malicious=False,
            confidence='low',
            source='local'
        )
    
    def _query_abuseipdb(self, ip_address: str) -> IPReputationResult:
        """Query AbuseIPDB for IP reputation."""
        api_key = self.config.config.api.abuseipdb_api_key
        
        if not api_key:
            return IPReputationResult(
                ip_address=ip_address,
                is_malicious=False,
                confidence='low',
                source='no_api_key'
            )
        
        try:
            self._rate_limit('abuseipdb')
            
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {'Key': api_key}
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90,
                'verbose': True
            }
            
            response = self._session.get(
                url,
                headers=headers,
                params=params,
                timeout=30
            )
            
            if response.status_code == 200:
                data = response.json().get('data', {})
                
                abuse_score = data.get('abuseConfidenceScore', 0)
                is_malicious = abuse_score >= 50
                
                result = IPReputationResult(
                    ip_address=ip_address,
                    is_malicious=is_malicious,
                    abuse_score=abuse_score,
                    threat_types=data.get('usageTypes', []),
                    country=data.get('countryCode', ''),
                    domain=data.get('domain', ''),
                    reports_count=data.get('totalReports', 0),
                    last_reported=data.get('lastReportedAt'),
                    source='abuseipdb',
                    confidence='high' if abuse_score >= 75 else ('medium' if abuse_score >= 25 else 'high')
                )
                
                self.cache.set_ip(result)
                return result
            
            else:
                logger.warning(f"AbuseIPDB API error: {response.status_code}")
                
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error: {e}")
        
        return IPReputationResult(
            ip_address=ip_address,
            is_malicious=False,
            confidence='low',
            source='error'
        )
    
    def check_domain_reputation(
        self,
        domain: str,
        use_online: bool = True
    ) -> DomainReputationResult:
        """
        Check domain reputation.
        
        Args:
            domain: Domain to check
            use_online: Whether to query online APIs
        
        Returns:
            DomainReputationResult with reputation data
        """
        domain = domain.lower().strip()
        
        # Check cache
        cached = self.cache.get_domain(domain)
        if cached:
            return cached
        
        # Check local known malicious domains
        if domain in self.KNOWN_MALICIOUS_DOMAINS:
            result = DomainReputationResult(
                domain=domain,
                is_malicious=True,
                threat_types=[self.KNOWN_MALICIOUS_DOMAINS[domain]],
                source='local',
                confidence='high'
            )
            self.cache.set_domain(result)
            return result
        
        # TODO: Implement online domain reputation check
        # (VirusTotal domains API, Cisco Umbrella, etc.)
        
        return DomainReputationResult(
            domain=domain,
            is_malicious=False,
            confidence='low',
            source='local'
        )
    
    def reverse_dns(self, ip_address: str) -> Optional[str]:
        """
        Perform reverse DNS lookup for an IP.
        
        Args:
            ip_address: IP to resolve
        
        Returns:
            Domain name if found, None otherwise
        """
        try:
            import socket
            hostname, _, _ = socket.gethostbyaddr(ip_address)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def calculate_file_hash(
        self,
        filepath: Path,
        algorithm: str = 'sha256'
    ) -> Optional[str]:
        """
        Calculate hash of a file.
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
        
        Returns:
            Hash string or None if error
        """
        try:
            if algorithm == 'md5':
                hasher = hashlib.md5()
            elif algorithm == 'sha1':
                hasher = hashlib.sha1()
            else:
                hasher = hashlib.sha256()
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(8192), b''):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Failed to hash {filepath}: {e}")
            return None
    
    def batch_hash_lookup(
        self,
        hashes: List[str],
        use_online: bool = True
    ) -> Dict[str, HashLookupResult]:
        """
        Look up multiple hashes.
        
        Args:
            hashes: List of hash values
            use_online: Whether to query online APIs
        
        Returns:
            Dictionary mapping hash to result
        """
        results = {}
        
        for hash_value in hashes:
            results[hash_value] = self.lookup_hash(hash_value, use_online)
        
        return results


# Global instance
_threat_intel_instance: Optional[ThreatIntelManager] = None


def get_threat_intel() -> ThreatIntelManager:
    """Get the global threat intelligence manager instance."""
    global _threat_intel_instance
    if _threat_intel_instance is None:
        _threat_intel_instance = ThreatIntelManager()
    return _threat_intel_instance
