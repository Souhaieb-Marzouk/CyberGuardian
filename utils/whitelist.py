"""
CyberGuardian Whitelist Management Module
=========================================
Manages whitelists for processes, files, registry entries,
and network connections to minimize false positives.
"""

import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime
import re

from .config import DATA_DIR, get_config

logger = logging.getLogger('cyberguardian.utils.whitelist')


@dataclass
class WhitelistEntry:
    """Represents a single whitelist entry."""
    identifier: str  # Hash, path, name, or IP
    entry_type: str  # 'hash', 'path', 'name', 'ip', 'domain', 'signature'
    source: str  # 'system', 'microsoft', 'user', 'third_party'
    description: str = ""
    added_date: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    expiry_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class WhitelistManager:
    """
    Central whitelist management for all scan types.
    Handles loading, saving, and querying whitelists.
    """
    
    WHITELIST_FILE = DATA_DIR / "whitelist.json"
    
    # Trusted publishers for signature verification
    TRUSTED_PUBLISHERS = {
        'Microsoft Corporation',
        'Microsoft Windows',
        'Microsoft Corp.',
        'Google LLC',
        'Google Inc',
        'Adobe Inc.',
        'Adobe Systems Incorporated',
        'Mozilla Corporation',
        'Apple Inc.',
        'Intel Corporation',
        'NVIDIA Corporation',
        'AVAST Software s.r.o.',
        'Malwarebytes Corporation',
        'Cisco Systems, Inc.',
        'Oracle Corporation',
        'VMware, Inc.',
        'Dropbox, Inc.',
        'Slack Technologies, Inc.',
        'Zoom Video Communications, Inc.',
        'Valve Corp.',
        'Steam',
    }
    
    # System processes that should never be flagged
    SYSTEM_PROCESSES = {
        'System',
        'System Idle Process',
        'smss.exe',
        'csrss.exe',
        'wininit.exe',
        'services.exe',
        'lsass.exe',
        'svchost.exe',
        'winlogon.exe',
        'explorer.exe',
        'dwm.exe',
        'ntoskrnl.exe',
        'runtimebroker.exe',
        'taskhostw.exe',
        'sihost.exe',
        'ctfmon.exe',
        'conhost.exe',
        'dllhost.exe',
        'fontdrvhost.exe',
        'spoolsv.exe',
        'searchindexer.exe',
        'wlanext.exe',
        'wudfhost.exe',
        'securityhealthservice.exe',
        'securityhealthsystray.exe',
        'antimalware_service_executable.exe',  # Windows Defender
        'msmpeng.exe',  # Windows Defender
        'nissrv.exe',  # Windows Defender Network Inspection
    }
    
    # Trusted file paths (Windows system directories)
    TRUSTED_PATHS = [
        r'^C:\\Windows\\System32\\',
        r'^C:\\Windows\\SysWOW64\\',
        r'^C:\\Windows\\WinSxS\\',
        r'^C:\\Windows\\SystemApps\\',
        r'^C:\\Windows\\ServiceProfiles\\',
        r'^C:\\Program Files\\Windows Defender\\',
        r'^C:\\Program Files\\Windows Security\\',
    ]
    
    # Trusted registry key patterns
    TRUSTED_REGISTRY_KEYS = [
        r'^HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run$',  # Standard autorun
        r'^HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run$',
        r'^HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run$',
        r'^HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\',  # Services
    ]
    
    # Trusted Microsoft IPs and domains
    TRUSTED_NETWORK_INDICATORS = {
        # Microsoft domains
        'microsoft.com',
        'windowsupdate.com',
        'msn.com',
        'live.com',
        'outlook.com',
        'office.com',
        'office365.com',
        'azure.com',
        'xbox.com',
        'skype.com',
        'bing.com',
        # Microsoft IP ranges (subset)
        '13.64.0.0/11',
        '13.96.0.0/13',
        '13.104.0.0/14',
        '20.0.0.0/8',
        '23.96.0.0/13',
        '40.0.0.0/8',
        '52.0.0.0/8',
        # Google
        'google.com',
        'googleapis.com',
        'gstatic.com',
        'ggpht.com',
        'youtube.com',
        'ytimg.com',
        # Apple
        'apple.com',
        'icloud.com',
        'mzstatic.com',
        # Common CDNs and services
        'cloudflare.com',
        'cloudfront.net',
        'akamaiedge.net',
        'akamai.net',
        'cdn77.org',
    }
    
    def __init__(self):
        self.entries: Dict[str, List[WhitelistEntry]] = {
            'hash': [],
            'path': [],
            'name': [],
            'ip': [],
            'domain': [],
            'signature': [],
            'registry_key': [],  # For registry key whitelisting
        }
        self._compile_regex_patterns()
        self._load_whitelist()
        self._initialize_system_whitelist()
    
    def _compile_regex_patterns(self) -> None:
        """Compile regex patterns for trusted paths."""
        self.trusted_path_patterns = [
            re.compile(pattern, re.IGNORECASE) 
            for pattern in self.TRUSTED_PATHS
        ]
        self.trusted_registry_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.TRUSTED_REGISTRY_KEYS
        ]
    
    def _load_whitelist(self) -> None:
        """Load whitelist from file."""
        if self.WHITELIST_FILE.exists():
            try:
                with open(self.WHITELIST_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for entry_type, entries in data.get('entries', {}).items():
                    for entry_data in entries:
                        entry = WhitelistEntry(**entry_data)
                        self.entries[entry_type].append(entry)
                
                logger.info(f"Loaded {sum(len(e) for e in self.entries.values())} whitelist entries")
            except Exception as e:
                logger.error(f"Failed to load whitelist: {e}")
    
    def _save_whitelist(self) -> None:
        """Save whitelist to file."""
        try:
            data = {
                'version': '1.0',
                'last_updated': datetime.utcnow().isoformat(),
                'entries': {
                    entry_type: [
                        {
                            'identifier': e.identifier,
                            'entry_type': e.entry_type,
                            'source': e.source,
                            'description': e.description,
                            'added_date': e.added_date,
                            'expiry_date': e.expiry_date,
                            'metadata': e.metadata,
                        }
                        for e in entries
                    ]
                    for entry_type, entries in self.entries.items()
                }
            }
            
            with open(self.WHITELIST_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save whitelist: {e}")
    
    def _initialize_system_whitelist(self) -> None:
        """Initialize system-level whitelist entries."""
        # Add system processes
        for proc_name in self.SYSTEM_PROCESSES:
            self.add_entry(
                identifier=proc_name.lower(),
                entry_type='name',
                source='system',
                description=f'Windows system process: {proc_name}'
            )
        
        # Add trusted publishers
        for publisher in self.TRUSTED_PUBLISHERS:
            self.add_entry(
                identifier=publisher.lower(),
                entry_type='signature',
                source='microsoft' if 'microsoft' in publisher.lower() else 'third_party',
                description=f'Trusted publisher: {publisher}'
            )
        
        # Add trusted network indicators
        for indicator in self.TRUSTED_NETWORK_INDICATORS:
            if '/' in indicator:  # IP range
                self.add_entry(
                    identifier=indicator,
                    entry_type='ip',
                    source='system',
                    description=f'Trusted IP range: {indicator}'
                )
            else:  # Domain
                self.add_entry(
                    identifier=indicator,
                    entry_type='domain',
                    source='system',
                    description=f'Trusted domain: {indicator}'
                )
    
    def add_entry(
        self,
        identifier: str,
        entry_type: str,
        source: str,
        description: str = "",
        expiry_date: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> bool:
        """
        Add an entry to the whitelist.
        
        Args:
            identifier: The value to whitelist
            entry_type: Type of entry ('hash', 'path', 'name', 'ip', 'domain', 'signature')
            source: Source of the whitelist entry
            description: Human-readable description
            expiry_date: Optional expiry date for temporary whitelists
            metadata: Additional metadata
        
        Returns:
            True if entry was added, False if already exists
        """
        if entry_type not in self.entries:
            logger.warning(f"Invalid whitelist entry type: {entry_type}")
            return False
        
        # Normalize identifier
        identifier = identifier.lower().strip()
        
        # Check for duplicates
        for existing in self.entries[entry_type]:
            if existing.identifier == identifier:
                return False
        
        # Create and add entry
        entry = WhitelistEntry(
            identifier=identifier,
            entry_type=entry_type,
            source=source,
            description=description,
            expiry_date=expiry_date,
            metadata=metadata or {}
        )
        
        self.entries[entry_type].append(entry)
        self._save_whitelist()
        
        logger.debug(f"Added whitelist entry: {entry_type}={identifier}")
        return True
    
    def remove_entry(self, identifier: str, entry_type: str) -> bool:
        """Remove an entry from the whitelist."""
        identifier = identifier.lower().strip()
        
        for i, entry in enumerate(self.entries.get(entry_type, [])):
            if entry.identifier == identifier:
                self.entries[entry_type].pop(i)
                self._save_whitelist()
                return True
        
        return False
    
    def is_whitelisted(
        self,
        identifier: str,
        entry_type: str,
        check_context: Optional[Dict] = None
    ) -> bool:
        """
        Check if an identifier is whitelisted.
        
        Args:
            identifier: The value to check
            entry_type: Type of entry
            check_context: Additional context (e.g., parent process, path)
        
        Returns:
            True if whitelisted, False otherwise
        """
        identifier = identifier.lower().strip()
        
        # Check direct match
        for entry in self.entries.get(entry_type, []):
            if entry.identifier == identifier:
                # Check expiry
                if entry.expiry_date:
                    if datetime.utcnow() > datetime.fromisoformat(entry.expiry_date):
                        continue  # Entry expired
                return True
        
        # Special handling for paths
        if entry_type == 'path':
            return self._is_trusted_path(identifier)
        
        # Special handling for registry keys
        if entry_type == 'registry_key':
            return self._is_trusted_registry_key(identifier)
        
        # Special handling for domains
        if entry_type == 'domain':
            return self._is_trusted_domain(identifier)
        
        # Special handling for IPs
        if entry_type == 'ip':
            return self._is_trusted_ip(identifier)
        
        return False
    
    def _is_trusted_path(self, path: str) -> bool:
        """Check if path matches trusted path patterns."""
        for pattern in self.trusted_path_patterns:
            if pattern.match(path):
                return True
        return False
    
    def _is_trusted_registry_key(self, key_path: str) -> bool:
        """Check if registry key matches trusted patterns."""
        key_path = key_path.lower().strip()
        for pattern in self.trusted_registry_patterns:
            if pattern.match(key_path):
                return True
        return False
    
    def _is_trusted_domain(self, domain: str) -> bool:
        """Check if domain or parent domain is trusted."""
        domain = domain.lower().strip()
        
        # Check direct match
        for entry in self.entries.get('domain', []):
            if domain == entry.identifier or domain.endswith('.' + entry.identifier):
                return True
        
        return False
    
    def _is_trusted_ip(self, ip: str) -> bool:
        """Check if IP is in trusted IP ranges."""
        # Simple check - for production, implement proper CIDR matching
        ip = ip.lower().strip()
        
        for entry in self.entries.get('ip', []):
            if '/' in entry.identifier:
                # CIDR range - simplified check
                # In production, use ipaddress module for proper matching
                prefix = entry.identifier.split('/')[0]
                if ip.startswith(prefix.rsplit('.', 1)[0]):
                    return True
            elif ip == entry.identifier:
                return True
        
        return False
    
    def is_system_process(self, process_name: str) -> bool:
        """Check if process is a known system process."""
        return process_name.lower() in [p.lower() for p in self.SYSTEM_PROCESSES]
    
    def is_trusted_signature(self, publisher: str) -> bool:
        """Check if publisher is in trusted list."""
        publisher = publisher.lower().strip()
        for trusted in self.TRUSTED_PUBLISHERS:
            if trusted.lower() in publisher or publisher in trusted.lower():
                return True
        return False
    
    def get_all_entries(self, entry_type: Optional[str] = None) -> List[WhitelistEntry]:
        """Get all whitelist entries, optionally filtered by type."""
        if entry_type:
            return self.entries.get(entry_type, [])
        
        all_entries = []
        for entries in self.entries.values():
            all_entries.extend(entries)
        return all_entries
    
    def export_whitelist(self, filepath: Path) -> bool:
        """Export whitelist to a JSON file."""
        try:
            self._save_whitelist()
            import shutil
            shutil.copy(self.WHITELIST_FILE, filepath)
            return True
        except Exception as e:
            logger.error(f"Failed to export whitelist: {e}")
            return False
    
    def import_whitelist(self, filepath: Path, merge: bool = True) -> bool:
        """
        Import whitelist from a JSON file.
        
        Args:
            filepath: Path to import file
            merge: If True, merge with existing; if False, replace
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not merge:
                self.entries = {k: [] for k in self.entries.keys()}
            
            for entry_type, entries in data.get('entries', {}).items():
                for entry_data in entries:
                    self.add_entry(
                        identifier=entry_data['identifier'],
                        entry_type=entry_type,
                        source=entry_data.get('source', 'user'),
                        description=entry_data.get('description', ''),
                        metadata=entry_data.get('metadata')
                    )
            
            return True
        except Exception as e:
            logger.error(f"Failed to import whitelist: {e}")
            return False


# Global whitelist instance
_whitelist_instance: Optional[WhitelistManager] = None


def get_whitelist() -> WhitelistManager:
    """Get the global whitelist manager instance."""
    global _whitelist_instance
    if _whitelist_instance is None:
        _whitelist_instance = WhitelistManager()
    return _whitelist_instance
