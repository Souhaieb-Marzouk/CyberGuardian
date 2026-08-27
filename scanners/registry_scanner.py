"""
CyberGuardian Registry Scanner Module
=====================================
Scans Windows registry for persistence mechanisms
and suspicious entries.
"""

import os
import sys
import logging
import re
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import threading

from scanners.base_scanner import (
    BaseScanner, ScanResult, ScanStatus, Detection, RiskLevel
)
from scanners.yara_manager import get_yara_manager
from utils.whitelist import get_whitelist
from utils.config import get_config
from utils.logging_utils import get_logger, log_scan_start, log_scan_complete, log_detection

logger = get_logger('scanners.registry_scanner')


@dataclass
class RegistryEntry:
    """Represents a registry entry."""
    key_path: str
    value_name: str
    value_type: str
    value_data: str
    hive: str = ""
    is_suspicious: bool = False


class RegistryScanner(BaseScanner):
    """
    Scanner for analyzing Windows registry.
    
    Detection Methods:
    - Autorun location scanning
    - Persistence mechanism detection
    - Suspicious command detection
    - Yara rule matching on values
    - Entropy analysis of data
    """
    
    # Common autorun and persistence locations
    AUTORUN_LOCATIONS = [
        # Standard Run keys
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM", "User programs run at logon"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM", "Programs run once at logon"),
        (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM", "32-bit programs at logon"),
        (r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM", "32-bit programs run once"),
        
        # User-specific run keys
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU", "User-specific programs at logon"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU", "User programs run once"),
        
        # Services
        (r"SYSTEM\CurrentControlSet\Services", "HKLM", "Windows services"),
        
        # Winlogon
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM", "Logon configuration"),
        
        # Shell extensions
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved", "HKLM", "Shell extensions"),
        
        # Browser Helper Objects (BHO)
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "HKLM", "Browser extensions"),
        
        # Startup folder
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupFolder", "HKLM", "Startup folder items"),
        
        # Active Setup
        (r"SOFTWARE\Microsoft\Active Setup\Installed Components", "HKLM", "Active setup components"),
        
        # LSA authentication packages
        (r"SYSTEM\CurrentControlSet\Control\Lsa", "HKLM", "Authentication packages"),
        
        # Security packages
        (r"SYSTEM\CurrentControlSet\Control\SecurityProviders", "HKLM", "Security providers"),
        
        # Network providers
        (r"SYSTEM\CurrentControlSet\Control\NetworkProvider\Order", "HKLM", "Network provider order"),
        
        # Session manager
        (r"SYSTEM\CurrentControlSet\Control\Session Manager", "HKLM", "Session manager settings"),
        
        # AppInit DLLs
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "HKLM", "AppInit DLLs"),
        
        # Image File Execution Options (IFEO) - debugger injection
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "HKLM", "IFEO debuggers"),
        
        # Boot execute
        (r"SYSTEM\CurrentControlSet\Control\Session Manager", "HKLM", "Boot execute"),
        
        # Userinit
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "HKLM", "Userinit path"),
        
        # Task scheduling
        (r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "HKLM", "Scheduled tasks"),
    ]
    
    # Suspicious patterns in registry values
    SUSPICIOUS_PATTERNS = [
        # PowerShell execution
        (r'powershell\.exe.*-enc', 'Encoded PowerShell command', 'high'),
        (r'powershell\.exe.*-w\s*hidden', 'Hidden PowerShell window', 'high'),
        (r'powershell\.exe.*downloadstring', 'PowerShell download', 'critical'),
        (r'powershell\.exe.*iex', 'PowerShell Invoke-Expression', 'high'),
        (r'powershell\.exe.*frombase64string', 'Base64 decode in PowerShell', 'high'),
        
        # Script execution
        (r'wscript\.exe', 'Windows Script Host execution', 'medium'),
        (r'cscript\.exe', 'Console script execution', 'medium'),
        (r'mshta\.exe', 'MSHTA execution', 'high'),
        
        # Download tools
        (r'certutil.*-urlcache', 'Certutil download', 'high'),
        (r'certutil.*-decode', 'Certutil decode', 'high'),
        (r'bitsadmin.*/transfer', 'BITS transfer', 'medium'),
        (r'curl\.exe.*-o', 'Curl download', 'medium'),
        (r'wget', 'Wget download', 'medium'),
        
        # Execution from suspicious locations
        (r'\\AppData\\Local\\Temp\\', 'Execution from Temp folder', 'high'),
        (r'\\AppData\\Roaming\\', 'Execution from Roaming folder', 'high'),
        (r'\\Users\\Public\\', 'Execution from Public folder', 'high'),
        (r'%TEMP%', 'Execution from TEMP', 'high'),
        (r'%APPDATA%', 'Execution from APPDATA', 'medium'),
        
        # LOLBAS (Living Off The Land Binaries)
        (r'regsvr32\.exe.*/i:.*http', 'Regsvr32 remote execution', 'critical'),
        (r'rundll32\.exe.*javascript', 'Rundll32 JavaScript execution', 'critical'),
        (r'wmic.*process.*create', 'WMIC process creation', 'high'),
        (r'forfiles.*/p.*/m.*/c', 'Forfiles execution', 'medium'),
        
        # Encoding/obfuscation
        (r'[A-Za-z0-9+/=]{50,}', 'Possible base64 encoded data', 'medium'),
        
        # Network connections
        (r'https?://\d+\.\d+\.\d+\.\d+', 'Direct IP URL', 'medium'),
        (r'\.onion', 'Tor hidden service', 'high'),
        
        # Malware-related strings
        (r'mimikatz', 'Mimikatz reference', 'critical'),
        (r'meterpreter', 'Meterpreter reference', 'critical'),
        (r'cobalt\s*strike', 'Cobalt Strike reference', 'critical'),
        (r'reverse.?shell', 'Reverse shell reference', 'critical'),
    ]
    
    # Trusted registry entries (Microsoft)
    TRUSTED_ENTRIES = {
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'SecurityHealth'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'AdobeAAMUpdater'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'AdobeGCInvoker'),
        ('HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run', 'SunJavaUpdateSched'),
    }
    
    # Entropy threshold for encoded data
    HIGH_ENTROPY_THRESHOLD = 4.5
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.whitelist = get_whitelist()
        self.yara_manager = get_yara_manager()
    
    @property
    def scanner_name(self) -> str:
        return "Registry Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "registry"
    
    def scan(self, target: Optional[str] = None) -> ScanResult:
        """
        Scan Windows registry.
        
        Args:
            target: Optional specific registry key to scan
        
        Returns:
            ScanResult with registry analysis findings
        """
        if sys.platform != 'win32':
            return ScanResult(
                scan_type='registry',
                status=ScanStatus.FAILED,
                start_time=datetime.utcnow(),
                error_message="Registry scanning is only available on Windows"
            )
        
        log_scan_start('registry', target or 'all autorun locations')
        
        result = ScanResult(
            scan_type='registry',
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target=target or 'all'
        )
        
        self.reset_cancel()
        
        try:
            # Scan all autorun locations
            entries = self._scan_autorun_locations(target)
            result.total_items = len(entries)
            
            self.logger.info(f"Scanning {len(entries)} registry entries")
            
            # Analyze each entry
            for i, entry in enumerate(entries):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                
                self._report_progress(i + 1, len(entries), f"Analyzing {entry.key_path}")
                
                detections = self._analyze_entry(entry)
                
                for detection in detections:
                    result.add_detection(detection)
                    self._report_detection(detection)
                    log_detection(
                        detection_type=detection.detection_type,
                        indicator=detection.indicator,
                        risk_level=detection.risk_level.value,
                        description=detection.description
                    )
            
            result.status = ScanStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Registry scan error: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
        
        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        log_scan_complete('registry', result.scan_target, len(result.detections))
        
        return result
    
    def _scan_autorun_locations(self, target_key: Optional[str] = None) -> List[RegistryEntry]:
        """Scan all autorun locations."""
        entries = []
        
        try:
            import winreg
            
            for key_path, hive_name, description in self.AUTORUN_LOCATIONS:
                if self.is_cancelled():
                    break
                
                if target_key and target_key.lower() not in key_path.lower():
                    continue
                
                hive = self._get_hive(hive_name)
                if hive is None:
                    continue
                
                try:
                    key_entries = self._enumerate_key(hive, key_path, hive_name)
                    entries.extend(key_entries)
                except Exception as e:
                    self.logger.debug(f"Error scanning {key_path}: {e}")
        
        except ImportError:
            self.logger.error("winreg module not available")
        
        return entries
    
    def _get_hive(self, hive_name: str):
        """Get registry hive constant."""
        try:
            import winreg
            hives = {
                'HKLM': winreg.HKEY_LOCAL_MACHINE,
                'HKCU': winreg.HKEY_CURRENT_USER,
                'HKCR': winreg.HKEY_CLASSES_ROOT,
                'HKU': winreg.HKEY_USERS,
                'HKCC': winreg.HKEY_CURRENT_CONFIG,
            }
            return hives.get(hive_name)
        except ImportError:
            return None
    
    def _enumerate_key(
        self,
        hive,
        key_path: str,
        hive_name: str
    ) -> List[RegistryEntry]:
        """Enumerate registry key and all its values."""
        entries = []
        
        try:
            import winreg
            
            key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
            
            # Enumerate values
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    # Convert value type to string
                    type_names = {
                        winreg.REG_SZ: 'REG_SZ',
                        winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
                        winreg.REG_BINARY: 'REG_BINARY',
                        winreg.REG_DWORD: 'REG_DWORD',
                        winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
                        winreg.REG_QWORD: 'REG_QWORD',
                    }
                    type_str = type_names.get(value_type, f'TYPE_{value_type}')
                    
                    # Convert data to string for analysis
                    if isinstance(value_data, bytes):
                        try:
                            value_data_str = value_data.decode('utf-8', errors='replace')
                        except:
                            value_data_str = value_data.hex()
                    elif isinstance(value_data, tuple):
                        value_data_str = '; '.join(str(v) for v in value_data)
                    else:
                        value_data_str = str(value_data)
                    
                    entry = RegistryEntry(
                        key_path=f"{hive_name}\\{key_path}",
                        value_name=value_name,
                        value_type=type_str,
                        value_data=value_data_str,
                        hive=hive_name
                    )
                    entries.append(entry)
                    
                    i += 1
                except OSError:
                    break
            
            # Recursively enumerate subkeys if it's a services key
            if 'Services' in key_path or 'Image File Execution' in key_path:
                i = 0
                while True:
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        subkey_path = f"{key_path}\\{subkey_name}"
                        subkey_entries = self._enumerate_key(hive, subkey_path, hive_name)
                        entries.extend(subkey_entries)
                        i += 1
                    except OSError:
                        break
            
            winreg.CloseKey(key)
        
        except FileNotFoundError:
            pass
        except PermissionError:
            self.logger.debug(f"Permission denied for key: {key_path}")
        except Exception as e:
            self.logger.debug(f"Error enumerating {key_path}: {e}")
        
        return entries
    
    def _analyze_entry(self, entry: RegistryEntry) -> List[Detection]:
        """Analyze a registry entry for suspicious indicators."""
        detections = []
        
        # Skip empty entries
        if not entry.value_data or entry.value_data == '(Default)':
            return detections
        
        # Check whitelist
        if self._is_trusted_entry(entry):
            return detections
        
        # Run detection checks
        detection_methods = [
            self._check_suspicious_patterns,
            self._check_suspicious_paths,
            self._check_yara_rules,
            self._check_entropy,
            self._check_service_hijacking,
        ]
        
        for method in detection_methods:
            try:
                method_detections = method(entry)
                detections.extend(method_detections)
            except Exception as e:
                self.logger.debug(f"Detection method error: {e}")
        
        # If detections found, collect full key evidence for AI analysis
        if detections:
            full_key_evidence = self._collect_key_evidence(entry)
            param_count = full_key_evidence.get('parameter_count', 0)
            self.logger.info(f"Registry detection in {entry.key_path}: collected {param_count} parameters as evidence for AI analysis")
            for detection in detections:
                if detection.evidence:
                    detection.evidence['full_key_parameters'] = full_key_evidence
        
        return detections
    
    def _collect_key_evidence(self, entry: RegistryEntry) -> Dict[str, Any]:
        """
        Collect all parameters and values from a registry key as evidence.
        
        This provides complete context for AI analysis when a suspicious
        value is found in a registry key.
        
        Args:
            entry: The suspicious registry entry
        
        Returns:
            Dictionary with all key parameters and their values
        """
        evidence = {
            'key_path': entry.key_path,
            'suspicious_value_name': entry.value_name,
            'suspicious_value_data': entry.value_data[:500],
            'all_parameters': [],
            'parameter_count': 0
        }
        
        try:
            import winreg
            
            # Parse the key path to get hive and subkey
            parts = entry.key_path.split('\\', 1)
            if len(parts) < 2:
                return evidence
            
            hive_name = parts[0]
            subkey_path = parts[1]
            
            hive = self._get_hive(hive_name)
            if hive is None:
                return evidence
            
            # Open the key and enumerate all values
            key = winreg.OpenKey(hive, subkey_path, 0, winreg.KEY_READ)
            
            # Type names for display
            type_names = {
                winreg.REG_SZ: 'REG_SZ',
                winreg.REG_EXPAND_SZ: 'REG_EXPAND_SZ',
                winreg.REG_BINARY: 'REG_BINARY',
                winreg.REG_DWORD: 'REG_DWORD',
                winreg.REG_MULTI_SZ: 'REG_MULTI_SZ',
                winreg.REG_QWORD: 'REG_QWORD',
            }
            
            i = 0
            while True:
                try:
                    value_name, value_data, value_type = winreg.EnumValue(key, i)
                    
                    # Convert data to string
                    if isinstance(value_data, bytes):
                        try:
                            value_data_str = value_data.decode('utf-8', errors='replace')
                        except:
                            value_data_str = value_data.hex()
                    elif isinstance(value_data, tuple):
                        value_data_str = '; '.join(str(v) for v in value_data)
                    elif isinstance(value_data, int):
                        value_data_str = str(value_data)
                    else:
                        value_data_str = str(value_data)
                    
                    type_str = type_names.get(value_type, f'TYPE_{value_type}')
                    
                    param_info = {
                        'name': value_name or '(Default)',
                        'type': type_str,
                        'value': value_data_str[:1000]  # Limit length
                    }
                    
                    # Mark if this is the suspicious one
                    if value_name == entry.value_name:
                        param_info['is_suspicious'] = True
                    
                    evidence['all_parameters'].append(param_info)
                    i += 1
                    
                except OSError:
                    break
            
            winreg.CloseKey(key)
            
            evidence['parameter_count'] = len(evidence['all_parameters'])
            
        except FileNotFoundError:
            evidence['error'] = 'Key not found'
        except PermissionError:
            evidence['error'] = 'Permission denied'
        except Exception as e:
            evidence['error'] = str(e)
        
        return evidence
    
    def _is_trusted_entry(self, entry: RegistryEntry) -> bool:
        """Check if entry is in trusted list or user whitelist."""
        key = (entry.key_path, entry.value_name)
        if key in self.TRUSTED_ENTRIES:
            return True
        
        # Check user whitelist for this registry key path (using 'registry_key' type)
        if self.whitelist.is_whitelisted(entry.key_path, 'registry_key'):
            self.logger.debug(f"Registry key in user whitelist: {entry.key_path}")
            return True
        
        # Check user whitelist for full key with value name
        full_key = f"{entry.key_path}\\{entry.value_name}"
        if self.whitelist.is_whitelisted(full_key, 'registry_key'):
            self.logger.debug(f"Full registry entry in user whitelist: {full_key}")
            return True
        
        # Check user whitelist for the value data (could be file path or other indicator)
        if entry.value_data:
            # Check as path
            if self.whitelist.is_whitelisted(entry.value_data, 'path'):
                self.logger.debug(f"Registry value data in user whitelist: {entry.value_data[:50]}")
                return True
            # Check as name (process name, etc.)
            if self.whitelist.is_whitelisted(entry.value_data, 'name'):
                self.logger.debug(f"Registry value in name whitelist: {entry.value_data[:50]}")
                return True
        
        return False
    
    def _check_suspicious_patterns(self, entry: RegistryEntry) -> List[Detection]:
        """Check for suspicious patterns in registry data."""
        detections = []
        
        for pattern, description, severity in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, entry.value_data, re.IGNORECASE):
                risk_level = RiskLevel.CRITICAL if severity == 'critical' else (
                    RiskLevel.HIGH if severity == 'high' else RiskLevel.MEDIUM
                )
                
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='registry_suspicious_pattern',
                    indicator=entry.key_path,
                    indicator_type='registry_key',
                    risk_level=risk_level,
                    confidence=0.8 if severity == 'critical' else 0.7,
                    description=f"{description} in registry",
                    detection_reason=f"Pattern matched: {description}",
                    remediation=[
                        f"Review registry key: {entry.key_path}",
                        f"Check value: {entry.value_name} = {entry.value_data[:100]}",
                        "Remove if unauthorized",
                        "Verify with system administrator"
                    ],
                    evidence={
                        'key_path': entry.key_path,
                        'value_name': entry.value_name,
                        'value_data': entry.value_data[:500],
                        'matched_pattern': pattern,
                        'description': description
                    }
                )
                detections.append(detection)
                break  # One match per entry
        
        return detections
    
    def _check_suspicious_paths(self, entry: RegistryEntry) -> List[Detection]:
        """Check for execution from suspicious paths."""
        detections = []
        
        suspicious_paths = [
            (r'\\Temp\\', 'Temporary folder execution'),
            (r'\\AppData\\', 'AppData folder execution'),
            (r'\\Public\\', 'Public folder execution'),
            (r'\\Downloads\\', 'Downloads folder execution'),
            (r'\\ProgramData\\', 'ProgramData folder execution'),
            (r'^[A-Z]:\\Users\\[^\\]+\\', 'User directory execution'),
        ]
        
        data_lower = entry.value_data.lower()
        
        for pattern, description in suspicious_paths:
            if re.search(pattern, data_lower, re.IGNORECASE):
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='registry_suspicious_path',
                    indicator=entry.key_path,
                    indicator_type='registry_key',
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.6,
                    description=f"{description} in registry autorun",
                    detection_reason=f"Execution from: {description}",
                    remediation=[
                        f"Review registry key: {entry.key_path}",
                        "Verify executable path is legitimate",
                        "Remove if unauthorized"
                    ],
                    evidence={
                        'key_path': entry.key_path,
                        'value_name': entry.value_name,
                        'value_data': entry.value_data[:500],
                        'suspicious_path': description
                    }
                )
                detections.append(detection)
                break
        
        return detections
    
    def _check_yara_rules(self, entry: RegistryEntry) -> List[Detection]:
        """Check registry data against Yara rules."""
        detections = []
        
        # Scan data with Yara
        yara_matches = self.yara_manager.scan_data(entry.value_data.encode('utf-8'))
        
        if yara_matches:
            high_matches = [m for m in yara_matches if m.severity in ['critical', 'high']]
            
            if high_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='registry_yara',
                    indicator=entry.key_path,
                    indicator_type='registry_key',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    description=f"Yara match in registry: {', '.join(m.rule for m in high_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in high_matches)}",
                    remediation=[
                        f"Remove registry value: {entry.key_path}\\{entry.value_name}",
                        "Investigate associated malware",
                        "Run full system scan"
                    ],
                    evidence={
                        'key_path': entry.key_path,
                        'value_name': entry.value_name,
                        'value_data': entry.value_data[:500],
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in high_matches]
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_entropy(self, entry: RegistryEntry) -> List[Detection]:
        """Check for high entropy (encoded data)."""
        detections = []
        
        if len(entry.value_data) < 50:
            return detections
        
        # Calculate entropy
        entropy = self._calculate_entropy(entry.value_data)
        
        if entropy > self.HIGH_ENTROPY_THRESHOLD:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='registry_high_entropy',
                indicator=entry.key_path,
                indicator_type='registry_key',
                risk_level=RiskLevel.LOW,
                confidence=0.4,
                description=f"High entropy data in registry ({entropy:.2f})",
                detection_reason="Possible encoded or encrypted payload",
                remediation=[
                    f"Investigate registry value: {entry.key_path}\\{entry.value_name}",
                    "Decode data if possible",
                    "Verify legitimacy"
                ],
                evidence={
                    'key_path': entry.key_path,
                    'value_name': entry.value_name,
                    'entropy': entropy
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_service_hijacking(self, entry: RegistryEntry) -> List[Detection]:
        """Check for service hijacking indicators."""
        detections = []
        
        # Check for IFEO debugger
        if 'Image File Execution Options' in entry.key_path:
            if entry.value_name.lower() == 'debugger':
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='registry_ifeo_debugger',
                    indicator=entry.key_path,
                    indicator_type='registry_key',
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.95,
                    description="IFEO Debugger injection detected",
                    detection_reason="Debugger value in Image File Execution Options",
                    remediation=[
                        f"Remove debugger value: {entry.key_path}",
                        f"Value: {entry.value_data}",
                        "This is a persistence mechanism",
                        "Check for associated malware"
                    ],
                    evidence={
                        'key_path': entry.key_path,
                        'value_name': entry.value_name,
                        'value_data': entry.value_data
                    }
                )
                detections.append(detection)
        
        # Check for suspicious service ImagePath
        if 'Services' in entry.key_path and entry.value_name.lower() == 'imagepath':
            if any(p in entry.value_data.lower() for p in ['temp', 'appdata', 'public', 'users\\']):
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='registry_service_path',
                    indicator=entry.key_path,
                    indicator_type='registry_key',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.8,
                    description="Service with suspicious ImagePath",
                    detection_reason="Service executable in user-writable location",
                    remediation=[
                        f"Investigate service: {entry.key_path}",
                        f"ImagePath: {entry.value_data}",
                        "Check if legitimate service",
                        "Remove if malicious"
                    ],
                    evidence={
                        'key_path': entry.key_path,
                        'value_name': entry.value_name,
                        'value_data': entry.value_data
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of string."""
        import math
        
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        length = len(data)
        
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return entropy
