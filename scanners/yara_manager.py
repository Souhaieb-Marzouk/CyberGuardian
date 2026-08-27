"""
CyberGuardian Yara Rules Manager
=================================
Manages Yara rule compilation, loading, and updates.
Provides a unified interface for rule matching across all scanners.
"""

import os
import logging
import yara
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
import json
import hashlib
import re
import threading
from concurrent.futures import ThreadPoolExecutor

from utils.config import YARA_RULES_DIR, CACHE_DIR, get_config
from utils.logging_utils import get_logger

logger = get_logger('scanners.yara_manager')


@dataclass
class YaraMatch:
    """Represents a Yara rule match."""
    rule: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Tuple[int, bytes, str]]  # (offset, data, identifier)
    file_path: Optional[str] = None
    severity: str = "medium"
    description: str = ""


@dataclass
class YaraRuleSet:
    """Represents a compiled set of Yara rules."""
    name: str
    compiled_rules: yara.Rules
    source_path: Path
    rule_count: int
    last_compiled: datetime
    error: Optional[str] = None


class YaraManager:
    """
    Central manager for Yara rules.
    Handles loading, compilation, caching, and scanning.
    """
    
    RULES_CACHE_FILE = CACHE_DIR / "yara_cache.json"
    
    # Default rule categories
    CATEGORIES = [
        'malware',
        'exploit',
        'packer',
        'crypto',
        'anti_debug',
        'anti_vm',
        'webshell',
        'ransomware',
        'trojan',
        'backdoor',
        'keylogger',
        'stealer',
        'downloader',
        'dropper',
    ]
    
    def __init__(self, rules_dir: Optional[Path] = None):
        self.rules_dir = rules_dir or YARA_RULES_DIR
        self.compiled_rulesets: Dict[str, YaraRuleSet] = {}
        self._lock = threading.RLock()
        self._loaded = False
        
        # Ensure rules directory exists
        self.rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Rule file patterns
        self.rule_extensions = {'.yar', '.yara'}
    
    def load_rules(self, force_reload: bool = False) -> bool:
        """
        Load and compile all Yara rules from the rules directory.
        
        Args:
            force_reload: If True, reload even if already loaded
        
        Returns:
            True if successful, False otherwise
        """
        with self._lock:
            if self._loaded and not force_reload:
                return True
            
            logger.info(f"Loading Yara rules from {self.rules_dir}")
            
            # Clear existing rules
            self.compiled_rulesets.clear()
            
            # Find all rule files
            rule_files = self._find_rule_files()
            
            if not rule_files:
                logger.warning("No Yara rule files found")
                self._create_default_rules()
                rule_files = self._find_rule_files()
            
            # Compile rules by category
            total_rules = 0
            errors = []
            
            for rule_file in rule_files:
                try:
                    ruleset = self._compile_rule_file(rule_file)
                    if ruleset:
                        self.compiled_rulesets[ruleset.name] = ruleset
                        total_rules += ruleset.rule_count
                except Exception as e:
                    error_msg = f"Failed to compile {rule_file}: {e}"
                    logger.error(error_msg)
                    errors.append(error_msg)
            
            self._loaded = True
            
            logger.info(
                f"Loaded {total_rules} Yara rules from "
                f"{len(self.compiled_rulesets)} rulesets"
            )
            
            return len(errors) == 0
    
    def _find_rule_files(self) -> List[Path]:
        """Find all Yara rule files in the rules directory."""
        rule_files = []
        
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if Path(file).suffix.lower() in self.rule_extensions:
                    rule_files.append(Path(root) / file)
        
        return sorted(rule_files)
    
    def _compile_rule_file(self, filepath: Path) -> Optional[YaraRuleSet]:
        """
        Compile a single Yara rule file.
        
        Args:
            filepath: Path to the Yara rule file
        
        Returns:
            YaraRuleSet if successful, None otherwise
        """
        try:
            # Read and parse rule count
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Count rules
            rule_count = len(re.findall(r'^\s*rule\s+\w+\s*[{:]', content, re.MULTILINE))
            
            if rule_count == 0:
                logger.debug(f"No rules found in {filepath}")
                return None
            
            # Compile the rules
            compiled = yara.compile(source=content)
            
            # Determine category from path
            relative_path = filepath.relative_to(self.rules_dir)
            category = relative_path.parts[0] if len(relative_path.parts) > 1 else 'general'
            
            return YaraRuleSet(
                name=f"{category}_{filepath.stem}",
                compiled_rules=compiled,
                source_path=filepath,
                rule_count=rule_count,
                last_compiled=datetime.utcnow(),
            )
        
        except yara.SyntaxError as e:
            logger.error(f"Yara syntax error in {filepath}: {e}")
            return None
        except yara.Error as e:
            logger.error(f"Yara error in {filepath}: {e}")
            return None
    
    def _create_default_rules(self) -> None:
        """Create default Yara rules if none exist."""
        default_rules = {
            'suspicious_apis.yar': '''// Suspicious Windows API calls
rule suspicious_api_calls {
    meta:
        description = "Detects suspicious Windows API calls commonly used by malware"
        author = "CyberGuardian"
        severity = "medium"
        date = "2024-01-01"
    
    strings:
        $api1 = "VirtualAlloc" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "NtUnmapViewOfSection" nocase
        $api5 = "QueueUserAPC" nocase
        $api6 = "SetWindowsHookEx" nocase
        $api7 = "GetAsyncKeyState" nocase
        $api8 = "CreateToolhelp32Snapshot" nocase
        $api9 = "OpenProcess" nocase
        $api10 = "VirtualProtect" nocase
    
    condition:
        any of ($api*)
}

rule process_injection_indicators {
    meta:
        description = "Detects process injection indicators"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $inject1 = "CreateRemoteThread" nocase
        $inject2 = "VirtualAllocEx" nocase
        $inject3 = "WriteProcessMemory" nocase
        $inject4 = "NtQueueApcThread" nocase
        
    condition:
        2 of ($inject*)
}
''',
            'powershell_suspicious.yar': '''// Suspicious PowerShell patterns
rule powershell_encoded_command {
    meta:
        description = "Detects encoded PowerShell commands"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $enc3 = "-e " nocase
        $enc4 = "FromBase64String" nocase
        
    condition:
        any of ($enc*)
}

rule powershell_download {
    meta:
        description = "Detects PowerShell download cradles"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $dl1 = "Net.WebClient" nocase
        $dl2 = "DownloadString" nocase
        $dl3 = "DownloadFile" nocase
        $dl4 = "Invoke-WebRequest" nocase
        $dl5 = "iwr " nocase
        $dl6 = "curl " nocase
        $dl7 = "wget " nocase
        
    condition:
        any of ($dl*)
}

rule powershell_execution_policy {
    meta:
        description = "Detects execution policy bypass attempts"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $ep1 = "Bypass" nocase
        $ep2 = "Unrestricted" nocase
        $ep3 = "ExecutionPolicy" nocase
        $ep4 = "-ep " nocase
        
    condition:
        2 of ($ep*)
}
''',
            'crypto_mining.yar': '''// Cryptocurrency mining indicators
rule crypto_miner_stratum {
    meta:
        description = "Detects cryptocurrency mining stratum protocol"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $stratum = "stratum+tcp://" nocase
        $pool1 = "pool.minero.cc" nocase
        $pool2 = "xmrpool.eu" nocase
        $pool3 = "nanopool.org" nocase
        $pool4 = "ethermine.org" nocase
        
    condition:
        any of them
}

rule crypto_miner_binaries {
    meta:
        description = "Detects common cryptocurrency miner binaries"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $miner1 = "xmrig" nocase
        $miner2 = "minerd" nocase
        $miner3 = "cpuminer" nocase
        $miner4 = "ethminer" nocase
        $miner5 = "claymore" nocase
        
    condition:
        any of ($miner*)
}
''',
            'ransomware.yar': '''// Ransomware indicators
rule ransomware_extensions {
    meta:
        description = "Detects common ransomware file extensions"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ext4 = ".ransom" nocase
        $ext5 = ".wannacry" nocase
        $ext6 = ".ryuk" nocase
        $ext7 = ".locky" nocase
        $ext8 = ".cryptolocker" nocase
        
    condition:
        any of ($ext*)
}

rule ransomware_strings {
    meta:
        description = "Detects ransomware-related strings"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $ransom1 = "YOUR FILES ARE ENCRYPTED" nocase
        $ransom2 = "PAY RANSOM" nocase
        $ransom3 = "BITCOIN" nocase
        $ransom4 = "DECRYPT_INSTRUCTIONS" nocase
        $ransom5 = "RESTORE_FILES" nocase
        
    condition:
        2 of ($ransom*)
}
''',
            'backdoor.yar': '''// Backdoor indicators
rule reverse_shell {
    meta:
        description = "Detects reverse shell patterns"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $shell1 = "nc -e" nocase
        $shell2 = "/bin/sh -i" nocase
        $shell3 = "cmd.exe" nocase
        $shell4 = "powershell -nop" nocase
        $shell5 = "socket.connect" nocase
        $shell6 = "subprocess.call" nocase
        
    condition:
        2 of ($shell*)
}

rule backdoor_c2 {
    meta:
        description = "Detects common C2 patterns"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $c2_1 = "beacon" nocase
        $c2_2 = "checkin" nocase
        $c2_3 = "heartbeat" nocase
        $c2_4 = "get_task" nocase
        $c2_5 = "post_result" nocase
        
    condition:
        2 of ($c2*)
}
''',
            'packed_executable.yar': '''// Packed executable detection
rule packed_executable {
    meta:
        description = "Detects packed/obfuscated executables"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $pack1 = "UPX" nocase
        $pack2 = "ASPack" nocase
        $pack3 = "PECompact" nocase
        $pack4 = "Themida" nocase
        $pack5 = "VMProtect" nocase
        $pack6 = "Armadillo" nocase
        $pack7 = "Petite" nocase
        $pack8 = "NSPack" nocase
        
    condition:
        any of ($pack*)
}

rule high_entropy_section {
    meta:
        description = "Detects high entropy sections (packed/encrypted)"
        author = "CyberGuardian"
        severity = "medium"
    
    condition:
        uint16(0) == 0x5A4D
}
''',
            'webshell.yar': '''// Webshell detection
rule php_webshell {
    meta:
        description = "Detects PHP webshell patterns"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $php1 = "eval($_POST" nocase
        $php2 = "assert($_POST" nocase
        $php3 = "base64_decode" nocase
        $php4 = "gzinflate" nocase
        $php5 = "str_rot13" nocase
        $php6 = "shell_exec" nocase
        $php7 = "passthru" nocase
        $php8 = "system($_" nocase
        
    condition:
        2 of ($php*)
}

rule asp_webshell {
    meta:
        description = "Detects ASP webshell patterns"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $asp1 = "WScript.Shell" nocase
        $asp2 = "cmd.exe" nocase
        $asp3 = "Request.Form" nocase
        $asp4 = "ExecuteGlobal" nocase
        
    condition:
        2 of ($asp*)
}
''',
            'anti_analysis.yar': '''// Anti-analysis techniques
rule anti_debug {
    meta:
        description = "Detects anti-debugging techniques"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $dbg1 = "IsDebuggerPresent" nocase
        $dbg2 = "CheckRemoteDebuggerPresent" nocase
        $dbg3 = "NtGlobalFlag" nocase
        $dbg4 = "OutputDebugString" nocase
        $dbg5 = "BeingDebugged" nocase
        
    condition:
        any of ($dbg*)
}

rule anti_vm {
    meta:
        description = "Detects anti-VM techniques"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $vm1 = "VMware" nocase
        $vm2 = "VirtualBox" nocase
        $vm3 = "Vbox" nocase
        $vm4 = "QEMU" nocase
        $vm5 = "Sandboxie" nocase
        $vm6 = "Cuckoo" nocase
        $vm7 = "JoeSandbox" nocase
        
    condition:
        2 of ($vm*)
}

rule anti_sandbox {
    meta:
        description = "Detects sandbox evasion techniques"
        author = "CyberGuardian"
        severity = "medium"
    
    strings:
        $sb1 = "Sleep(" nocase
        $sb2 = "GetTickCount" nocase
        $sb3 = "QueryPerformanceCounter" nocase
        $sb4 = "InternetGetConnectedState" nocase
        
    condition:
        2 of ($sb*)
}
''',
            'credentials.yar': '''// Credential theft indicators
rule keylogger_indicators {
    meta:
        description = "Detects keylogger-related functionality"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $key1 = "GetAsyncKeyState" nocase
        $key2 = "GetKeyState" nocase
        $key3 = "SetWindowsHookEx" nocase
        $key4 = "CallNextHookEx" nocase
        $key5 = "keylog" nocase
        
    condition:
        2 of ($key*)
}

rule credential_dumping {
    meta:
        description = "Detects credential dumping tools"
        author = "CyberGuardian"
        severity = "critical"
    
    strings:
        $cred1 = "mimikatz" nocase
        $cred2 = "lsass.exe" nocase
        $cred3 = "SAM" nocase
        $cred4 = "SYSTEM" nocase
        $cred5 = "SECURITY" nocase
        $cred6 = "NTDS.dit" nocase
        
    condition:
        2 of ($cred*)
}

rule browser_stealer {
    meta:
        description = "Detects browser credential stealing"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $br1 = "Login Data" nocase
        $br2 = "Web Data" nocase
        $br3 = "Cookies" nocase
        $br4 = "sqlite3" nocase
        $br5 = "chrome.dll" nocase
        $br6 = "firefox" nocase
        
    condition:
        2 of ($br*)
}
''',
            'dropper.yar': '''// Dropper/Downloader indicators
rule dropper_patterns {
    meta:
        description = "Detects dropper patterns"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $drop1 = "URLDownloadToFile" nocase
        $drop2 = "WinHttp" nocase
        $drop3 = "WinINet" nocase
        $drop4 = "HttpOpenRequest" nocase
        $drop5 = "InternetReadFile" nocase
        $drop6 = "ShellExecute" nocase
        
    condition:
        2 of ($drop*)
}

rule suspicious_child_process {
    meta:
        description = "Detects suspicious parent-child process relationships"
        author = "CyberGuardian"
        severity = "high"
    
    strings:
        $proc1 = "winword.exe" nocase
        $proc2 = "excel.exe" nocase
        $proc3 = "powerpnt.exe" nocase
        $proc4 = "outlook.exe" nocase
        $child1 = "powershell.exe" nocase
        $child2 = "cmd.exe" nocase
        $child3 = "wscript.exe" nocase
        $child4 = "cscript.exe" nocase
        
    condition:
        any of ($proc*) and any of ($child*)
}
''',
        }
        
        # Write default rules
        for filename, content in default_rules.items():
            filepath = self.rules_dir / filename
            if not filepath.exists():
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                logger.info(f"Created default rule file: {filename}")
    
    def scan_file(self, filepath: Path, timeout: int = 60) -> List[YaraMatch]:
        """
        Scan a file with all loaded Yara rules.
        
        Args:
            filepath: Path to file to scan
            timeout: Timeout in seconds for the scan
        
        Returns:
            List of YaraMatch objects
        """
        if not self._loaded:
            self.load_rules()
        
        matches = []
        
        for name, ruleset in self.compiled_rulesets.items():
            try:
                rule_matches = ruleset.compiled_rules.match(
                    str(filepath),
                    timeout=timeout
                )
                
                for match in rule_matches:
                    yara_match = YaraMatch(
                        rule=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        meta=dict(match.meta),
                        strings=[(s[0], s[2], s[1]) for s in match.strings],
                        file_path=str(filepath),
                        severity=match.meta.get('severity', 'medium'),
                        description=match.meta.get('description', ''),
                    )
                    matches.append(yara_match)
                    
            except yara.TimeoutError:
                logger.warning(f"Yara scan timeout for {filepath}")
            except yara.Error as e:
                logger.debug(f"Yara error scanning {filepath}: {e}")
        
        return matches
    
    def scan_data(self, data: bytes, timeout: int = 30) -> List[YaraMatch]:
        """
        Scan raw data with all loaded Yara rules.
        
        Args:
            data: Raw bytes to scan
            timeout: Timeout in seconds
        
        Returns:
            List of YaraMatch objects
        """
        if not self._loaded:
            self.load_rules()
        
        matches = []
        
        for name, ruleset in self.compiled_rulesets.items():
            try:
                rule_matches = ruleset.compiled_rules.match(
                    data=data,
                    timeout=timeout
                )
                
                for match in rule_matches:
                    yara_match = YaraMatch(
                        rule=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        meta=dict(match.meta),
                        strings=[(s[0], s[2], s[1]) for s in match.strings],
                        severity=match.meta.get('severity', 'medium'),
                        description=match.meta.get('description', ''),
                    )
                    matches.append(yara_match)
                    
            except yara.TimeoutError:
                logger.warning("Yara scan timeout for data")
            except yara.Error as e:
                logger.debug(f"Yara error scanning data: {e}")
        
        return matches
    
    def scan_process_memory(self, pid: int, timeout: int = 60) -> List[YaraMatch]:
        """
        Scan process memory with Yara rules.
        Note: Requires Yara Python bindings compiled with process scanning support.
        
        Args:
            pid: Process ID to scan
            timeout: Timeout in seconds
        
        Returns:
            List of YaraMatch objects
        """
        if not self._loaded:
            self.load_rules()
        
        matches = []
        
        for name, ruleset in self.compiled_rulesets.items():
            try:
                # Try to scan process memory
                # Note: This requires appropriate privileges
                rule_matches = ruleset.compiled_rules.match(
                    pid=pid,
                    timeout=timeout
                )
                
                for match in rule_matches:
                    yara_match = YaraMatch(
                        rule=match.rule,
                        namespace=match.namespace,
                        tags=list(match.tags),
                        meta=dict(match.meta),
                        strings=[(s[0], s[2], s[1]) for s in match.strings],
                        severity=match.meta.get('severity', 'medium'),
                        description=match.meta.get('description', ''),
                    )
                    matches.append(yara_match)
                    
            except yara.TimeoutError:
                logger.warning(f"Yara scan timeout for process {pid}")
            except yara.Error as e:
                # Process scanning may not be available
                logger.debug(f"Yara process scan error for PID {pid}: {e}")
        
        return matches
    
    def get_rule_stats(self) -> Dict[str, Any]:
        """Get statistics about loaded rules."""
        return {
            'total_rulesets': len(self.compiled_rulesets),
            'total_rules': sum(r.rule_count for r in self.compiled_rulesets.values()),
            'rulesets': {
                name: {
                    'rule_count': rs.rule_count,
                    'last_compiled': rs.last_compiled.isoformat(),
                    'source': str(rs.source_path),
                }
                for name, rs in self.compiled_rulesets.items()
            }
        }
    
    def update_rules_from_remote(self, url: Optional[str] = None) -> bool:
        """
        Update rules from a remote repository.
        
        Args:
            url: URL to fetch rules from (uses config default if not provided)
        
        Returns:
            True if update successful
        """
        # Placeholder for remote update functionality
        # In production, implement git clone or HTTP download
        logger.info("Remote rule update not yet implemented")
        return False


# Global Yara manager instance
_yara_instance: Optional[YaraManager] = None


def get_yara_manager() -> YaraManager:
    """Get the global Yara manager instance."""
    global _yara_instance
    if _yara_instance is None:
        _yara_instance = YaraManager()
    return _yara_instance
