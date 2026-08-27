"""
CyberGuardian Memory Analyzer Module
=====================================
Advanced memory forensics for malware detection.

Features:
- Safe memory dumping and artifact extraction
- Process memory scanning with string extraction
- Injection detection (DLL injection, process hollowing, etc.)
- Network IOC extraction from memory
- YARA memory scanning
- Secure cleanup of sensitive data

This module requires Administrator privileges for full functionality.
"""

import os
import sys
import re
import struct
import ctypes
import ctypes.wintypes as wintypes
import logging
import time
import hashlib
import json
import tempfile
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple, Generator
from datetime import datetime
from dataclasses import dataclass, field
from collections import defaultdict
import threading
import gc

# Try to import psutil for process operations
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from scanners.base_scanner import Detection, RiskLevel
from utils.logging_utils import get_logger

logger = get_logger('scanners.memory_analyzer')


# ============================================================================
# Windows API Structures and Constants for Memory Operations
# ============================================================================

# Memory protection constants
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
PAGE_ENCLAVE_THREAD_CONTROL = 0x80000000
PAGE_TARGETS_NO_UPDATE = 0x40000000
PAGE_TARGETS_INVALID = 0x40000000

# Memory state constants
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000

# Memory types
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

# Process access rights
PROCESS_ALL_ACCESS = 0x1F0FFF
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400

# Token privileges
SE_DEBUG_NAME = "SeDebugPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    """Windows MEMORY_BASIC_INFORMATION structure."""
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class LUID(ctypes.Structure):
    """Windows LUID structure."""
    _fields_ = [
        ("LowPart", wintypes.DWORD),
        ("HighPart", wintypes.LONG),
    ]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    """Windows LUID_AND_ATTRIBUTES structure."""
    _fields_ = [
        ("Luid", LUID),
        ("Attributes", wintypes.DWORD),
    ]


class TOKEN_PRIVILEGES(ctypes.Structure):
    """Windows TOKEN_PRIVILEGES structure."""
    _fields_ = [
        ("PrivilegeCount", wintypes.DWORD),
        ("Privileges", LUID_AND_ATTRIBUTES * 1),
    ]


# ============================================================================
# Data Classes for Memory Analysis Results
# ============================================================================

@dataclass
class MemoryRegion:
    """Information about a memory region."""
    base_address: int
    allocation_base: int
    region_size: int
    state: str  # COMMIT, RESERVE, FREE
    protection: str  # RWX, RW, R, etc.
    memory_type: str  # PRIVATE, MAPPED, IMAGE
    is_executable: bool
    is_writable: bool
    is_suspicious: bool = False
    suspicion_reasons: List[str] = field(default_factory=list)


@dataclass
class ExtractedString:
    """An extracted string from memory."""
    value: str
    string_type: str  # URL, IP, DOMAIN, PATH, EMAIL, BASE64, MUTEX, etc.
    address: int
    context: str = ""  # Surrounding context
    is_suspicious: bool = False


@dataclass
class InjectedCode:
    """Detected injected code in a process."""
    process_id: int
    process_name: str
    injection_type: str  # DLL_INJECTION, PROCESS_HOLLOWING, REFLECTIVE_INJECTION, etc.
    memory_address: int
    region_size: int
    protection: str
    confidence: float
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MemoryIOC:
    """Indicator of Compromise found in memory."""
    ioc_type: str  # URL, IP, DOMAIN, HASH, MUTEX, REGISTRY_KEY, FILE_PATH
    value: str
    source_process: str
    source_pid: int
    memory_address: int
    context: str
    confidence: float = 0.5
    is_malicious: bool = False


@dataclass
class ProcessMemoryInfo:
    """Complete memory information for a process."""
    process_id: int
    process_name: str
    process_path: str
    memory_regions: List[MemoryRegion] = field(default_factory=list)
    extracted_strings: List[ExtractedString] = field(default_factory=list)
    loaded_modules: List[Dict] = field(default_factory=list)
    injected_code: List[InjectedCode] = field(default_factory=list)
    iocs: List[MemoryIOC] = field(default_factory=list)
    suspicious_regions: List[MemoryRegion] = field(default_factory=list)
    total_memory_scanned: int = 0
    scan_duration: float = 0.0


# ============================================================================
# Memory Analyzer Class
# ============================================================================

class MemoryAnalyzer:
    """
    Advanced memory analyzer for malware detection.
    
    Capabilities:
    - Safe memory dumping and artifact extraction
    - Process memory scanning with string extraction
    - Injection detection (DLL injection, process hollowing, etc.)
    - Network IOC extraction from memory
    - YARA memory scanning
    - Secure cleanup of sensitive data
    
    Requires Administrator privileges for full functionality.
    """
    
    # Suspicious memory protection patterns
    SUSPICIOUS_PROTECTIONS = [
        PAGE_EXECUTE_READWRITE,  # RWX - highly suspicious
        PAGE_EXECUTE_WRITECOPY,  # Can become RWX
    ]
    
    # Patterns for string extraction
    STRING_PATTERNS = {
        'URL': re.compile(rb'https?://[^\s<>"\']+', re.IGNORECASE),
        'IP': re.compile(rb'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
        'DOMAIN': re.compile(rb'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
        'EMAIL': re.compile(rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
        'BASE64': re.compile(rb'[A-Za-z0-9+/]{40,}={0,2}'),
        'MUTEX': re.compile(rb'(?:Global\\|Local\\)?[A-Za-z0-9_\-\\]{3,}', re.IGNORECASE),
        'REGISTRY': re.compile(rb'(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU)\\[A-Za-z0-9_\\\-]+', re.IGNORECASE),
        'FILE_PATH': re.compile(rb'[A-Z]:\\[A-Za-z0-9_\-\\\.]+(?:\.exe|\.dll|\.sys|\.bat|\.ps1|\.vbs|\.js)', re.IGNORECASE),
        'MUTEX_GLOBAL': re.compile(rb'Global\\[A-Za-z0-9_\-]+'),
        'PIPE_NAME': re.compile(rb'\\\\\.\\pipe\\[A-Za-z0-9_\-]+'),
        'USER_AGENT': re.compile(rb'[Mm]ozilla/[0-9.]+\s+\([^)]+\)\s+[A-Za-z0-9/\.\s\-]+'),
        'POWER_SHELL': re.compile(rb'(?:powershell|pwsh)\s+(?:-[A-Za-z]+\s+)?[A-Za-z0-9_\-\\\.]+', re.IGNORECASE),
    }
    
    # Suspicious strings that indicate malware
    SUSPICIOUS_STRINGS = [
        # Process manipulation
        b'CreateRemoteThread', b'WriteProcessMemory', b'ReadProcessMemory',
        b'VirtualAllocEx', b'VirtualProtectEx', b'NtUnmapViewOfSection',
        b'SetThreadContext', b'GetThreadContext', b'QueueUserAPC',
        
        # Injection techniques
        b'process_injection', b'dll_injection', b'reflective_injection',
        b'process_hollowing', b'atom_bombing', b'process_doppelganging',
        b'proc_inject', b'dll_inject',
        
        # Shellcode indicators
        b'\x90\x90\x90\x90',  # NOP sled
        b'\xCC\xCC\xCC\xCC',  # INT3 breakpoint
        b'\xEB\xFE',  # Infinite loop
        b'shellcode', b'metasploit', b'meterpreter',
        
        # C2 patterns
        b'beacon', b'c2_server', b'command_and_control', b'callback',
        b'checkin', b'heartbeat', b'get_task', b'send_result',
        b'implant', b'payload', b'stager', b'dropper',
        
        # Anti-analysis
        b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent',
        b'anti_debug', b'anti_vm', b'anti_sandbox',
        b'VirtualBox', b'VMware', b'Sandboxie', b'Wine',
        b'sandbox', b'debugger', b'analyzer',
        
        # Crypto
        b'AES_set_encrypt_key', b'AES_encrypt', b'RC4', b'XOR_key',
        b'encryption_key', b'decryption_key',
        
        # Credential theft
        b'lsass.exe', b'SAM', b'SECURITY', b'SYSTEM',
        b'mimikatz', b'wce', b'procdump',
        b'logonpasswords', b'sekurlsa', b'privilege::debug',
        
        # Network patterns
        b'torproject', b'tor2web', b'onion', b'hidden_service',
        b'pastebin', b'hastebin', b'ghostbin',
    ]
    
    # Max memory to read per region (to avoid memory issues)
    MAX_REGION_SIZE = 50 * 1024 * 1024  # 50 MB
    MAX_TOTAL_SCAN_SIZE = 500 * 1024 * 1024  # 500 MB total
    
    # Minimum string length for extraction
    MIN_STRING_LENGTH = 6
    
    def __init__(self):
        """Initialize the memory analyzer."""
        self._is_admin = self._check_admin_privileges()
        self._debug_enabled = False
        self._temp_dir = None
        self._scanned_size = 0
        self._cancel_flag = False
        
        # Windows API functions
        if sys.platform == 'win32':
            self._setup_windows_api()
        
        logger.info(f"MemoryAnalyzer initialized (admin={self._is_admin})")
    
    def _check_admin_privileges(self) -> bool:
        """Check if running with administrator privileges."""
        try:
            if sys.platform == 'win32':
                return ctypes.windll.shell32.IsUserAnAdmin()
            else:
                return os.geteuid() == 0
        except:
            return False
    
    def _setup_windows_api(self):
        """Setup Windows API functions for memory operations."""
        try:
            self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self.advapi32 = ctypes.WinDLL('advapi32', use_last_error=True)
            
            # Define function prototypes
            self.kernel32.OpenProcess.restype = wintypes.HANDLE
            self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
            
            self.kernel32.ReadProcessMemory.restype = wintypes.BOOL
            self.kernel32.ReadProcessMemory.argtypes = [
                wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID,
                ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
            ]
            
            self.kernel32.VirtualQueryEx.restype = ctypes.c_size_t
            self.kernel32.VirtualQueryEx.argtypes = [
                wintypes.HANDLE, wintypes.LPCVOID,
                ctypes.POINTER(MEMORY_BASIC_INFORMATION),
                ctypes.c_size_t
            ]
            
            self.kernel32.CloseHandle.restype = wintypes.BOOL
            self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            
            self.advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
            self.advapi32.LookupPrivilegeValueW.argtypes = [
                wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)
            ]
            
            self.advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
            self.advapi32.AdjustTokenPrivileges.argtypes = [
                wintypes.HANDLE, wintypes.BOOL,
                ctypes.POINTER(TOKEN_PRIVILEGES),
                wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID
            ]
            
        except Exception as e:
            logger.error(f"Failed to setup Windows API: {e}")
            raise
    
    def _enable_debug_privilege(self) -> bool:
        """Enable SeDebugPrivilege for better process access."""
        if not sys.platform == 'win32':
            return False
        
        try:
            h_token = wintypes.HANDLE()
            h_process = self.kernel32.GetCurrentProcess()
            
            if not self.advapi32.OpenProcessToken(
                h_process, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                ctypes.byref(h_token)
            ):
                return False
            
            luid = LUID()
            if not self.advapi32.LookupPrivilegeValueW(
                None, SE_DEBUG_NAME, ctypes.byref(luid)
            ):
                self.kernel32.CloseHandle(h_token)
                return False
            
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            
            result = self.advapi32.AdjustTokenPrivileges(
                h_token, False, ctypes.byref(tp), 0, None, None
            )
            
            self.kernel32.CloseHandle(h_token)
            self._debug_enabled = result != 0
            return self._debug_enabled
            
        except Exception as e:
            logger.debug(f"Failed to enable debug privilege: {e}")
            return False
    
    def cancel(self):
        """Cancel the current operation."""
        self._cancel_flag = True
    
    def reset_cancel(self):
        """Reset the cancel flag."""
        self._cancel_flag = False
    
    def is_cancelled(self) -> bool:
        """Check if operation was cancelled."""
        return self._cancel_flag
    
    # ========================================================================
    # Memory Region Analysis
    # ========================================================================
    
    def _get_protection_string(self, protection: int) -> str:
        """Convert protection flags to human-readable string."""
        protections = []
        
        # Check for execute
        if protection & PAGE_EXECUTE:
            protections.append('X')
        elif protection & PAGE_EXECUTE_READ:
            protections.append('XR')
        elif protection & PAGE_EXECUTE_READWRITE:
            protections.append('XRW')
        elif protection & PAGE_EXECUTE_WRITECOPY:
            protections.append('XRW-C')
        elif protection & PAGE_READWRITE:
            protections.append('RW')
        elif protection & PAGE_READONLY:
            protections.append('R')
        elif protection & PAGE_WRITECOPY:
            protections.append('W-C')
        else:
            protections.append('-')
        
        # Check for special flags
        if protection & PAGE_GUARD:
            protections.append('G')
        if protection & PAGE_NOCACHE:
            protections.append('NC')
        if protection & PAGE_WRITECOMBINE:
            protections.append('WC')
        
        return ''.join(protections)
    
    def _get_state_string(self, state: int) -> str:
        """Convert state flags to human-readable string."""
        if state & MEM_COMMIT:
            return 'COMMIT'
        elif state & MEM_RESERVE:
            return 'RESERVE'
        elif state & MEM_FREE:
            return 'FREE'
        return 'UNKNOWN'
    
    def _get_type_string(self, mem_type: int) -> str:
        """Convert type flags to human-readable string."""
        if mem_type & MEM_IMAGE:
            return 'IMAGE'
        elif mem_type & MEM_MAPPED:
            return 'MAPPED'
        elif mem_type & MEM_PRIVATE:
            return 'PRIVATE'
        return 'UNKNOWN'
    
    def _is_suspicious_region(self, region: MemoryRegion) -> Tuple[bool, List[str]]:
        """Check if a memory region is suspicious."""
        reasons = []
        
        # RWX memory is highly suspicious
        if region.protection in ['XRW', 'XRW-C']:
            reasons.append("RWX (Read-Write-Execute) memory")
        
        # Executable private memory not backed by image
        if region.is_executable and region.memory_type == 'PRIVATE':
            reasons.append("Executable private memory (possible injection)")
        
        # Large RWX regions
        if region.region_size > 1024 * 1024 and 'RW' in region.protection and 'X' in region.protection:
            reasons.append(f"Large ({region.region_size // 1024}KB) RWX region")
        
        # Guard pages with execute access
        if 'G' in region.protection and region.is_executable:
            reasons.append("Guard page with execute access")
        
        # Very small executable regions (could be shellcode)
        if region.is_executable and region.region_size < 4096:
            reasons.append("Small executable region (possible shellcode)")
        
        return len(reasons) > 0, reasons
    
    def enumerate_memory_regions(self, process_handle, pid: int) -> List[MemoryRegion]:
        """
        Enumerate all memory regions of a process.
        
        Args:
            process_handle: Handle to the process
            pid: Process ID
        
        Returns:
            List of MemoryRegion objects
        """
        regions = []
        address = 0
        max_address = 0x7FFFFFFF0000 if sys.maxsize > 2**32 else 0x7FFFFFFF
        
        try:
            while address < max_address:
                if self._cancel_flag:
                    break
                
                mbi = MEMORY_BASIC_INFORMATION()
                result = self.kernel32.VirtualQueryEx(
                    process_handle,
                    ctypes.c_void_p(address),
                    ctypes.byref(mbi),
                    ctypes.sizeof(mbi)
                )
                
                if result == 0:
                    break
                
                if mbi.State != MEM_FREE:
                    protection_str = self._get_protection_string(mbi.Protect)
                    is_executable = 'X' in protection_str
                    is_writable = 'W' in protection_str
                    
                    region = MemoryRegion(
                        base_address=mbi.BaseAddress,
                        allocation_base=mbi.AllocationBase,
                        region_size=mbi.RegionSize,
                        state=self._get_state_string(mbi.State),
                        protection=protection_str,
                        memory_type=self._get_type_string(mbi.Type),
                        is_executable=is_executable,
                        is_writable=is_writable
                    )
                    
                    # Check for suspicious characteristics
                    is_suspicious, reasons = self._is_suspicious_region(region)
                    region.is_suspicious = is_suspicious
                    region.suspicion_reasons = reasons
                    
                    regions.append(region)
                
                # Move to next region
                address = mbi.BaseAddress + mbi.RegionSize
                if address <= mbi.BaseAddress:  # Overflow check
                    break
                    
        except Exception as e:
            logger.debug(f"Error enumerating memory regions for PID {pid}: {e}")
        
        return regions
    
    # ========================================================================
    # Memory Reading and String Extraction
    # ========================================================================
    
    def read_memory_region(self, process_handle, base_address: int, size: int) -> Optional[bytes]:
        """
        Read memory from a process.
        
        Args:
            process_handle: Handle to the process
            base_address: Base address to read from
            size: Number of bytes to read
        
        Returns:
            Bytes read or None on failure
        """
        # Limit size to prevent memory issues
        if size > self.MAX_REGION_SIZE:
            size = self.MAX_REGION_SIZE
        
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            result = self.kernel32.ReadProcessMemory(
                process_handle,
                ctypes.c_void_p(base_address),
                buffer,
                size,
                ctypes.byref(bytes_read)
            )
            
            if result and bytes_read.value > 0:
                return buffer.raw[:bytes_read.value]
            
        except Exception as e:
            logger.debug(f"Error reading memory at 0x{base_address:X}: {e}")
        
        return None
    
    def extract_strings(self, data: bytes, min_length: int = None) -> List[ExtractedString]:
        """
        Extract meaningful strings from memory data.
        
        Args:
            data: Raw bytes to extract strings from
            min_length: Minimum string length
        
        Returns:
            List of ExtractedString objects
        """
        if min_length is None:
            min_length = self.MIN_STRING_LENGTH
        
        strings = []
        seen_values = set()
        
        # Extract ASCII strings
        ascii_pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        for match in re.finditer(ascii_pattern, data):
            value = match.group().decode('ascii', errors='ignore')
            if value not in seen_values and not value.isspace():
                seen_values.add(value)
                
                # Determine string type
                string_type = self._classify_string(value)
                
                # Get context (surrounding bytes)
                start = max(0, match.start() - 20)
                end = min(len(data), match.end() + 20)
                context = data[start:end].hex()
                
                strings.append(ExtractedString(
                    value=value,
                    string_type=string_type,
                    address=0,  # Will be updated by caller
                    context=context,
                    is_suspicious=self._is_suspicious_string(value)
                ))
        
        # Extract Unicode strings (UTF-16LE)
        unicode_pattern = rb'(?:[\x20-\x7E]\x00){' + str(min_length).encode() + rb',}'
        for match in re.finditer(unicode_pattern, data):
            try:
                value = match.group().decode('utf-16le', errors='ignore').strip('\x00')
                if value not in seen_values and not value.isspace() and len(value) >= min_length:
                    seen_values.add(value)
                    
                    string_type = self._classify_string(value)
                    
                    start = max(0, match.start() - 20)
                    end = min(len(data), match.end() + 20)
                    context = data[start:end].hex()
                    
                    strings.append(ExtractedString(
                        value=value,
                        string_type=string_type,
                        address=0,
                        context=context,
                        is_suspicious=self._is_suspicious_string(value)
                    ))
            except:
                pass
        
        # Extract pattern-based strings (URLs, IPs, etc.)
        for pattern_name, pattern in self.STRING_PATTERNS.items():
            for match in re.finditer(pattern, data):
                try:
                    value = match.group().decode('utf-8', errors='ignore')
                    if value not in seen_values:
                        seen_values.add(value)
                        
                        start = max(0, match.start() - 20)
                        end = min(len(data), match.end() + 20)
                        context = data[start:end].hex()
                        
                        strings.append(ExtractedString(
                            value=value,
                            string_type=pattern_name,
                            address=0,
                            context=context,
                            is_suspicious=True  # Pattern matches are inherently interesting
                        ))
                except:
                    pass
        
        return strings
    
    def _classify_string(self, value: str) -> str:
        """Classify the type of a string."""
        value_lower = value.lower()
        
        # Check for known patterns
        if re.match(r'https?://', value, re.IGNORECASE):
            return 'URL'
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return 'IP'
        if re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$', value):
            return 'EMAIL'
        if re.match(r'^[A-Z]:\\', value, re.IGNORECASE):
            return 'FILE_PATH'
        if re.match(r'^(HKEY_|HKLM|HKCU|HKCR|HKU)', value, re.IGNORECASE):
            return 'REGISTRY'
        if re.match(r'^(Global\\|Local\\)', value, re.IGNORECASE):
            return 'MUTEX'
        if re.match(r'^[A-Za-z0-9+/]{20,}={0,2}$', value):
            return 'BASE64'
        if re.match(r'^[A-Fa-f0-9]{32,}$', value):
            return 'HASH'
        
        # Check for suspicious keywords
        suspicious_keywords = [
            'password', 'passwd', 'pwd', 'key', 'secret', 'token', 'credential',
            'shell', 'cmd', 'powershell', 'inject', 'hook', 'patch',
            'malware', 'virus', 'trojan', 'backdoor', 'exploit',
            'c2', 'command', 'control', 'beacon', 'payload'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in value_lower:
                return 'SUSPICIOUS_KEYWORD'
        
        return 'STRING'
    
    def _is_suspicious_string(self, value: str) -> bool:
        """Check if a string is suspicious."""
        value_lower = value.lower()
        
        suspicious_keywords = [
            'inject', 'hook', 'patch', 'shellcode', 'metasploit', 'meterpreter',
            'mimikatz', 'beacon', 'payload', 'exploit', 'backdoor',
            'password', 'credential', 'secret_key', 'api_key',
            'c2', 'command_and_control', 'callback', 'checkin',
            'procdump', 'lsass', 'sam', 'ntds.dit',
            'process_hollowing', 'dll_injection', 'reflective',
            'anti_debug', 'anti_vm', 'anti_sandbox',
            'virtualbox', 'vmware', 'sandboxie', 'analysis'
        ]
        
        for keyword in suspicious_keywords:
            if keyword in value_lower:
                return True
        
        # Check against byte patterns
        value_bytes = value.encode('utf-8', errors='ignore')
        for pattern in self.SUSPICIOUS_STRINGS:
            if pattern in value_bytes or pattern in value_lower.encode():
                return True
        
        return False
    
    # ========================================================================
    # Injection Detection
    # ========================================================================
    
    def detect_injection(self, pid: int, process_handle, regions: List[MemoryRegion],
                         process_name: str) -> List[InjectedCode]:
        """
        Detect code injection in a process.
        
        Args:
            pid: Process ID
            process_handle: Handle to the process
            regions: Memory regions of the process
            process_name: Name of the process
        
        Returns:
            List of InjectedCode objects
        """
        injections = []
        
        for region in regions:
            if self._cancel_flag:
                break
            
            # Check for classic DLL injection: RWX private memory
            if (region.is_executable and region.is_writable and 
                region.memory_type == 'PRIVATE' and 
                region.state == 'COMMIT'):
                
                # Read the memory to check for PE header (DLL)
                memory_data = self.read_memory_region(
                    process_handle,
                    region.base_address,
                    min(region.region_size, 4096)
                )
                
                injection_type = 'UNKNOWN_INJECTION'
                confidence = 0.6
                evidence = {
                    'base_address': f'0x{region.base_address:X}',
                    'region_size': region.region_size,
                    'protection': region.protection,
                    'memory_type': region.memory_type,
                }
                
                if memory_data:
                    # Check for PE header (MZ header)
                    if memory_data[:2] == b'MZ':
                        injection_type = 'DLL_INJECTION'
                        confidence = 0.85
                        
                        # Try to get DLL name
                        try:
                            # Parse PE header to get export name
                            pe_offset = struct.unpack('<I', memory_data[0x3C:0x40])[0]
                            if pe_offset < len(memory_data) - 0x18:
                                pe_sig = memory_data[pe_offset:pe_offset+4]
                                if pe_sig == b'PE\x00\x00':
                                    evidence['pe_valid'] = True
                        except:
                            pass
                    
                    # Check for shellcode patterns
                    elif self._contains_shellcode_patterns(memory_data):
                        injection_type = 'SHELLCODE_INJECTION'
                        confidence = 0.8
                        evidence['shellcode_detected'] = True
                    
                    # Check for reflective loader patterns
                    elif self._check_reflective_patterns(memory_data):
                        injection_type = 'REFLECTIVE_INJECTION'
                        confidence = 0.75
                        evidence['reflective_patterns'] = True
                
                injections.append(InjectedCode(
                    process_id=pid,
                    process_name=process_name,
                    injection_type=injection_type,
                    memory_address=region.base_address,
                    region_size=region.region_size,
                    protection=region.protection,
                    confidence=confidence,
                    evidence=evidence
                ))
            
            # Check for process hollowing: Unusual memory layout
            if region.memory_type == 'IMAGE' and region.protection in ['XRW', 'RW']:
                # This could indicate process hollowing where .text section is writable
                injections.append(InjectedCode(
                    process_id=pid,
                    process_name=process_name,
                    injection_type='PROCESS_HOLLOWING',
                    memory_address=region.base_address,
                    region_size=region.region_size,
                    protection=region.protection,
                    confidence=0.5,
                    evidence={
                        'base_address': f'0x{region.base_address:X}',
                        'protection': region.protection,
                        'type': region.memory_type,
                    }
                ))
        
        return injections
    
    def _contains_shellcode_patterns(self, data: bytes) -> bool:
        """Check if data contains shellcode patterns."""
        patterns = [
            b'\x90\x90\x90\x90',  # NOP sled
            b'\xCC\xCC\xCC\xCC',  # INT3 breakpoint
            b'\xEB\xFE',  # Infinite loop
            b'\xFF\xE4',  # JMP ESP
            b'\xFF\xE0',  # JMP EAX
            b'\xFF\xD0',  # CALL EAX
            # Common shellcode prologues
            b'\x55\x8B\xEC',  # PUSH EBP; MOV EBP, ESP
            b'\xFC\xE8',  # CLD; CALL
            # GetPC routines
            b'\xE8\x00\x00\x00\x00',  # CALL $+5
        ]
        
        for pattern in patterns:
            if pattern in data:
                return True
        
        # Check for high entropy (packed/encrypted shellcode)
        if len(data) > 100:
            entropy = self._calculate_entropy(data)
            if entropy > 7.0:
                return True
        
        return False
    
    def _check_reflective_patterns(self, data: bytes) -> bool:
        """Check for reflective DLL injection patterns."""
        patterns = [
            b'VirtualAlloc', b'LoadLibraryA', b'GetProcAddress',
            b'NtAllocateVirtualMemory', b'LdrLoadDll',
            b'reflective', b'loader', b'inject'
        ]
        
        for pattern in patterns:
            if pattern in data:
                return True
        
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        freq = {}
        for byte in data:
            freq[byte] = freq.get(byte, 0) + 1
        
        import math
        entropy = 0.0
        for count in freq.values():
            p = count / len(data)
            entropy -= p * math.log2(p)
        
        return entropy
    
    # ========================================================================
    # IOC Extraction
    # ========================================================================
    
    def extract_iocs(self, strings: List[ExtractedString], process_name: str,
                     pid: int) -> List[MemoryIOC]:
        """
        Extract Indicators of Compromise from strings.
        
        Args:
            strings: List of extracted strings
            process_name: Name of the source process
            pid: Process ID
        
        Returns:
            List of MemoryIOC objects
        """
        iocs = []
        seen_values = set()
        
        for string in strings:
            if string.value in seen_values:
                continue
            seen_values.add(string.value)
            
            # URLs
            if string.string_type == 'URL':
                iocs.append(MemoryIOC(
                    ioc_type='URL',
                    value=string.value,
                    source_process=process_name,
                    source_pid=pid,
                    memory_address=string.address,
                    context=string.context,
                    confidence=0.8 if string.is_suspicious else 0.5
                ))
            
            # IPs
            elif string.string_type == 'IP':
                # Skip private IPs
                if not self._is_private_ip(string.value):
                    iocs.append(MemoryIOC(
                        ioc_type='IP',
                        value=string.value,
                        source_process=process_name,
                        source_pid=pid,
                        memory_address=string.address,
                        context=string.context,
                        confidence=0.6
                    ))
            
            # Domains
            elif string.string_type == 'DOMAIN':
                # Skip common legitimate domains
                if not self._is_common_domain(string.value):
                    iocs.append(MemoryIOC(
                        ioc_type='DOMAIN',
                        value=string.value,
                        source_process=process_name,
                        source_pid=pid,
                        memory_address=string.address,
                        context=string.context,
                        confidence=0.6 if string.is_suspicious else 0.3
                    ))
            
            # File paths (suspicious ones)
            elif string.string_type == 'FILE_PATH':
                if self._is_suspicious_path(string.value):
                    iocs.append(MemoryIOC(
                        ioc_type='FILE_PATH',
                        value=string.value,
                        source_process=process_name,
                        source_pid=pid,
                        memory_address=string.address,
                        context=string.context,
                        confidence=0.7
                    ))
            
            # Registry keys (suspicious ones)
            elif string.string_type == 'REGISTRY':
                if self._is_suspicious_registry(string.value):
                    iocs.append(MemoryIOC(
                        ioc_type='REGISTRY_KEY',
                        value=string.value,
                        source_process=process_name,
                        source_pid=pid,
                        memory_address=string.address,
                        context=string.context,
                        confidence=0.6
                    ))
            
            # Mutexes
            elif string.string_type == 'MUTEX':
                iocs.append(MemoryIOC(
                    ioc_type='MUTEX',
                    value=string.value,
                    source_process=process_name,
                    source_pid=pid,
                    memory_address=string.address,
                    context=string.context,
                    confidence=0.5
                ))
            
            # Suspicious keywords
            elif string.string_type == 'SUSPICIOUS_KEYWORD':
                iocs.append(MemoryIOC(
                    ioc_type='SUSPICIOUS_STRING',
                    value=string.value,
                    source_process=process_name,
                    source_pid=pid,
                    memory_address=string.address,
                    context=string.context,
                    confidence=0.8
                ))
        
        return iocs
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        import ipaddress
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def _is_common_domain(self, domain: str) -> bool:
        """Check if domain is a common legitimate domain."""
        common_domains = {
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'facebook.com', 'twitter.com', 'youtube.com', 'yahoo.com',
            'live.com', 'outlook.com', 'gmail.com', 'cloudflare.com',
            'github.com', 'linkedin.com', 'instagram.com', 'reddit.com',
            'wikipedia.org', 'office.com', 'windows.com', 'msn.com',
            'akamai.net', 'cloudfront.net', 'azure.com', 'windows.net'
        }
        
        domain_lower = domain.lower()
        for common in common_domains:
            if domain_lower == common or domain_lower.endswith('.' + common):
                return True
        
        return False
    
    def _is_suspicious_path(self, path: str) -> bool:
        """Check if file path is suspicious."""
        suspicious_patterns = [
            '\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\',
            '\\programdata\\', '\\public\\', '\\downloads\\',
            '\\startup\\', '\\start menu\\programs\\startup\\',
            '\\windows\\temp\\', 'c:\\users\\', '\\program files (x86)\\',
        ]
        
        path_lower = path.lower()
        for pattern in suspicious_patterns:
            if pattern in path_lower:
                return True
        
        return False
    
    def _is_suspicious_registry(self, key: str) -> bool:
        """Check if registry key is suspicious (persistence locations)."""
        suspicious_patterns = [
            'run', 'runonce', 'startup', 'currentversion\\run',
            'winlogon', 'shell', 'userinit', 'policies',
            'service', 'image file execution options',
            'appinit_dlls', 'load', 'shell folders',
            'active setup', 'browser helper objects', 'shellexecutehooks',
        ]
        
        key_lower = key.lower()
        for pattern in suspicious_patterns:
            if pattern in key_lower:
                return True
        
        return False
    
    # ========================================================================
    # Main Analysis Functions
    # ========================================================================
    
    def analyze_process(self, pid: int, progress_callback=None) -> ProcessMemoryInfo:
        """
        Perform comprehensive memory analysis on a process.
        
        Args:
            pid: Process ID to analyze
            progress_callback: Optional callback for progress updates
        
        Returns:
            ProcessMemoryInfo with all analysis results
        """
        start_time = time.time()
        self._scanned_size = 0
        self.reset_cancel()
        
        # Get process info
        process_name = "Unknown"
        process_path = ""
        
        if PSUTIL_AVAILABLE:
            try:
                proc = psutil.Process(pid)
                process_name = proc.name()
                process_path = proc.exe() or ""
            except:
                pass
        
        result = ProcessMemoryInfo(
            process_id=pid,
            process_name=process_name,
            process_path=process_path
        )
        
        # Enable debug privilege
        if not self._debug_enabled:
            self._enable_debug_privilege()
        
        # Open process handle
        process_handle = None
        try:
            process_handle = self.kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False, pid
            )
            
            if not process_handle:
                logger.debug(f"Could not open process {pid}")
                return result
            
            # Step 1: Enumerate memory regions
            if progress_callback:
                progress_callback(0, 100, f"Enumerating memory regions for {process_name}...")
            
            regions = self.enumerate_memory_regions(process_handle, pid)
            result.memory_regions = regions
            
            # Find suspicious regions
            result.suspicious_regions = [r for r in regions if r.is_suspicious]
            
            # Step 2: Detect injection
            if progress_callback:
                progress_callback(20, 100, f"Detecting code injection...")
            
            injections = self.detect_injection(pid, process_handle, regions, process_name)
            result.injected_code = injections
            
            # Step 3: Extract strings from suspicious regions
            if progress_callback:
                progress_callback(40, 100, f"Extracting strings from memory...")
            
            all_strings = []
            for i, region in enumerate(regions):
                if self._cancel_flag:
                    break
                
                # Limit total scanned size
                if self._scanned_size > self.MAX_TOTAL_SCAN_SIZE:
                    break
                
                # Only scan committed memory
                if region.state != 'COMMIT':
                    continue
                
                # Prioritize suspicious and executable regions
                priority = region.is_suspicious or region.is_executable
                
                if region.region_size <= self.MAX_REGION_SIZE:
                    memory_data = self.read_memory_region(
                        process_handle,
                        region.base_address,
                        region.region_size
                    )
                    
                    if memory_data:
                        self._scanned_size += len(memory_data)
                        result.total_memory_scanned += len(memory_data)
                        
                        # Extract strings
                        strings = self.extract_strings(memory_data)
                        
                        # Update addresses
                        for s in strings:
                            s.address = region.base_address + memory_data.find(s.value.encode()[:100]) if s.value else region.base_address
                        
                        all_strings.extend(strings)
                        
                        # Update progress
                        if progress_callback:
                            progress = 40 + int((i / len(regions)) * 40)
                            progress_callback(progress, 100, f"Scanning region {i+1}/{len(regions)}...")
            
            result.extracted_strings = all_strings
            
            # Step 4: Extract IOCs
            if progress_callback:
                progress_callback(85, 100, f"Extracting IOCs...")
            
            iocs = self.extract_iocs(all_strings, process_name, pid)
            result.iocs = iocs
            
            # Step 5: Get loaded modules
            if progress_callback:
                progress_callback(95, 100, f"Analyzing loaded modules...")
            
            if PSUTIL_AVAILABLE:
                try:
                    proc = psutil.Process(pid)
                    result.loaded_modules = [
                        {'path': dll.path, 'name': Path(dll.path).name if dll.path else ''}
                        for dll in proc.memory_maps() if dll.path
                    ]
                except:
                    pass
            
            if progress_callback:
                progress_callback(100, 100, f"Memory analysis complete for {process_name}")
            
        except Exception as e:
            logger.error(f"Error analyzing process {pid}: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        finally:
            if process_handle:
                self.kernel32.CloseHandle(process_handle)
        
        result.scan_duration = time.time() - start_time
        return result
    
    def analyze_network_process(self, pid: int, process_name: str,
                                progress_callback=None) -> ProcessMemoryInfo:
        """
        Analyze a network-connected process for IOCs.
        
        This is a specialized analysis for processes with network connections,
        focusing on extracting network-related artifacts from memory.
        
        Args:
            pid: Process ID
            process_name: Name of the process
            progress_callback: Optional callback for progress updates
        
        Returns:
            ProcessMemoryInfo with network-related IOCs
        """
        result = self.analyze_process(pid, progress_callback)
        
        # Filter IOCs to network-related ones
        network_ioc_types = {'URL', 'IP', 'DOMAIN', 'EMAIL'}
        network_iocs = [ioc for ioc in result.iocs if ioc.ioc_type in network_ioc_types]
        
        # Add additional network-related strings
        network_strings = [
            s for s in result.extracted_strings
            if s.string_type in {'URL', 'IP', 'DOMAIN', 'EMAIL', 'USER_AGENT', 'BASE64'}
        ]
        
        # Update result
        result.iocs = network_iocs
        result.extracted_strings = network_strings
        
        return result
    
    def quick_memory_scan(self, pid: int) -> Dict[str, Any]:
        """
        Perform a quick memory scan for suspicious patterns.
        
        This is a faster scan that only checks for injection and
        extracts high-confidence IOCs.
        
        Args:
            pid: Process ID
        
        Returns:
            Dictionary with scan results
        """
        result = {
            'pid': pid,
            'suspicious_regions': 0,
            'injections': [],
            'suspicious_strings': [],
            'is_suspicious': False
        }
        
        # Enable debug privilege
        if not self._debug_enabled:
            self._enable_debug_privilege()
        
        process_handle = None
        try:
            process_handle = self.kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False, pid
            )
            
            if not process_handle:
                return result
            
            # Enumerate regions
            regions = self.enumerate_memory_regions(process_handle, pid)
            
            # Count suspicious regions
            suspicious = [r for r in regions if r.is_suspicious]
            result['suspicious_regions'] = len(suspicious)
            
            # Quick injection check
            if PSUTIL_AVAILABLE:
                try:
                    proc = psutil.Process(pid)
                    process_name = proc.name()
                except:
                    process_name = f"PID-{pid}"
            else:
                process_name = f"PID-{pid}"
            
            injections = self.detect_injection(pid, process_handle, regions, process_name)
            result['injections'] = [
                {
                    'type': inj.injection_type,
                    'address': f'0x{inj.memory_address:X}',
                    'confidence': inj.confidence
                }
                for inj in injections
            ]
            
            # Quick string scan of suspicious regions
            for region in suspicious[:5]:  # Limit to first 5 suspicious regions
                memory_data = self.read_memory_region(
                    process_handle,
                    region.base_address,
                    min(region.region_size, 65536)  # Max 64KB per region
                )
                
                if memory_data:
                    strings = self.extract_strings(memory_data)
                    suspicious_strings = [s.value for s in strings if s.is_suspicious]
                    result['suspicious_strings'].extend(suspicious_strings)
            
            # Determine if process is suspicious
            result['is_suspicious'] = (
                result['suspicious_regions'] > 0 or
                len(result['injections']) > 0 or
                len(result['suspicious_strings']) > 3
            )
            
        except Exception as e:
            logger.debug(f"Quick scan error for PID {pid}: {e}")
        
        finally:
            if process_handle:
                self.kernel32.CloseHandle(process_handle)
        
        return result
    
    # ========================================================================
    # YARA Memory Scanning
    # ========================================================================
    
    def scan_memory_with_yara(self, pid: int, yara_rules=None,
                              progress_callback=None) -> List[Dict]:
        """
        Scan process memory with YARA rules.
        
        Args:
            pid: Process ID
            yara_rules: YARA rules object (from yara_manager)
            progress_callback: Optional callback for progress updates
        
        Returns:
            List of YARA match dictionaries
        """
        matches = []
        
        if not yara_rules:
            logger.warning("No YARA rules provided for memory scan")
            return matches
        
        # Enable debug privilege
        if not self._debug_enabled:
            self._enable_debug_privilege()
        
        process_handle = None
        try:
            process_handle = self.kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False, pid
            )
            
            if not process_handle:
                return matches
            
            # Enumerate regions
            regions = self.enumerate_memory_regions(process_handle, pid)
            
            total_regions = len(regions)
            for i, region in enumerate(regions):
                if self._cancel_flag:
                    break
                
                # Only scan committed, readable memory
                if region.state != 'COMMIT':
                    continue
                
                if progress_callback:
                    progress_callback(i, total_regions, 
                                    f"YARA scanning region {i+1}/{total_regions}...")
                
                # Skip very large regions
                if region.region_size > self.MAX_REGION_SIZE:
                    continue
                
                memory_data = self.read_memory_region(
                    process_handle,
                    region.base_address,
                    region.region_size
                )
                
                if memory_data:
                    try:
                        # Scan with YARA
                        yara_matches = yara_rules.match(data=memory_data)
                        
                        for match in yara_matches:
                            match_info = {
                                'rule': match.rule,
                                'namespace': getattr(match, 'namespace', ''),
                                'tags': list(match.tags) if hasattr(match, 'tags') else [],
                                'meta': dict(match.meta) if hasattr(match, 'meta') else {},
                                'strings': [],
                                'memory_address': f'0x{region.base_address:X}',
                                'region_size': region.region_size,
                                'process_id': pid
                            }
                            
                            # Add matched strings
                            for offset, identifier, data in match.strings:
                                match_info['strings'].append({
                                    'offset': offset,
                                    'identifier': identifier,
                                    'data': data[:100] if len(data) > 100 else data
                                })
                            
                            matches.append(match_info)
                    
                    except Exception as e:
                        logger.debug(f"YARA scan error in region: {e}")
        
        except Exception as e:
            logger.error(f"YARA memory scan error for PID {pid}: {e}")
        
        finally:
            if process_handle:
                self.kernel32.CloseHandle(process_handle)
        
        return matches
    
    # ========================================================================
    # Secure Cleanup
    # ========================================================================
    
    def secure_cleanup(self):
        """
        Securely clean up temporary files and sensitive data.
        """
        # Clear temp directory
        if self._temp_dir and os.path.exists(self._temp_dir):
            try:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
                self._temp_dir = None
            except Exception as e:
                logger.debug(f"Error cleaning temp directory: {e}")
        
        # Force garbage collection
        gc.collect()
        
        logger.info("Memory analyzer cleanup complete")
    
    def __del__(self):
        """Destructor - ensure cleanup."""
        try:
            self.secure_cleanup()
        except:
            pass


# ============================================================================
# Convenience Functions
# ============================================================================

def get_memory_analyzer() -> MemoryAnalyzer:
    """Get a MemoryAnalyzer instance."""
    return MemoryAnalyzer()


def is_memory_analysis_available() -> bool:
    """Check if memory analysis is available."""
    if sys.platform != 'win32':
        return False
    if not PSUTIL_AVAILABLE:
        return False
    return True
