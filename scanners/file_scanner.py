"""
CyberGuardian File Scanner Module
=================================
Scans files and folders for malicious indicators
using Yara, entropy analysis, PE analysis, and steganography detection.

Enhanced with Deep Analysis Mode for memory forensics of running files.
"""

import os
import math
import logging
import time
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import struct
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from scanners.base_scanner import (
    BaseScanner, ScanResult, ScanStatus, Detection, RiskLevel
)
from scanners.yara_manager import get_yara_manager, YaraMatch
from utils.whitelist import get_whitelist
from utils.config import get_config
from utils.logging_utils import get_logger, log_scan_start, log_scan_complete, log_detection
from threat_intel.intel import get_threat_intel

# Import memory analyzer for deep analysis
try:
    from scanners.memory_analyzer import MemoryAnalyzer, is_memory_analysis_available
    MEMORY_ANALYSIS_AVAILABLE = is_memory_analysis_available()
except ImportError:
    MEMORY_ANALYSIS_AVAILABLE = False
    logging.warning("Memory analyzer not available - file deep analysis will be limited")

logger = get_logger('scanners.file_scanner')


@dataclass
class FileInfo:
    """Information about a file."""
    path: Path
    name: str
    size: int
    extension: str
    mime_type: str
    entropy: float
    sha256: str
    md5: str
    is_pe: bool = False
    is_office: bool = False
    is_image: bool = False
    is_archive: bool = False
    is_whitelisted: bool = False
    has_macros: bool = False
    pe_info: Dict[str, Any] = field(default_factory=dict)


class EntropyCalculator:
    """Calculate entropy for data analysis."""
    
    @staticmethod
    def calculate(data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    @staticmethod
    def calculate_file(filepath: Path, chunk_size: int = 65536) -> float:
        """Calculate entropy of a file."""
        try:
            with open(filepath, 'rb') as f:
                data = f.read(chunk_size)
            return EntropyCalculator.calculate(data)
        except Exception:
            return 0.0
    
    @staticmethod
    def calculate_sections(filepath: Path, section_size: int = 1024) -> List[float]:
        """Calculate entropy for file sections."""
        entropies = []
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(section_size)
                    if not data:
                        break
                    entropies.append(EntropyCalculator.calculate(data))
        except Exception:
            pass
        return entropies


class PEAnalyzer:
    """Analyze PE (Portable Executable) files."""
    
    # Suspicious imports
    SUSPICIOUS_IMPORTS = {
        'VirtualAlloc': 'Memory allocation (common in malware)',
        'VirtualAllocEx': 'Remote memory allocation (process injection)',
        'WriteProcessMemory': 'Write to remote process (process injection)',
        'CreateRemoteThread': 'Create thread in remote process (injection)',
        'NtUnmapViewOfSection': 'Process hollowing',
        'QueueUserAPC': 'APC injection',
        'SetWindowsHookEx': 'Hook installation (keylogging)',
        'GetAsyncKeyState': 'Key state detection (keylogging)',
        'GetKeyState': 'Key state detection (keylogging)',
        'UrlDownloadToFile': 'File download',
        'InternetOpen': 'Internet access',
        'InternetOpenUrl': 'URL access',
        'InternetReadFile': 'Internet file reading',
        'WinHttpOpen': 'HTTP access',
        'ShellExecute': 'Command execution',
        'WinExec': 'Command execution',
        'CreateProcess': 'Process creation',
    }
    
    # Suspicious section names
    SUSPICIOUS_SECTIONS = {
        '.UPX': 'UPX packed',
        '.ASPack': 'ASPack packed',
        '.PCMP': 'PECompact packed',
        '.Themida': 'Themida protected',
        '.VMProt': 'VMProtect protected',
        '.vmp0': 'VMProtect protected',
        '.MPRESS': 'MPRESS packed',
        '.-packed': 'Packed executable',
    }
    
    @staticmethod
    def is_pe_file(filepath: Path) -> bool:
        """Check if file is a PE executable."""
        try:
            with open(filepath, 'rb') as f:
                dos_header = f.read(2)
                if dos_header != b'MZ':
                    return False
                
                # Check PE header
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset)
                pe_header = f.read(4)
                return pe_header == b'PE\x00\x00'
        except Exception:
            return False
    
    @staticmethod
    def analyze(filepath: Path) -> Dict[str, Any]:
        """Analyze PE file structure."""
        result = {
            'is_pe': False,
            'is_dll': False,
            'is_64bit': False,
            'sections': [],
            'imports': [],
            'suspicious_imports': [],
            'suspicious_sections': [],
            'entry_point': 0,
            'compile_time': None,
            'has_resources': False,
            'has_tls': False,
            'is_packed': False,
            'warnings': [],
        }
        
        try:
            import pefile
            pe = pefile.PE(str(filepath))
            
            result['is_pe'] = True
            result['is_dll'] = pe.is_dll()
            result['is_64bit'] = pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS
            result['entry_point'] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            
            # Compile timestamp
            if hasattr(pe.FILE_HEADER, 'TimeDateStamp'):
                timestamp = pe.FILE_HEADER.TimeDateStamp
                result['compile_time'] = datetime.utcfromtimestamp(timestamp).isoformat()
            
            # Analyze sections
            for section in pe.sections:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                entropy = section.get_entropy()
                
                section_info = {
                    'name': name,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'entropy': round(entropy, 2),
                }
                result['sections'].append(section_info)
                
                # Check for suspicious sections
                for sus_name, desc in PEAnalyzer.SUSPICIOUS_SECTIONS.items():
                    if sus_name.lower() in name.lower():
                        result['suspicious_sections'].append({
                            'section': name,
                            'reason': desc
                        })
                        result['is_packed'] = True
                
                # High entropy section (packed/encrypted)
                if entropy > 7.0:
                    result['warnings'].append(f"High entropy section: {name} ({entropy:.2f})")
                    result['is_packed'] = True
            
            # Analyze imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore')
                    
                    for imp in entry.imports:
                        if imp.name:
                            name = imp.name.decode('utf-8', errors='ignore')
                            result['imports'].append(f"{dll}!{name}")
                            
                            # Check suspicious imports
                            for sus_imp, desc in PEAnalyzer.SUSPICIOUS_IMPORTS.items():
                                if sus_imp.lower() == name.lower():
                                    result['suspicious_imports'].append({
                                        'import': name,
                                        'dll': dll,
                                        'reason': desc
                                    })
            
            # Check for resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                result['has_resources'] = True
            
            # Check for TLS
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                result['has_tls'] = True
                result['warnings'].append("TLS callbacks present (anti-debug)")
            
            pe.close()
            
        except ImportError:
            result['warnings'].append("pefile not available for detailed analysis")
        except Exception as e:
            result['warnings'].append(f"PE analysis error: {str(e)}")
        
        return result


class OfficeAnalyzer:
    """Analyze Office documents for malicious content."""
    
    @staticmethod
    def is_office_file(filepath: Path) -> bool:
        """Check if file is an Office document."""
        office_extensions = {
            '.doc', '.docx', '.docm', '.dot', '.dotm',
            '.xls', '.xlsx', '.xlsm', '.xlt', '.xltm',
            '.ppt', '.pptx', '.pptm', '.pot', '.potm',
            '.odt', '.ods', '.odp',
        }
        return filepath.suffix.lower() in office_extensions
    
    @staticmethod
    def analyze(filepath: Path) -> Dict[str, Any]:
        """Analyze Office document for malicious indicators."""
        result = {
            'is_office': True,
            'has_macros': False,
            'macro_suspicious': False,
            'embedded_objects': [],
            'external_links': [],
            'suspicious_strings': [],
            'warnings': [],
        }
        
        # Check for macro-enabled extension
        if filepath.suffix.lower() in ['.docm', '.xlsm', '.pptm', '.dotm', '.xltm', '.potm']:
            result['has_macros'] = True
            result['warnings'].append("Macro-enabled document")
        
        try:
            import olefile
            
            # Check if it's an OLE file (older formats)
            if olefile.isOleFile(str(filepath)):
                ole = olefile.OleFileIO(str(filepath))
                
                # Check for VBA macros
                if ole.exists('Macros') or ole.exists('VBA'):
                    result['has_macros'] = True
                    result['warnings'].append("VBA macros detected in OLE file")
                
                # List streams
                for stream in ole.listdir():
                    stream_name = '/'.join(stream)
                    if any(s in stream_name.lower() for s in ['macro', 'vba', 'code']):
                        result['suspicious_strings'].append(f"Stream: {stream_name}")
                
                ole.close()
        
        except ImportError:
            result['warnings'].append("olefile not available for OLE analysis")
        except Exception as e:
            result['warnings'].append(f"OLE analysis error: {str(e)}")
        
        # Try oletools for deeper analysis
        try:
            import oletools.olevba
            import oletools.msodde
            
            vba = oletools.olevba.VBA_Parser(str(filepath))
            
            if vba.detect_vba_macros():
                result['has_macros'] = True
                
                # Extract and analyze macros
                for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
                    if vba_code:
                        result['suspicious_strings'].append(f"Macro in {vba_filename}")
                        
                        # Check for suspicious VBA patterns
                        suspicious_patterns = [
                            ('CreateObject', 'COM object creation'),
                            ('Shell', 'Shell command execution'),
                            ('WScript', 'Windows Script Host'),
                            ('PowerShell', 'PowerShell execution'),
                            ('DownloadFile', 'File download'),
                            ('URLDownload', 'URL download'),
                            ('AutoOpen', 'Auto-execution'),
                            ('Document_Open', 'Auto-execution'),
                            ('Workbook_Open', 'Auto-execution'),
                        ]
                        
                        for pattern, desc in suspicious_patterns:
                            if pattern.lower() in vba_code.lower():
                                result['macro_suspicious'] = True
                                result['suspicious_strings'].append(
                                    f"Suspicious: {desc} in {vba_filename}"
                                )
            
            vba.close()
            
        except ImportError:
            result['warnings'].append("oletools not available for macro analysis")
        except Exception as e:
            result['warnings'].append(f"Macro analysis error: {str(e)}")
        
        return result


class SteganographyDetector:
    """
    Advanced steganography detection in images and media files.
    
    Detection Methods:
    - Multi-layer LSB analysis (1-bit, 2-bit, 4-bit planes)
    - EOF appended data detection
    - Known steganography tool signatures
    - Hidden data extraction and analysis
    - Malicious content detection in extracted data
    """
    
    IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}
    
    # Known steganography tool signatures/magic bytes
    STEGO_SIGNATURES = {
        b'STEG': 'OpenStego',
        b'stego': 'Generic Stego Tool',
        b'\\\\x89PNG\\\\r\\\\n\\\\x1a\\\\n': 'PNG with hidden data',
        b'PK\\x03\\x04': 'ZIP archive appended (possible hidden content)',
        b'Rar!': 'RAR archive appended',
        b'\\x1f\\x8b': 'GZIP data appended',
        b'BZh': 'BZIP2 data appended',
        b'\\x50\\x4b\\x03\\x04': 'ZIP embedded in image',
    }
    
    # EOF markers for different image formats
    EOF_MARKERS = {
        '.jpg': [b'\\xff\\xd9'],  # JPEG EOI marker
        '.jpeg': [b'\\xff\\xd9'],
        '.png': [b'IEND\\xae\\x42\\x60\\x82'],  # PNG IEND chunk
        '.gif': [b'\\x00\\x3b'],  # GIF trailer
        '.bmp': [],  # BMP has size in header
    }
    
    # Suspicious strings to detect in extracted data
    MALICIOUS_PATTERNS = [
        # URLs and network indicators
        (rb'https?://[^\s<>"{}|\\^`\[\]]+', 'URL'),
        (rb'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', 'IP Address'),
        (rb'[a-zA-Z0-9-]+\.(com|net|org|io|tk|ml|ga|cf|onion)', 'Domain'),
        
        # Executable indicators
        (rb'MZ\\x90\\x00', 'PE Executable header'),
        (rb'\\x7fELF', 'ELF Executable header'),
        (rb'\\xca\\xfe\\xba\\xbe', 'Mach-O Executable'),
        (rb'PK\\x03\\x04', 'ZIP/Archive (could contain malware)'),
        
        # Script indicators
        (rb'<script', 'JavaScript code'),
        (rb'#!/bin/', 'Shell script'),
        (rb'#!/usr/bin/python', 'Python script'),
        (rb'powershell', 'PowerShell reference'),
        (rb'cmd\.exe', 'CMD reference'),
        (rb'wscript', 'Windows Script Host'),
        
        # Malware-related strings
        (rb'mimikatz', 'Mimikatz reference'),
        (rb'meterpreter', 'Meterpreter reference'),
        (rb'cobalt\s*strike', 'Cobalt Strike'),
        (rb'reverse\s*shell', 'Reverse shell'),
        (rb'backdoor', 'Backdoor reference'),
        (rb'keylog', 'Keylogger reference'),
        (rb'password', 'Password reference'),
        (rb'credential', 'Credential reference'),
        
        # Base64 patterns (long strings that could be encoded data)
        (rb'[A-Za-z0-9+/=]{40,}', 'Possible Base64 encoded data'),
        
        # Crypto addresses
        (rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', 'Bitcoin address'),
        (rb'0x[a-fA-F0-9]{40}', 'Ethereum address'),
    ]
    
    # Suspicious file signatures that might be hidden
    HIDDEN_FILE_SIGNATURES = {
        b'MZ': 'Windows Executable (.exe)',
        b'PK': 'ZIP Archive',
        b'Rar!': 'RAR Archive',
        b'\\x7fELF': 'Linux Executable',
        b'%PDF': 'PDF Document',
        b'\\xd0\\xcf\\x11\\xe0': 'MS Office Document',
    }
    
    @staticmethod
    def is_image_file(filepath: Path) -> bool:
        """Check if file is an image."""
        return filepath.suffix.lower() in SteganographyDetector.IMAGE_EXTENSIONS
    
    @classmethod
    def analyze(cls, filepath: Path, max_extract_size: int = 1024 * 1024) -> Dict[str, Any]:
        """
        Perform comprehensive steganography analysis on an image.
        
        Args:
            filepath: Path to the image file
            max_extract_size: Maximum bytes to extract for analysis
            
        Returns:
            Dictionary with analysis results including:
            - has_steganography: bool
            - confidence: float (0.0-1.0)
            - threat_level: str ('clean', 'suspicious', 'malicious')
            - detection_methods: list of methods that detected steganography
            - extracted_data: analysis of any extracted hidden content
            - lsb_analysis: detailed LSB analysis results
            - eof_analysis: appended data analysis
            - warnings: list of warning messages
        """
        result = {
            'is_image': True,
            'has_steganography': False,
            'confidence': 0.0,
            'threat_level': 'clean',
            'detection_methods': [],
            'lsb_analysis': {},
            'eof_analysis': {},
            'extracted_data': {},
            'entropy_analysis': {},
            'warnings': [],
            'indicators': [],
        }
        
        try:
            # Read image data
            with open(filepath, 'rb') as f:
                image_data = f.read()
            
            file_size = len(image_data)
            
            # Run all detection methods
            lsb_result = cls._analyze_lsb(image_data)
            if lsb_result['detected']:
                result['has_steganography'] = True
                result['detection_methods'].append('lsb_analysis')
                result['lsb_analysis'] = lsb_result
            
            eof_result = cls._analyze_eof_appended(filepath, image_data)
            if eof_result['detected']:
                result['has_steganography'] = True
                result['detection_methods'].append('eof_appended')
                result['eof_analysis'] = eof_result
            
            # Entropy analysis
            entropy = EntropyCalculator.calculate(image_data[:min(len(image_data), 65536)])
            result['entropy_analysis'] = {
                'overall': round(entropy, 2),
                'high_entropy': entropy > 7.8
            }
            
            if entropy > 7.8:
                result['warnings'].append(f"High entropy ({entropy:.2f}) - possible encrypted/hidden data")
            
            # If steganography detected, try to extract and analyze hidden data
            if result['has_steganography']:
                extracted = cls._extract_and_analyze(filepath, image_data, lsb_result, eof_result)
                result['extracted_data'] = extracted
                
                # Determine threat level based on extracted content
                if extracted.get('is_malicious'):
                    result['threat_level'] = 'malicious'
                    result['confidence'] = 0.9
                elif extracted.get('is_suspicious'):
                    result['threat_level'] = 'suspicious'
                    result['confidence'] = 0.7
                else:
                    result['threat_level'] = 'suspicious'
                    result['confidence'] = 0.5
                
                # Collect indicators
                result['indicators'] = extracted.get('indicators', [])
                
        except Exception as e:
            result['warnings'].append(f"Steganography analysis error: {str(e)}")
        
        return result
    
    @classmethod
    def _analyze_lsb(cls, data: bytes) -> Dict[str, Any]:
        """
        Perform multi-layer LSB analysis on image data.
        
        Analyzes 1-bit, 2-bit, and 4-bit LSB planes for hidden data patterns.
        """
        result = {
            'detected': False,
            'confidence': 0.0,
            'plane_1': {},
            'plane_2': {},
            'plane_4': {},
            'patterns_found': [],
        }
        
        if len(data) < 1024:
            return result
        
        sample_size = min(len(data), 65536)  # Analyze up to 64KB
        sample = data[:sample_size]
        
        # 1-bit LSB analysis (least significant bit)
        lsb_bits = []
        for byte in sample:
            lsb_bits.append(byte & 0x01)
        
        ones_count = sum(lsb_bits)
        zeros_count = len(lsb_bits) - ones_count
        
        # Chi-square test for randomness
        expected = len(lsb_bits) / 2
        chi_square = ((ones_count - expected) ** 2 + (zeros_count - expected) ** 2) / expected
        
        # Balanced LSB indicates possible hidden data
        ratio = ones_count / (zeros_count + 1)
        is_balanced = 0.45 < ratio < 1.55
        
        result['plane_1'] = {
            'ones': ones_count,
            'zeros': zeros_count,
            'ratio': round(ratio, 3),
            'chi_square': round(chi_square, 3),
            'is_balanced': is_balanced,
            'randomness': round(1 - min(chi_square / 100, 1), 3)  # Higher = more random
        }
        
        if is_balanced and chi_square < 10:
            result['patterns_found'].append('Balanced 1-bit LSB pattern')
            result['confidence'] += 0.3
        
        # 2-bit LSB analysis (2 least significant bits)
        lsb2_values = []
        for byte in sample:
            lsb2_values.append(byte & 0x03)
        
        # Check distribution of 2-bit values (should be uniform if hidden data)
        value_counts = [0] * 4
        for v in lsb2_values:
            value_counts[v] += 1
        
        expected_2bit = len(lsb2_values) / 4
        chi_square_2bit = sum((c - expected_2bit) ** 2 for c in value_counts) / expected_2bit
        
        result['plane_2'] = {
            'distribution': value_counts,
            'chi_square': round(chi_square_2bit, 3),
            'is_uniform': chi_square_2bit < 20
        }
        
        if chi_square_2bit < 20:
            result['patterns_found'].append('Uniform 2-bit LSB pattern')
            result['confidence'] += 0.2
        
        # Check for sequential patterns in LSB (could indicate structured data)
        sequential_runs = cls._count_sequential_runs(lsb_bits)
        result['plane_1']['sequential_runs'] = sequential_runs
        
        # High number of alternating bits suggests encoded data
        if sequential_runs.get('alternating', 0) > len(lsb_bits) * 0.3:
            result['patterns_found'].append('High alternating bit pattern')
            result['confidence'] += 0.2
        
        # Detect if there's readable content in LSB
        lsb_extracted = cls._extract_lsb_bytes(sample, bits=1)
        readable_ratio = cls._check_readable_content(lsb_extracted)
        
        result['plane_1']['readable_ratio'] = round(readable_ratio, 3)
        
        if readable_ratio > 0.1:  # More than 10% readable ASCII
            result['patterns_found'].append(f'Readable content in LSB ({readable_ratio:.1%})')
            result['confidence'] += 0.3
        
        result['detected'] = result['confidence'] >= 0.4 or len(result['patterns_found']) >= 2
        
        return result
    
    @staticmethod
    def _count_sequential_runs(bits: List[int]) -> Dict[str, int]:
        """Count different types of sequential patterns in bit sequence."""
        runs = {
            'zeros': 0,
            'ones': 0,
            'alternating': 0,
        }
        
        if len(bits) < 2:
            return runs
        
        current_run = 1
        last_bit = bits[0]
        is_alternating = True
        
        for i in range(1, len(bits)):
            if bits[i] == last_bit:
                current_run += 1
                is_alternating = False
            else:
                if current_run >= 4:
                    if last_bit == 0:
                        runs['zeros'] += 1
                    else:
                        runs['ones'] += 1
                current_run = 1
                last_bit = bits[i]
            
            # Check alternating pattern
            if i >= 2 and bits[i] != bits[i-1] and bits[i-1] != bits[i-2]:
                runs['alternating'] += 1
        
        return runs
    
    @staticmethod
    def _extract_lsb_bytes(data: bytes, bits: int = 1) -> bytes:
        """Extract bytes from LSB plane."""
        result = bytearray()
        
        if bits == 1:
            # Extract 1 bit from each byte to form new bytes
            for i in range(0, len(data) - 7, 8):
                byte_val = 0
                for j in range(8):
                    byte_val |= ((data[i + j] & 0x01) << (7 - j))
                result.append(byte_val)
        
        elif bits == 2:
            # Extract 2 bits from each byte
            for i in range(0, len(data) - 3, 4):
                byte_val = 0
                for j in range(4):
                    byte_val |= ((data[i + j] & 0x03) << (6 - j * 2))
                result.append(byte_val)
        
        return bytes(result)
    
    @staticmethod
    def _check_readable_content(data: bytes) -> float:
        """Check ratio of readable ASCII/printable characters."""
        if not data:
            return 0.0
        
        readable_count = 0
        for byte in data:
            # Printable ASCII range (32-126) plus common whitespace
            if 32 <= byte <= 126 or byte in (9, 10, 13):
                readable_count += 1
        
        return readable_count / len(data)
    
    @classmethod
    def _analyze_eof_appended(cls, filepath: Path, data: bytes) -> Dict[str, Any]:
        """
        Check for data appended after the end of image marker.
        
        This is a common steganography technique where data is simply
        appended after the legitimate image data ends.
        """
        result = {
            'detected': False,
            'appended_size': 0,
            'appended_data_preview': '',
            'file_type': '',
        }
        
        ext = filepath.suffix.lower()
        eof_markers = cls.EOF_MARKERS.get(ext, [])
        
        if not eof_markers:
            return result
        
        # Find the last occurrence of EOF marker
        last_eof_pos = -1
        for marker in eof_markers:
            pos = data.rfind(marker)
            if pos > last_eof_pos:
                last_eof_pos = pos + len(marker)
        
        if last_eof_pos > 0 and last_eof_pos < len(data):
            # Data exists after EOF marker
            appended = data[last_eof_pos:]
            
            if len(appended) > 4:  # Minimum threshold
                result['detected'] = True
                result['appended_size'] = len(appended)
                
                # Preview of appended data (hex and readable)
                preview_len = min(len(appended), 256)
                result['appended_data_preview'] = appended[:preview_len].hex()
                
                # Check for known file signatures in appended data
                for sig, file_type in cls.HIDDEN_FILE_SIGNATURES.items():
                    if appended.startswith(sig):
                        result['file_type'] = file_type
                        break
                
                # Check for embedded archives
                for sig, name in [(b'PK\\x03\\x04', 'ZIP'), (b'Rar!', 'RAR'), (b'\\x1f\\x8b', 'GZIP')]:
                    if sig in appended[:1024]:
                        result['file_type'] = f'{name} archive'
                        break
        
        return result
    
    @classmethod
    def _extract_and_analyze(cls, filepath: Path, image_data: bytes,
                             lsb_result: Dict, eof_result: Dict) -> Dict[str, Any]:
        """
        Extract hidden data and analyze it for malicious content.
        
        Returns analysis of extracted content including:
        - is_malicious: bool
        - is_suspicious: bool
        - content_type: str
        - indicators: list of detected indicators
        - extracted_preview: preview of extracted data
        """
        result = {
            'is_malicious': False,
            'is_suspicious': False,
            'content_type': 'unknown',
            'indicators': [],
            'extracted_preview': '',
            'extracted_size': 0,
        }
        
        extracted_data = bytearray()
        
        # Try to extract from LSB
        if lsb_result.get('detected'):
            lsb_extracted = cls._extract_lsb_bytes(image_data[:min(len(image_data), 100000)], bits=1)
            extracted_data.extend(lsb_extracted[:10240])  # Limit extraction size
        
        # Add EOF appended data
        if eof_result.get('detected') and eof_result.get('appended_size', 0) > 0:
            ext = filepath.suffix.lower()
            eof_markers = cls.EOF_MARKERS.get(ext, [])
            
            last_eof_pos = -1
            for marker in eof_markers:
                pos = image_data.rfind(marker)
                if pos > last_eof_pos:
                    last_eof_pos = pos + len(marker)
            
            if last_eof_pos > 0:
                appended = image_data[last_eof_pos:]
                extracted_data.extend(appended[:10240])
        
        if not extracted_data:
            return result
        
        result['extracted_size'] = len(extracted_data)
        result['extracted_preview'] = extracted_data[:512].hex()
        
        # Convert to string for pattern matching
        try:
            extracted_str = extracted_data.decode('latin-1')  # Safe decoding
        except:
            extracted_str = str(extracted_data)
        
        # Check for malicious patterns
        import re
        for pattern, indicator_name in cls.MALICIOUS_PATTERNS:
            try:
                matches = re.findall(pattern, extracted_data + extracted_str.encode('latin-1', errors='ignore'))
                if matches:
                    result['indicators'].append({
                        'type': indicator_name,
                        'count': len(matches),
                        'sample': str(matches[:3])[:100]  # First 3 matches, truncated
                    })
                    
                    # Determine threat level
                    if indicator_name in ['PE Executable header', 'ELF Executable header', 
                                          'Mach-O Executable', 'Mimikatz reference',
                                          'Meterpreter reference', 'Cobalt Strike']:
                        result['is_malicious'] = True
                    elif indicator_name in ['URL', 'IP Address', 'Possible Base64 encoded data',
                                           'PowerShell reference', 'Reverse shell', 'Backdoor reference']:
                        result['is_suspicious'] = True
            except Exception:
                continue
        
        # Check for file signatures
        for sig, file_type in cls.HIDDEN_FILE_SIGNATURES.items():
            if bytes(extracted_data).startswith(sig):
                result['indicators'].append({
                    'type': 'Embedded File',
                    'file_type': file_type,
                    'count': 1
                })
                result['is_suspicious'] = True
                result['content_type'] = file_type
                break
        
        # Determine overall content type
        if not result['indicators']:
            readable_ratio = cls._check_readable_content(bytes(extracted_data))
            if readable_ratio > 0.3:
                result['content_type'] = 'text'
            else:
                result['content_type'] = 'binary'
        
        return result


class FileScanner(BaseScanner):
    """
    Scanner for analyzing files and directories.
    
    Detection Methods:
    - Yara static scanning
    - Entropy analysis
    - PE file analysis
    - Office document analysis
    - Steganography detection
    - Hash lookup
    
    Deep Analysis Mode:
    - Memory analysis of running executables
    - IOC extraction from process memory
    - Injection detection in running files
    """
    
    # Maximum file size to scan (100 MB)
    MAX_FILE_SIZE = 100 * 1024 * 1024
    
    # High entropy threshold
    HIGH_ENTROPY_THRESHOLD = 7.0
    
    # Archive extensions
    ARCHIVE_EXTENSIONS = {'.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz', '.cab'}
    
    # Executable extensions for memory analysis
    EXECUTABLE_EXTENSIONS = {'.exe', '.dll', '.sys', '.com', '.scr'}
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.whitelist = get_whitelist()
        self.yara_manager = get_yara_manager()
        self.threat_intel = get_threat_intel()
        self._deep_analysis = False
        self._memory_analyzer = None
    
    @property
    def scanner_name(self) -> str:
        return "File Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "file"
    
    def scan(self, target: Optional[str] = None, deep_analysis: bool = False) -> ScanResult:
        """
        Scan files or directories.
        
        Args:
            target: File path or directory path to scan
            deep_analysis: Enable memory analysis for running executables
        
        Returns:
            ScanResult with file analysis findings
        """
        target_path = Path(target) if target else Path.cwd()
        
        log_scan_start('file', str(target_path))
        
        self._deep_analysis = deep_analysis
        
        # Initialize memory analyzer for deep analysis
        if deep_analysis and MEMORY_ANALYSIS_AVAILABLE:
            try:
                self._memory_analyzer = MemoryAnalyzer()
                self.logger.info("Memory analyzer initialized for file deep analysis")
            except Exception as e:
                self.logger.warning(f"Could not initialize memory analyzer: {e}")
                self._memory_analyzer = None
        
        result = ScanResult(
            scan_type='file',
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target=str(target_path)
        )
        
        self.reset_cancel()
        
        try:
            # Collect files to scan
            files = self._collect_files(target_path)
            result.total_items = len(files)
            
            self.logger.info(f"Scanning {len(files)} files (deep_analysis={deep_analysis})")
            
            # Scan each file
            for i, filepath in enumerate(files):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                
                self._report_progress(i + 1, len(files), f"Analyzing {filepath.name}")
                
                # Get file info
                file_info = self._get_file_info(filepath)
                
                if not file_info:
                    continue
                
                # Skip whitelisted
                if file_info.is_whitelisted:
                    result.clean_items += 1
                    continue
                
                # Run detections
                detections = self._analyze_file(file_info)
                
                for detection in detections:
                    result.add_detection(detection)
                    self._report_detection(detection)
                    log_detection(
                        detection_type=detection.detection_type,
                        indicator=detection.indicator,
                        risk_level=detection.risk_level.value,
                        description=detection.description
                    )
                
                # Deep analysis: Memory analysis for running executables
                if deep_analysis and self._memory_analyzer and filepath.suffix.lower() in self.EXECUTABLE_EXTENSIONS:
                    memory_detections = self._analyze_running_file_memory(filepath, detections)
                    for detection in memory_detections:
                        result.add_detection(detection)
                        self._report_detection(detection)
                        log_detection(
                            detection_type=detection.detection_type,
                            indicator=detection.indicator,
                            risk_level=detection.risk_level.value,
                            description=detection.description
                        )
                
                if not detections:
                    result.clean_items += 1
            
            result.status = ScanStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"File scan error: {e}")
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
        
        finally:
            # Cleanup memory analyzer
            if self._memory_analyzer:
                try:
                    self._memory_analyzer.secure_cleanup()
                except:
                    pass
        
        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        log_scan_complete('file', result.scan_target, len(result.detections))
        
        return result
    
    def _find_processes_for_file(self, filepath: Path) -> List[Dict[str, Any]]:
        """Find all processes running from a specific file."""
        processes = []
        
        try:
            import psutil
            
            file_path_str = str(filepath.resolve()).lower()
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_exe = proc.info.get('exe', '')
                    if proc_exe and proc_exe.lower() == file_path_str:
                        processes.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'exe': proc_exe
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        
        except ImportError:
            self.logger.debug("psutil not available for process enumeration")
        
        return processes
    
    def _analyze_running_file_memory(self, filepath: Path, existing_detections: List[Detection]) -> List[Detection]:
        """
        Analyze memory of processes running this file.
        
        Args:
            filepath: Path to the executable file
            existing_detections: Detections from static analysis
        
        Returns:
            List of additional detections from memory analysis
        """
        detections = []
        
        if not self._memory_analyzer:
            return detections
        
        # Find processes running this file
        running_processes = self._find_processes_for_file(filepath)
        
        if not running_processes:
            return detections
        
        self.logger.info(f"Found {len(running_processes)} running processes for {filepath.name}")
        
        for proc_info in running_processes[:3]:  # Limit to 3 processes
            if self.is_cancelled():
                break
            
            pid = proc_info['pid']
            process_name = proc_info['name']
            
            try:
                # Perform memory analysis
                memory_result = self._memory_analyzer.analyze_process(pid)
                
                # Check for code injection
                for injection in memory_result.injected_code:
                    risk_level = RiskLevel.HIGH if injection.confidence >= 0.7 else RiskLevel.MEDIUM
                    
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type=f'file_memory_{injection.injection_type.lower()}',
                        indicator=f"{filepath.name} (PID: {pid})",
                        indicator_type='file',
                        risk_level=risk_level,
                        confidence=injection.confidence,
                        description=f"Code injection in running file {filepath.name}: {injection.injection_type}",
                        detection_reason=f"{injection.injection_type} detected at 0x{injection.memory_address:X} in process {pid}",
                        remediation=[
                            f"Terminate process (PID: {pid})",
                            f"Quarantine file: {filepath}",
                            "Scan system for additional malware",
                            "Investigate process origin"
                        ],
                        file_path=str(filepath),
                        process_name=process_name,
                        process_id=pid,
                        evidence={
                            'injection_type': injection.injection_type,
                            'memory_address': f'0x{injection.memory_address:X}',
                            'region_size': injection.region_size,
                            'protection': injection.protection,
                            'pid': pid,
                            'confidence': injection.confidence,
                            **injection.evidence
                        }
                    )
                    detections.append(detection)
                
                # Check for suspicious IOCs in memory
                for ioc in memory_result.iocs:
                    if ioc.confidence >= 0.7:
                        detection = Detection(
                            detection_id=self._generate_detection_id(),
                            detection_type=f'file_memory_ioc_{ioc.ioc_type.lower()}',
                            indicator=ioc.value,
                            indicator_type='network' if ioc.ioc_type in ['URL', 'IP', 'DOMAIN'] else 'string',
                            risk_level=RiskLevel.MEDIUM if ioc.confidence >= 0.8 else RiskLevel.LOW,
                            confidence=ioc.confidence,
                            description=f"IOC found in {filepath.name} memory: {ioc.value[:50]}",
                            detection_reason=f"Extracted from process memory at 0x{ioc.memory_address:X}",
                            remediation=[
                                f"Investigate {ioc.ioc_type}: {ioc.value}",
                                f"Analyze running process (PID: {pid})",
                                "Check for data exfiltration"
                            ],
                            file_path=str(filepath),
                            process_name=process_name,
                            process_id=pid,
                            evidence={
                                'ioc_type': ioc.ioc_type,
                                'ioc_value': ioc.value,
                                'memory_address': f'0x{ioc.memory_address:X}',
                                'context': ioc.context[:200] if ioc.context else '',
                                'pid': pid
                            }
                        )
                        detections.append(detection)
                
                # Check for suspicious memory regions
                if memory_result.suspicious_regions:
                    for region in memory_result.suspicious_regions[:3]:
                        detection = Detection(
                            detection_id=self._generate_detection_id(),
                            detection_type='file_memory_suspicious_region',
                            indicator=f"{filepath.name}:0x{region.base_address:X}",
                            indicator_type='file',
                            risk_level=RiskLevel.MEDIUM,
                            confidence=0.6,
                            description=f"Suspicious memory region in {filepath.name}: {', '.join(region.suspicion_reasons)}",
                            detection_reason=f"Memory region at 0x{region.base_address:X} shows suspicious characteristics",
                            remediation=[
                                f"Investigate process (PID: {pid})",
                                "Check for code injection",
                                f"Analyze memory at 0x{region.base_address:X}"
                            ],
                            file_path=str(filepath),
                            process_name=process_name,
                            process_id=pid,
                            evidence={
                                'base_address': f'0x{region.base_address:X}',
                                'region_size': region.region_size,
                                'protection': region.protection,
                                'memory_type': region.memory_type,
                                'reasons': region.suspicion_reasons,
                                'pid': pid
                            }
                        )
                        detections.append(detection)
            
            except Exception as e:
                self.logger.debug(f"Memory analysis error for {filepath.name} PID {pid}: {e}")
        
        return detections
    
    def _collect_files(self, target: Path) -> List[Path]:
        """Collect all files to scan from target path."""
        files = []
        
        if target.is_file():
            files.append(target)
        elif target.is_dir():
            for root, _, filenames in os.walk(target):
                for filename in filenames:
                    try:
                        filepath = Path(root) / filename
                        files.append(filepath)
                    except Exception:
                        continue
        
        # Filter by size
        files = [f for f in files if f.exists() and f.stat().st_size <= self.MAX_FILE_SIZE]
        
        return files
    
    def _get_file_info(self, filepath: Path) -> Optional[FileInfo]:
        """Get comprehensive file information."""
        try:
            stat = filepath.stat()
            
            # Calculate hashes
            sha256 = self.threat_intel.calculate_file_hash(filepath, 'sha256')
            md5 = self.threat_intel.calculate_file_hash(filepath, 'md5')
            
            # Calculate entropy
            entropy = EntropyCalculator.calculate_file(filepath)
            
            # Check whitelist
            is_whitelisted = (
                self.whitelist.is_whitelisted(str(filepath), 'path') or
                self.whitelist.is_whitelisted(sha256, 'hash') if sha256 else False
            )
            
            return FileInfo(
                path=filepath,
                name=filepath.name,
                size=stat.st_size,
                extension=filepath.suffix.lower(),
                mime_type=self._get_mime_type(filepath),
                entropy=entropy,
                sha256=sha256 or '',
                md5=md5 or '',
                is_pe=PEAnalyzer.is_pe_file(filepath),
                is_office=OfficeAnalyzer.is_office_file(filepath),
                is_image=SteganographyDetector.is_image_file(filepath),
                is_archive=filepath.suffix.lower() in self.ARCHIVE_EXTENSIONS,
                is_whitelisted=is_whitelisted,
            )
        
        except Exception as e:
            self.logger.debug(f"Error getting file info for {filepath}: {e}")
            return None
    
    def _get_mime_type(self, filepath: Path) -> str:
        """Get MIME type of file."""
        try:
            import mimetypes
            mime_type, _ = mimetypes.guess_type(str(filepath))
            return mime_type or 'application/octet-stream'
        except Exception:
            return 'application/octet-stream'
    
    def _analyze_file(self, file_info: FileInfo) -> List[Detection]:
        """Run all detection checks on a file."""
        detections = []
        
        detection_methods = [
            self._check_yara_rules,
            self._check_entropy,
            self._check_hash_reputation,
            self._check_pe_file,
            self._check_office_document,
            self._check_steganography,
        ]
        
        for method in detection_methods:
            if self.is_cancelled():
                break
            
            try:
                method_detections = method(file_info)
                detections.extend(method_detections)
            except Exception as e:
                self.logger.debug(f"Detection method error: {e}")
        
        return detections
    
    def _check_yara_rules(self, file_info: FileInfo) -> List[Detection]:
        """Check file against Yara rules."""
        detections = []
        
        yara_matches = self.yara_manager.scan_file(file_info.path)
        
        if yara_matches:
            critical_matches = [m for m in yara_matches if m.severity == 'critical']
            high_matches = [m for m in yara_matches if m.severity == 'high']
            medium_matches = [m for m in yara_matches if m.severity == 'medium']
            
            if critical_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_critical',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.CRITICAL,
                    confidence=0.95,
                    description=f"Critical malware signature: {', '.join(m.rule for m in critical_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in critical_matches)}",
                    remediation=[
                        f"Quarantine file: {file_info.path}",
                        "Delete file after verification",
                        "Run full system scan",
                        "Check for related malware components"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in critical_matches],
                        'sha256': file_info.sha256,
                        'entropy': file_info.entropy
                    }
                )
                detections.append(detection)
            
            elif high_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_high',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    description=f"Malicious patterns: {', '.join(m.rule for m in high_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in high_matches)}",
                    remediation=[
                        f"Quarantine file: {file_info.path}",
                        "Analyze file in sandbox",
                        "Verify file source"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in high_matches],
                        'sha256': file_info.sha256
                    }
                )
                detections.append(detection)
            
            elif medium_matches:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='yara_medium',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.7,
                    description=f"Suspicious patterns: {', '.join(m.rule for m in medium_matches)}",
                    detection_reason=f"Yara rules matched: {', '.join(m.rule for m in medium_matches)}",
                    remediation=[
                        "Investigate file purpose",
                        "Verify file legitimacy"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'yara_matches': [{'rule': m.rule, 'meta': m.meta} for m in medium_matches]
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_entropy(self, file_info: FileInfo) -> List[Detection]:
        """Check for high entropy (packed/encrypted content)."""
        detections = []
        
        if file_info.entropy > self.HIGH_ENTROPY_THRESHOLD:
            # Only flag non-image files for high entropy
            if not file_info.is_image and not file_info.is_archive:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='high_entropy',
                    indicator=file_info.name,
                    indicator_type='file',
                    risk_level=RiskLevel.LOW,
                    confidence=0.5,
                    description=f"High entropy file ({file_info.entropy:.2f}) - possible packed/encrypted content",
                    detection_reason="High Shannon entropy indicates packed or encrypted data",
                    remediation=[
                        "Analyze file with appropriate tools",
                        "Check if file is legitimate encrypted archive",
                        "Scan with anti-malware"
                    ],
                    file_path=str(file_info.path),
                    evidence={
                        'entropy': file_info.entropy,
                        'threshold': self.HIGH_ENTROPY_THRESHOLD
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_hash_reputation(self, file_info: FileInfo) -> List[Detection]:
        """Check file hash against threat intelligence."""
        detections = []
        
        if not file_info.sha256:
            return detections
        
        hash_result = self.threat_intel.lookup_hash(file_info.sha256, use_online=True)
        
        if hash_result.is_malicious and hash_result.confidence in ['high', 'medium']:
            risk_level = RiskLevel.CRITICAL if hash_result.confidence == 'high' else RiskLevel.HIGH
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='hash_malicious',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=risk_level,
                confidence=0.9 if hash_result.confidence == 'high' else 0.7,
                description=f"Malicious file hash: {hash_result.detection_ratio}",
                detection_reason=f"Threat intelligence match: {', '.join(hash_result.threat_names[:3])}",
                remediation=[
                    f"Delete file: {file_info.path}",
                    "Quarantine and investigate",
                    "Run full system scan",
                    "Check for related infections"
                ],
                file_path=str(file_info.path),
                evidence={
                    'sha256': file_info.sha256,
                    'md5': file_info.md5,
                    'detection_ratio': hash_result.detection_ratio,
                    'threat_names': hash_result.threat_names,
                    'source': hash_result.source
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_pe_file(self, file_info: FileInfo) -> List[Detection]:
        """Analyze PE executable files."""
        detections = []
        
        if not file_info.is_pe:
            return detections
        
        pe_result = PEAnalyzer.analyze(file_info.path)
        file_info.pe_info = pe_result
        
        # Check for packed executable
        if pe_result.get('is_packed'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='pe_packed',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description="Packed or obfuscated executable detected",
                detection_reason=f"Packing indicators: {', '.join(str(s) for s in pe_result.get('suspicious_sections', []))}",
                remediation=[
                    "Unpack executable for analysis",
                    "Scan with anti-malware",
                    f"Quarantine file: {file_info.path}"
                ],
                file_path=str(file_info.path),
                evidence={
                    'packed': True,
                    'suspicious_sections': pe_result.get('suspicious_sections', []),
                    'warnings': pe_result.get('warnings', [])
                }
            )
            detections.append(detection)
        
        # Check for suspicious imports
        suspicious_imports = pe_result.get('suspicious_imports', [])
        if len(suspicious_imports) >= 3:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='pe_suspicious_imports',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                description=f"Multiple suspicious imports: {len(suspicious_imports)}",
                detection_reason=f"Suspicious API calls: {', '.join(i['import'] for i in suspicious_imports[:5])}",
                remediation=[
                    "Analyze file behavior",
                    f"Quarantine file: {file_info.path}",
                    "Check file source and legitimacy"
                ],
                file_path=str(file_info.path),
                evidence={
                    'suspicious_imports': suspicious_imports,
                    'is_64bit': pe_result.get('is_64bit'),
                    'compile_time': pe_result.get('compile_time')
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_office_document(self, file_info: FileInfo) -> List[Detection]:
        """Analyze Office documents for malicious content."""
        detections = []
        
        if not file_info.is_office:
            return detections
        
        office_result = OfficeAnalyzer.analyze(file_info.path)
        file_info.has_macros = office_result.get('has_macros', False)
        
        # Suspicious macros
        if office_result.get('macro_suspicious'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='office_macro_suspicious',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                description="Suspicious macros detected in Office document",
                detection_reason=f"Malicious macro patterns: {', '.join(office_result.get('suspicious_strings', [])[:3])}",
                remediation=[
                    "Remove macros from document",
                    f"Delete file if untrusted: {file_info.path}",
                    "Do not enable macros",
                    "Scan with anti-malware"
                ],
                file_path=str(file_info.path),
                evidence={
                    'has_macros': True,
                    'suspicious_strings': office_result.get('suspicious_strings', []),
                    'warnings': office_result.get('warnings', [])
                }
            )
            detections.append(detection)
        
        # Has macros but not flagged as suspicious
        elif office_result.get('has_macros'):
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='office_macro',
                indicator=file_info.name,
                indicator_type='file',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description="Office document contains macros",
                detection_reason="Macro content detected - requires verification",
                remediation=[
                    "Verify document source",
                    "Remove macros if not needed",
                    "Do not enable macros unless trusted"
                ],
                file_path=str(file_info.path),
                evidence={
                    'has_macros': True
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_steganography(self, file_info: FileInfo) -> List[Detection]:
        """Check images for steganography with enhanced threat analysis."""
        detections = []
        
        if not file_info.is_image:
            return detections
        
        stego_result = SteganographyDetector.analyze(file_info.path)
        
        if stego_result.get('has_steganography'):
            # Determine risk level based on threat analysis
            threat_level = stego_result.get('threat_level', 'suspicious')
            confidence = stego_result.get('confidence', 0.5)
            extracted_data = stego_result.get('extracted_data', {})
            indicators = stego_result.get('indicators', [])
            
            # Map threat level to risk level
            if threat_level == 'malicious' or extracted_data.get('is_malicious'):
                risk_level = RiskLevel.HIGH
                confidence = max(confidence, 0.85)
                detection_type = 'steganography_malicious'
                base_description = "Malicious content detected in steganography"
            elif threat_level == 'suspicious' or extracted_data.get('is_suspicious'):
                risk_level = RiskLevel.MEDIUM
                confidence = max(confidence, 0.7)
                detection_type = 'steganography_suspicious'
                base_description = "Suspicious content detected in steganography"
            else:
                risk_level = RiskLevel.LOW
                confidence = max(confidence, 0.5)
                detection_type = 'steganography'
                base_description = "Possible steganography detected"
            
            # Build detailed description with indicators
            description_parts = [base_description]
            detection_reasons = []
            
            # Add detection method info
            detection_methods = stego_result.get('detection_methods', [])
            if 'lsb_analysis' in detection_methods:
                lsb_info = stego_result.get('lsb_analysis', {})
                patterns = lsb_info.get('patterns_found', [])
                if patterns:
                    detection_reasons.append(f"LSB patterns: {', '.join(patterns[:3])}")
            if 'eof_appended' in detection_methods:
                eof_info = stego_result.get('eof_analysis', {})
                appended_size = eof_info.get('appended_size', 0)
                file_type = eof_info.get('file_type', 'unknown')
                detection_reasons.append(f"Data appended after EOF ({appended_size} bytes, type: {file_type})")
            
            # Add indicator info
            if indicators:
                indicator_types = [i.get('type', 'unknown') for i in indicators[:5]]
                description_parts.append(f"Indicators: {', '.join(indicator_types)}")
            
            description = '. '.join(description_parts)
            detection_reason = '; '.join(detection_reasons) if detection_reasons else "Steganography patterns detected"
            
            # Build evidence dictionary
            evidence = {
                'threat_level': threat_level,
                'detection_methods': detection_methods,
                'lsb_analysis': stego_result.get('lsb_analysis', {}),
                'eof_analysis': stego_result.get('eof_analysis', {}),
                'entropy_analysis': stego_result.get('entropy_analysis', {}),
                'extracted_size': extracted_data.get('extracted_size', 0),
                'content_type': extracted_data.get('content_type', 'unknown'),
                'indicators': indicators,
                'warnings': stego_result.get('warnings', [])
            }
            
            # Build remediation steps based on threat level
            if threat_level == 'malicious':
                remediation = [
                    f"QUARANTINE IMMEDIATELY: {file_info.path}",
                    "Extract and analyze hidden content in sandbox",
                    "Run full system malware scan",
                    "Check for related compromise indicators",
                    "Preserve image for forensic analysis"
                ]
            elif threat_level == 'suspicious':
                remediation = [
                    f"Investigate image source: {file_info.path}",
                    "Extract and analyze hidden content",
                    "Check indicators against threat intelligence",
                    "Quarantine if verification fails",
                    "Monitor for related network activity"
                ]
            else:
                remediation = [
                    "Verify image source and legitimacy",
                    "Extract and analyze hidden data",
                    "Check for benign steganography uses",
                    f"Quarantine if suspicious: {file_info.path}"
                ]
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type=detection_type,
                indicator=file_info.name,
                indicator_type='file',
                risk_level=risk_level,
                confidence=confidence,
                description=description,
                detection_reason=detection_reason,
                remediation=remediation,
                file_path=str(file_info.path),
                evidence=evidence
            )
            detections.append(detection)
        
        return detections
