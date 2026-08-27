"""
CyberGuardian Network Scanner Module
====================================
Scans network connections for suspicious activity
and threat intelligence correlation.

Enhanced with Deep Analysis Mode for comprehensive network forensics
including memory analysis of network-connected processes.
"""

import os
import sys
import socket
import logging
import time
import subprocess
import re
import platform
from pathlib import Path
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime
from dataclasses import dataclass, field
import threading
from collections import defaultdict
import ipaddress

from scanners.base_scanner import (
    BaseScanner, ScanResult, ScanStatus, Detection, RiskLevel
)
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
    logging.warning("Memory analyzer not available - network deep analysis will be limited")

logger = get_logger('scanners.network_scanner')


@dataclass
class ConnectionInfo:
    """Information about a network connection."""
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    protocol: str
    pid: int
    process_name: str
    process_path: str = ""
    remote_hostname: str = ""
    is_whitelisted: bool = False
    is_suspicious: bool = False
    # Deep analysis fields
    mac_address: str = ""
    adapter_name: str = ""
    bytes_sent: int = 0
    bytes_recv: int = 0
    connection_age: float = 0.0
    process_owner: str = ""
    process_cmdline: str = ""
    loaded_modules: List[str] = field(default_factory=list)
    related_files: List[str] = field(default_factory=list)
    ssl_cert_info: Dict[str, Any] = field(default_factory=dict)
    dns_queries: List[str] = field(default_factory=list)


@dataclass
class NetworkAdapter:
    """Information about a network adapter."""
    name: str
    description: str
    mac_address: str
    ipv4_addresses: List[str]
    ipv6_addresses: List[str]
    is_up: bool
    is_loopback: bool
    mtu: int
    speed: int  # bits per second


@dataclass
class DnsCacheEntry:
    """DNS cache entry."""
    hostname: str
    ip_addresses: List[str]
    ttl: int = 0
    record_type: str = "A"


@dataclass
class ArpEntry:
    """ARP table entry."""
    ip_address: str
    mac_address: str
    interface: str
    is_dynamic: bool = True


class NetworkScanner(BaseScanner):
    """
    Scanner for analyzing network connections.
    
    Detection Methods:
    - Connection enumeration (all connections, not just established)
    - IP/Domain threat intelligence lookup
    - Beaconing detection
    - Suspicious port detection
    - Process correlation
    
    Deep Analysis Mode (when deep_analysis=True):
    - DNS cache analysis
    - ARP table inspection (MAC addresses)
    - Hostname resolution for all IPs
    - Process-to-network correlation
    - Related file detection
    - Network adapter information
    - Routing table analysis
    - SSL/TLS certificate inspection
    """
    
    # Suspicious ports commonly used by malware
    SUSPICIOUS_PORTS = {
        # Common malware C2 ports
        4444: 'Metasploit default',
        5555: 'Common backdoor',
        6666: 'Common backdoor',
        6667: 'IRC (often used by botnets)',
        8888: 'Common backdoor',
        9999: 'Common backdoor',
        12345: 'NetBus',
        12346: 'NetBus',
        31337: 'Elite/Backdoor',
        4443: 'Metasploit HTTPS',
        5554: 'Common worm',
        3389: 'RDP (check for unauthorized)',
        5800: 'VNC HTTP',
        5900: 'VNC',
        5901: 'VNC',
        
        # Database ports (often targeted)
        1433: 'MSSQL',
        1434: 'MSSQL Monitor',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        
        # SMB/Windows
        445: 'SMB (check for external connections)',
        139: 'NetBIOS',
    }
    
    # Trusted ports for common services
    TRUSTED_PORTS = {
        80: 'HTTP',
        443: 'HTTPS',
        53: 'DNS',
        25: 'SMTP',
        587: 'SMTP TLS',
        993: 'IMAPS',
        995: 'POP3S',
        110: 'POP3',
        143: 'IMAP',
        21: 'FTP',
        22: 'SSH',
        123: 'NTP',
    }
    
    # All connection statuses to analyze
    ALL_STATUSES = {
        'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'FIN_WAIT1', 'FIN_WAIT2',
        'TIME_WAIT', 'CLOSE', 'CLOSE_WAIT', 'LAST_ACK', 'LISTEN', 'CLOSING'
    }
    
    # Connection statuses considered active/suspicious
    ACTIVE_STATUSES = {'ESTABLISHED', 'SYN_SENT', 'SYN_RECV', 'TIME_WAIT'}
    
    # Beaconing detection thresholds
    BEACON_INTERVAL_MIN = 5  # seconds
    BEACON_INTERVAL_MAX = 3600  # 1 hour
    BEACON_TOLERANCE = 0.2  # 20% tolerance in interval
    
    def __init__(self):
        super().__init__()
        self.config = get_config()
        self.whitelist = get_whitelist()
        self.threat_intel = get_threat_intel()
        
        # Connection history for beaconing detection
        self._connection_history: Dict[str, List[float]] = defaultdict(list)
        self._last_snapshot: Set[Tuple] = set()
        
        # Deep analysis caches
        self._dns_cache: List[DnsCacheEntry] = []
        self._arp_table: List[ArpEntry] = []
        self._adapters: List[NetworkAdapter] = []
        self._routing_table: List[Dict] = []
        
        # Deep analysis flag
        self._deep_analysis = False
        
        # Memory analyzer for deep analysis
        self._memory_analyzer: Optional[Any] = None
        
        # Track scanned PIDs to avoid duplicate memory scans
        self._scanned_pids: Set[int] = set()
    
    @property
    def scanner_name(self) -> str:
        return "Network Scanner"
    
    @property
    def scanner_type(self) -> str:
        return "network"
    
    def scan(self, target: Optional[str] = None, deep_analysis: bool = False) -> ScanResult:
        """
        Scan network connections.
        
        Args:
            target: Optional specific IP or process to analyze
            deep_analysis: Enable comprehensive forensic analysis
        
        Returns:
            ScanResult with network analysis findings
        """
        log_scan_start('network', target or 'all connections')
        
        self._deep_analysis = deep_analysis
        
        result = ScanResult(
            scan_type='network',
            status=ScanStatus.RUNNING,
            start_time=datetime.utcnow(),
            scan_target=target or 'all'
        )
        
        self.reset_cancel()
        
        try:
            # Collect system network information
            if deep_analysis:
                self._collect_deep_network_info(result)
            
            # Enumerate ALL connections
            connections = self._enumerate_connections(target)
            result.total_items = len(connections)
            
            self.logger.info(f"Scanning {len(connections)} network connections (deep_analysis={deep_analysis})")
            
            # Analyze each connection
            for i, conn in enumerate(connections):
                if self.is_cancelled():
                    result.status = ScanStatus.CANCELLED
                    break
                
                # Create progress message
                if conn.remote_ip:
                    self._report_progress(i + 1, len(connections), f"Analyzing {conn.remote_ip}:{conn.remote_port}")
                else:
                    self._report_progress(i + 1, len(connections), f"Analyzing listening on {conn.local_port}")
                
                # Skip whitelisted
                if conn.is_whitelisted:
                    result.clean_items += 1
                    continue
                
                # Run detections
                detections = self._analyze_connection(conn)
                
                for detection in detections:
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
            
            # Deep analysis: Check for suspicious network patterns
            if deep_analysis and not self.is_cancelled():
                self._deep_network_analysis(result)
            
            result.status = ScanStatus.COMPLETED
            
        except Exception as e:
            self.logger.error(f"Network scan error: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
            result.status = ScanStatus.FAILED
            result.error_message = str(e)
        
        result.end_time = datetime.utcnow()
        result.scan_duration_seconds = (result.end_time - result.start_time).total_seconds()
        
        log_scan_complete('network', result.scan_target, len(result.detections))
        
        return result
    
    def _collect_deep_network_info(self, result: ScanResult) -> None:
        """Collect comprehensive network information for deep analysis."""
        self._report_progress(0, 5, "Collecting DNS cache...")
        self._collect_dns_cache()
        
        self._report_progress(1, 5, "Collecting ARP table...")
        self._collect_arp_table()
        
        self._report_progress(2, 5, "Collecting network adapters...")
        self._collect_network_adapters()
        
        self._report_progress(3, 5, "Collecting routing table...")
        self._collect_routing_table()
        
        self._report_progress(4, 5, "Collecting hosts file entries...")
        self._collect_hosts_file()
        
        self._report_progress(5, 5, "Analyzing network configuration...")
    
    def _collect_dns_cache(self) -> None:
        """Collect DNS cache entries (Windows)."""
        self._dns_cache = []
        
        try:
            # Windows: use ipconfig /displaydns
            result = subprocess.run(
                ['ipconfig', '/displaydns'],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            if result.returncode == 0:
                current_entry = {}
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    if 'Record Name' in line:
                        if current_entry.get('hostname'):
                            self._dns_cache.append(DnsCacheEntry(
                                hostname=current_entry.get('hostname', ''),
                                ip_addresses=current_entry.get('ips', []),
                                ttl=current_entry.get('ttl', 0),
                                record_type=current_entry.get('type', 'A')
                            ))
                        current_entry = {'hostname': line.split(':', 1)[1].strip(), 'ips': []}
                    
                    elif 'A (Host) Record' in line or 'AAAA' in line:
                        ip = line.split(':', 1)[1].strip()
                        if ip and ip != 'n/a':
                            current_entry.setdefault('ips', []).append(ip)
                    
                    elif 'Time to Live' in line:
                        try:
                            current_entry['ttl'] = int(line.split(':', 1)[1].strip())
                        except:
                            pass
                
                # Don't forget last entry
                if current_entry.get('hostname'):
                    self._dns_cache.append(DnsCacheEntry(
                        hostname=current_entry.get('hostname', ''),
                        ip_addresses=current_entry.get('ips', []),
                        ttl=current_entry.get('ttl', 0)
                    ))
                    
                self.logger.info(f"Collected {len(self._dns_cache)} DNS cache entries")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("DNS cache collection timed out")
        except Exception as e:
            self.logger.debug(f"Could not collect DNS cache: {e}")
    
    def _collect_arp_table(self) -> None:
        """Collect ARP table entries (MAC address mappings)."""
        self._arp_table = []
        
        try:
            # Use arp -a command
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                timeout=15,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
            )
            
            if result.returncode == 0:
                # Parse ARP output
                # Format: "  192.168.1.1           00-aa-bb-cc-dd-ee     dynamic"
                pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]+)\s+(\w+)'
                
                current_interface = ""
                for line in result.stdout.split('\n'):
                    line = line.strip()
                    
                    # Check for interface line
                    if 'Interface:' in line:
                        match = re.search(r'Interface:\s*([\d.]+)', line)
                        if match:
                            current_interface = match.group(1)
                        continue
                    
                    match = re.search(pattern, line)
                    if match:
                        ip = match.group(1)
                        mac = match.group(2).replace('-', ':').lower()
                        entry_type = match.group(3).lower()
                        
                        self._arp_table.append(ArpEntry(
                            ip_address=ip,
                            mac_address=mac,
                            interface=current_interface,
                            is_dynamic=entry_type == 'dynamic'
                        ))
                
                self.logger.info(f"Collected {len(self._arp_table)} ARP table entries")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("ARP table collection timed out")
        except Exception as e:
            self.logger.debug(f"Could not collect ARP table: {e}")
    
    def _collect_network_adapters(self) -> None:
        """Collect network adapter information."""
        self._adapters = []
        
        try:
            import psutil
            
            # Get network I/O stats
            io_stats = psutil.net_io_counters(pernic=True)
            
            # Get interface addresses
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
            
            for name, addr_list in addrs.items():
                ipv4_addrs = []
                ipv6_addrs = []
                mac_addr = ""
                
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ipv4_addrs.append(addr.address)
                    elif addr.family == socket.AF_INET6:
                        ipv6_addrs.append(addr.address)
                    elif hasattr(socket, 'AF_LINK') and addr.family == socket.AF_LINK:
                        mac_addr = addr.address
                
                # Get interface stats
                interface_stats = stats.get(name)
                is_up = interface_stats.isup if interface_stats else False
                mtu = interface_stats.mtu if interface_stats else 0
                speed = interface_stats.speed if interface_stats else 0
                
                self._adapters.append(NetworkAdapter(
                    name=name,
                    description=name,  # Could enhance with WMI for description
                    mac_address=mac_addr,
                    ipv4_addresses=ipv4_addrs,
                    ipv6_addresses=ipv6_addrs,
                    is_up=is_up,
                    is_loopback=name.lower().startswith('loopback'),
                    mtu=mtu,
                    speed=speed
                ))
            
            self.logger.info(f"Collected {len(self._adapters)} network adapters")
            
        except Exception as e:
            self.logger.debug(f"Could not collect network adapters: {e}")
    
    def _collect_routing_table(self) -> None:
        """Collect routing table information."""
        self._routing_table = []
        
        try:
            # Use route print (Windows) or netstat -rn
            if sys.platform == 'win32':
                result = subprocess.run(
                    ['route', 'print'],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    creationflags=subprocess.CREATE_NO_WINDOW
                )
                
                if result.returncode == 0:
                    # Parse Windows route output
                    in_routes = False
                    for line in result.stdout.split('\n'):
                        if 'Network Destination' in line and 'Netmask' in line:
                            in_routes = True
                            continue
                        
                        if in_routes and line.strip():
                            parts = line.split()
                            if len(parts) >= 4:
                                try:
                                    # Validate it looks like IP addresses
                                    if re.match(r'\d+\.\d+\.\d+\.\d+', parts[0]):
                                        self._routing_table.append({
                                            'destination': parts[0],
                                            'netmask': parts[1],
                                            'gateway': parts[2],
                                            'interface': parts[3],
                                            'metric': parts[4] if len(parts) > 4 else ''
                                        })
                                except:
                                    pass
                        
                        # Stop at persistent routes section
                        if 'Persistent Routes' in line:
                            break
            
            self.logger.info(f"Collected {len(self._routing_table)} routing table entries")
            
        except Exception as e:
            self.logger.debug(f"Could not collect routing table: {e}")
    
    def _collect_hosts_file(self) -> None:
        """Collect hosts file entries for DNS hijacking detection."""
        self._hosts_entries = []
        
        try:
            if sys.platform == 'win32':
                hosts_path = Path(os.environ.get('SystemRoot', 'C:\\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts'
            else:
                hosts_path = Path('/etc/hosts')
            
            if hosts_path.exists():
                with open(hosts_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            parts = line.split()
                            if len(parts) >= 2:
                                self._hosts_entries.append({
                                    'ip': parts[0],
                                    'hostnames': parts[1:],
                                    'source': str(hosts_path)
                                })
            
            self.logger.info(f"Collected {len(self._hosts_entries)} hosts file entries")
            
        except Exception as e:
            self.logger.debug(f"Could not collect hosts file: {e}")
    
    def _enumerate_connections(self, target: Optional[str] = None) -> List[ConnectionInfo]:
        """Enumerate ALL network connections (including listening sockets)."""
        connections = []
        seen_connections = set()  # Track unique connections
        
        try:
            import psutil
            
            # Get all connections with extended info
            for conn in psutil.net_connections(kind='inet'):
                try:
                    # Get local address
                    if conn.laddr:
                        local_ip, local_port = conn.laddr
                    else:
                        local_ip = "0.0.0.0"
                        local_port = 0
                    
                    # Get remote address (may be None for listening sockets)
                    if conn.raddr:
                        remote_ip, remote_port = conn.raddr
                    else:
                        # For listening sockets, mark as listening
                        remote_ip = ""
                        remote_port = 0
                    
                    # Create unique key for deduplication
                    conn_key = (local_ip, local_port, remote_ip, remote_port, 
                               conn.status, conn.pid or 0)
                    
                    if conn_key in seen_connections:
                        continue
                    seen_connections.add(conn_key)
                    
                    # Filter by target if specified
                    if target:
                        if target not in remote_ip and target not in local_ip and target != str(conn.pid):
                            continue
                    
                    # Get process info
                    process_name = ""
                    process_path = ""
                    process_owner = ""
                    process_cmdline = ""
                    loaded_modules = []
                    
                    if conn.pid:
                        try:
                            proc = psutil.Process(conn.pid)
                            process_name = proc.name()
                            process_path = proc.exe() or ""
                            
                            # Deep analysis: get more process info
                            if self._deep_analysis:
                                try:
                                    process_cmdline = ' '.join(proc.cmdline()) if proc.cmdline() else ""
                                except:
                                    pass
                                
                                try:
                                    process_owner = proc.username()
                                except:
                                    pass
                                
                                # Get loaded modules (DLLs)
                                try:
                                    for dll in proc.memory_maps():
                                        if dll.path.endswith('.dll'):
                                            loaded_modules.append(dll.path)
                                except:
                                    pass
                        except:
                            process_name = f"PID-{conn.pid}"
                    
                    # Determine protocol
                    protocol = 'TCP' if conn.family == socket.AF_INET else 'TCP6'
                    if conn.type == socket.SOCK_DGRAM:
                        protocol = 'UDP' if conn.family == socket.AF_INET else 'UDP6'
                    
                    # Check whitelist
                    is_whitelisted = False
                    if remote_ip:
                        is_whitelisted = self.whitelist.is_whitelisted(remote_ip, 'ip')
                    if not is_whitelisted and self._is_trusted_port(local_port):
                        is_whitelisted = True
                    
                    # Reverse DNS lookup (or use DNS cache in deep mode)
                    remote_hostname = ""
                    if remote_ip:
                        if self._deep_analysis:
                            # Check DNS cache first
                            for entry in self._dns_cache:
                                if remote_ip in entry.ip_addresses:
                                    remote_hostname = entry.hostname
                                    break
                            
                            # If not in cache, do lookup
                            if not remote_hostname and self.config.config.scan.network_resolve_dns:
                                try:
                                    remote_hostname = self.threat_intel.reverse_dns(remote_ip) or ""
                                except:
                                    pass
                        elif self.config.config.scan.network_resolve_dns:
                            try:
                                remote_hostname = self.threat_intel.reverse_dns(remote_ip) or ""
                            except:
                                pass
                        
                        if remote_hostname and self.whitelist.is_whitelisted(remote_hostname, 'domain'):
                            is_whitelisted = True
                    
                    # Find MAC address from ARP table (deep analysis)
                    mac_address = ""
                    adapter_name = ""
                    if self._deep_analysis and remote_ip:
                        for arp in self._arp_table:
                            if arp.ip_address == remote_ip:
                                mac_address = arp.mac_address
                                break
                    
                    # Find related files (deep analysis)
                    related_files = []
                    if self._deep_analysis and process_path:
                        try:
                            proc_dir = Path(process_path).parent
                            if proc_dir.exists():
                                for f in proc_dir.iterdir():
                                    if f.is_file() and f.suffix.lower() in ['.exe', '.dll', '.sys', '.dat']:
                                        related_files.append(str(f))
                        except:
                            pass
                    
                    conn_info = ConnectionInfo(
                        local_ip=local_ip,
                        local_port=local_port,
                        remote_ip=remote_ip,
                        remote_port=remote_port,
                        status=conn.status or "UNKNOWN",
                        protocol=protocol,
                        pid=conn.pid or 0,
                        process_name=process_name,
                        process_path=process_path,
                        remote_hostname=remote_hostname,
                        is_whitelisted=is_whitelisted,
                        mac_address=mac_address,
                        adapter_name=adapter_name,
                        process_owner=process_owner,
                        process_cmdline=process_cmdline,
                        loaded_modules=loaded_modules[:20],  # Limit to 20 modules
                        related_files=related_files[:10]  # Limit to 10 files
                    )
                    
                    connections.append(conn_info)
                    
                except Exception as e:
                    self.logger.debug(f"Error processing connection: {e}")
                    continue
        
        except ImportError:
            self.logger.error("psutil not available for network scanning")
        
        return connections
    
    def _is_trusted_port(self, port: int) -> bool:
        """Check if port is a trusted service port."""
        return port in self.TRUSTED_PORTS
    
    def _analyze_connection(self, conn: ConnectionInfo) -> List[Detection]:
        """Analyze a network connection for suspicious indicators."""
        detections = []
        
        # Standard detection methods
        detection_methods = [
            self._check_suspicious_port,
            self._check_threat_intelligence,
            self._check_suspicious_process,
            self._check_unusual_destination,
            self._check_listening_services,
        ]
        
        # Deep analysis detection methods
        if self._deep_analysis:
            detection_methods.extend([
                self._check_dns_hijacking,
                self._check_suspicious_mac,
                self._check_process_modules,
                self._check_connection_geolocation,
            ])
        
        for method in detection_methods:
            if self.is_cancelled():
                break
            
            try:
                method_detections = method(conn)
                detections.extend(method_detections)
            except Exception as e:
                self.logger.debug(f"Detection method error: {e}")
        
        return detections
    
    def _check_listening_services(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for suspicious listening services."""
        detections = []
        
        # Only check LISTEN status
        if conn.status != 'LISTEN':
            return detections
        
        # Check for listening on suspicious ports
        if conn.local_port in self.SUSPICIOUS_PORTS:
            port_desc = self.SUSPICIOUS_PORTS[conn.local_port]
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_suspicious_listener',
                indicator=f"{conn.local_ip}:{conn.local_port}",
                indicator_type='network',
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                description=f"Process listening on suspicious port {conn.local_port} ({port_desc})",
                detection_reason=f"Port {conn.local_port} is commonly used by malware: {port_desc}",
                remediation=[
                    f"Investigate process: {conn.process_name} (PID: {conn.pid})",
                    f"Check if this service is authorized: {conn.process_path}",
                    "Block port in firewall if unauthorized",
                    "Scan system for malware"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                file_path=conn.process_path,
                evidence={
                    'local_ip': conn.local_ip,
                    'local_port': conn.local_port,
                    'port_description': port_desc,
                    'process_name': conn.process_name,
                    'process_path': conn.process_path,
                    'protocol': conn.protocol,
                    'status': 'LISTEN'
                }
            )
            detections.append(detection)
        
        # Check for listening on all interfaces (0.0.0.0) on sensitive ports
        sensitive_ports = {3389: 'RDP', 5900: 'VNC', 5800: 'VNC HTTP', 22: 'SSH', 23: 'Telnet'}
        if conn.local_ip in ['0.0.0.0', '::', ''] and conn.local_port in sensitive_ports:
            service = sensitive_ports[conn.local_port]
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_exposed_service',
                indicator=f"0.0.0.0:{conn.local_port}",
                indicator_type='network',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description=f"{service} service exposed on all interfaces (port {conn.local_port})",
                detection_reason=f"{service} is listening on all network interfaces, potentially exposing it to external networks",
                remediation=[
                    f"Verify {service} is intentionally exposed",
                    "Consider binding to specific IP if internal only",
                    "Ensure strong authentication is configured",
                    "Check firewall rules"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'service': service,
                    'port': conn.local_port,
                    'process_name': conn.process_name
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_suspicious_port(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for connections to suspicious ports."""
        detections = []
        
        if not conn.remote_port:
            return detections
        
        if conn.remote_port in self.SUSPICIOUS_PORTS:
            port_desc = self.SUSPICIOUS_PORTS[conn.remote_port]
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_suspicious_port',
                indicator=f"{conn.remote_ip}:{conn.remote_port}",
                indicator_type='network',
                risk_level=RiskLevel.HIGH,
                confidence=0.7,
                description=f"Connection to suspicious port {conn.remote_port} ({port_desc})",
                detection_reason=f"Port {conn.remote_port} commonly used by malware: {port_desc}",
                remediation=[
                    f"Block IP in firewall: {conn.remote_ip}",
                    f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                    "Investigate process behavior",
                    "Check for malware on system"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'port_description': port_desc,
                    'process_name': conn.process_name,
                    'protocol': conn.protocol,
                    'hostname': conn.remote_hostname,
                    'mac_address': conn.mac_address if self._deep_analysis else None
                }
            )
            detections.append(detection)
        
        return detections
    
    def _check_threat_intelligence(self, conn: ConnectionInfo) -> List[Detection]:
        """Check IP against threat intelligence feeds."""
        detections = []
        
        if not conn.remote_ip:
            return detections
        
        # Check IP reputation
        ip_result = self.threat_intel.check_ip_reputation(conn.remote_ip, use_online=True)
        
        if ip_result.is_malicious:
            risk_level = RiskLevel.HIGH if ip_result.abuse_score >= 75 else RiskLevel.MEDIUM
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_malicious_ip',
                indicator=conn.remote_ip,
                indicator_type='network',
                risk_level=risk_level,
                confidence=0.85 if ip_result.confidence == 'high' else 0.6,
                description=f"Connection to malicious IP: {conn.remote_ip}",
                detection_reason=f"IP has abuse score {ip_result.abuse_score}%, {ip_result.reports_count} reports",
                remediation=[
                    f"Block IP in firewall: {conn.remote_ip}",
                    f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                    "Run full system scan",
                    "Check for data exfiltration"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'abuse_score': ip_result.abuse_score,
                    'threat_types': ip_result.threat_types,
                    'country': ip_result.country,
                    'reports_count': ip_result.reports_count,
                    'source': ip_result.source,
                    'hostname': conn.remote_hostname,
                    'mac_address': conn.mac_address if self._deep_analysis else None
                }
            )
            detections.append(detection)
        
        # Check domain reputation if available
        if conn.remote_hostname:
            domain_result = self.threat_intel.check_domain_reputation(conn.remote_hostname)
            
            if domain_result.is_malicious:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_malicious_domain',
                    indicator=conn.remote_hostname,
                    indicator_type='network',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.8,
                    description=f"Connection to malicious domain: {conn.remote_hostname}",
                    detection_reason=f"Domain flagged as malicious: {', '.join(domain_result.threat_types)}",
                    remediation=[
                        f"Block domain: {conn.remote_hostname}",
                        f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                        "Flush DNS cache",
                        "Check hosts file for modifications"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    evidence={
                        'domain': conn.remote_hostname,
                        'remote_ip': conn.remote_ip,
                        'threat_types': domain_result.threat_types,
                        'categories': domain_result.categories
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_suspicious_process(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for suspicious processes making network connections."""
        detections = []
        
        # Processes that shouldn't make outbound connections
        no_network_processes = {
            'notepad.exe', 'calc.exe', 'mspaint.exe', 'wordpad.exe',
            'write.exe', 'sndrec32.exe', 'charmap.exe',
        }
        
        if conn.process_name.lower() in no_network_processes:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_unexpected_process',
                indicator=conn.process_name,
                indicator_type='network',
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                description=f"Unexpected network activity from {conn.process_name}",
                detection_reason=f"{conn.process_name} should not make network connections",
                remediation=[
                    f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                    f"Quarantine executable: {conn.process_path}",
                    "Scan system for malware",
                    "Investigate process injection"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                file_path=conn.process_path,
                evidence={
                    'process_name': conn.process_name,
                    'process_path': conn.process_path,
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'cmdline': conn.process_cmdline if self._deep_analysis else None
                }
            )
            detections.append(detection)
        
        # Check for system processes making external connections
        system_processes = {
            'svchost.exe', 'lsass.exe', 'csrss.exe', 'winlogon.exe',
            'services.exe', 'smss.exe', 'wininit.exe'
        }
        
        if conn.process_name.lower() in system_processes:
            # Check if connecting to external (non-local) IP
            if conn.remote_ip and not self._is_private_ip(conn.remote_ip):
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_system_process_external',
                    indicator=conn.process_name,
                    indicator_type='network',
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.6,
                    description=f"System process {conn.process_name} connecting externally",
                    detection_reason=f"{conn.process_name} making external connection to {conn.remote_ip}",
                    remediation=[
                        f"Verify process legitimacy: {conn.process_name} (PID: {conn.pid})",
                        f"Check if {conn.process_name} is genuine Windows binary",
                        "Monitor connection behavior"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    file_path=conn.process_path,
                    evidence={
                        'process_name': conn.process_name,
                        'remote_ip': conn.remote_ip,
                        'remote_port': conn.remote_port,
                        'cmdline': conn.process_cmdline if self._deep_analysis else None
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_unusual_destination(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for unusual destination patterns."""
        detections = []
        
        if not conn.remote_ip:
            return detections
        
        # Check for direct IP connections (no DNS resolution)
        if not conn.remote_hostname and conn.remote_port in [80, 443]:
            # HTTP/HTTPS to direct IP is suspicious
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_direct_ip_http',
                indicator=conn.remote_ip,
                indicator_type='network',
                risk_level=RiskLevel.LOW,
                confidence=0.5,
                description=f"HTTP connection to IP without DNS: {conn.remote_ip}",
                detection_reason="Direct IP connection bypasses DNS filtering",
                remediation=[
                    "Verify connection legitimacy",
                    f"Check process: {conn.process_name}",
                    "Consider blocking if unauthorized"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'remote_port': conn.remote_port,
                    'process_name': conn.process_name
                }
            )
            detections.append(detection)
        
        # Check for high-numbered ports with significant data transfer
        if conn.remote_port > 49152:
            browser_processes = {'chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe', 
                                'opera.exe', 'brave.exe', 'vivaldi.exe'}
            if conn.process_name.lower() not in browser_processes:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_ephemeral_port',
                    indicator=f"{conn.remote_ip}:{conn.remote_port}",
                    indicator_type='network',
                    risk_level=RiskLevel.LOW,
                    confidence=0.4,
                    description=f"Connection to ephemeral port: {conn.remote_port}",
                    detection_reason="High port number may indicate custom C2 protocol",
                    remediation=[
                        "Monitor connection behavior",
                        "Verify process legitimacy"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    evidence={
                        'remote_ip': conn.remote_ip,
                        'remote_port': conn.remote_port,
                        'process_name': conn.process_name
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_dns_hijacking(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for DNS hijacking indicators (deep analysis)."""
        detections = []
        
        # Check hosts file entries for suspicious redirects
        for entry in getattr(self, '_hosts_entries', []):
            ip = entry.get('ip', '')
            hostnames = entry.get('hostnames', [])
            
            # Check if redirecting popular sites to non-standard IPs
            popular_sites = {'google.com', 'www.google.com', 'facebook.com', 'microsoft.com', 
                           'apple.com', 'amazon.com', 'twitter.com', 'linkedin.com', 'github.com'}
            
            for hostname in hostnames:
                if hostname.lower() in popular_sites:
                    if not self._is_private_ip(ip) or ip not in ['127.0.0.1', '::1']:
                        detection = Detection(
                            detection_id=self._generate_detection_id(),
                            detection_type='network_dns_hijack',
                            indicator=f"{hostname} -> {ip}",
                            indicator_type='network',
                            risk_level=RiskLevel.HIGH,
                            confidence=0.9,
                            description=f"DNS hijacking detected: {hostname} redirected to {ip}",
                            detection_reason=f"Hosts file redirects popular site {hostname} to non-standard IP",
                            remediation=[
                                f"Remove entry from hosts file: {entry.get('source', '')}",
                                "Scan system for malware",
                                "Check for browser hijackers",
                                "Verify no proxy settings are forced"
                            ],
                            evidence={
                                'hostname': hostname,
                                'redirected_ip': ip,
                                'hosts_file': entry.get('source', ''),
                                'type': 'hosts_file_hijack'
                            }
                        )
                        detections.append(detection)
        
        return detections
    
    def _check_suspicious_mac(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for suspicious MAC addresses (deep analysis)."""
        detections = []
        
        if not conn.mac_address:
            return detections
        
        # Known MAC address prefixes for common legitimate vendors
        # If MAC doesn't match expected patterns, it could be spoofed
        mac = conn.mac_address.lower().replace(':', '').replace('-', '')
        
        # Check for suspicious MAC patterns
        suspicious_patterns = [
            ('000000', 'Null MAC'),
            ('ffffffff', 'Broadcast MAC'),
            ('01005e', 'Multicast'),  # Not inherently bad, but worth noting
        ]
        
        for pattern, desc in suspicious_patterns:
            if mac.startswith(pattern):
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_suspicious_mac',
                    indicator=conn.remote_ip,
                    indicator_type='network',
                    risk_level=RiskLevel.MEDIUM if pattern in ['000000', 'ffffffff'] else RiskLevel.LOW,
                    confidence=0.7,
                    description=f"Suspicious MAC address for {conn.remote_ip}: {conn.mac_address} ({desc})",
                    detection_reason=f"MAC address {conn.mac_address} matches {desc} pattern",
                    remediation=[
                        "Investigate the device with this MAC",
                        "Check for ARP spoofing",
                        "Verify network segment security"
                    ],
                    process_name=conn.process_name,
                    process_id=conn.pid,
                    evidence={
                        'remote_ip': conn.remote_ip,
                        'mac_address': conn.mac_address,
                        'pattern_type': desc
                    }
                )
                detections.append(detection)
        
        return detections
    
    def _check_process_modules(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for suspicious loaded modules in network processes (deep analysis)."""
        detections = []
        
        if not conn.loaded_modules:
            return detections
        
        # Suspicious DLL patterns
        suspicious_dll_patterns = [
            ('inject', 'Injection DLL'),
            ('hook', 'Hooking DLL'),
            ('keylog', 'Keylogger'),
            ('capture', 'Screen capture'),
            ('screenshot', 'Screenshot'),
            ('miner', 'Cryptominer'),
            ('hack', 'Hacking tool'),
            ('cheat', 'Cheat tool'),
            ('nmap', 'Nmap library'),
            ('metasploit', 'Metasploit'),
            ('meterpreter', 'Meterpreter'),
            ('cobaltstrike', 'Cobalt Strike'),
        ]
        
        for module_path in conn.loaded_modules:
            module_lower = module_path.lower()
            for pattern, desc in suspicious_dll_patterns:
                if pattern in module_lower:
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type='network_suspicious_module',
                        indicator=module_path,
                        indicator_type='file',
                        risk_level=RiskLevel.HIGH,
                        confidence=0.75,
                        description=f"Suspicious module loaded by {conn.process_name}: {desc}",
                        detection_reason=f"Process {conn.process_name} has loaded {desc} library",
                        remediation=[
                            f"Terminate process: {conn.process_name} (PID: {conn.pid})",
                            f"Investigate module: {module_path}",
                            "Scan system for malware",
                            "Check process memory for injection"
                        ],
                        process_name=conn.process_name,
                        process_id=conn.pid,
                        file_path=conn.process_path,
                        evidence={
                            'module_path': module_path,
                            'module_type': desc,
                            'process_path': conn.process_path,
                            'remote_ip': conn.remote_ip
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def _check_connection_geolocation(self, conn: ConnectionInfo) -> List[Detection]:
        """Check for connections to high-risk countries (deep analysis)."""
        detections = []
        
        if not conn.remote_ip:
            return detections
        
        # Get IP geolocation from threat intel
        ip_result = self.threat_intel.check_ip_reputation(conn.remote_ip, use_online=True)
        
        # High-risk countries for malware C2
        # Note: This is not definitive - legitimate traffic can go anywhere
        high_risk_countries = {
            'CN': 'China', 'RU': 'Russia', 'KP': 'North Korea', 'IR': 'Iran',
        }
        
        country_code = getattr(ip_result, 'country', '') or ''
        
        if country_code in high_risk_countries:
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_high_risk_country',
                indicator=conn.remote_ip,
                indicator_type='network',
                risk_level=RiskLevel.LOW,  # Low confidence - many false positives
                confidence=0.3,
                description=f"Connection to {high_risk_countries[country_code]} ({conn.remote_ip})",
                detection_reason=f"IP {conn.remote_ip} is located in {high_risk_countries[country_code]}",
                remediation=[
                    "Verify this connection is expected",
                    f"Check process: {conn.process_name}",
                    "Block if not authorized"
                ],
                process_name=conn.process_name,
                process_id=conn.pid,
                evidence={
                    'remote_ip': conn.remote_ip,
                    'country_code': country_code,
                    'country_name': high_risk_countries[country_code],
                    'hostname': conn.remote_hostname
                }
            )
            detections.append(detection)
        
        return detections
    
    def _deep_network_analysis(self, result: ScanResult) -> None:
        """Perform deep network analysis and add detections."""
        # Initialize memory analyzer if available
        if MEMORY_ANALYSIS_AVAILABLE and not self._memory_analyzer:
            try:
                self._memory_analyzer = MemoryAnalyzer()
                self.logger.info("[DEEP ANALYSIS] Memory analyzer initialized for network forensics")
            except Exception as e:
                self.logger.warning(f"Could not initialize memory analyzer: {e}")
        
        self._report_progress(0, 5, "Analyzing DNS cache for threats...")
        self._analyze_dns_cache_threats(result)
        
        self._report_progress(1, 5, "Analyzing network adapters...")
        self._analyze_network_adapters(result)
        
        self._report_progress(2, 5, "Analyzing routing table...")
        self._analyze_routing_table(result)
        
        # Memory analysis for network processes
        self._report_progress(3, 5, "Analyzing network process memory...")
        memory_analysis_count = self._analyze_network_process_memory(result)
        
        self._report_progress(4, 5, "Finalizing deep analysis...")
        
        # Log deep analysis summary
        self.logger.info(f"[DEEP ANALYSIS] Network forensics completed: analyzed {memory_analysis_count} network process memories")
        
        # Cleanup memory analyzer
        if self._memory_analyzer:
            try:
                self._memory_analyzer.secure_cleanup()
            except:
                pass
    
    def _analyze_network_process_memory(self, result: ScanResult) -> int:
        """Analyze memory of network-connected processes for IOCs.
        
        Returns:
            Number of processes analyzed
        """
        analyzed_count = 0
        
        if not self._memory_analyzer:
            return analyzed_count
        
        # Get unique PIDs from connections
        unique_connections: Dict[int, List[ConnectionInfo]] = defaultdict(list)
        for conn in self._enumerate_connections():
            if conn.pid and conn.pid > 0 and conn.pid not in self._scanned_pids:
                unique_connections[conn.pid].append(conn)
        
        # Prioritize suspicious connections for memory analysis
        priority_pids = []
        for pid, conns in unique_connections.items():
            for conn in conns:
                # Check if this is a suspicious connection
                if (conn.remote_port in self.SUSPICIOUS_PORTS or
                    not conn.remote_hostname or
                    conn.process_name.lower() in {'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe'}):
                    priority_pids.append(pid)
                    break
        
        # Limit to top 10 most suspicious processes
        priority_pids = priority_pids[:10]
        
        for i, pid in enumerate(priority_pids):
            if self.is_cancelled():
                break
            
            self._scanned_pids.add(pid)
            
            # Get process name
            process_name = "Unknown"
            connections = unique_connections[pid]
            if connections:
                process_name = connections[0].process_name
            
            self._report_progress(
                3 + (i / max(len(priority_pids), 1)),
                5,
                f"Memory scanning {process_name} (PID: {pid})..."
            )
            
            try:
                # Perform specialized network memory analysis
                memory_result = self._memory_analyzer.analyze_network_process(
                    pid,
                    process_name,
                    progress_callback=None  # Don't show internal progress
                )
                
                # Extract network-related IOCs from memory
                self._process_network_memory_iocs(memory_result, connections, result)
                
                analyzed_count += 1
                self.logger.info(f"[DEEP ANALYSIS] Memory analysis completed for {process_name} (PID: {pid})")
                
            except Exception as e:
                self.logger.debug(f"Memory analysis error for PID {pid}: {e}")
        
        return analyzed_count
    
    def _process_network_memory_iocs(self, memory_result: Any, 
                                      connections: List['ConnectionInfo'],
                                      result: ScanResult) -> None:
        """Process IOCs found in network process memory."""
        if not memory_result:
            return
        
        process_name = memory_result.process_name
        process_id = memory_result.process_id
        
        # Check for code injection in network processes (highly suspicious)
        for injection in memory_result.injected_code:
            risk_level = RiskLevel.HIGH if injection.confidence >= 0.7 else RiskLevel.MEDIUM
            
            # Get related connection info
            conn_info = connections[0] if connections else None
            remote_ip = conn_info.remote_ip if conn_info else "Unknown"
            remote_port = conn_info.remote_port if conn_info else 0
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type=f'network_memory_{injection.injection_type.lower()}',
                indicator=f"{process_name} -> {remote_ip}:{remote_port}",
                indicator_type='network',
                risk_level=risk_level,
                confidence=injection.confidence,
                description=f"Code injection in network process {process_name}: {injection.injection_type}",
                detection_reason=f"Injected code detected at 0x{injection.memory_address:X} in process communicating with {remote_ip}",
                remediation=[
                    f"Terminate process immediately (PID: {process_id})",
                    f"Block connection to {remote_ip}",
                    "Investigate for malware or RAT",
                    "Perform full system scan"
                ],
                process_name=process_name,
                process_id=process_id,
                evidence={
                    'injection_type': injection.injection_type,
                    'memory_address': f'0x{injection.memory_address:X}',
                    'remote_ip': remote_ip,
                    'remote_port': remote_port,
                    'confidence': injection.confidence
                }
            )
            result.add_detection(detection)
        
        # Check for network IOCs in memory
        for ioc in memory_result.iocs:
            if ioc.ioc_type in ['URL', 'IP', 'DOMAIN']:
                # Check if this IOC matches any connection
                matches_connection = False
                for conn in connections:
                    if (ioc.value == conn.remote_ip or 
                        ioc.value == conn.remote_hostname or
                        ioc.value in (conn.remote_hostname or '')):
                        matches_connection = True
                        break
                
                # Only report if confidence is high or it matches an active connection
                if ioc.confidence >= 0.8 or matches_connection:
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type=f'network_memory_ioc_{ioc.ioc_type.lower()}',
                        indicator=ioc.value,
                        indicator_type='network',
                        risk_level=RiskLevel.HIGH if ioc.confidence >= 0.9 else RiskLevel.MEDIUM,
                        confidence=ioc.confidence,
                        description=f"Network IOC in {process_name} memory: {ioc.value}",
                        detection_reason=f"Suspicious {ioc.ioc_type} found in process memory: {ioc.value}",
                        remediation=[
                            f"Investigate connection to {ioc.value}",
                            f"Analyze process {process_name} (PID: {process_id})",
                            "Block if malicious"
                        ],
                        process_name=process_name,
                        process_id=process_id,
                        evidence={
                            'ioc_type': ioc.ioc_type,
                            'ioc_value': ioc.value,
                            'memory_address': f'0x{ioc.memory_address:X}',
                            'context': ioc.context[:200] if ioc.context else ''
                        }
                    )
                    result.add_detection(detection)
        
        # Check for suspicious strings related to network activity
        suspicious_strings = [s for s in memory_result.extracted_strings 
                            if s.is_suspicious and s.string_type in ['URL', 'IP', 'DOMAIN', 'BASE64', 'SUSPICIOUS_KEYWORD']]
        
        if len(suspicious_strings) > 5:
            # Group by type
            type_counts = defaultdict(int)
            for s in suspicious_strings:
                type_counts[s.string_type] += 1
            
            detection = Detection(
                detection_id=self._generate_detection_id(),
                detection_type='network_memory_suspicious_patterns',
                indicator=process_name,
                indicator_type='network',
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                description=f"Suspicious network patterns in {process_name} memory",
                detection_reason=f"Found {len(suspicious_strings)} suspicious strings in network process memory",
                remediation=[
                    f"Investigate process (PID: {process_id})",
                    "Analyze network traffic from this process",
                    "Check for data exfiltration"
                ],
                process_name=process_name,
                process_id=process_id,
                evidence={
                    'suspicious_string_count': len(suspicious_strings),
                    'type_breakdown': dict(type_counts),
                    'sample_values': [s.value[:100] for s in suspicious_strings[:10]]
                }
            )
            result.add_detection(detection)
    
    def _analyze_dns_cache_threats(self, result: ScanResult) -> None:
        """Analyze DNS cache for malicious domains."""
        for entry in self._dns_cache:
            if self.is_cancelled():
                break
            
            hostname = entry.hostname
            if not hostname:
                continue
            
            # Check domain reputation
            domain_result = self.threat_intel.check_domain_reputation(hostname)
            
            if domain_result.is_malicious:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_malicious_dns_cache',
                    indicator=hostname,
                    indicator_type='network',
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    description=f"Malicious domain in DNS cache: {hostname}",
                    detection_reason=f"Domain {hostname} was recently resolved and is flagged as: {', '.join(domain_result.threat_types)}",
                    remediation=[
                        f"Block domain: {hostname}",
                        "Flush DNS cache: ipconfig /flushdns",
                        "Check browser history",
                        "Scan system for malware"
                    ],
                    evidence={
                        'domain': hostname,
                        'resolved_ips': entry.ip_addresses,
                        'threat_types': domain_result.threat_types,
                        'ttl': entry.ttl
                    }
                )
                result.add_detection(detection)
    
    def _analyze_network_adapters(self, result: ScanResult) -> None:
        """Analyze network adapters for suspicious configurations."""
        for adapter in self._adapters:
            if self.is_cancelled():
                break
            
            # Check for adapters with multiple public IPs (could indicate bridging/VM)
            public_ips = [ip for ip in adapter.ipv4_addresses if not self._is_private_ip(ip)]
            
            if len(public_ips) > 1:
                detection = Detection(
                    detection_id=self._generate_detection_id(),
                    detection_type='network_multiple_public_ips',
                    indicator=adapter.name,
                    indicator_type='network',
                    risk_level=RiskLevel.LOW,
                    confidence=0.4,
                    description=f"Adapter '{adapter.name}' has multiple public IPs",
                    detection_reason="Multiple public IPs on single adapter could indicate network bridging",
                    remediation=[
                        "Verify adapter configuration is intentional",
                        "Check for unauthorized network bridges",
                        "Review VM settings if applicable"
                    ],
                    evidence={
                        'adapter_name': adapter.name,
                        'public_ips': public_ips,
                        'mac_address': adapter.mac_address
                    }
                )
                result.add_detection(detection)
    
    def _analyze_routing_table(self, result: ScanResult) -> None:
        """Analyze routing table for suspicious routes."""
        default_gateway = None
        
        for route in self._routing_table:
            if self.is_cancelled():
                break
            
            dest = route.get('destination', '')
            gateway = route.get('gateway', '')
            
            # Track default gateway
            if dest == '0.0.0.0':
                if default_gateway and default_gateway != gateway:
                    # Multiple default gateways
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type='network_multiple_gateways',
                        indicator=gateway,
                        indicator_type='network',
                        risk_level=RiskLevel.MEDIUM,
                        confidence=0.5,
                        description="Multiple default gateways detected",
                        detection_reason="Multiple default routes could indicate network manipulation",
                        remediation=[
                            "Verify routing configuration",
                            "Check for VPN software",
                            "Investigate potential man-in-the-middle"
                        ],
                        evidence={
                            'gateways': [default_gateway, gateway]
                        }
                    )
                    result.add_detection(detection)
                default_gateway = gateway
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/internal."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    def detect_beaconing(self, observation_window: int = 300) -> List[Detection]:
        """
        Detect beaconing behavior over time.
        Must be called repeatedly to build connection history.
        
        Args:
            observation_window: Time window in seconds to analyze
        
        Returns:
            List of detections for beaconing behavior
        """
        detections = []
        current_time = time.time()
        
        # Get current connections
        connections = self._enumerate_connections()
        current_snapshot = {
            (c.remote_ip, c.remote_port, c.pid)
            for c in connections if c.remote_ip  # Only track connections with remote IP
        }
        
        # Record timestamps for each connection
        for conn in connections:
            if conn.remote_ip:
                key = f"{conn.remote_ip}:{conn.remote_port}:{conn.pid}"
                self._connection_history[key].append(current_time)
        
        # Trim history to observation window
        for key in self._connection_history:
            self._connection_history[key] = [
                t for t in self._connection_history[key]
                if current_time - t <= observation_window
            ]
        
        # Analyze for beaconing patterns
        for key, timestamps in self._connection_history.items():
            if len(timestamps) < 5:  # Need enough samples
                continue
            
            # Sort timestamps
            timestamps = sorted(timestamps)
            
            # Calculate intervals
            intervals = [
                timestamps[i+1] - timestamps[i]
                for i in range(len(timestamps) - 1)
            ]
            
            if not intervals:
                continue
            
            # Calculate mean and variance
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((i - mean_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # Check for regular intervals (low variance)
            if mean_interval >= self.BEACON_INTERVAL_MIN and mean_interval <= self.BEACON_INTERVAL_MAX:
                # Low coefficient of variation indicates beaconing
                cv = std_dev / mean_interval if mean_interval > 0 else 0
                
                if cv < self.BEACON_TOLERANCE:
                    # Parse key
                    parts = key.rsplit(':', 2)
                    remote_ip = parts[0]
                    remote_port = int(parts[1])
                    pid = int(parts[2])
                    
                    # Find process name
                    process_name = "unknown"
                    for conn in connections:
                        if conn.remote_ip == remote_ip and conn.remote_port == remote_port and conn.pid == pid:
                            process_name = conn.process_name
                            break
                    
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type='network_beaconing',
                        indicator=f"{remote_ip}:{remote_port}",
                        indicator_type='network',
                        risk_level=RiskLevel.HIGH,
                        confidence=0.75,
                        description=f"Beaconing detected: {mean_interval:.1f}s interval",
                        detection_reason=f"Regular connection interval ({mean_interval:.1f}s) indicates C2 beaconing",
                        remediation=[
                            f"Block IP: {remote_ip}",
                            f"Terminate process: {process_name} (PID: {pid})",
                            "Investigate for malware",
                            "Check for data exfiltration"
                        ],
                        process_name=process_name,
                        process_id=pid,
                        evidence={
                            'remote_ip': remote_ip,
                            'remote_port': remote_port,
                            'mean_interval': mean_interval,
                            'std_deviation': std_dev,
                            'sample_count': len(timestamps),
                            'intervals': intervals[:10]  # First 10 intervals
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def get_network_summary(self) -> Dict[str, Any]:
        """Get a summary of network state (useful for reports)."""
        connections = self._enumerate_connections()
        
        # Count by status
        status_counts = defaultdict(int)
        for conn in connections:
            status_counts[conn.status] += 1
        
        # Count by process
        process_counts = defaultdict(int)
        for conn in connections:
            process_counts[conn.process_name] += 1
        
        # Get unique remote IPs
        remote_ips = set(conn.remote_ip for conn in connections if conn.remote_ip)
        
        # Get listening ports
        listening_ports = [
            (conn.local_port, conn.process_name, conn.local_ip)
            for conn in connections if conn.status == 'LISTEN'
        ]
        
        return {
            'total_connections': len(connections),
            'status_breakdown': dict(status_counts),
            'process_breakdown': dict(process_counts),
            'unique_remote_ips': len(remote_ips),
            'listening_ports': listening_ports,
            'adapters': [
                {
                    'name': a.name,
                    'mac': a.mac_address,
                    'ipv4': a.ipv4_addresses,
                    'is_up': a.is_up
                }
                for a in self._adapters
            ],
            'dns_cache_size': len(self._dns_cache),
            'arp_table_size': len(self._arp_table),
            'deep_analysis': self._deep_analysis
        }
