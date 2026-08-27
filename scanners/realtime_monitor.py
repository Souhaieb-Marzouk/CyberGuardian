"""
CyberGuardian Real-Time Monitoring Module
=========================================
Provides real-time monitoring for processes, files, registry,
and network activity.

Enhanced with memory analysis for suspicious processes.
"""

import os
import sys
import logging
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Any, Callable, Set
from datetime import datetime
from dataclasses import dataclass, field
import queue

from scanners.base_scanner import Detection, RiskLevel
from scanners.process_scanner import ProcessScanner
from scanners.file_scanner import FileScanner
from scanners.registry_scanner import RegistryScanner
from scanners.network_scanner import NetworkScanner
from utils.config import get_config
from utils.logging_utils import get_logger, log_detection
from utils.whitelist import get_whitelist

# Import memory analyzer for real-time deep analysis
try:
    from scanners.memory_analyzer import MemoryAnalyzer, is_memory_analysis_available
    MEMORY_ANALYSIS_AVAILABLE = is_memory_analysis_available()
except ImportError:
    MEMORY_ANALYSIS_AVAILABLE = False
    logging.warning("Memory analyzer not available - real-time memory analysis disabled")

logger = get_logger('monitoring.realtime')


@dataclass
class MonitorEvent:
    """Represents a monitoring event."""
    event_type: str  # 'process', 'file', 'registry', 'network'
    event_action: str  # 'create', 'modify', 'delete', 'connect'
    timestamp: datetime
    details: Dict[str, Any]
    detections: List[Detection] = field(default_factory=list)


class RealTimeMonitor:
    """
    Real-time monitoring system for detecting threats as they occur.
    
    Monitors:
    - Process creation and termination
    - File system changes
    - Registry modifications
    - Network connections
    
    Enhanced Features:
    - Memory analysis for suspicious processes
    - Memory analysis for suspicious network connections
    - IOC extraction from running processes
    """
    
    # Processes that trigger automatic memory analysis
    HIGH_RISK_PROCESSES = {
        'powershell.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'certutil.exe',
    }
    
    def __init__(self):
        self.config = get_config()
        self.whitelist = get_whitelist()
        
        # Scanners
        self.process_scanner = ProcessScanner()
        self.file_scanner = FileScanner()
        self.registry_scanner = RegistryScanner()
        self.network_scanner = NetworkScanner()
        
        # Memory analyzer for deep analysis
        self._memory_analyzer = None
        self._memory_analysis_lock = threading.Lock()
        self._analyzed_pids: Set[int] = set()  # Track analyzed PIDs to avoid duplicates
        
        # Monitoring state
        self._running = False
        self._threads: List[threading.Thread] = []
        self._stop_events: Dict[str, threading.Event] = {}
        
        # Baseline initialization tracking
        self._baselines_initialized = False
        self._baseline_lock = threading.Lock()
        
        # Callbacks
        self._detection_callback: Optional[Callable[[Detection], None]] = None
        self._event_callback: Optional[Callable[[MonitorEvent], None]] = None
        
        # Event queue for batching
        self._event_queue: queue.Queue = queue.Queue()
        
        # Process tracking
        self._known_pids: Set[int] = set()
        self._previous_connections: Set[tuple] = set()
        
        # Registry baseline
        self._registry_baseline: Dict[str, str] = {}
    
    def _get_memory_analyzer(self) -> Optional[Any]:
        """Get or create memory analyzer instance (thread-safe)."""
        if not MEMORY_ANALYSIS_AVAILABLE:
            return None
        
        with self._memory_analysis_lock:
            if self._memory_analyzer is None:
                try:
                    self._memory_analyzer = MemoryAnalyzer()
                    logger.info("Memory analyzer initialized for real-time monitoring")
                except Exception as e:
                    logger.warning(f"Could not initialize memory analyzer: {e}")
                    return None
            return self._memory_analyzer
    
    def set_detection_callback(self, callback: Callable[[Detection], None]) -> None:
        """Set callback for detections."""
        self._detection_callback = callback
    
    def set_event_callback(self, callback: Callable[[MonitorEvent], None]) -> None:
        """Set callback for monitoring events."""
        self._event_callback = callback
    
    def start(self, monitor_types: Optional[List[str]] = None) -> bool:
        """
        Start real-time monitoring.
        
        Args:
            monitor_types: Types to monitor ('process', 'file', 'registry', 'network')
                          If None, all types are monitored.
        
        Returns:
            True if monitoring started successfully
        """
        if self._running:
            logger.warning("Monitoring already running")
            return False
        
        monitor_types = monitor_types or ['process', 'file', 'registry', 'network']
        
        self._running = True
        logger.info(f"Starting real-time monitoring for: {monitor_types}")
        
        # Initialize baselines in a background thread to avoid UI freeze
        baseline_thread = threading.Thread(
            target=self._initialize_baselines,
            name='BaselineInit',
            daemon=True
        )
        baseline_thread.start()
        
        # Give baseline thread a moment to start (non-blocking)
        time.sleep(0.1)
        
        # Start monitoring threads
        if 'process' in monitor_types:
            self._start_process_monitor()
        
        if 'file' in monitor_types:
            self._start_file_monitor()
        
        if 'registry' in monitor_types:
            self._start_registry_monitor()
        
        if 'network' in monitor_types:
            self._start_network_monitor()
        
        # Start event processor thread
        self._start_event_processor()
        
        return True
    
    def stop(self) -> None:
        """Stop all monitoring."""
        logger.info("Stopping real-time monitoring")
        
        self._running = False
        
        # Signal all threads to stop
        for name, event in self._stop_events.items():
            event.set()
        
        # Wait for threads to finish
        for thread in self._threads:
            thread.join(timeout=5)
        
        self._threads.clear()
        self._stop_events.clear()
        
        logger.info("Monitoring stopped")
    
    def is_running(self) -> bool:
        """Check if monitoring is active."""
        return self._running
    
    def _initialize_baselines(self) -> None:
        """Initialize baseline state for comparison."""
        import psutil
        
        logger.info("Starting baseline initialization...")
        
        # Get current processes
        try:
            self._known_pids = {p.pid for p in psutil.process_iter(['pid'])}
            logger.debug(f"Got process baseline: {len(self._known_pids)} processes")
        except Exception as e:
            logger.error(f"Failed to get process baseline: {e}")
            self._known_pids = set()
        
        # Get current connections
        try:
            connections = self.network_scanner._enumerate_connections()
            self._previous_connections = {
                (c.remote_ip, c.remote_port, c.pid)
                for c in connections
            }
            logger.debug(f"Got network baseline: {len(self._previous_connections)} connections")
        except Exception as e:
            logger.error(f"Failed to get network baseline: {e}")
            self._previous_connections = set()
        
        # Mark baselines as initialized
        with self._baseline_lock:
            self._baselines_initialized = True
        
        logger.info(f"Baseline initialization complete: {len(self._known_pids)} processes, "
                    f"{len(self._previous_connections)} connections")
    
    def _start_process_monitor(self) -> None:
        """Start process monitoring thread."""
        stop_event = threading.Event()
        self._stop_events['process'] = stop_event
        
        thread = threading.Thread(
            target=self._process_monitor_loop,
            args=(stop_event,),
            name='ProcessMonitor',
            daemon=True
        )
        thread.start()
        self._threads.append(thread)
    
    def _start_file_monitor(self) -> None:
        """Start file system monitoring."""
        stop_event = threading.Event()
        self._stop_events['file'] = stop_event
        
        thread = threading.Thread(
            target=self._file_monitor_loop,
            args=(stop_event,),
            name='FileMonitor',
            daemon=True
        )
        thread.start()
        self._threads.append(thread)
    
    def _start_registry_monitor(self) -> None:
        """Start registry monitoring."""
        stop_event = threading.Event()
        self._stop_events['registry'] = stop_event
        
        thread = threading.Thread(
            target=self._registry_monitor_loop,
            args=(stop_event,),
            name='RegistryMonitor',
            daemon=True
        )
        thread.start()
        self._threads.append(thread)
    
    def _start_network_monitor(self) -> None:
        """Start network monitoring."""
        stop_event = threading.Event()
        self._stop_events['network'] = stop_event
        
        thread = threading.Thread(
            target=self._network_monitor_loop,
            args=(stop_event,),
            name='NetworkMonitor',
            daemon=True
        )
        thread.start()
        self._threads.append(thread)
    
    def _start_event_processor(self) -> None:
        """Start event processing thread."""
        stop_event = threading.Event()
        self._stop_events['processor'] = stop_event
        
        thread = threading.Thread(
            target=self._event_processor_loop,
            args=(stop_event,),
            name='EventProcessor',
            daemon=True
        )
        thread.start()
        self._threads.append(thread)
    
    def _process_monitor_loop(self, stop_event: threading.Event) -> None:
        """Monitor for new processes."""
        import psutil
        
        logger.info("Process monitor started")
        poll_interval = self.config.config.scan.realtime_poll_interval
        
        # Wait for baselines to be initialized (with timeout)
        max_wait = 30  # seconds
        wait_count = 0
        while not self._baselines_initialized and wait_count < max_wait:
            if stop_event.is_set():
                return
            time.sleep(1)
            wait_count += 1
        
        if not self._baselines_initialized:
            logger.warning("Baselines not initialized after 30 seconds, starting anyway")
        
        while not stop_event.is_set():
            try:
                # Get current processes
                current_pids = {p.pid for p in psutil.process_iter(['pid'])}
                
                # Find new processes
                new_pids = current_pids - self._known_pids
                
                for pid in new_pids:
                    if stop_event.is_set():
                        break
                    
                    try:
                        # Get process info
                        proc_info = self.process_scanner.get_process_info(pid)
                        
                        if proc_info:
                            # Create event
                            event = MonitorEvent(
                                event_type='process',
                                event_action='create',
                                timestamp=datetime.utcnow(),
                                details={
                                    'pid': proc_info.pid,
                                    'name': proc_info.name,
                                    'path': proc_info.path,
                                    'command_line': proc_info.command_line,
                                    'parent_pid': proc_info.parent_pid,
                                    'parent_name': proc_info.parent_name,
                                }
                            )
                            
                            # Analyze new process
                            detections = self.process_scanner._analyze_process(proc_info)
                            event.detections = detections
                            
                            # Queue event
                            self._event_queue.put(event)
                            
                            # Report detections
                            for detection in detections:
                                self._report_detection(detection)
                            
                            # Memory analysis for high-risk processes or processes with detections
                            if (proc_info.name.lower() in self.HIGH_RISK_PROCESSES or detections):
                                memory_detections = self._analyze_process_memory_realtime(proc_info)
                                for detection in memory_detections:
                                    self._report_detection(detection)
                                    event.detections.append(detection)
                    
                    except Exception as e:
                        logger.debug(f"Error analyzing new process {pid}: {e}")
                
                # Update known PIDs
                self._known_pids = current_pids
                
            except Exception as e:
                logger.error(f"Process monitor error: {e}")
            
            stop_event.wait(poll_interval)
        
        logger.info("Process monitor stopped")
    
    def _analyze_process_memory_realtime(self, proc_info) -> List[Detection]:
        """
        Perform quick memory analysis on a suspicious process in real-time.
        
        Args:
            proc_info: ProcessInfo object for the process
        
        Returns:
            List of detections from memory analysis
        """
        detections = []
        
        # Skip if already analyzed
        if proc_info.pid in self._analyzed_pids:
            return detections
        
        self._analyzed_pids.add(proc_info.pid)
        
        memory_analyzer = self._get_memory_analyzer()
        if not memory_analyzer:
            return detections
        
        try:
            logger.info(f"Performing memory analysis on {proc_info.name} (PID: {proc_info.pid})")
            
            # Perform quick memory scan
            quick_result = memory_analyzer.quick_memory_scan(proc_info.pid)
            
            if quick_result.get('is_suspicious'):
                # Perform full memory analysis for suspicious processes
                memory_result = memory_analyzer.analyze_process(proc_info.pid)
                
                # Check for code injection
                for injection in memory_result.injected_code:
                    risk_level = RiskLevel.HIGH if injection.confidence >= 0.7 else RiskLevel.MEDIUM
                    
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type=f'realtime_memory_{injection.injection_type.lower()}',
                        indicator=f"{proc_info.name} (PID: {proc_info.pid})",
                        indicator_type='process',
                        risk_level=risk_level,
                        confidence=injection.confidence,
                        description=f"Code injection detected in {proc_info.name}: {injection.injection_type}",
                        detection_reason=f"{injection.injection_type} at 0x{injection.memory_address:X}",
                        remediation=[
                            f"Terminate process (PID: {proc_info.pid})",
                            "Investigate for malware",
                            "Check process origin"
                        ],
                        process_name=proc_info.name,
                        process_id=proc_info.pid,
                        file_path=proc_info.path,
                        evidence={
                            'injection_type': injection.injection_type,
                            'memory_address': f'0x{injection.memory_address:X}',
                            'region_size': injection.region_size,
                            **injection.evidence
                        }
                    )
                    detections.append(detection)
                
                # Check for IOCs in memory
                for ioc in memory_result.iocs:
                    if ioc.confidence >= 0.8:
                        detection = Detection(
                            detection_id=self._generate_detection_id(),
                            detection_type=f'realtime_memory_ioc_{ioc.ioc_type.lower()}',
                            indicator=ioc.value,
                            indicator_type='network' if ioc.ioc_type in ['URL', 'IP', 'DOMAIN'] else 'string',
                            risk_level=RiskLevel.HIGH if ioc.confidence >= 0.9 else RiskLevel.MEDIUM,
                            confidence=ioc.confidence,
                            description=f"Suspicious IOC in {proc_info.name} memory: {ioc.value[:50]}",
                            detection_reason=f"Extracted from memory at 0x{ioc.memory_address:X}",
                            remediation=[
                                f"Investigate {ioc.ioc_type}: {ioc.value}",
                                f"Analyze process (PID: {proc_info.pid})",
                                "Check for data exfiltration"
                            ],
                            process_name=proc_info.name,
                            process_id=proc_info.pid,
                            file_path=proc_info.path,
                            evidence={
                                'ioc_type': ioc.ioc_type,
                                'ioc_value': ioc.value,
                                'memory_address': f'0x{ioc.memory_address:X}',
                            }
                        )
                        detections.append(detection)
        
        except Exception as e:
            logger.debug(f"Memory analysis error for {proc_info.name} (PID {proc_info.pid}): {e}")
        
        return detections
    
    def _file_monitor_loop(self, stop_event: threading.Event) -> None:
        """Monitor file system changes."""
        logger.info("File monitor started")
        
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
            
            class FileEventHandler(FileSystemEventHandler):
                def __init__(self, monitor):
                    self.monitor = monitor
                
                def on_created(self, event):
                    if not event.is_directory:
                        self.monitor._handle_file_event('create', event.src_path)
                
                def on_modified(self, event):
                    if not event.is_directory:
                        self.monitor._handle_file_event('modify', event.src_path)
            
            observer = Observer()
            handler = FileEventHandler(self)
            
            # Watch common locations
            watch_paths = [
                os.path.expanduser('~'),  # User home
                os.path.join(os.environ.get('TEMP', '')),  # Temp folder
                os.path.join(os.environ.get('APPDATA', '')),  # AppData
            ]
            
            for path in watch_paths:
                if os.path.exists(path):
                    observer.schedule(handler, path, recursive=True)
                    logger.debug(f"Watching path: {path}")
            
            observer.start()
            
            while not stop_event.is_set():
                stop_event.wait(1)
            
            observer.stop()
            observer.join()
            
        except ImportError:
            logger.warning("watchdog not available, using polling")
            self._file_poll_loop(stop_event)
        
        logger.info("File monitor stopped")
    
    def _file_poll_loop(self, stop_event: threading.Event) -> None:
        """Fallback polling-based file monitoring."""
        poll_interval = self.config.config.scan.realtime_poll_interval * 2
        
        watched_dirs = [
            os.path.expanduser('~/Downloads'),
            os.path.expanduser('~/Desktop'),
            os.environ.get('TEMP', ''),
        ]
        
        file_states: Dict[str, float] = {}
        
        while not stop_event.is_set():
            try:
                for watch_dir in watched_dirs:
                    if not os.path.exists(watch_dir):
                        continue
                    
                    for root, _, files in os.walk(watch_dir):
                        for filename in files:
                            filepath = os.path.join(root, filename)
                            
                            try:
                                mtime = os.path.getmtime(filepath)
                                
                                if filepath not in file_states:
                                    # New file
                                    self._handle_file_event('create', filepath)
                                elif file_states[filepath] != mtime:
                                    # Modified file
                                    self._handle_file_event('modify', filepath)
                                
                                file_states[filepath] = mtime
                            
                            except OSError:
                                continue
            
            except Exception as e:
                logger.error(f"File poll error: {e}")
            
            stop_event.wait(poll_interval)
    
    def _handle_file_event(self, action: str, filepath: str) -> None:
        """Handle a file system event."""
        try:
            path = Path(filepath)
            
            # Skip if file too small or doesn't exist
            if not path.exists() or path.stat().st_size < 100:
                return
            
            # Get file info
            file_info = self.file_scanner._get_file_info(path)
            
            if not file_info or file_info.is_whitelisted:
                return
            
            # Create event
            event = MonitorEvent(
                event_type='file',
                event_action=action,
                timestamp=datetime.utcnow(),
                details={
                    'path': str(filepath),
                    'size': file_info.size,
                    'extension': file_info.extension,
                }
            )
            
            # Analyze file
            detections = self.file_scanner._analyze_file(file_info)
            event.detections = detections
            
            # Queue event
            self._event_queue.put(event)
            
            # Report detections
            for detection in detections:
                self._report_detection(detection)
        
        except Exception as e:
            logger.debug(f"Error handling file event: {e}")
    
    def _registry_monitor_loop(self, stop_event: threading.Event) -> None:
        """Monitor registry changes."""
        logger.info("Registry monitor started")
        
        if sys.platform != 'win32':
            logger.info("Registry monitoring only available on Windows")
            return
        
        poll_interval = self.config.config.scan.realtime_poll_interval * 2
        
        # Build initial baseline for autorun locations
        self._build_registry_baseline()
        
        while not stop_event.is_set():
            try:
                # Check for changes in autorun locations
                self._check_registry_changes()
            
            except Exception as e:
                logger.error(f"Registry monitor error: {e}")
            
            stop_event.wait(poll_interval)
        
        logger.info("Registry monitor stopped")
    
    def _build_registry_baseline(self) -> None:
        """Build baseline of registry autorun entries."""
        try:
            import winreg
            
            for key_path, hive_name, _ in RegistryScanner.AUTORUN_LOCATIONS:
                hive = self.registry_scanner._get_hive(hive_name)
                if hive is None:
                    continue
                
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            full_key = f"{hive_name}\\{key_path}\\{value_name}"
                            self._registry_baseline[full_key] = str(value_data)
                            i += 1
                        except OSError:
                            break
                    
                    winreg.CloseKey(key)
                
                except Exception:
                    pass
        
        except ImportError:
            pass
        
        logger.debug(f"Registry baseline: {len(self._registry_baseline)} entries")
    
    def _check_registry_changes(self) -> None:
        """Check for registry changes."""
        try:
            import winreg
            
            for key_path, hive_name, _ in RegistryScanner.AUTORUN_LOCATIONS:
                hive = self.registry_scanner._get_hive(hive_name)
                if hive is None:
                    continue
                
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    
                    i = 0
                    while True:
                        try:
                            value_name, value_data, _ = winreg.EnumValue(key, i)
                            full_key = f"{hive_name}\\{key_path}\\{value_name}"
                            current_data = str(value_data)
                            
                            # Check if new or changed
                            if full_key not in self._registry_baseline:
                                # New entry
                                self._handle_registry_event('create', full_key, current_data)
                            elif self._registry_baseline[full_key] != current_data:
                                # Changed entry
                                self._handle_registry_event('modify', full_key, current_data)
                            
                            self._registry_baseline[full_key] = current_data
                            i += 1
                        except OSError:
                            break
                    
                    winreg.CloseKey(key)
                
                except Exception:
                    pass
        
        except ImportError:
            pass
    
    def _handle_registry_event(self, action: str, key_path: str, value_data: str) -> None:
        """Handle a registry change event."""
        # Create registry entry
        from scanners.registry_scanner import RegistryEntry
        
        entry = RegistryEntry(
            key_path=key_path.rsplit('\\', 1)[0],
            value_name=key_path.rsplit('\\', 1)[-1],
            value_type='REG_SZ',
            value_data=value_data
        )
        
        # Analyze entry
        detections = self.registry_scanner._analyze_entry(entry)
        
        if detections:
            event = MonitorEvent(
                event_type='registry',
                event_action=action,
                timestamp=datetime.utcnow(),
                details={
                    'key_path': key_path,
                    'value_data': value_data[:500]
                },
                detections=detections
            )
            
            self._event_queue.put(event)
            
            for detection in detections:
                self._report_detection(detection)
    
    def _network_monitor_loop(self, stop_event: threading.Event) -> None:
        """Monitor network connections."""
        logger.info("Network monitor started")
        
        poll_interval = self.config.config.scan.realtime_poll_interval
        
        # Wait for baselines to be initialized (with timeout)
        max_wait = 30  # seconds
        wait_count = 0
        while not self._baselines_initialized and wait_count < max_wait:
            if stop_event.is_set():
                return
            time.sleep(1)
            wait_count += 1
        
        if not self._baselines_initialized:
            logger.warning("Baselines not initialized after 30 seconds, starting anyway")
        
        while not stop_event.is_set():
            try:
                # Get current connections
                connections = self.network_scanner._enumerate_connections()
                current_connections = {
                    (c.remote_ip, c.remote_port, c.pid)
                    for c in connections
                }
                
                # Find new connections
                new_connections = current_connections - self._previous_connections
                
                for remote_ip, remote_port, pid in new_connections:
                    if stop_event.is_set():
                        break
                    
                    # Find connection details
                    conn_info = None
                    for c in connections:
                        if c.remote_ip == remote_ip and c.remote_port == remote_port and c.pid == pid:
                            conn_info = c
                            break
                    
                    if conn_info and not conn_info.is_whitelisted:
                        # Create event
                        event = MonitorEvent(
                            event_type='network',
                            event_action='connect',
                            timestamp=datetime.utcnow(),
                            details={
                                'remote_ip': remote_ip,
                                'remote_port': remote_port,
                                'pid': pid,
                                'process_name': conn_info.process_name,
                                'hostname': conn_info.remote_hostname
                            }
                        )
                        
                        # Analyze connection
                        detections = self.network_scanner._analyze_connection(conn_info)
                        event.detections = detections
                        
                        self._event_queue.put(event)
                        
                        for detection in detections:
                            self._report_detection(detection)
                        
                        # Memory analysis for suspicious network connections
                        if detections or remote_port in self.network_scanner.SUSPICIOUS_PORTS:
                            memory_detections = self._analyze_network_process_memory(pid, conn_info)
                            for detection in memory_detections:
                                self._report_detection(detection)
                                event.detections.append(detection)
                
                # Check for beaconing periodically
                beacon_detections = self.network_scanner.detect_beaconing()
                for detection in beacon_detections:
                    self._report_detection(detection)
                
                self._previous_connections = current_connections
            
            except Exception as e:
                logger.error(f"Network monitor error: {e}")
            
            stop_event.wait(poll_interval)
        
        logger.info("Network monitor stopped")
    
    def _analyze_network_process_memory(self, pid: int, conn_info: Any) -> List[Detection]:
        """
        Perform memory analysis on a process with suspicious network connections.
        
        Args:
            pid: Process ID
            conn_info: ConnectionInfo object
        
        Returns:
            List of detections from memory analysis
        """
        detections = []
        
        # Skip if already analyzed
        if pid in self._analyzed_pids:
            return detections
        
        self._analyzed_pids.add(pid)
        
        memory_analyzer = self._get_memory_analyzer()
        if not memory_analyzer:
            return detections
        
        process_name = conn_info.process_name if hasattr(conn_info, 'process_name') else f"PID-{pid}"
        
        try:
            logger.info(f"Performing memory analysis on network process {process_name} (PID: {pid})")
            
            # Perform quick memory scan
            quick_result = memory_analyzer.quick_memory_scan(pid)
            
            if quick_result.get('is_suspicious'):
                # Perform full memory analysis
                memory_result = memory_analyzer.analyze_network_process(pid, process_name)
                
                # Check for code injection in network processes
                for injection in memory_result.injected_code:
                    risk_level = RiskLevel.HIGH if injection.confidence >= 0.7 else RiskLevel.MEDIUM
                    
                    detection = Detection(
                        detection_id=self._generate_detection_id(),
                        detection_type=f'realtime_network_memory_{injection.injection_type.lower()}',
                        indicator=f"{process_name} -> {conn_info.remote_ip}:{conn_info.remote_port}",
                        indicator_type='network',
                        risk_level=risk_level,
                        confidence=injection.confidence,
                        description=f"Code injection in network process {process_name}: {injection.injection_type}",
                        detection_reason=f"Injected code at 0x{injection.memory_address:X} in process communicating with {conn_info.remote_ip}",
                        remediation=[
                            f"Terminate process (PID: {pid})",
                            f"Block connection to {conn_info.remote_ip}",
                            "Investigate for malware or RAT",
                            "Perform full system scan"
                        ],
                        process_name=process_name,
                        process_id=pid,
                        evidence={
                            'injection_type': injection.injection_type,
                            'memory_address': f'0x{injection.memory_address:X}',
                            'remote_ip': conn_info.remote_ip,
                            'remote_port': conn_info.remote_port,
                            **injection.evidence
                        }
                    )
                    detections.append(detection)
                
                # Check for network IOCs in memory
                for ioc in memory_result.iocs:
                    if ioc.ioc_type in ['URL', 'IP', 'DOMAIN'] and ioc.confidence >= 0.8:
                        detection = Detection(
                            detection_id=self._generate_detection_id(),
                            detection_type=f'realtime_network_memory_ioc_{ioc.ioc_type.lower()}',
                            indicator=ioc.value,
                            indicator_type='network',
                            risk_level=RiskLevel.HIGH if ioc.confidence >= 0.9 else RiskLevel.MEDIUM,
                            confidence=ioc.confidence,
                            description=f"Network IOC in {process_name} memory: {ioc.value[:50]}",
                            detection_reason=f"Extracted from memory at 0x{ioc.memory_address:X}",
                            remediation=[
                                f"Investigate {ioc.ioc_type}: {ioc.value}",
                                f"Analyze network process (PID: {pid})",
                                "Check for data exfiltration"
                            ],
                            process_name=process_name,
                            process_id=pid,
                            evidence={
                                'ioc_type': ioc.ioc_type,
                                'ioc_value': ioc.value,
                                'memory_address': f'0x{ioc.memory_address:X}',
                            }
                        )
                        detections.append(detection)
        
        except Exception as e:
            logger.debug(f"Memory analysis error for {process_name} (PID {pid}): {e}")
        
        return detections
    
    def _event_processor_loop(self, stop_event: threading.Event) -> None:
        """Process events from queue."""
        logger.info("Event processor started")
        
        while not stop_event.is_set():
            try:
                event = self._event_queue.get(timeout=1)
                self._process_event(event)
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Event processor error: {e}")
        
        logger.info("Event processor stopped")
    
    def _process_event(self, event: MonitorEvent) -> None:
        """Process a monitoring event."""
        # Log event
        logger.debug(f"Event: {event.event_type}.{event.event_action} - "
                    f"{len(event.detections)} detections")
        
        # Call callback if set
        if self._event_callback:
            try:
                self._event_callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")
    
    def _generate_detection_id(self) -> str:
        """Generate a unique detection ID."""
        import uuid
        return f"RTD-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8].upper()}"
    
    def _report_detection(self, detection: Detection) -> None:
        """Report a detection."""
        log_detection(
            detection_type=detection.detection_type,
            indicator=detection.indicator,
            risk_level=detection.risk_level.value,
            description=detection.description
        )
        
        if self._detection_callback:
            try:
                self._detection_callback(detection)
            except Exception as e:
                logger.error(f"Detection callback error: {e}")


# Global monitor instance
_monitor_instance: Optional[RealTimeMonitor] = None


def get_monitor() -> RealTimeMonitor:
    """Get the global real-time monitor instance."""
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = RealTimeMonitor()
    return _monitor_instance
