"""
CyberGuardian Base Scanner Module
=================================
Base class for all scanner modules with common functionality.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import threading
import time

from utils.logging_utils import get_logger

logger = get_logger('scanners.base')


class RiskLevel(Enum):
    """Risk level classification for detections."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    CLEAN = "clean"


class ScanStatus(Enum):
    """Status of a scan operation."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Detection:
    """Represents a single detection/finding."""
    detection_id: str
    detection_type: str
    indicator: str  # What was detected (process name, file path, IP, etc.)
    indicator_type: str  # Type of indicator (process, file, registry_key, ip)
    risk_level: RiskLevel
    confidence: float  # 0.0 to 1.0
    description: str
    detection_reason: str
    remediation: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    # Additional context
    process_name: Optional[str] = None
    process_id: Optional[int] = None
    file_path: Optional[str] = None
    command_line: Optional[str] = None
    user: Optional[str] = None
    
    # Evidence
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Results of a complete scan operation."""
    scan_type: str
    status: ScanStatus
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Summary
    total_items: int = 0
    clean_items: int = 0
    suspicious_items: int = 0
    malicious_items: int = 0
    
    # Detections
    detections: List[Detection] = field(default_factory=list)
    
    # Scan details
    scan_target: str = ""
    scan_duration_seconds: float = 0.0
    error_message: Optional[str] = None
    
    # Statistics
    stats: Dict[str, Any] = field(default_factory=dict)
    
    def add_detection(self, detection: Detection) -> None:
        """Add a detection to the results."""
        self.detections.append(detection)
        
        if detection.risk_level in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            self.malicious_items += 1
        elif detection.risk_level == RiskLevel.MEDIUM:
            self.suspicious_items += 1
        elif detection.risk_level == RiskLevel.LOW:
            self.suspicious_items += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results."""
        return {
            'scan_type': self.scan_type,
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'duration_seconds': self.scan_duration_seconds,
            'total_items': self.total_items,
            'clean_items': self.clean_items,
            'suspicious_items': self.suspicious_items,
            'malicious_items': self.malicious_items,
            'critical_detections': sum(1 for d in self.detections if d.risk_level == RiskLevel.CRITICAL),
            'high_detections': sum(1 for d in self.detections if d.risk_level == RiskLevel.HIGH),
            'medium_detections': sum(1 for d in self.detections if d.risk_level == RiskLevel.MEDIUM),
            'low_detections': sum(1 for d in self.detections if d.risk_level == RiskLevel.LOW),
        }
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'scan_type': self.scan_type,
            'status': self.status.value,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'scan_duration_seconds': self.scan_duration_seconds,
            'total_items': self.total_items,
            'clean_items': self.clean_items,
            'suspicious_items': self.suspicious_items,
            'malicious_items': self.malicious_items,
            'scan_target': self.scan_target,
            'error_message': self.error_message,
            'detections': [
                {
                    'detection_id': d.detection_id,
                    'detection_type': d.detection_type,
                    'indicator': d.indicator,
                    'indicator_type': d.indicator_type,
                    'risk_level': d.risk_level.value,
                    'confidence': d.confidence,
                    'description': d.description,
                    'detection_reason': d.detection_reason,
                    'remediation': d.remediation,
                    'timestamp': d.timestamp,
                    'process_name': d.process_name,
                    'process_id': d.process_id,
                    'file_path': d.file_path,
                    'command_line': d.command_line,
                    'user': d.user,
                    'metadata': d.metadata,
                    'evidence': d.evidence,
                }
                for d in self.detections
            ],
            'stats': self.stats,
        }


class BaseScanner(ABC):
    """
    Abstract base class for all scanners.
    Provides common functionality and interface.
    """
    
    def __init__(self):
        self.logger = get_logger(f'scanners.{self.__class__.__name__.lower()}')
        self._cancel_event = threading.Event()
        self._progress_callback: Optional[Callable[[int, int, str], None]] = None
        self._detection_callback: Optional[Callable[[Detection], None]] = None
    
    @property
    @abstractmethod
    def scanner_name(self) -> str:
        """Return the name of this scanner."""
        pass
    
    @property
    @abstractmethod
    def scanner_type(self) -> str:
        """Return the type of scanner (process, file, registry, network)."""
        pass
    
    @abstractmethod
    def scan(self, target: Optional[Any] = None) -> ScanResult:
        """
        Perform the scan operation.
        
        Args:
            target: Optional target for the scan (file path, PID, etc.)
        
        Returns:
            ScanResult with all findings
        """
        pass
    
    def set_progress_callback(
        self,
        callback: Callable[[int, int, str], None]
    ) -> None:
        """
        Set callback for progress updates.
        
        Args:
            callback: Function(current, total, message)
        """
        self._progress_callback = callback
    
    def set_detection_callback(
        self,
        callback: Callable[[Detection], None]
    ) -> None:
        """
        Set callback for real-time detection notifications.
        
        Args:
            callback: Function to call when a detection is made
        """
        self._detection_callback = callback
    
    def _report_progress(self, current: int, total: int, message: str) -> None:
        """Report progress to callback if set."""
        if self._progress_callback:
            self._progress_callback(current, total, message)
    
    def _report_detection(self, detection: Detection) -> None:
        """Report a detection to callback if set."""
        if self._detection_callback:
            self._detection_callback(detection)
    
    def cancel(self) -> None:
        """Request cancellation of the current scan."""
        self._cancel_event.set()
    
    def is_cancelled(self) -> bool:
        """Check if cancellation was requested."""
        return self._cancel_event.is_set()
    
    def reset_cancel(self) -> None:
        """Reset the cancellation flag."""
        self._cancel_event.clear()
    
    def _generate_detection_id(self) -> str:
        """Generate a unique detection ID."""
        import uuid
        return f"DET-{self.scanner_type.upper()}-{uuid.uuid4().hex[:8].upper()}"
    
    def _calculate_confidence(
        self,
        detection_count: int,
        whitelist_match: bool = False,
        signature_match: bool = False,
        heuristics_match: bool = False,
        threat_intel_match: bool = False
    ) -> float:
        """
        Calculate confidence score for a detection.
        
        Higher confidence when multiple detection methods agree.
        """
        confidence = 0.0
        
        # Base confidence from detection count
        confidence += min(detection_count * 0.2, 0.4)
        
        # Bonus for specific detection methods
        if signature_match:
            confidence += 0.3
        if threat_intel_match:
            confidence += 0.25
        if heuristics_match:
            confidence += 0.15
        
        # Penalty for whitelist match (reduces confidence)
        if whitelist_match:
            confidence *= 0.5
        
        return min(max(confidence, 0.0), 1.0)
    
    def _determine_risk_level(
        self,
        confidence: float,
        severity: str = "medium",
        known_malware: bool = False
    ) -> RiskLevel:
        """
        Determine risk level based on confidence and severity.
        """
        if known_malware:
            return RiskLevel.CRITICAL
        
        if severity == "critical":
            return RiskLevel.CRITICAL
        elif severity == "high":
            if confidence >= 0.7:
                return RiskLevel.HIGH
            else:
                return RiskLevel.MEDIUM
        elif severity == "medium":
            if confidence >= 0.7:
                return RiskLevel.MEDIUM
            else:
                return RiskLevel.LOW
        else:
            if confidence >= 0.5:
                return RiskLevel.LOW
            else:
                return RiskLevel.INFO
