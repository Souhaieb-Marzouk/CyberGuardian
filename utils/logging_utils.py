"""
CyberGuardian Logging Module
============================
Comprehensive logging system with file rotation,
structured formatting, and audit trail support.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from datetime import datetime
from typing import Optional
import json
from .config import LOG_DIR, get_config


class CyberFormatter(logging.Formatter):
    """
    Custom formatter for CyberGuardian logs with
    cyber-themed colors and structured output.
    """
    
    # ANSI color codes for terminal
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
    }
    RESET = '\033[0m'
    
    # Custom format
    FORMAT = (
        '[%(asctime)s] %(levelname)-8s | %(name)-20s | %(message)s'
    )
    
    def __init__(self, use_colors: bool = True):
        super().__init__(self.FORMAT, datefmt='%Y-%m-%d %H:%M:%S')
        self.use_colors = use_colors
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record with optional colors."""
        # Add color if enabled and outputting to terminal
        if self.use_colors and sys.stdout.isatty():
            color = self.COLORS.get(record.levelname, '')
            record.levelname = f"{color}{record.levelname}{self.RESET}"
        
        return super().format(record)


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured log output."""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format the log record as JSON."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'created', 'filename',
                          'funcName', 'levelname', 'levelno', 'lineno',
                          'module', 'msecs', 'pathname', 'process',
                          'processName', 'relativeCreated', 'stack_info',
                          'exc_info', 'exc_text', 'message', 'asctime']:
                log_entry[key] = value
        
        return json.dumps(log_entry)


class AuditLogHandler(logging.Handler):
    """
    Special handler for security audit events.
    Maintains a separate log file for security-relevant events.
    """
    
    def __init__(self, log_file: Path):
        super().__init__()
        self.log_file = log_file
        self.formatter = JSONFormatter()
    
    def emit(self, record: logging.LogRecord) -> None:
        """Write audit log entry to file."""
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(self.format(record) + '\n')
        except Exception:
            self.handleError(record)


# Global reference to handlers for dynamic level changes
_log_handlers = {
    'console': None,
    'file': None,
    'json': None,
}


def setup_logging(
    log_level: Optional[str] = None,
    log_dir: Optional[Path] = None,
    max_size_mb: int = 10,
    backup_count: int = 5
) -> logging.Logger:
    """
    Set up the logging system for CyberGuardian.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_dir: Directory for log files
        max_size_mb: Maximum size of each log file in MB
        backup_count: Number of backup log files to keep
    
    Returns:
        Configured root logger
    """
    # Get configuration
    config = get_config()
    
    # Use provided values or config defaults
    log_level = log_level or config.config.log_level
    log_dir = log_dir or LOG_DIR
    max_size_mb = max_size_mb or config.config.log_max_size_mb
    backup_count = backup_count or config.config.log_backup_count
    
    # Ensure log directory exists
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Main log file
    log_file = log_dir / 'cyberguardian.log'
    audit_log_file = log_dir / 'audit.log'
    
    # Convert log level string to constant
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger('cyberguardian')
    root_logger.setLevel(level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with colors - use configured level
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)  # Use configured level, not hardcoded INFO
    console_handler.setFormatter(CyberFormatter(use_colors=True))
    root_logger.addHandler(console_handler)
    _log_handlers['console'] = console_handler
    
    # File handler with rotation - always DEBUG to capture everything
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(CyberFormatter(use_colors=False))
    root_logger.addHandler(file_handler)
    _log_handlers['file'] = file_handler
    
    # JSON log for machine parsing
    json_log_file = log_dir / 'cyberguardian.json'
    json_handler = logging.handlers.RotatingFileHandler(
        json_log_file,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count,
        encoding='utf-8'
    )
    json_handler.setLevel(logging.DEBUG)
    json_handler.setFormatter(JSONFormatter())
    root_logger.addHandler(json_handler)
    _log_handlers['json'] = json_handler
    
    # Audit log handler
    audit_handler = AuditLogHandler(audit_log_file)
    audit_handler.setLevel(logging.INFO)
    
    # Create audit logger
    audit_logger = logging.getLogger('cyberguardian.audit')
    audit_logger.addHandler(audit_handler)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    
    return root_logger


def set_log_level(log_level: str) -> None:
    """
    Dynamically update the logging level.
    
    This function updates the log level for both the root logger
    and the console handler, allowing real-time changes from the GUI.
    
    Args:
        log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Update root logger
    root_logger = logging.getLogger('cyberguardian')
    root_logger.setLevel(level)
    
    # Update console handler (for GUI log display)
    if _log_handlers['console'] is not None:
        _log_handlers['console'].setLevel(level)
    
    # Log the change
    root_logger.info(f"Log level changed to: {log_level.upper()}")


def get_log_level() -> str:
    """
    Get the current logging level name.
    
    Returns:
        Current log level as string (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    root_logger = logging.getLogger('cyberguardian')
    level = root_logger.level
    return logging.getLevelName(level)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a specific module.
    
    Args:
        name: Logger name (usually __name__)
    
    Returns:
        Configured logger instance
    """
    return logging.getLogger(f'cyberguardian.{name}')


def audit_event(
    event_type: str,
    description: str,
    severity: str = 'INFO',
    **kwargs
) -> None:
    """
    Log a security audit event.
    
    Args:
        event_type: Type of event (SCAN, DETECTION, ACTION, CONFIG_CHANGE)
        description: Human-readable description
        severity: Event severity (INFO, WARNING, ERROR, CRITICAL)
        **kwargs: Additional context data
    """
    audit_logger = logging.getLogger('cyberguardian.audit')
    
    extra = {
        'event_type': event_type,
        'severity': severity,
        **kwargs
    }
    
    audit_logger.info(description, extra=extra)


# Convenience functions for common log operations
def log_scan_start(scan_type: str, target: str) -> None:
    """Log the start of a scan operation."""
    audit_event('SCAN_START', f'Starting {scan_type} scan', target=target)


def log_scan_complete(scan_type: str, target: str, findings: int) -> None:
    """Log the completion of a scan operation."""
    audit_event('SCAN_COMPLETE', f'Completed {scan_type} scan',
                target=target, findings=findings)


def log_detection(
    detection_type: str,
    indicator: str,
    risk_level: str,
    description: str
) -> None:
    """Log a threat detection."""
    audit_event(
        'DETECTION',
        description,
        severity=risk_level,
        detection_type=detection_type,
        indicator=indicator,
        risk_level=risk_level
    )


def log_action(action: str, target: str, result: str) -> None:
    """Log a remediation action."""
    audit_event(
        'ACTION',
        f'Action: {action}',
        target=target,
        result=result
    )
