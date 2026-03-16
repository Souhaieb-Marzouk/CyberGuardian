"""
CyberGuardian Configuration Module
===================================
Central configuration management for the application.
Handles settings, API keys, and runtime parameters.
"""

import os
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import logging

logger = logging.getLogger(__name__)

# Base paths - Handle both regular Python and frozen (PyInstaller) executables
def get_app_dir() -> Path:
    """Get the application directory, handling both regular and frozen modes."""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable (PyInstaller)
        # sys._MEIPASS is the temp folder where PyInstaller extracts files
        # sys.executable is the actual exe location
        return Path(sys._MEIPASS)
    else:
        # Running as Python script
        return Path(__file__).parent.parent.absolute()

def get_user_data_dir() -> Path:
    """Get user-writable data directory for logs, config, etc.
    
    When running as a frozen executable, we can't write to the bundled
    directories, so we use AppData/Local.
    """
    if getattr(sys, 'frozen', False):
        # Running as compiled executable - use AppData
        app_data = os.environ.get('LOCALAPPDATA', os.environ.get('APPDATA', ''))
        if app_data:
            user_dir = Path(app_data) / 'CyberGuardian'
            user_dir.mkdir(parents=True, exist_ok=True)
            return user_dir
    
    # Running as script - use project directory
    return Path(__file__).parent.parent.absolute()

# Application directory (for bundled resources like YARA rules)
APP_DIR = get_app_dir()

# User-writable directories
USER_DATA_DIR = get_user_data_dir()
CONFIG_DIR = USER_DATA_DIR / "config"
DATA_DIR = USER_DATA_DIR / "data"
LOG_DIR = USER_DATA_DIR / "logs"
REPORTS_DIR = USER_DATA_DIR / "reports"
CACHE_DIR = USER_DATA_DIR / "cache"

# YARA rules - bundled with executable (read-only)
YARA_RULES_DIR = APP_DIR / "yara_rules"

# Ensure user-writable directories exist
for directory in [CONFIG_DIR, DATA_DIR, LOG_DIR, REPORTS_DIR, CACHE_DIR]:
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.warning(f"Could not create directory {directory}: {e}")


@dataclass
class ScanConfig:
    """Configuration for scanning operations."""
    # Process scanning
    process_scan_memory: bool = True
    process_scan_behavior: bool = True
    process_scan_hashes: bool = True
    process_scan_signatures: bool = True
    
    # File scanning
    file_scan_yara: bool = True
    file_scan_entropy: bool = True
    file_scan_pe: bool = True
    file_scan_stego: bool = True
    file_scan_hashes: bool = True
    
    # Registry scanning
    registry_scan_autorun: bool = True
    registry_scan_services: bool = True
    registry_scan_yara: bool = True
    
    # Network scanning
    network_resolve_dns: bool = True
    network_threat_lookup: bool = True
    network_detect_beaconing: bool = True
    
    # Real-time monitoring
    realtime_process_monitor: bool = True
    realtime_file_monitor: bool = True
    realtime_registry_monitor: bool = True
    realtime_network_monitor: bool = True
    realtime_poll_interval: int = 5  # seconds


@dataclass
class APIConfig:
    """API configuration for threat intelligence services."""
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    alienvault_api_key: str = ""
    
    # AI Provider API Keys
    deepseek_api_key: str = ""
    openai_api_key: str = ""
    gemini_api_key: str = ""
    
    # AI Analysis Settings
    ai_analysis_enabled: bool = True
    ai_auto_analyze: bool = False  # Auto-analyze all detections
    ai_preferred_provider: str = "deepseek"  # deepseek, openai, gemini
    
    # Rate limiting
    virustotal_rate_limit: int = 4  # requests per minute (free tier)
    abuseipdb_rate_limit: int = 1000  # requests per day
    
    # Caching
    cache_ttl_hours: int = 24
    max_cache_size_mb: int = 100


@dataclass
class UIConfig:
    """User interface configuration."""
    theme: str = "cyber_dark"
    primary_color: str = "#00ff9d"
    secondary_color: str = "#00b8ff"
    background_color: str = "#0a0f0f"
    text_color: str = "#e0e0e0"
    font_family: str = "Consolas"
    font_size: int = 10
    
    # Window settings
    window_width: int = 1400
    window_height: int = 900
    remember_position: bool = True
    
    # Notifications
    show_popup_alerts: bool = True
    popup_duration_seconds: int = 10
    sound_alerts: bool = False


@dataclass
class AppConfig:
    """Main application configuration."""
    app_name: str = "CyberGuardian"
    version: str = "1.1.0"
    author: str = "Souhaieb Marzouk"
    
    scan: ScanConfig = field(default_factory=ScanConfig)
    api: APIConfig = field(default_factory=APIConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    
    # Update settings
    auto_update_rules: bool = True
    rules_update_url: str = "https://raw.githubusercontent.com/Yara-Rules/rules/master/"
    update_check_interval_hours: int = 24
    
    # Logging
    log_level: str = "INFO"
    log_max_size_mb: int = 10
    log_backup_count: int = 5
    
    # Performance
    max_scan_threads: int = 4
    scan_timeout_seconds: int = 300


class ConfigManager:
    """
    Manages application configuration.
    Loads from file, provides defaults, and saves changes.
    """
    
    DEFAULT_CONFIG_FILE = CONFIG_DIR / "config.yaml"
    ENV_PREFIX = "CYBERGUARDIAN_"
    
    def __init__(self, config_file: Optional[Path] = None):
        self.config_file = config_file or self.DEFAULT_CONFIG_FILE
        self.config = AppConfig()
        self._load_config()
    
    def _load_config(self) -> None:
        """Load configuration from file or create default."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f) or {}
                self._apply_config_dict(data)
                logger.info(f"Configuration loaded from {self.config_file}")
            except Exception as e:
                logger.error(f"Failed to load config: {e}, using defaults")
        else:
            self._save_config()
            logger.info("Created default configuration file")
        
        # Override with environment variables
        self._load_env_overrides()
    
    def _apply_config_dict(self, data: Dict[str, Any]) -> None:
        """Apply dictionary values to config object."""
        # Scan settings
        if 'scan' in data:
            for key, value in data['scan'].items():
                if hasattr(self.config.scan, key):
                    setattr(self.config.scan, key, value)
        
        # API settings
        if 'api' in data:
            for key, value in data['api'].items():
                if hasattr(self.config.api, key):
                    setattr(self.config.api, key, value)
        
        # UI settings
        if 'ui' in data:
            for key, value in data['ui'].items():
                if hasattr(self.config.ui, key):
                    setattr(self.config.ui, key, value)
        
        # Top-level settings
        for key in ['auto_update_rules', 'rules_update_url', 'update_check_interval_hours',
                    'log_level', 'log_max_size_mb', 'log_backup_count',
                    'max_scan_threads', 'scan_timeout_seconds']:
            if key in data:
                setattr(self.config, key, data[key])
    
    def _load_env_overrides(self) -> None:
        """Load configuration overrides from environment variables."""
        env_mappings = {
            f'{self.ENV_PREFIX}VIRUSTOTAL_API_KEY': ('api', 'virustotal_api_key'),
            f'{self.ENV_PREFIX}ABUSEIPDB_API_KEY': ('api', 'abuseipdb_api_key'),
            f'{self.ENV_PREFIX}ALIENVAULT_API_KEY': ('api', 'alienvault_api_key'),
            f'{self.ENV_PREFIX}LOG_LEVEL': (None, 'log_level'),
        }
        
        for env_var, (section, attr) in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                if section:
                    obj = getattr(self.config, section)
                    setattr(obj, attr, value)
                else:
                    setattr(self.config, attr, value)
    
    def _save_config(self) -> None:
        """Save current configuration to file."""
        data = {
            'app_name': self.config.app_name,
            'version': self.config.version,
            'auto_update_rules': self.config.auto_update_rules,
            'rules_update_url': self.config.rules_update_url,
            'update_check_interval_hours': self.config.update_check_interval_hours,
            'log_level': self.config.log_level,
            'log_max_size_mb': self.config.log_max_size_mb,
            'log_backup_count': self.config.log_backup_count,
            'max_scan_threads': self.config.max_scan_threads,
            'scan_timeout_seconds': self.config.scan_timeout_seconds,
            'scan': {
                k: v for k, v in vars(self.config.scan).items()
            },
            'api': {
                k: v for k, v in vars(self.config.api).items()
                if 'api_key' not in k.lower()  # Don't save API keys to file
            },
            'ui': {
                k: v for k, v in vars(self.config.ui).items()
            },
        }
        
        with open(self.config_file, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False)
    
    def save(self) -> None:
        """Public method to save configuration."""
        self._save_config()
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key (dot notation supported)."""
        parts = key.split('.')
        obj = self.config
        
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                return default
        
        final_key = parts[-1]
        return getattr(obj, final_key, default)
    
    def set(self, key: str, value: Any) -> None:
        """Set a configuration value by key (dot notation supported)."""
        parts = key.split('.')
        obj = self.config
        
        for part in parts[:-1]:
            if hasattr(obj, part):
                obj = getattr(obj, part)
            else:
                raise ValueError(f"Invalid config key: {key}")
        
        final_key = parts[-1]
        if hasattr(obj, final_key):
            setattr(obj, final_key, value)
        else:
            raise ValueError(f"Invalid config key: {key}")


# Global configuration instance
_config_instance: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Get the global configuration instance."""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance


def reset_config() -> None:
    """Reset the global configuration instance."""
    global _config_instance
    _config_instance = None
