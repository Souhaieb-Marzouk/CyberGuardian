"""
CyberGuardian Secure Storage Module
====================================
Secure storage for API keys using OS-native credential managers.
Uses Windows Credential Manager on Windows, Keychain on macOS, 
and SecretService on Linux.
"""

import os
import sys
import logging
import json
from typing import Optional, Dict, Any
from pathlib import Path

logger = logging.getLogger('cyberguardian.secure_storage')

# Try to import keyring for secure storage
try:
    import keyring
    import keyring.errors
    KEYRING_AVAILABLE = True
    logger.info("Keyring module available for secure credential storage")
except ImportError:
    KEYRING_AVAILABLE = False
    logger.warning("Keyring module not available - falling back to encrypted file storage")

# Service name for credential storage
SERVICE_NAME = "CyberGuardian"


class SecureStorage:
    """
    Secure storage for API keys and sensitive data.
    
    Uses keyring (Windows Credential Manager / macOS Keychain / Linux SecretService)
    if available, otherwise falls back to DPAPI-encrypted file storage on Windows.
    """
    
    def __init__(self):
        self._use_keyring = KEYRING_AVAILABLE
        self._cache: Dict[str, str] = {}
        self._use_dpapi = False
        
        # For fallback encrypted storage
        self._storage_dir = Path(__file__).parent.parent / "data" / "secure"
        self._storage_file = self._storage_dir / ".credentials"
        
        if not self._use_keyring:
            self._setup_fallback_storage()
    
    def _setup_fallback_storage(self):
        """Setup fallback encrypted file storage."""
        try:
            self._storage_dir.mkdir(parents=True, exist_ok=True)
            
            # On Windows, we can use DPAPI for encryption
            if sys.platform == 'win32':
                self._use_dpapi = True
                logger.info("Using DPAPI for encrypted credential storage")
            else:
                self._use_dpapi = False
                logger.warning("Falling back to plaintext storage - consider installing keyring package")
        except Exception as e:
            logger.error(f"Failed to setup fallback storage: {e}")
            self._use_dpapi = False
    
    def save_api_key(self, key_name: str, api_key: str) -> bool:
        """
        Store an API key securely (alias for store_key).
        
        Args:
            key_name: Name/identifier for the key (e.g., 'virustotal_api_key')
            api_key: The API key to store
        
        Returns:
            True if stored successfully, False otherwise
        """
        return self.store_key(key_name, api_key)
    
    def get_api_key(self, key_name: str) -> Optional[str]:
        """
        Retrieve an API key from secure storage (alias for retrieve_key).
        
        Args:
            key_name: Name/identifier for the key
        
        Returns:
            The API key if found, None otherwise
        """
        return self.retrieve_key(key_name)
    
    def store_key(self, key_name: str, api_key: str) -> bool:
        """
        Store an API key securely.
        
        Args:
            key_name: Name/identifier for the key (e.g., 'virustotal_api_key')
            api_key: The API key to store
        
        Returns:
            True if stored successfully, False otherwise
        """
        if not api_key:
            # If key is empty, delete it
            return self.delete_key(key_name)
        
        try:
            if self._use_keyring:
                keyring.set_password(SERVICE_NAME, key_name, api_key)
                logger.info(f"Stored {key_name} in secure credential storage")
            else:
                self._store_fallback(key_name, api_key)
            
            # Update cache
            self._cache[key_name] = api_key
            return True
            
        except Exception as e:
            logger.error(f"Failed to store {key_name}: {e}")
            # Don't crash - just return False
            return False
    
    def retrieve_key(self, key_name: str) -> Optional[str]:
        """
        Retrieve an API key from secure storage.
        
        Args:
            key_name: Name/identifier for the key
        
        Returns:
            The API key if found, None otherwise
        """
        # Check cache first
        if key_name in self._cache:
            return self._cache[key_name]
        
        try:
            if self._use_keyring:
                api_key = keyring.get_password(SERVICE_NAME, key_name)
                if api_key:
                    self._cache[key_name] = api_key
                return api_key
            else:
                return self._retrieve_fallback(key_name)
                
        except Exception as e:
            logger.error(f"Failed to retrieve {key_name}: {e}")
            return None
    
    def delete_key(self, key_name: str) -> bool:
        """
        Delete an API key from secure storage.
        
        Args:
            key_name: Name/identifier for the key
        
        Returns:
            True if deleted successfully, False otherwise
        """
        try:
            if self._use_keyring:
                try:
                    keyring.delete_password(SERVICE_NAME, key_name)
                except keyring.errors.PasswordNotFoundError:
                    pass  # Key doesn't exist, that's fine
                except Exception as e:
                    logger.debug(f"Key not found in keyring: {e}")
            
            # Clear from cache
            self._cache.pop(key_name, None)
            
            # Also remove from fallback storage if it exists
            self._delete_fallback(key_name)
            
            logger.info(f"Deleted {key_name} from secure storage")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete {key_name}: {e}")
            return False
    
    def store_all_keys(self, keys: Dict[str, str]) -> bool:
        """
        Store multiple API keys at once.
        
        Args:
            keys: Dictionary of key_name -> api_key pairs
        
        Returns:
            True if all keys stored successfully
        """
        success = True
        for key_name, api_key in keys.items():
            if not self.store_key(key_name, api_key):
                success = False
        return success
    
    def retrieve_all_keys(self, key_names: list) -> Dict[str, Optional[str]]:
        """
        Retrieve multiple API keys at once.
        
        Args:
            key_names: List of key names to retrieve
        
        Returns:
            Dictionary of key_name -> api_key pairs
        """
        result = {}
        for name in key_names:
            try:
                result[name] = self.retrieve_key(name)
            except Exception as e:
                logger.error(f"Error retrieving {name}: {e}")
                result[name] = None
        return result
    
    def _store_fallback(self, key_name: str, api_key: str):
        """Store key in fallback encrypted storage."""
        try:
            credentials = self._load_fallback_file()
            credentials[key_name] = api_key
            self._save_fallback_file(credentials)
        except Exception as e:
            logger.error(f"Failed to store key in fallback: {e}")
            raise
    
    def _retrieve_fallback(self, key_name: str) -> Optional[str]:
        """Retrieve key from fallback encrypted storage."""
        try:
            credentials = self._load_fallback_file()
            api_key = credentials.get(key_name)
            if api_key:
                self._cache[key_name] = api_key
            return api_key
        except Exception as e:
            logger.error(f"Failed to retrieve key from fallback: {e}")
            return None
    
    def _delete_fallback(self, key_name: str):
        """Delete key from fallback storage."""
        try:
            credentials = self._load_fallback_file()
            credentials.pop(key_name, None)
            self._save_fallback_file(credentials)
        except Exception as e:
            logger.error(f"Failed to delete key from fallback: {e}")
    
    def _load_fallback_file(self) -> Dict[str, str]:
        """Load credentials from encrypted file."""
        if not self._storage_file.exists():
            return {}
        
        try:
            if self._use_dpapi:
                return self._load_dpapi_file()
            else:
                # Plaintext fallback (not recommended)
                with open(self._storage_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
                    
        except Exception as e:
            logger.error(f"Failed to load credentials file: {e}")
            return {}
    
    def _load_dpapi_file(self) -> Dict[str, str]:
        """Load and decrypt DPAPI-encrypted file."""
        try:
            import ctypes
            from ctypes import wintypes
            
            # Read encrypted file
            with open(self._storage_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                return {}
            
            # Decrypt using DPAPI
            class DATA_BLOB(ctypes.Structure):
                _fields_ = [
                    ('cbData', wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))
                ]
            
            blob_in = DATA_BLOB()
            blob_in.cbData = len(encrypted_data)
            blob_in.pbData = (ctypes.c_char * len(encrypted_data))(*list(encrypted_data))
            
            blob_out = DATA_BLOB()
            
            crypt32 = ctypes.windll.crypt32
            
            if crypt32.CryptUnprotectData(
                ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
            ):
                decrypted = ctypes.string_at(blob_out.pbData, blob_out.cbData).decode('utf-8')
                # Free memory
                try:
                    ctypes.windll.kernel32.LocalFree(blob_out.pbData)
                except:
                    pass
                return json.loads(decrypted)
            else:
                logger.error("Failed to decrypt credentials file")
                return {}
                
        except Exception as e:
            logger.error(f"DPAPI decryption error: {e}")
            return {}
    
    def _save_fallback_file(self, credentials: Dict[str, str]):
        """Save credentials to encrypted file."""
        try:
            json_data = json.dumps(credentials)
            
            if self._use_dpapi:
                self._save_dpapi_file(json_data)
            else:
                # Plaintext fallback
                with open(self._storage_file, 'w', encoding='utf-8') as f:
                    json.dump(credentials, f)
                try:
                    os.chmod(self._storage_file, 0o600)
                except:
                    pass
                
        except Exception as e:
            logger.error(f"Failed to save credentials file: {e}")
            raise
    
    def _save_dpapi_file(self, json_data: str):
        """Save data encrypted with DPAPI."""
        import ctypes
        from ctypes import wintypes
        
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ('cbData', wintypes.DWORD),
                ('pbData', ctypes.POINTER(ctypes.c_char))
            ]
        
        data_bytes = json_data.encode('utf-8')
        blob_in = DATA_BLOB()
        blob_in.cbData = len(data_bytes)
        blob_in.pbData = (ctypes.c_char * len(data_bytes))(*list(data_bytes))
        
        blob_out = DATA_BLOB()
        
        crypt32 = ctypes.windll.crypt32
        
        if crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)
        ):
            encrypted = bytes(ctypes.string_at(blob_out.pbData, blob_out.cbData))
            # Free memory
            try:
                ctypes.windll.kernel32.LocalFree(blob_out.pbData)
            except:
                pass
            
            # Write encrypted data
            with open(self._storage_file, 'wb') as f:
                f.write(encrypted)
            
            # Set file permissions (only owner can read/write)
            try:
                os.chmod(self._storage_file, 0o600)
            except:
                pass
        else:
            raise RuntimeError("Failed to encrypt credentials file")
    
    def is_secure_storage_available(self) -> bool:
        """Check if secure storage is available."""
        return self._use_keyring or self._use_dpapi
    
    def get_storage_type(self) -> str:
        """Get the type of storage being used."""
        if self._use_keyring:
            return "System Credential Manager (Secure)"
        elif self._use_dpapi:
            return "DPAPI Encrypted File (Secure)"
        else:
            return "Plaintext File (Not Secure - Install keyring package)"


# Global instance
_storage_instance: Optional[SecureStorage] = None


def get_secure_storage() -> SecureStorage:
    """Get the global secure storage instance."""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = SecureStorage()
    return _storage_instance


# API Key names
API_KEY_NAMES = {
    'virustotal_api_key',
    'abuseipdb_api_key', 
    'alienvault_api_key',
    'deepseek_api_key',
    'openai_api_key',
    'gemini_api_key',
}


def save_all_api_keys(
    virustotal: str = '',
    abuseipdb: str = '',
    alienvault: str = '',
    deepseek: str = '',
    openai: str = '',
    gemini: str = ''
) -> bool:
    """
    Save all API keys to secure storage.
    
    Args:
        virustotal: VirusTotal API key
        abuseipdb: AbuseIPDB API key
        alienvault: AlienVault OTX API key
        deepseek: Deepseek AI API key
        openai: OpenAI API key
        gemini: Google Gemini API key
    
    Returns:
        True if all keys saved successfully
    """
    storage = get_secure_storage()
    
    keys = {
        'virustotal_api_key': virustotal,
        'abuseipdb_api_key': abuseipdb,
        'alienvault_api_key': alienvault,
        'deepseek_api_key': deepseek,
        'openai_api_key': openai,
        'gemini_api_key': gemini,
    }
    
    return storage.store_all_keys(keys)


def load_all_api_keys() -> Dict[str, Optional[str]]:
    """
    Load all API keys from secure storage.
    
    Returns:
        Dictionary with all API keys
    """
    storage = get_secure_storage()
    
    return storage.retrieve_all_keys(list(API_KEY_NAMES))
