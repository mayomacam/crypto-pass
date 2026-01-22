"""
Session management with hardware fingerprinting and secure credential storage.
"""
import os
import hashlib
import json
import keyring
import wmi
from typing import Optional, Any, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from core.secure_memory import zero_memory

class SessionManager:
    """Handles device-specific session persistence."""
    
    SERVICE_NAME = "BitMarrow-Session"
    
    def __init__(self):
        self._hardware_id = self._get_hardware_id()
        self._device_secret = self._get_or_create_device_secret()

    def _get_or_create_device_secret(self) -> str:
        try:
            secret = keyring.get_password(self.SERVICE_NAME, "device_secret")
            if secret:
                return secret
            secret = os.urandom(32).hex()
            keyring.set_password(self.SERVICE_NAME, "device_secret", secret)
            return secret
        except Exception:
            return os.urandom(32).hex()

    def _get_hardware_id(self) -> str:
        """Retrieves a unique hardware identifier (Machine GUID on Windows)."""
        try:
            # We use WMI to get the UUID of the computer system
            c = wmi.WMI()
            for system in c.Win32_ComputerSystemProduct():
                return system.UUID
        except Exception:
            # Fallback to a combine of env variables if WMI fails
            fallback = os.environ.get('COMPUTERNAME', '') + os.environ.get('PROCESSOR_IDENTIFIER', '')
            return hashlib.sha256(fallback.encode()).hexdigest()

    def _derive_session_key(self, hardware_id: str) -> bytes:
        """Derives a key from the hardware ID for session encryption."""
        combined = f"{hardware_id}:{self._device_secret}"
        return hashlib.sha256(combined.encode()).digest()

    def save_session(self, master_key_hex: str, user_id: str = "default", pin_key: Optional[bytes] = None):
        """
        Encrypts and stores the master key in the system keyring.
        If pin_key is provided, the session is 'PIN-Locked'.
        Includes creation timestamp for 24h expiry.
        """
        import time
        
        # Base key from hardware ID
        base_key = self._derive_session_key(self._hardware_id)
        
        # If gated by PIN, we combine the hardware key with the PIN key
        if pin_key:
            encryption_key = hashlib.sha256(base_key + pin_key).digest()
        else:
            encryption_key = base_key
            
        aesgcm = AESGCM(encryption_key)
        nonce = os.urandom(12)
        
        encrypted_data = aesgcm.encrypt(nonce, master_key_hex.encode(), None)
        payload = {
            "nonce": nonce.hex(),
            "ciphertext": encrypted_data.hex(),
            "is_pin_gated": pin_key is not None,
            "created_at": time.time()
        }
        
        keyring.set_password(self.SERVICE_NAME, user_id, json.dumps(payload))

    def load_session(self, user_id: str = "default", pin_key: Optional[bytes] = None) -> Optional[str]:
        """Retrieves and decrypts the master key if within valid timeframe."""
        import time
        from config import SESSION_LIFETIME_HOURS
        
        try:
            data_raw = keyring.get_password(self.SERVICE_NAME, user_id)
            if not data_raw:
                return None
            
            payload = json.loads(data_raw)
            
            # Check Expiry (24 hours default)
            created_at = payload.get("created_at", 0)
            if time.time() - created_at > (SESSION_LIFETIME_HOURS * 3600):
                self.clear_session(user_id)
                return "SESSION_EXPIRED"

            is_pin_gated = payload.get("is_pin_gated", False)
            
            # Check if we have the required PIN to unlock
            if is_pin_gated and not pin_key:
                return "PIN_REQUIRED"
            
            nonce = bytes.fromhex(payload["nonce"])
            ciphertext = bytes.fromhex(payload["ciphertext"])
            
            base_key = self._derive_session_key(self._hardware_id)
            if is_pin_gated:
                encryption_key = hashlib.sha256(base_key + pin_key).digest()
            else:
                encryption_key = base_key
                
            aesgcm = AESGCM(encryption_key)
            
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode()
        except Exception:
            return None

    def get_session_info(self, user_id: str = "default") -> Dict:
        """Returns metadata about the stored session."""
        try:
            data_raw = keyring.get_password(self.SERVICE_NAME, user_id)
            if not data_raw:
                return {"exists": False}
            payload = json.loads(data_raw)
            return {
                "exists": True,
                "is_pin_gated": payload.get("is_pin_gated", False),
                "created_at": payload.get("created_at", 0)
            }
        except Exception:
            return {"exists": False}

    def clear_session(self, user_id: str = "default"):
        """Removes the session from the keyring."""
        try:
            keyring.delete_password(self.SERVICE_NAME, user_id)
        except Exception:
            pass

    def get_current_hwid(self) -> str:
        return self._hardware_id
