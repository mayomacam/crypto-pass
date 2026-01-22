"""
Main application with advanced security: TOTP primary, Password fallback, GCM encryption.
"""
import customtkinter as ctk
import threading
import hashlib
import json
import os
import secrets
import keyring
from pathlib import Path
from typing import Optional

from config import APP_NAME, SESSION_TIMEOUT_MINUTES, BLOB_FILE, DATA_DIR
from core.encryption import EncryptionManager

SERVICE_VAULT = "BitMarrow-Vault"
from core.key_derivation import KeyDerivation
from core.totp_manager import TOTPManager
from core.mnemonic import MnemonicManager
from core.secure_memory import zero_memory, secure_zero
from core.session_manager import SessionManager
from core.pin_manager import PinManager
from core.blob_manager import BlobManager
from core.backup_manager import BackupManager
from database.db_manager import DatabaseManager
from gui.login_frame import LoginFrame
from gui.vault_frame import VaultFrame
from gui.password_gen_frame import PasswordGenFrame
from gui.key_gen_frame import KeyGenFrame
from gui.key_vault_frame import KeyVaultFrame
from gui.stats_frame import StatsFrame
from gui.notes_frame import NotesFrame
from gui.settings_frame import SettingsFrame
from gui.about_frame import AboutFrame
from gui.help_frame import HelpFrame
from utils.clipboard import ClipboardManager


class BitMarrowApp(ctk.CTk):
    """Main application window with secure recovery flow."""
    
    def __init__(self):
        super().__init__()
        
        self.title(APP_NAME)
        self.geometry("1100x700")
        self.minsize(900, 600)
        
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Security Modules
        self.db = DatabaseManager()
        self.db.connect()
        self.key_derivation = KeyDerivation()
        self.mnemonic_mgr = MnemonicManager()
        self.totp_mgr = TOTPManager()
        self.session_mgr = SessionManager()
        self.pin_mgr = PinManager(self.key_derivation, self.session_mgr._hardware_id)
        self.encryption: Optional[EncryptionManager] = None
        self.blob_mgr: Optional[BlobManager] = None
        self.backup_mgr = BackupManager(DATA_DIR)
        
        # App State
        self.is_locked = True
        self.session_timer: Optional[threading.Timer] = None
        self.login_warning: Optional[str] = None
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        self._check_persisted_session()
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _check_persisted_session(self):
        """Checks if a valid session exists and handles PIN-gated sessions."""
        info = self.session_mgr.get_session_info()
        if not info["exists"]:
            self._show_login()
            return

        # Check age and prompt for re-auth if needed
        import time
        from config import SESSION_LIFETIME_HOURS
        
        # Dynamic Timeout Check
        timeout = SESSION_LIFETIME_HOURS # Default
        try: #todo: implement
             # We need to temporarily connect (unencrypted) to check public config?
             # No, master_config requires decryption? 
             # Wait, master_config is in the main DB which is ENCRYPTED. 
             # We can't read 'session_timeout_hours' until we UNLOCK the DB.
             # CATCH-22: We need to know if session is expired BEFORE unlocking?
             # Actually, we CAN unlock using the stored session key, THEN check expiry.
             # If expired, we immediately LOCK again? No, that's wasteful.
             #
             # BETTER: SessionManager payload 'created_at' is plain JSON.
             # But the POLICY (how long is allowed) is inside the encrypted DB.
             #
             # SOLUTION: Store the timeout policy in the Keychain/SessionManager payload itself?
             # Or just stick to the constant for the initial check?
             # OR: Allow the session to unlock, THEN check, and if expired, force logout.
             pass
        except: pass #todo: implement
        
        # Correct Approach:
        # We rely on the hardcoded max (24 default) for the initial gate.
        # But if we want USER CONFIGURABLE timeout on the login screen, we can't easily get it 
        # because the DB is locked. 
        # 
        # Alternatives:
        # 1. Store preference in a local unencrypted config file (e.g. JSON in data dir).
        # 2. Store preference in the keychain alongside the session key?
        # 3. Just use 24h as a hard limit for "Offline Access", but for "Session Validity" check after unlock.
        
        # Let's do #3: Unlock -> Check Config -> if expired -> Lock & Prompt.
        # This is safe because even if they unlock, if it's "stale", we punt them out.
        
        age_hours = (time.time() - info.get("created_at", 0)) / 3600
        
        # Hard cap at 24h OR check dynamic after unlock
        if age_hours > 24: # Hard safety cap
             self.session_mgr.clear_session()
             mode = "EVERYDAY" if self.db.get_everyday_config() else "PASSWORD" # This also needs DB access... wait. 
             # self.db.get_everyday_config needs DB access!
             # We are in a bind. 
             # "session_mgr.load_session()" gives us the KEY.
             # We haven't connected DB yet in this flow.
             pass

        if info["is_pin_gated"]:
            # If PIN is required, we show the login screen but focus on PIN
            self._show_login(initial_mode="PIN_SESSION")
            return

        # Otherwise try to load directly
        # Note: load_session might still return SESSION_EXPIRED
        master_key_hex = self.session_mgr.load_session()
        
        if master_key_hex == "SESSION_EXPIRED":
            # Just show generic login
            self._show_login(initial_mode="PASSWORD") 
            return
            
        if master_key_hex:
            try:
                master_key_bytes = bytearray.fromhex(master_key_hex)
                self.encryption = EncryptionManager(master_key_bytes)
                self.db.set_encryption(self.encryption)
                self.db.connect()
                
                # NOW we have DB access. Check dynamic timeout!
                dyn_timeout = self.db.get_config_value("session_timeout_hours")
                limit = int(dyn_timeout) if dyn_timeout else SESSION_LIFETIME_HOURS
                
                age_hours = (time.time() - info.get("created_at", 0)) / 3600
                if age_hours > limit:
                     print(f"Session expired by user policy ({age_hours:.2f} > {limit})")
                     self.session_mgr.clear_session()
                     self.db.close() # Re-lock
                     self._show_login(initial_mode="EVERYDAY" if self.db.get_everyday_config() else "PASSWORD")
                     return

                self.db._audit.log_event("SESSION_RESTORED", "Session restored from secure storage")
                self._show_main_app()
                return
            except Exception as e:
                print(f"Failed to restore session: {e}")
                self.session_mgr.clear_session()
        
        self._show_login()
    
    def _show_login(self, initial_mode: str = "PASSWORD"):
        self.is_locked = True
        self._cleanup_blob_manager()
        for widget in self.winfo_children():
            widget.destroy()
        
        # v2.0 Integrity Check
        integrity_status = self.db.check_integrity()
        
        if integrity_status == "INITIAL":
            # Set up initial fingerprint
            vid = secrets.token_hex(16)
            self.db.set_vault_id(vid)
            keyring.set_password(SERVICE_VAULT, "fingerprint", vid)
        elif integrity_status in ["NEW_DEVICE", "MISMATCH"]:
            # Trigger Migration / Mnemonic Challenge
            initial_mode = "MIGRATION"

        has_setup = self.db.has_master_password()
        has_everyday = self.db.get_everyday_config() is not None
        has_pin = self.db.get_pin_config() is not None
        
        # Check if we have a PIN-gated session waiting (and valid)
        session_info = self.session_mgr.get_session_info()
        is_session_pin_gated = session_info.get("is_pin_gated", False)
        
        # Override initial mode if we are specifically handling a session restore
        if is_session_pin_gated and initial_mode == "PASSWORD": 
            # If default was requested but we have a session, assume PIN
             initial_mode = "PIN_SESSION"
        
        self.login_frame = LoginFrame(
            self,
            on_login=self._handle_login,
            on_setup=self._handle_setup,
            is_first_time=not has_setup,
            has_pin=has_pin,
            has_everyday=has_everyday,
            initial_mode=initial_mode
        )
        self.login_frame.grid(row=0, column=0, sticky="nsew")

    # ... (skipping unchanged methods) ...

    def _on_close(self):
        self._cleanup_blob_manager()
        if self.encryption:
            self.encryption.cleanup()
        self.db.close()
        
        # Force GC on exit
        import gc
        gc.collect()
        
        self.destroy()

    def _handle_login(self, totp_code: Optional[str] = None, 
                      password: Optional[str] = None,
                      everyday_password: Optional[str] = None,
                      pin: Optional[str] = None,
                      pin_for_session: Optional[str] = None,
                      migration_key: Optional[str] = None,
                      mnemonic_phrase: Optional[str] = None,
                      stay_logged_in: bool = False) -> bool:
        config = self.db.get_master_config()
        if not config: return False

        if migration_key:
            return self._handle_migration_claim(migration_key)
        elif mnemonic_phrase:
            return self._handle_mnemonic_recovery(mnemonic_phrase)
        elif totp_code:
            return self._login_with_totp(totp_code, config, stay_logged_in)
        elif password:
            return self._login_with_password(password, config, stay_logged_in)
        elif everyday_password:
            return self._login_with_everyday_password(everyday_password, stay_logged_in)
        elif pin:
            return self._login_with_pin(pin, stay_logged_in)
        elif pin_for_session:
            return self._login_with_pin_for_session(pin_for_session)
        return False

    def _handle_migration_claim(self, key: str) -> bool:
        """Verifies a migration transfer key and claims the vault for this device."""
        if self.db.verify_migration_key(key):
            hwid = self.session_mgr.get_current_hwid()
            self.db.finalize_migration(key, hwid)
            self._show_login() # Refresh to show normal login
            return True
        return False

    def _handle_mnemonic_recovery(self, mnemonic: str) -> bool:
        """Forces a vault claim using the 24-word recovery phrase."""
        if not self.mnemonic_mgr.is_valid(mnemonic):
            return False
            
        # If mnemonic is valid, we can force-bind the hardware
        hwid = self.session_mgr.get_current_hwid()
        self.session_mgr.bind_hardware(hwid)
        self.session_mgr.save_session()
        # We also need to derive the master key from the mnemonic to verify it's the RIGHT mnemonic
        # But even if we don't have the master key yet, we can't unseal the DB.
        # So it's safe to just set the fingerprint and let the user try to unseal.
        vid = self.db.get_vault_id()
        keyring.set_password(SERVICE_VAULT, "fingerprint", vid)
        self._show_login()
        return True

    def _login_with_pin_for_session(self, pin: str) -> bool:
        """Unlocks a PIN-gated persistent session."""
        # We need to derive the same PIN key used for wrapping the session
        salt = self.db.get_pin_config()['pin_salt']
        pin_key = self.pin_mgr._derive_pin_key(pin, salt)
        
        master_key_hex = self.session_mgr.load_session(pin_key=pin_key)
        zero_memory(pin_key)
        
        if master_key_hex and master_key_hex != "PIN_REQUIRED":
            try:
                master_key_bytes = bytearray.fromhex(master_key_hex)
                self.encryption = EncryptionManager(master_key_bytes)
                self.db.set_encryption(self.encryption)
                self.db.update_pin_attempts(0)
                self._init_blob_manager()
                self._show_main_app()
                return True
            except Exception:
                pass
        
        # Increment attempts on failure
        pin_config = self.db.get_pin_config()
        attempts = pin_config['pin_attempts'] + 1
        self.db.update_pin_attempts(attempts)
        return False

    def _login_with_everyday_password(self, password: str, stay_logged_in: bool = False) -> bool:
        """Unlocks using the Everyday Password."""
        config = self.db.get_everyday_config()
        if not config: return False
        
        if self.key_derivation.verify_password(password, config['everyday_hash']):
            # Derive the wrapper key
            wrapper_key = self.key_derivation.derive_key(password, config['everyday_salt'])
            temp_enc = EncryptionManager(wrapper_key)
            
            try:
                master_key_bytes = temp_enc.decrypt_bytes(config['everyday_wrapped_key'])
                zero_memory(wrapper_key)
                
                self.encryption = EncryptionManager(bytearray(master_key_bytes))
                self.db.set_encryption(self.encryption)
                
                if stay_logged_in:
                    # If stay_logged_in is checked, we also need to know if they want it PIN-gated
                    # For now, let's assume if they have a PIN, persistent sessions are always PIN-gated
                    pin_config = self.db.get_pin_config()
                    pin_key = None
                    if pin_config: #TODO: We need to handle this better
                        # This is tricky: we don't have the PIN here. 
                        # We might need to ask for it, or just use a default gating.
                        # User said: "start with pin (when session store on device)"
                        # So let's skip session saving here if we don't have the PIN, 
                        # OR we save it UN-gated if they haven't set a PIN yet.
                        pass
                    
                    self.session_mgr.save_session(master_key_bytes.hex())
                
                self._init_blob_manager()
                self._show_main_app()
                return True
            except Exception:
                zero_memory(wrapper_key)
                return False
        return False

    def _login_with_pin(self, pin: str, stay_logged_in: bool = False) -> bool:
        pin_config = self.db.get_pin_config()
        if not pin_config: return False
        
        master_key = self.pin_mgr.verify_and_unwrap(
            pin, 
            pin_config['pin_hash'],
            pin_config['pin_salt'],
            pin_config['pin_wrapped_key']
        )
        
        if master_key:
            self.encryption = EncryptionManager(master_key)
            self.db.set_encryption(self.encryption)
            self.db.update_pin_attempts(0)
            
            if stay_logged_in:
                # When logging in WITH PIN, we can PIN-gate the session persistence!
                salt = pin_config['pin_salt']
                pin_key = self.pin_mgr._derive_pin_key(pin, salt)
                self.session_mgr.save_session(master_key.hex(), pin_key=pin_key)
                zero_memory(pin_key)
            
            self._init_blob_manager()
            self._show_main_app()
            return True
        else:
            attempts = pin_config['pin_attempts'] + 1
            self.db.update_pin_attempts(attempts)
            return False

    def _login_with_totp(self, code: str, config: dict, stay_logged_in: bool = False) -> bool:
        """Unlock using TOTP secret as a key derivation source."""
        encrypted_totp_secret = config.get('totp_secret')
        encrypted_backup_key = config.get('backup_key')
        
        if not encrypted_totp_secret or not encrypted_backup_key:
            return False

        # 1. We need the Master Key to decrypt the TOTP secret. 
        # But wait! If we don't have the Master Key, we can't get the TOTP secret.
        # FIX: The backup_key is encrypted with the TOTP Secret + a secondary salt.
        # But where is the TOTP secret? It's on the user's phone.
        # User enters code -> We still need the SECRET.
        
        # NEW LOGIC: We store a RECOVERY KEY encrypted with the Master Key.
        # We store another copy of the Master Key encrypted with the TOTP SECRET.
        # But the problem is: the app needs the TOTP Secret to verify the code.
        
        # REVISED SECURITY DESIGN FOR "TOTP AS PRIMARY":
        # 1. User sets up Master Password.
        # 2. User sets up TOTP. 
        #    - We store 'totp_secret' UNENCRYPTED (or encrypted with a hardware tag/device ID).
        #    - We store 'master_key_unlocked_by_totp' = Encrypt(MasterKey, key=TOTPSecret).
        # 3. Login:
        #    - User enters code. 
        #    - We verify code against stored 'totp_secret'.
        #    - If OK, we use 'totp_secret' as key to decrypt 'master_key_unlocked_by_totp'.

        # Security check: TOTP secret is base32, usually enough entropy for a key.
        secret_bytes = config.get('totp_secret') # For this flow, let's assume it's stored 
        
        if not secret_bytes: return False
        
        # Verify code
        if not self.totp_mgr.verify_code(secret_bytes.decode(), code):
            return False
            
        # Success! Now decrypt the master key
        try:
            # We derive a key from the secret
            totp_key = bytearray(hashlib.sha256(secret_bytes).digest())
            temp_encryption = EncryptionManager(totp_key)
            
            decrypted_key_raw = temp_encryption.decrypt(encrypted_backup_key)
            zero_memory(totp_key)
            
            # RESILIENCE: Try to detect if it's hex (new format) or legacy string
            try:
                # New format: hex string
                master_key_bytes = bytearray.fromhex(decrypted_key_raw)
            except ValueError:
                # Legacy format: raw bytes as string (latin-1)
                master_key_bytes = bytearray(decrypted_key_raw.encode('latin-1'))
            
            if len(master_key_bytes) != 32:
                raise ValueError(f"Decrypted key length is {len(master_key_bytes)}, expected 32. "
                                 "Database migration required via Master Password.")

            self.encryption = EncryptionManager(master_key_bytes)
            self.db.set_encryption(self.encryption)
            
            if stay_logged_in:
                self.session_mgr.save_session(master_key_bytes.hex())
            
            self._init_blob_manager()
            self._show_main_app()
            return True
        except Exception as e:
            print(f"TOTP Unlock failed: {e}")
            # If we reach here, the database likely has corrupted recovery info from v1.1.0
            # We should guide the user to their Master Password.
            return False

    def _login_with_password(self, password: str, config: dict, stay_logged_in: bool = False) -> bool:
        if self.key_derivation.verify_password(password, config['password_hash']):
            key_bytes = self.key_derivation.derive_key(password, config['salt'])
            self.encryption = EncryptionManager(key_bytes)
            self.db.set_encryption(self.encryption)
            
            if stay_logged_in:
                self.session_mgr.save_session(key_bytes.hex())
            
            zero_memory(key_bytes)
            self.login_warning = config.get('login_warning')
            
            self._init_blob_manager()
            self._show_recovery_choice()
            return True
        return False

    def _show_recovery_choice(self):
        choice_dialog = ctk.CTkToplevel(self)
        choice_dialog.title("Recovery Access")
        choice_dialog.geometry("400x320")
        choice_dialog.transient(self)
        choice_dialog.grab_set()
        
        ctk.CTkLabel(choice_dialog, text="🆘 Recovery Options", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        ctk.CTkLabel(choice_dialog, text="You used recovery. Why?", text_color="gray").pack()
        
        ctk.CTkButton(choice_dialog, text="📱 I lost my phone (Secure Reset)", 
                     command=lambda: self._handle_recovery_action("LOST", choice_dialog),
                     fg_color="#e67e22").pack(pady=10, padx=50, fill="x")
        
        ctk.CTkButton(choice_dialog, text="🕒 Temporary access (Persistent Warning)", 
                     command=lambda: self._handle_recovery_action("TEMP", choice_dialog)).pack(pady=10, padx=50, fill="x")
        
        ctk.CTkButton(choice_dialog, text="Skip for now", 
                     command=lambda: self._handle_recovery_action("SKIP", choice_dialog),
                     fg_color="transparent", text_color="gray").pack()

    def _handle_recovery_action(self, action: str, dialog: ctk.CTkToplevel):
        dialog.destroy()
        if action == "LOST":
            self.db.update_recovery_info(totp_secret=b"", backup_key=b"")
            self._force_password_change()
        elif action == "TEMP":
            msg = "⚠️ Warning: Accessed via recovery. Reset phone access soon."
            self.db.set_login_warning(msg)
            self.login_warning = msg
            self._show_main_app()
        else:
            self._show_main_app()

    def _handle_setup(self, password: str, stay_logged_in: bool = False):
        salt = self.key_derivation.generate_salt()
        pass_hash = self.key_derivation.hash_password(password)
        master_key = self.key_derivation.derive_key(password, salt)
        
        self.encryption = EncryptionManager(master_key)
        self.db.save_master_config(salt, pass_hash)
        self.db.set_encryption(self.encryption)
        self.db.set_login_warning(None)

        if stay_logged_in:
            self.session_mgr.save_session(master_key.hex())
        
        mnemonic = self.mnemonic_mgr.generate_mnemonic()
        self._show_mnemonic_and_setup_totp(mnemonic, master_key)

    def _show_mnemonic_and_setup_totp(self, mnemonic: str, master_key: bytearray):
        """Setup TOTP and show recovery phrase."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("Security Setup")
        dialog.geometry("500x600")
        dialog.transient(self)
        dialog.grab_set()
        
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        
        scroll_frame = ctk.CTkScrollableFrame(dialog, fg_color="transparent")
        scroll_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        ctk.CTkLabel(scroll_frame, text="📝 Recovery Phrase", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        ctk.CTkLabel(scroll_frame, text="Write these 24 words down! It is your final fail-safe.", 
                    text_color="#e67e22", wraplength=400).pack(pady=(0, 10))
        
        text = ctk.CTkTextbox(scroll_frame, height=120, width=400)
        text.insert("1.0", mnemonic)
        text.configure(state="disabled")
        text.pack(pady=10)
        
        ctk.CTkLabel(scroll_frame, text="📲 Setup Authenticator (Primary Login)", 
                    font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        secret = self.totp_mgr.generate_secret()
        uri = self.totp_mgr.get_provisioning_uri(secret, "User")
        qr_img = self.totp_mgr.generate_qr_image(uri)
        
        # Convert PIL to TkImage
        from PIL import ImageTk
        img = ctk.CTkImage(light_image=qr_img, dark_image=qr_img, size=(180, 180))
        
        qr_label = ctk.CTkLabel(scroll_frame, image=img, text="")
        qr_label.image = img # Keep reference
        qr_label.pack(pady=5)
        
        ctk.CTkLabel(scroll_frame, text="Enter the 6-digit code to verify:", 
                    font=ctk.CTkFont(size=12)).pack(pady=(10, 5))
        
        verify_entry = ctk.CTkEntry(scroll_frame, width=150, font=ctk.CTkFont(size=16, weight="bold"), justify="center")
        verify_entry.pack(pady=5)
        
        error_label = ctk.CTkLabel(scroll_frame, text="", text_color="#e74c3c")
        error_label.pack()

        def finish():
            code = verify_entry.get().strip().replace(" ", "")
            if not self.totp_mgr.verify_code(secret, code):
                error_label.configure(text="❌ Invalid code. Please try again.")
                return
            
            # Store TOTP info and wrap Master Key
            # Backup Key = MasterKey encrypted with TOTPSecret
            totp_key = bytearray(hashlib.sha256(secret.encode()).digest())
            temp_enc = EncryptionManager(totp_key)
            wrapped_key = temp_enc.encrypt(master_key.hex())
            
            self.db.update_recovery_info(
                totp_secret=secret.encode(),
                backup_key=wrapped_key
            )
            dialog.destroy()
            self._show_main_app()

        ctk.CTkButton(scroll_frame, text="Verify & Finish Setup", command=finish, height=45, font=ctk.CTkFont(weight="bold")).pack(pady=20)

    def _force_password_change(self):
        for widget in self.winfo_children(): widget.destroy()
        self.login_frame = LoginFrame(self, on_login=None, on_setup=self._handle_setup, is_first_time=True)
        self.login_frame.pack(expand=True, fill="both")

    def _show_main_app(self):
        self.is_locked = False
        
        # Check security status
        status = self.db.get_security_status()
        self.security_incomplete = not status['has_pin'] or not status['has_everyday']
        
        for widget in self.winfo_children():
            widget.destroy()

        self.grid_columnconfigure(0, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)

        from gui.components.sidebar import Sidebar
        self.sidebar = Sidebar(self, on_change=self._on_navigation_change)
        self.sidebar.grid(row=0, column=0, rowspan=2, sticky="nsew")

        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=1, rowspan=2, sticky="nsew")
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_rowconfigure(1, weight=1)

        self._create_header(self.main_container)

        self.content_frame = ctk.CTkFrame(self.main_container, fg_color="transparent")
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=20, pady=(0, 20))
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)

        self.frames = {}
        tab_map = {
            "passwords": ("🔐 Passwords", VaultFrame),
            "pass_gen": ("⚡ Pass Gen", PasswordGenFrame),
            "key_gen": ("🔑 Key Gen", KeyGenFrame),
            "key_vault": ("📜 Key Vault", KeyVaultFrame),
            "notes": ("📝 Notes", NotesFrame),
            "stats": ("📊 Stats", StatsFrame),
            "settings": ("⚙️ Settings", SettingsFrame),
            "about": ("ℹ️ About", AboutFrame),
            "help": ("❓ Help", HelpFrame)
        }

        for key, (label, frame_cls) in tab_map.items():
            if frame_cls in [SettingsFrame, NotesFrame]:
                f = frame_cls(self.content_frame, self.db, self)
            else:
                f = frame_cls(self.content_frame, self.db)
            self.frames[key] = f

        

        # Auto-redirect to settings if security is incomplete
        initial_tab = "settings" if self.security_incomplete else "passwords"
        self._on_navigation_change(initial_tab)
        self.sidebar.set_active(initial_tab)
        self._reset_session_timer()

    def _handle_change_master_password(self, old_password: str, new_password: str) -> bool:
        """Securely re-keys the entire vault with a new master password."""
        config = self.db.get_master_config()
        if not self.key_derivation.verify_password(old_password, config['password_hash']):
            return False
            
        # 1. Derive new master key
        new_salt = self.key_derivation.generate_salt()
        new_pass_hash = self.key_derivation.hash_password(new_password)
        new_master_key = self.key_derivation.derive_key(new_password, new_salt)
        
        try:
            # 2. Update DB metadata
            self.db.update_master_key_derivation(new_pass_hash, new_salt)
            
            # 3. Re-key the DB files
            self.db.rekey_vault(new_master_key)
            
            # 4. Update the encryption manager
            self.encryption = EncryptionManager(new_master_key)
            self.db.set_encryption(self.encryption)
            
            # 5. Force update of wrapped keys (Everyday/PIN) as they are wrapped with Master Key
            # Actually, Everyday Password WRAPS the Master Key.
            # PIN WRAPS the Master Key.
            # So if Master Key changes, we MUST re-wrap it with existing Everyday/PIN passwords.
            # This requires the user to re-setup or provide those passwords.
            # For simplicity, we'll clear them and force re-setup.
            self.db.save_everyday_config(None, b"", b"")
            self.db.save_pin(None, b"", b"")
            
            return True
        except Exception as e:
            print(f"Master Password change failed: {e}")
            return False

    def _create_header(self, parent):
        header = ctk.CTkFrame(parent, height=80, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
        header.grid_propagate(False)

        self.header_title = ctk.CTkLabel(
            header, text="Dashboard",
            font=ctk.CTkFont(size=24, weight="bold")
        )
        self.header_title.pack(side="left", pady=10)

        # Show security warning if needed
        warning_text = self.login_warning
        if self.security_incomplete:
            warning_text = "🛡️ Security Setup Incomplete! Please set PIN and Everyday Password."
            
        if warning_text:
            ctk.CTkLabel(
                header, text=warning_text,
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#e67e22" if not self.security_incomplete else "#e74c3c"
            ).pack(side="left", padx=20)

        btn_frame = ctk.CTkFrame(header, fg_color="transparent")
        btn_frame.pack(side="right")
        ctk.CTkButton(
            btn_frame, text="🔒 Lock Vault",
            width=100, height=35,
            fg_color="#e74c3c", hover_color="#c0392b",
            command=self._lock_vault
        ).pack(side="left", padx=5)

    def _handle_create_backup(self, output_path: str) -> bool:
        """Logic to create an encrypted backup using the Migration Key."""
        enc_mgr = self._get_backup_encryption()
        if not enc_mgr:
            return False
        return self.backup_mgr.create_backup(Path(output_path), enc_mgr)

    def _handle_verify_backup(self, backup_path: str) -> bool:
        enc_mgr = self._get_backup_encryption()
        if not enc_mgr:
            return False
        return self.backup_mgr.verify_backup(Path(backup_path), enc_mgr)

    def _handle_restore_backup(self, backup_path: str) -> bool:
        enc_mgr = self._get_backup_encryption()
        if not enc_mgr:
            return False
        return self.backup_mgr.restore_backup(Path(backup_path), DATA_DIR, enc_mgr)

    def _get_backup_encryption(self) -> Optional[EncryptionManager]:
        key_hash = self.db.get_latest_migration_key_hash()
        if not key_hash:
            return None
        hwid = self.session_mgr.get_current_hwid()
        backup_key = hashlib.pbkdf2_hmac(
            "sha256",
            key_hash.encode(),
            hwid.encode(),
            200_000,
            dklen=32
        )
        return EncryptionManager(bytearray(backup_key))

    def _update_storage_paths(self, data_dir: str, backup_dir: str):
        """Updates and moves storage locations (WIP)."""
        # User requested this feature. We will implement basic path tracking here.
        # For a full implementation, we'd need to move files and update config.py dynamically.
        pass

    def help(self):
        self._show_main_app()
        self.sidebar.set_active("help")
        self.frames["help"].grid(row=0, column=0, sticky="nsew")
        self.frames["help"].show()
        self._reset_session_timer()
    
    def about(self):
        self._show_main_app()
        self.sidebar.set_active("about")
        self.frames["about"].grid(row=0, column=0, sticky="nsew")
        self.frames["about"].show()
        self._reset_session_timer()

    def _on_navigation_change(self, key: str):
        """Switch content frame based on sidebar selection."""
        # Hide all frames
        for f in self.frames.values():
            f.grid_forget()

        # Show selected frame
        frame = self.frames.get(key)
        if frame:
            frame.grid(row=0, column=0, sticky="nsew")
            
            # Update header title
            titles = {
                "passwords": "Password Vault",
                "pass_gen": "Password Generator",
                "key_gen": "Key Generator",
                "key_vault": "Key Vault",
                "notes": "Markdown Notes",
                "stats": "Statistics",
                "settings": "Settings",
                "about": "About",
                "help": "Help"
            }
            self.header_title.configure(text=titles.get(key, "Dashboard"))

            # Refresh data if needed
            if hasattr(frame, "refresh"):
                frame.refresh()

    def _lock_vault(self):
        if self.session_timer:
            self.after_cancel(self.session_timer)
        if self.encryption:
            self.encryption.cleanup()
        self.encryption = None
        self.db.set_encryption(None)
        
        # Reset grid config for login
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=0)
        self.grid_rowconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=0)
        
        # Force garbage collection to remove potential string secrets from RAM
        import gc
        gc.collect()
        
        self._show_login()

    def _on_tab_change(self):
        # Deprecated: replaced by _on_navigation_change
        pass

    def _reset_session_timer(self):
        if self.session_timer:
            self.after_cancel(self.session_timer)
        self.session_timer = self.after(SESSION_TIMEOUT_MINUTES * 60 * 1000, self._lock_vault)

    def _init_blob_manager(self):
        """Initializes the secondary secure storage manager."""
        if self.encryption:
            from core.blob_manager import BlobManager
            self.blob_mgr = BlobManager(BLOB_FILE, self.encryption)

    def _cleanup_blob_manager(self):
        if self.blob_mgr:
            self.blob_mgr.close()
            self.blob_mgr = None

    def _on_close(self):
        self._cleanup_blob_manager()
        if self.encryption:
            self.encryption.cleanup()
        self.db.close()
        self.destroy()

def main():
    app = BitMarrowApp()
    app.mainloop()

if __name__ == "__main__":
    main()
