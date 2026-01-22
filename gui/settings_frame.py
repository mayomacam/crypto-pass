"""
Settings frame for configuring security features like PIN and Master Password.
"""
import hashlib
import json
import customtkinter as ctk
import os
import secrets
from pathlib import Path
from typing import Optional

from config import COLOR_BG, COLOR_SURFACE, COLOR_ACCENT, COLOR_TEXT, COLOR_TEXT_DIM, DATA_DIR
from core.encryption import EncryptionManager

class SettingsFrame(ctk.CTkFrame):
    """Settings interface for security and app configuration."""
    
    def __init__(self, master, db_manager, app_instance, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.db = db_manager
        self.app = app_instance # Reference to get encryption key and pin_mgr
        
        self.grid_columnconfigure(0, weight=1)
        self._create_widgets()
        
    def _create_widgets(self):
        # Header
        ctk.CTkLabel(
            self, text="Application Settings (v3.0)",
            font=ctk.CTkFont(size=22, weight="bold")
        ).pack(anchor="w", padx=20, pady=20)
        
        # Tabs for better organization
        self.tabview = ctk.CTkTabview(self, fg_color="transparent")
        self.tabview.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        self.tab_creds = self.tabview.add("🔐 Credentials")
        self.tab_prefs = self.tabview.add("⚙️ Preferences")
        self.tab_storage = self.tabview.add("📂 Storage Paths")
        self.tab_migration = self.tabview.add("📜 Migration & Backup")
        
        self._setup_credentials_tab()
        self._setup_preferences_tab()
        self._setup_storage_tab()
        self._setup_migration_tab()

    def _setup_preferences_tab(self):
        scroll = ctk.CTkScrollableFrame(self.tab_prefs, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # Session Timeout Configuration
        session_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        session_container.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(session_container, text="Session Persistence", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(session_container, text="How long 'Stay Logged In' sessions last before forcing a re-login.", text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 20))
        
        slider_frame = ctk.CTkFrame(session_container, fg_color="transparent")
        slider_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.timeout_label = ctk.CTkLabel(slider_frame, text="24 Hours", width=60)
        self.timeout_label.pack(side="right", padx=10)
        
        self.timeout_slider = ctk.CTkSlider(
            slider_frame, from_=1, to=24, number_of_steps=23,
            command=self._update_slider_label
        )
        self.timeout_slider.pack(side="left", fill="x", expand=True)
        
        # Load current value (default 24)
        current_timeout = self.db.get_config_value("session_timeout_hours")
        current_val = int(current_timeout) if current_timeout else 24
        self.timeout_slider.set(current_val)
        self.timeout_label.configure(text=f"{current_val} Hours")
        
        ctk.CTkButton(session_container, text="Save Preference", command=self._handle_save_preference, width=150, height=40, fg_color=COLOR_ACCENT, text_color="black").pack(padx=20, pady=(0, 20))

    def _update_slider_label(self, value):
        self.timeout_label.configure(text=f"{int(value)} Hours")

    def _handle_save_preference(self):
        val = int(self.timeout_slider.get())
        try:
            self.db.set_config_value("session_timeout_hours", str(val))
            self.info_label.configure(text=f"✅ Session timeout set to {val} hours", text_color=COLOR_ACCENT)
        except Exception as e:
            self.info_label.configure(text=f"❌ Save failed: {e}", text_color="#e74c3c")

    def _setup_credentials_tab(self):
        scroll = ctk.CTkScrollableFrame(self.tab_creds, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # --- Change Master Password Section ---
        master_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        master_container.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(master_container, text="Change Master Password", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(master_container, text="Warning: This re-encrypts the entire database. Very intensive.", text_color="#e74c3c", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 20))
        
        self.old_master_entry = ctk.CTkEntry(master_container, placeholder_text="Current Master Password", show="•", width=380, height=40)
        self.old_master_entry.pack(padx=20, pady=(0, 10))
        self.new_master_entry = ctk.CTkEntry(master_container, placeholder_text="New Master Password", show="•", width=380, height=40)
        self.new_master_entry.pack(padx=20, pady=(0, 20))
        
        ctk.CTkButton(master_container, text="🔥 Re-key Vault", command=self._handle_rekey_vault, fg_color="#e74c3c", height=40).pack(padx=20, pady=(0, 20), fill="x")

        # --- Everyday Password Section ---
        everyday_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        everyday_container.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(everyday_container, text="Everyday Login Password", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(everyday_container, text="A faster password for daily use. Wraps the Master Key.", text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 20))
        
        ev_input_frame = ctk.CTkFrame(everyday_container, fg_color="transparent")
        ev_input_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.ev_pass_entry = ctk.CTkEntry(ev_input_frame, placeholder_text="New Everyday Pass", show="•", width=200, height=40)
        self.ev_pass_entry.pack(side="left")
        
        self.save_ev_btn = ctk.CTkButton(ev_input_frame, text="Set Everyday Pass", command=self._handle_save_everyday, width=150, height=40, fg_color=COLOR_ACCENT, text_color="black")
        self.save_ev_btn.pack(side="left", padx=10)

        # --- Quick Unlock PIN Section ---
        pin_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        pin_container.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(pin_container, text="Quick Unlock PIN", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(pin_container, text="4-8 digits. Bound to this device only.", text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 20))
        
        pin_input_frame = ctk.CTkFrame(pin_container, fg_color="transparent")
        pin_input_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        self.pin_entry = ctk.CTkEntry(pin_input_frame, placeholder_text="Enter PIN", show="•", width=150, height=40)
        self.pin_entry.pack(side="left")
        
        self.save_pin_btn = ctk.CTkButton(pin_input_frame, text="Set PIN", command=self._handle_save_pin, width=100, height=40, fg_color=COLOR_ACCENT, text_color="black")
        self.save_pin_btn.pack(side="left", padx=10)
        
        self.clear_pin_btn = ctk.CTkButton(pin_input_frame, text="Remove PIN", command=self._handle_clear_pin, width=100, height=40, fg_color="#e74c3c")
        self.clear_pin_btn.pack(side="left")

        self.info_label = ctk.CTkLabel(self.tab_creds, text="", text_color=COLOR_ACCENT)
        self.info_label.pack(pady=10)

    def _setup_storage_tab(self):
        scroll = ctk.CTkScrollableFrame(self.tab_storage, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        ctk.CTkLabel(scroll, text="Vault Storage Locations", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        # Path configuration
        
        def add_path_setting(label, current_path):
            frame = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
            frame.pack(fill="x", padx=10, pady=5)
            ctk.CTkLabel(frame, text=label, font=ctk.CTkFont(weight="bold")).pack(anchor="w", padx=20, pady=(15, 0))
            
            entry_frame = ctk.CTkFrame(frame, fg_color="transparent")
            entry_frame.pack(fill="x", padx=20, pady=15)
            
            e = ctk.CTkEntry(entry_frame, width=300, height=35)
            e.insert(0, str(current_path))
            e.pack(side="left", fill="x", expand=True)
            
            ctk.CTkButton(entry_frame, text="Browse", width=80, height=35, fg_color="#34495e").pack(side="left", padx=5)
            return e

        self.data_path_entry = add_path_setting("Main Data Directory", DATA_DIR)
        ctk.CTkButton(scroll, text="Update Path (Requires Restart)", command=self._handle_save_paths, height=40).pack(padx=10, pady=20, fill="x")

    def _setup_migration_tab(self):
        scroll = ctk.CTkScrollableFrame(self.tab_migration, fg_color="transparent")
        scroll.pack(fill="both", expand=True)

        # Backups
        backup_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        backup_container.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(backup_container, text="Encrypted Backups", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        ctk.CTkLabel(backup_container, text="Creates an encrypted archive of your vault using your current Migration Key.", text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=12)).pack(anchor="w", padx=20, pady=(0, 20))
        
        ctk.CTkButton(backup_container, text="Create Encrypted Backup (.cpback)", command=self._handle_create_backup, fg_color="#3498db", height=40).pack(padx=20, pady=(0, 10), fill="x")
        ctk.CTkButton(backup_container, text="Verify Backup", command=self._handle_verify_backup, fg_color="transparent", border_width=1, border_color="#555555", height=35).pack(padx=20, pady=(0, 10), fill="x")
        ctk.CTkButton(backup_container, text="Restore Backup", command=self._handle_restore_backup, fg_color="transparent", border_width=1, border_color="#555555", height=35).pack(padx=20, pady=(0, 20), fill="x")

        # Migration History
        mig_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        mig_container.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(mig_container, text="Migration Audit Ledger", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.mig_list = ctk.CTkLabel(mig_container, text="No migration history found.", text_color=COLOR_TEXT_DIM, font=ctk.CTkFont(size=11), justify="left")
        self.mig_list.pack(anchor="w", padx=20, pady=(0, 20))

        ctk.CTkButton(mig_container, text="Generate Migration Transfer Key", command=self._handle_gen_migration, fg_color="#3498db").pack(pady=(0, 20))

        audit_container = ctk.CTkFrame(scroll, fg_color=COLOR_SURFACE, corner_radius=15)
        audit_container.pack(fill="x", padx=10, pady=10)

        ctk.CTkLabel(audit_container, text="Security Event Logs", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=20, pady=(20, 5))
        self.audit_text = ctk.CTkTextbox(audit_container, height=160, fg_color=COLOR_BG, border_color="#333333", border_width=1, font=ctk.CTkFont(size=11, family="Consolas"))
        self.audit_text.pack(fill="x", padx=20, pady=(0, 10))
        self.audit_text.configure(state="disabled")
        ctk.CTkButton(audit_container, text="Refresh Logs", command=self._refresh_audit_logs, fg_color="transparent", border_width=1, border_color="#555555").pack(pady=(0, 20))

        self.migration_info_label = ctk.CTkLabel(scroll, text="", text_color=COLOR_ACCENT)
        self.migration_info_label.pack(pady=(0, 10))

    def _handle_save_paths(self):
        """Placeholder for path saving logic."""
        self.info_label.configure(text="✅ Path settings saved (Not yet implemented in engine)", text_color=COLOR_ACCENT)

    def _handle_rekey_vault(self):
        old = self.old_master_entry.get().strip()
        new = self.new_master_entry.get().strip()
        
        if not old or not new:
            self.info_label.configure(text="❌ Both fields required", text_color="#e74c3c")
            return
            
        if self.app._handle_change_master_password(old, new):
            self.info_label.configure(text="✅ Vault successfully re-keyed!", text_color=COLOR_ACCENT)
            self.old_master_entry.delete(0, 'end')
            self.new_master_entry.delete(0, 'end')
        else:
            self.info_label.configure(text="❌ Error: Password mismatch or internal error", text_color="#e74c3c")

    def _handle_save_everyday(self):
        password = self.ev_pass_entry.get().strip()
        if len(password) < 8:
            self.info_label.configure(text="❌ Everyday password must be at least 8 chars", text_color="#e74c3c")
            return
            
        try:
            # Need Master Key to wrap
            master_key = self.app.encryption._key
            salt = os.urandom(16)
            
            # Derive everyday key
            ev_key = self.app.key_derivation.derive_key(password, salt)
            temp_enc = EncryptionManager(ev_key)
            wrapped = temp_enc.encrypt_bytes(bytes(master_key))
            
            pass_hash = self.app.key_derivation.hash_password(password)
            self.db.save_everyday_config(pass_hash, salt, wrapped)
            
            self.info_label.configure(text="✅ Everyday Password set!", text_color=COLOR_ACCENT)
            self.ev_pass_entry.delete(0, 'end')
        except Exception as e:
            self.info_label.configure(text=f"❌ Error: {e}", text_color="#e74c3c")

    def _handle_save_pin(self):
        pin = self.pin_entry.get().strip()
        if not pin.isdigit() or len(pin) < 4 or len(pin) > 8:
            self.info_label.configure(text="❌ PIN must be 4-8 digits", text_color="#e74c3c")
            return
            
        try:
            master_key = self.app.encryption._key
            pin_hash, salt, wrapped = self.app.pin_mgr.setup_pin(pin, master_key)
            self.db.save_pin(pin_hash, salt, wrapped)
            
            self.info_label.configure(text="✅ PIN successfully set!", text_color=COLOR_ACCENT)
            self.pin_entry.delete(0, 'end')
        except Exception as e:
            self.info_label.configure(text=f"❌ Error: {e}", text_color="#e74c3c")

    def _handle_clear_pin(self):
        self.db.update_pin_attempts(5) # Wipes PIN
        self.info_label.configure(text="✅ PIN removed", text_color=COLOR_ACCENT)

    def _handle_gen_migration(self):
        """Generates a high-entropy Transfer Key and stores its hash for later claiming."""
        key = secrets.token_hex(16).upper()
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        
        try:
            hwid = self.app.session_mgr.get_current_hwid()
            stats = self.db.get_password_stats()
            details = json.dumps({
                "passwords": stats['total'],
                "keys": stats['key_count'],
                "generated_on": hwid
            })
            
            self.db.save_migration_key(key_hash, hwid, details)
            
            # Show the key to the user (crucial: only once)
            self.migration_info_label.configure(
                text=f"TRANSFER KEY: {key}\nWrite this down! It is required to move your vault.",
                text_color="#3498db"
            )
            self.refresh()
        except Exception as e:
            self.migration_info_label.configure(text=f"Migration Init Error: {e}", text_color="#e74c3c")

    def _handle_create_backup(self):
        """Creates an encrypted zip of the vault data."""
        from tkinter import filedialog
        output_path = filedialog.asksaveasfilename(
            defaultextension=".cpback",
            filetypes=[("Encrypted Backup", "*.cpback"), ("All files", "*.*")],
            title="Save Encrypted Backup"
        )
        if not output_path:
            return
        self.migration_info_label.configure(text="Preparing backup...", text_color=COLOR_ACCENT)
        try:
            success = self.app._handle_create_backup(output_path)
            if success:
                self.migration_info_label.configure(text="Backup created successfully.", text_color=COLOR_ACCENT)
            else:
                self.migration_info_label.configure(text="Backup failed. Generate a migration key first.", text_color="#e74c3c")
        except Exception as e:
            self.migration_info_label.configure(text=f"Backup failed: {e}", text_color="#e74c3c")

    def _handle_verify_backup(self):
        from tkinter import filedialog
        backup_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Backup", "*.cpback"), ("All files", "*.*")],
            title="Verify Backup"
        )
        if not backup_path:
            return
        self.migration_info_label.configure(text="Verifying backup...", text_color=COLOR_ACCENT)
        try:
            success = self.app._handle_verify_backup(backup_path)
            if success:
                self.migration_info_label.configure(text="Backup verified successfully.", text_color=COLOR_ACCENT)
            else:
                self.migration_info_label.configure(text="Backup verification failed.", text_color="#e74c3c")
        except Exception as e:
            self.migration_info_label.configure(text=f"Verification failed: {e}", text_color="#e74c3c")

    def _handle_restore_backup(self):
        from tkinter import filedialog
        backup_path = filedialog.askopenfilename(
            filetypes=[("Encrypted Backup", "*.cpback"), ("All files", "*.*")],
            title="Restore Backup"
        )
        if not backup_path:
            return
        self.migration_info_label.configure(text="Restoring backup...", text_color=COLOR_ACCENT)
        try:
            success = self.app._handle_restore_backup(backup_path)
            if success:
                self.migration_info_label.configure(text="Backup restored successfully.", text_color=COLOR_ACCENT)
            else:
                self.migration_info_label.configure(text="Backup restore failed.", text_color="#e74c3c")
        except Exception as e:
            self.migration_info_label.configure(text=f"Restore failed: {e}", text_color="#e74c3c")

    def refresh(self):
        """Updates the migration history list."""
        try:
            history = self.db.get_migration_history()
            if not history:
                self.mig_list.configure(text="No migration history found.")
                return
                
            text = "ID | Old Device | Status | Created At\n"
            text += "-" * 50 + "\n"
            for row in history[:5]: # Show last 5
                # row = (id, old_id, new_id, status, created, migrated)
                text += f"{row[0]} | {row[1][:8]}... | {row[3]} | {row[4][:16]}\n"
            self.mig_list.configure(text=text)
        except Exception:
            pass

        self._refresh_audit_logs()

    def _refresh_audit_logs(self):
        try:
            rows = self.db.get_audit_logs()
            self.audit_text.configure(state="normal")
            self.audit_text.delete("1.0", "end")
            if not rows:
                self.audit_text.insert("1.0", "No audit events found.")
            else:
                for row in rows:
                    line = f"{row[3]} | {row[0]} | {row[2]} | {row[1]}\n"
                    self.audit_text.insert("end", line)
            self.audit_text.configure(state="disabled")
        except Exception:
            pass
