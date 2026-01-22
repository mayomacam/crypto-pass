import sqlite3
import os
import time
import json
import keyring
import secrets
import hashlib
from datetime import datetime
from typing import Optional, List, Dict, Any
from pathlib import Path

from config import DATA_DIR, DB_FILE
from core.encryption import EncryptionManager
from utils.audit_logger import AuditLogger, EVENT_DB_MIGRATION, EVENT_LOGIN_SUCCESS

SERVICE_VAULT = "BitMarrow-Vault"


class DatabaseManager:
    """Manages encrypted SQLite database operations."""
    
    def __init__(self, encryption_manager: Optional[EncryptionManager] = None):
        self._encryption = encryption_manager
        self._conn: Optional[sqlite3.Connection] = None
        self._db_key: Optional[str] = None
        self._audit = AuditLogger(self)
        self._temp_db_path: Optional[str] = None
        self._ensure_data_dir()
    
    def _ensure_data_dir(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    def set_encryption(self, encryption_manager: EncryptionManager):
        self._encryption = encryption_manager
        self._audit = AuditLogger(self)  # Re-init with encryption context

    def connect(self):
        """
        Establish database connection.
        If the database is already fully encrypted, we need the key FIRST.
        For migration: if it's plain SQLite, we connect normally then encrypt after.
        """
        if self._encryption:
             # If we already have encryption manager (e.g. from session persistence)
             self._open_sealed_db()
             
             # MIGRATION CHECK: If it was plain SQLite, seal it now
             if DB_FILE.exists():
                 with open(DB_FILE, "rb") as f:
                     header = f.read(16)
                 if header.startswith(b"SQLITE"):
                     self._seal_db()
                     self._audit.log_event("DB_MIGRATION", "Migrated plain vault to full-file encryption")
        else:
             # Standard connect for initial setup or first login
             self._conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
             self._conn.row_factory = sqlite3.Row
             self._init_tables()

    def _open_sealed_db(self):
        """Decrypts the sealed vault into an in-memory database."""
        if not DB_FILE.exists():
            return

        with open(DB_FILE, "rb") as f:
            header = f.read(16)
        
        if header.startswith(b"SQLITE"):
            # It's an unencrypted/legacy database
            self._conn = sqlite3.connect(str(DB_FILE), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            self._init_tables()
            return

        # It's encrypted. Decrypt to RAM and deserialize.
        try:
            encrypted_data = DB_FILE.read_bytes()
            decrypted_data = self._encryption.decrypt_bytes(encrypted_data)
            
            # Create in-memory DB
            self._conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
            
            # FAST LOAD: Deserialize bytes directly into the connection
            # This requires Python 3.10+ and a compatible sqlite3 build
            self._conn.deserialize(decrypted_data)
            
            # Clear decrypted buffer from generic variable, though python GC handles finding it eventually
            del decrypted_data
            
            self._init_tables()
        except Exception as e:
            print(f"Failed to open sealed DB: {e}")
            # Fallback (shouldn't happen)
            raise e

    def close(self):
        if self._conn:
            # Re-seal before closing if it was encrypted
            if self._encryption:
                self._seal_db()
            
            self._conn.close()
            self._conn = None
        
        self._temp_db_path = None

    def _seal_db(self):
        """Encrypts the in-memory database back to the main vault file."""
        if not self._conn or not self._encryption:
            return
        
        try:
            # Serialize in-memory DB to bytes
            data = self._conn.serialize()
            
            # Encrypt and write to disk
            encrypted = self._encryption.encrypt_bytes(data)
            
            # Write safely using a .tmp file then rename to avoid corruption on crash
            start_time = datetime.now()
            temp_target = DB_FILE.with_suffix(".new")
            temp_target.write_bytes(encrypted)

            for attempt in range(3):
                try:
                    try:
                        os.chmod(temp_target, 0o600)
                    except OSError:
                        pass
                    temp_target.replace(DB_FILE)
                    break
                except PermissionError:
                    if attempt == 2:
                        raise
                    time.sleep(0.1)
            
        except Exception as e:
            print(f"Failed to seal database: {e}")
    
    def _init_tables(self):
        cursor = self._conn.cursor()
        
        # Master configuration with recovery fields
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS master_config (
                id INTEGER PRIMARY KEY,
                salt BLOB NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret BLOB,           -- Encrypted
                backup_key BLOB,            -- Master key encrypted with TOTP
                mnemonic_hash TEXT,         -- Hash of the 24 words
                login_warning TEXT,         -- Persistent warning message
                pin_hash TEXT,              -- Hash of the PIN
                pin_salt BLOB,              -- Salt for PIN derivation
                pin_wrapped_key BLOB,       -- Master key encrypted with PIN-derived key
                pin_attempts INTEGER DEFAULT 0,
                everyday_hash TEXT,         -- Everyday (Login) Password
                everyday_salt BLOB,
                everyday_wrapped_key BLOB,  -- Master key encrypted with Everyday Pass
                vault_id TEXT,              -- Unique fingerprint
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Standard password entries
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title BLOB NOT NULL,
                username BLOB,
                password BLOB NOT NULL,
                url BLOB,
                notes BLOB,
                category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Crypto keys
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS crypto_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name BLOB NOT NULL,
                key_type TEXT NOT NULL,
                public_key BLOB,
                private_key BLOB,
                key_size INTEGER,
                expiry_date TIMESTAMP,
                metadata BLOB,              -- Encrypted JSON
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes BLOB
            )
        ''')

        # Markdown Notes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS markdown_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title BLOB NOT NULL,
                content BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Attachments linking notes to blobs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS attachments (
                id TEXT PRIMARY KEY,
                note_id INTEGER,
                blob_id TEXT,
                filename TEXT,
                file_type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (note_id) REFERENCES markdown_notes(id)
            )
        ''')

        # Audit Logs
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                details TEXT,
                status TEXT DEFAULT 'SUCCESS',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Migration Audit History (Permanent)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS migration_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                transfer_key_hash TEXT,
                old_device_id TEXT,
                new_device_id TEXT,
                details TEXT,               -- JSON stats: password_count, key_count, etc.
                status TEXT DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                migrated_at TIMESTAMP
            )
        ''')
        
        self._migrate_tables()
        self._conn.commit()

    def _migrate_tables(self):
        """Adds missing columns to existing tables."""
        cursor = self._conn.cursor()
        
        # Check if PIN columns exist in master_config
        cursor.execute("PRAGMA table_info(master_config)")
        columns = [row[1] for row in cursor.fetchall()]
        
        needed = {
            'totp_secret': 'BLOB',
            'backup_key': 'BLOB',
            'mnemonic_hash': 'TEXT',
            'login_warning': 'TEXT',
            'pin_hash': 'TEXT',
            'pin_salt': 'BLOB',
            'pin_wrapped_key': 'BLOB',
            'pin_attempts': 'INTEGER DEFAULT 0',
            'everyday_hash': 'TEXT',
            'everyday_salt': 'BLOB',
            'everyday_wrapped_key': 'BLOB',
            'vault_id': 'TEXT'
        }
        
        for col, col_type in needed.items():
            if col not in columns:
                try:
                    cursor.execute(f"ALTER TABLE master_config ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass

        cursor.execute("PRAGMA table_info(migration_history)")
        mig_columns = [row[1] for row in cursor.fetchall()]
        mig_needed = {
            "transfer_key_hash": "TEXT",
            "migrated_at": "TIMESTAMP"
        }
        for col, col_type in mig_needed.items():
            if col not in mig_columns:
                try:
                    cursor.execute(f"ALTER TABLE migration_history ADD COLUMN {col} {col_type}")
                except sqlite3.OperationalError:
                    pass
        
        self._conn.commit()

    # ============== Master Config Operations ==============
    
    def has_master_password(self) -> bool:
        cursor = self._conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM master_config')
        count = cursor.fetchone()[0]
        return count > 0
    
    def save_master_config(self, salt: bytes, password_hash: str):
        cursor = self._conn.cursor()
        cursor.execute(
            'INSERT INTO master_config (salt, password_hash) VALUES (?, ?)',
            (salt, password_hash)
        )
        self._conn.commit()
        self._audit.log_event("VAULT_INITIALIZED", "Vault created with master password")

    def get_master_config(self) -> Optional[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM master_config LIMIT 1')
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None

    def update_recovery_info(self, totp_secret: Optional[bytes] = None, 
                             backup_key: Optional[bytes] = None,
                             mnemonic_hash: Optional[str] = None):
        cursor = self._conn.cursor()
        if totp_secret:
            cursor.execute('UPDATE master_config SET totp_secret = ?', (totp_secret,))
        if backup_key:
            cursor.execute('UPDATE master_config SET backup_key = ?', (backup_key,))
        if mnemonic_hash:
            cursor.execute('UPDATE master_config SET mnemonic_hash = ?', (mnemonic_hash,))
        self._conn.commit()

    def set_login_warning(self, message: Optional[str]):
        cursor = self._conn.cursor()
        cursor.execute('UPDATE master_config SET login_warning = ?', (message,))
        self._conn.commit()

    def save_pin(self, pin_hash: str, salt: bytes, wrapped_key: bytes):
        """Saves PIN configuration to master_config."""
        self._conn.execute('''
            UPDATE master_config 
            SET pin_hash = ?, pin_salt = ?, pin_wrapped_key = ?, pin_attempts = 0
        ''', (pin_hash, salt, wrapped_key))
        self._conn.commit()
        self._audit.log_event("PIN_SETUP", "Quick access PIN configured")

    def get_pin_config(self) -> Optional[dict]:
        """Retrieves PIN configuration."""
        cursor = self._conn.execute('SELECT pin_hash, pin_salt, pin_wrapped_key, pin_attempts FROM master_config')
        row = cursor.fetchone()
        if row and row[0]:
            return {
                'pin_hash': row[0],
                'pin_salt': row[1],
                'pin_wrapped_key': row[2],
                'pin_attempts': row[3]
            }
        return None

    def update_pin_attempts(self, attempts: int):
        """Self-destruct mechanism: wipes PIN after 5 attempts."""
        if attempts >= 5:
            # Wipe PIN
            self._conn.execute('UPDATE master_config SET pin_hash = NULL, pin_salt = NULL, pin_wrapped_key = NULL, pin_attempts = 0')
            self._audit.log_event("PIN_WIPED", "PIN cleared due to too many failed attempts", "WARNING")
        else:
            self._conn.execute('UPDATE master_config SET pin_attempts = ?', (attempts,))
        self._conn.commit()

    def save_everyday_config(self, everyday_hash: str, salt: bytes, wrapped_key: bytes):
        """Saves Everyday Password configuration."""
        self._conn.execute('''
            UPDATE master_config 
            SET everyday_hash = ?, everyday_salt = ?, everyday_wrapped_key = ?
        ''', (everyday_hash, salt, wrapped_key))
        self._conn.commit()
        self._audit.log_event("EVERYDAY_PASS_SETUP", "Everyday login password configured")

    def get_everyday_config(self) -> Optional[dict]:
        """Retrieves Everyday Password configuration."""
        cursor = self._conn.execute('SELECT everyday_hash, everyday_salt, everyday_wrapped_key FROM master_config')
        row = cursor.fetchone()
        if row and row[0]:
            return {
                'everyday_hash': row[0],
                'everyday_salt': row[1],
                'everyday_wrapped_key': row[2]
            }
        return None

    def save_migration_key(self, key_hash: str, old_device_id: str, details: str):
        """Starts a migration record."""
        self._conn.execute('''
            INSERT INTO migration_history (transfer_key_hash, old_device_id, details, status)
            VALUES (?, ?, ?, 'PENDING')
        ''', (key_hash, old_device_id, details))
        self._conn.commit()

    def get_migration_history(self) -> list:
        """Retrieves the full auditable migration history."""
        cursor = self._conn.execute('SELECT id, old_device_id, new_device_id, status, created_at, migrated_at FROM migration_history ORDER BY id DESC')
        return cursor.fetchall()

    def get_vault_id(self) -> Optional[str]:
        cursor = self._conn.execute('SELECT vault_id FROM master_config')
        row = cursor.fetchone()
        return row[0] if row else None

    def set_vault_id(self, vault_id: str):
        self._conn.execute('UPDATE master_config SET vault_id = ?', (vault_id,))
        self._conn.commit()

    def check_integrity(self) -> str:
        """Verifies vault fingerprinting for hardware binding."""
        db_id = self.get_vault_id()
        if not db_id:
            return "INITIAL"
        
        stored_id = keyring.get_password(SERVICE_VAULT, "fingerprint")
        if not stored_id:
            return "NEW_DEVICE"
            
        if stored_id != db_id:
            return "MISMATCH"
            
        return "MATCH"

    def get_latest_migration_key_hash(self) -> Optional[str]:
        """Returns the most recent pending migration key hash."""
        cursor = self._conn.execute('SELECT transfer_key_hash FROM migration_history WHERE status = "PENDING" ORDER BY created_at DESC LIMIT 1')
        row = cursor.fetchone()
        return row[0] if row else None

    def verify_migration_key(self, key: str) -> bool:
        """Checks if the provided key matches a PENDING migration record."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        cursor = self._conn.execute('SELECT id FROM migration_history WHERE transfer_key_hash = ? AND status = "PENDING"', (key_hash,))
        return cursor.fetchone() is not None

    def get_security_status(self) -> Dict[str, bool]:
        """Checks if PIN and Everyday Password have been configured."""
        config = self.get_master_config()
        if not config:
            return {"has_pin": False, "has_everyday": False}
        
        return {
            "has_pin": config.get('pin_hash') is not None,
            "has_everyday": config.get('everyday_hash') is not None
        }

    def rekey_vault(self, new_master_key: bytes):
        """
        Re-encrypts the entire database with a new master key.
        This is a critical operation.
        """
        if not self._encryption:
            raise Exception("Database must be unlocked to re-key")
            
        # 1. Create new encryption manager
        new_encryption = EncryptionManager(new_master_key)
        
        # 2. Update all wrapped keys in master_config if they exist
        # Wait, if we change the master password, we need to unwrap current master key first.
        # Actually, if we change the MASTER password, the master key ITSELF might change 
        # OR we just change the password that derives it.
        # In BitMarrow, the Master Password DERIVES the Master Key.
        # So changing the Master Password = CHANGING the Master Key.
        
        # This requires re-encrypting everything.
        # Let's perform a full migration to a new temp DB and then swap.
        
        import tempfile
        temp_path = Path(tempfile.gettempdir()) / f"rekey_{secrets.token_hex(4)}.db"
        
        try:
            # Connect to new DB
            new_conn = sqlite3.connect(str(temp_path))
            new_conn.row_factory = sqlite3.Row
            
            # Copy schema and re-encrypt data
            # This is complex. A simpler way is to:
            # 1. Decrypt current DB to memory/temp file (already done in self._conn)
            # 2. Update self._encryption to new one
            # 3. Call self._seal_db() which uses self._encryption to write to DB_FILE
            
            # But we need to update master_config too (new salt, new hash)
            # The caller (app.py) should handle updating master_config table data
            # then call this to finalize the encryption swap.
            
            self._encryption = new_encryption
            self._seal_db() # Overwrites DB_FILE with new encryption
            self._audit.log_event("MASTER_PASS_CHANGED", "Vault re-keyed with new master password")
            
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def update_master_key_derivation(self, password_hash: str, salt: bytes):
        """Updates the root password hash and salt in master_config."""
        self._conn.execute('''
            UPDATE master_config 
            SET password_hash = ?, salt = ?
        ''', (password_hash, salt))
        self._conn.commit()

    def set_config_value(self, key: str, value: str):
        """Stores a generic configuration string in the master_config table."""
        # Using a dynamic column approach or a key-value table would be better,
        # but for now we'll add columns to master_config as needed.
        # Check if column exists, if not add it.
        try:
            self._conn.execute(f"UPDATE master_config SET {key} = ?", (value,))
            self._conn.commit()
        except sqlite3.OperationalError:
            # Column might not exist
            self._conn.execute(f"ALTER TABLE master_config ADD COLUMN {key} TEXT")
            self._conn.commit()
            self._conn.execute(f"UPDATE master_config SET {key} = ?", (value,))
            self._conn.commit()

    def get_config_value(self, key: str) -> Optional[str]:
        """Retrieves a generic configuration string."""
        try:
            cursor = self._conn.execute(f"SELECT {key} FROM master_config")
            row = cursor.fetchone()
            return row[0] if row else None
        except sqlite3.OperationalError:
            return None

    def finalize_migration(self, key: str, new_device_id: str):
        """Completes the migration and binds the vault to the new device."""
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        self._conn.execute('''
            UPDATE migration_history 
            SET status = 'COMPLETED', new_device_id = ?, migrated_at = CURRENT_TIMESTAMP
            WHERE transfer_key_hash = ?
        ''', (new_device_id, key_hash))
        
        # Store local fingerprint
        vault_id = self.get_vault_id()
        if vault_id:
            keyring.set_password(SERVICE_VAULT, "vault_id", vault_id)
            
        self._conn.commit()
        self._audit.log_event("VAULT_MIGRATED", f"Vault claimed by device {new_device_id}")

    # ============== Encryption Wrappers ==============

    def _encrypt(self, value: str) -> Optional[bytes]:
        if self._encryption and value is not None:
            return self._encryption.encrypt(value)
        return None

    def _decrypt(self, value: Optional[bytes]) -> Optional[str]:
        if self._encryption and value:
            return self._encryption.decrypt(value)
        return None

    # ============== Password Operations ==============

    def add_password(self, title: str, username: str, password: str,
                     url: str = "", notes: str = "", category: str = "") -> int:
        cursor = self._conn.cursor()
        cursor.execute('''
            INSERT INTO passwords (title, username, password, url, notes, category)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            self._encrypt(title),
            self._encrypt(username),
            self._encrypt(password),
            self._encrypt(url),
            self._encrypt(notes),
            category
        ))
        self._conn.commit()
        entry_id = cursor.lastrowid
        if hasattr(self, '_audit') and self._audit:
            self._audit.log_event("PASSWORD_ADD", f"Added entry: {title}")
        return entry_id
    
    def get_all_passwords(self) -> List[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM passwords ORDER BY id DESC')
        rows = cursor.fetchall()
        result = []
        for row in rows:
            try:
                result.append({
                    'id': row['id'],
                    'title': self._decrypt(row['title']),
                    'username': self._decrypt(row['username']),
                    'password': self._decrypt(row['password']),
                    'url': self._decrypt(row['url']),
                    'notes': self._decrypt(row['notes']),
                    'category': row['category'],
                    'created_at': row['created_at']
                })
            except Exception:
                continue # Skip if decryption fails
        return result

    def delete_password(self, entry_id: int):
        self._conn.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
        self._conn.commit()
        self._audit.log_event("PASSWORD_DELETE", f"Deleted entry ID: {entry_id}")
    
    def get_password(self, entry_id: int) -> Optional[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM passwords WHERE id = ?', (entry_id,))
        row = cursor.fetchone()
        if not row: return None
        
        try:
            return {
                'id': row['id'],
                'title': self._decrypt(row['title']),
                'username': self._decrypt(row['username']),
                'password': self._decrypt(row['password']),
                'url': self._decrypt(row['url']),
                'notes': self._decrypt(row['notes']),
                'category': row['category'],
                'created_at': row['created_at']
            }
        except Exception:
            return None

    def update_password(self, entry_id: int, title: str, username: str, password: str,
                        url: str = "", notes: str = "", category: str = ""):
        cursor = self._conn.cursor()
        cursor.execute('''
            UPDATE passwords 
            SET title = ?, username = ?, password = ?, url = ?, notes = ?, 
                category = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            self._encrypt(title),
            self._encrypt(username),
            self._encrypt(password),
            self._encrypt(url),
            self._encrypt(notes),
            category,
            entry_id
        ))
        self._conn.commit()
        if hasattr(self, '_audit') and self._audit:
            self._audit.log_event("PASSWORD_EDIT", f"Updated entry: {title}")

    # ============== Crypto Key Operations ==============

    def add_crypto_key(self, name: str, key_type: str, public_key: str = "",
                       private_key: str = "", key_size: int = 0, 
                       expiry_date: Optional[str] = None,
                       metadata: Optional[Dict] = None,
                       notes: str = "") -> int:
        cursor = self._conn.cursor()
        
        metadata_json = json.dumps(metadata) if metadata else None
        
        cursor.execute('''
            INSERT INTO crypto_keys (name, key_type, public_key, private_key, key_size, expiry_date, metadata, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            self._encrypt(name),
            key_type,
            self._encrypt(public_key),
            self._encrypt(private_key),
            key_size,
            expiry_date,
            self._encrypt(metadata_json),
            self._encrypt(notes)
        ))
        self._conn.commit()
        entry_id = cursor.lastrowid
        if hasattr(self, '_audit') and self._audit:
             self._audit.log_event("KEY_GEN", f"Generated key: {name}")
        return entry_id

    def get_crypto_key(self, key_id: int) -> Optional[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM crypto_keys WHERE id = ?', (key_id,))
        row = cursor.fetchone()
        if not row: return None
        
        try:
            metadata_raw = self._decrypt(row['metadata'])
            metadata = json.loads(metadata_raw) if metadata_raw else None
            
            return {
                'id': row['id'],
                'name': self._decrypt(row['name']),
                'key_type': row['key_type'],
                'public_key': self._decrypt(row['public_key']),
                'private_key': self._decrypt(row['private_key']),
                'key_size': row['key_size'],
                'expiry_date': row['expiry_date'],
                'metadata': metadata,
                'notes': self._decrypt(row['notes']),
                'created_at': row['created_at']
            }
        except Exception:
            return None

    def get_all_crypto_keys(self) -> List[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT * FROM crypto_keys ORDER BY id DESC')
        rows = cursor.fetchall()
        result = []
        for row in rows:
            try:
                metadata_raw = self._decrypt(row['metadata'])
                metadata = json.loads(metadata_raw) if metadata_raw else None
                
                result.append({
                    'id': row['id'],
                    'name': self._decrypt(row['name']),
                    'key_type': row['key_type'],
                    'public_key': self._decrypt(row['public_key']),
                    'private_key': self._decrypt(row['private_key']),
                    'key_size': row['key_size'],
                    'expiry_date': row['expiry_date'],
                    'metadata': metadata
                })
            except Exception:
                continue
        return result

    def delete_crypto_key(self, key_id: int):
        self._conn.execute('DELETE FROM crypto_keys WHERE id = ?', (key_id,))
        self._conn.commit()

    def update_crypto_key_notes(self, key_id: int, notes: str):
        self._conn.execute('UPDATE crypto_keys SET notes = ? WHERE id = ?', (self._encrypt(notes), key_id))
        self._conn.commit()

    def get_password_stats(self) -> Dict[str, Any]:
        passwords = self.get_all_passwords()
        total = len(passwords)
        categories = {}
        weak_count = 0
        for p in passwords:
            cat = p['category'] or 'Uncategorized'
            categories[cat] = categories.get(cat, 0) + 1
            if len(p['password'] or '') < 12:
                weak_count += 1
        return {
            'total': total,
            'categories': categories,
            'weak_count': weak_count,
            'key_count': len(self.get_all_crypto_keys())
        }

    def get_unique_categories(self) -> List[str]:
        """Fetches all unique category names from the vault."""
        cursor = self._conn.execute('SELECT DISTINCT category FROM passwords WHERE category IS NOT NULL AND category != ""')
        return [row[0] for row in cursor.fetchall()]

    def get_audit_logs(self, limit: int = 50) -> List[sqlite3.Row]:
        cursor = self._conn.execute(
            'SELECT event_type, details, status, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT ?',
            (limit,)
        )
        return cursor.fetchall()

    # ============== Markdown Note Operations ==============

    def add_note(self, title: str, content: str) -> int:
        cursor = self._conn.cursor()
        cursor.execute('''
            INSERT INTO markdown_notes (title, content)
            VALUES (?, ?)
        ''', (self._encrypt(title), self._encrypt(content)))
        self._conn.commit()
        return cursor.lastrowid

    def get_all_notes(self) -> List[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT id, title, updated_at FROM markdown_notes ORDER BY updated_at DESC')
        rows = cursor.fetchall()
        result = []
        for row in rows:
            try:
                result.append({
                    'id': row['id'],
                    'title': self._decrypt(row['title']),
                    'updated_at': row['updated_at']
                })
            except Exception:
                continue
        return result

    def get_note(self, note_id: int) -> Optional[Dict[str, Any]]:
        cursor = self._conn.cursor()
        cursor.execute('SELECT id, title, content, created_at, updated_at FROM markdown_notes WHERE id = ?', (note_id,))
        row = cursor.fetchone()
        if not row: return None
        try:
            return {
                'id': row['id'],
                'title': self._decrypt(row['title']),
                'content': self._decrypt(row['content']),
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }
        except Exception:
            return None

    # ============== Attachment Operations ==============

    def add_attachment(self, note_id: int, blob_id: str, filename: str, file_type: str):
        import secrets
        att_id = secrets.token_hex(8)
        self._conn.execute('''
            INSERT INTO attachments (id, note_id, blob_id, filename, file_type)
            VALUES (?, ?, ?, ?, ?)
        ''', (att_id, note_id, blob_id, filename, file_type))
        self._conn.commit()
        self._audit.log_event("ATTACHMENT_ADDED", f"Added file {filename} to note {note_id}")

    def get_attachments(self, note_id: int) -> List[Dict[str, Any]]:
        cursor = self._conn.execute('SELECT * FROM attachments WHERE note_id = ?', (note_id,))
        return [dict(row) for row in cursor.fetchall()]

    def delete_attachment(self, att_id: str):
        self._conn.execute('DELETE FROM attachments WHERE id = ?', (att_id,))
        self._conn.commit()

    def update_note(self, note_id: int, title: str, content: str):
        cursor = self._conn.cursor()
        cursor.execute('''
            UPDATE markdown_notes 
            SET title = ?, content = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (self._encrypt(title), self._encrypt(content), note_id))
        self._conn.commit()

    def delete_note(self, note_id: int):
        self._conn.execute('DELETE FROM markdown_notes WHERE id = ?', (note_id,))
        self._conn.commit()
    # ============== Blob Operations ==============
