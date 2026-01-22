# Security Architecture and Crypto Flow
Version: v5.0.0

 This document describes the encryption and decryption flow across the codebase,
 highlights layering, and notes improvement areas.

 ## High-Level Layers
 1) Master key derivation and wrapping
 2) Vault database full-file encryption (AES-256-GCM)
 3) Per-field encryption for records inside the DB
 4) Blob storage encryption (secondary DB)
 5) Session persistence encryption (keyring)
 6) Backup encryption (transfer key based)

 ## Layer 1: Master Key Derivation and Wrapping
 - Primary key material is derived from the Master Password via Argon2id in
   `core/key_derivation.py`.
 - Everyday Password and PIN do not replace the master key; they wrap the master
   key using a derived wrapper key (PIN and everyday password flows in
   `core/pin_manager.py` and `gui/app.py`).
 - TOTP recovery stores an encrypted backup key for master key recovery.

 Decryption flow:
 - User authenticates (master password / everyday password / PIN / TOTP).
 - Wrapper key is derived and used to decrypt the master key.
 - Master key is passed to `core/encryption.py` as a 32-byte bytearray.

 Improvement areas:
 - Ensure recovery flows use consistent, modern derivation and do not expose
   plaintext key material in logs or UI.

 ## Layer 2: Vault DB Full-File Encryption
 - The database file is fully encrypted using AES-256-GCM in
   `database/db_manager.py` via `EncryptionManager.encrypt_bytes`.
 - Decrypts into memory with `sqlite3.deserialize` and re-encrypts on close.

 Decryption flow:
 - Read encrypted file into memory.
 - Decrypt into bytes.
 - Deserialize into an in-memory SQLite connection.

 Risks / issues:
 - File permissions are currently broadened with `chmod 0o666` during seal,
   which can allow local tampering.

 ## Layer 3: Per-Field Encryption
 - Sensitive fields (title, username, password, notes, keys) are encrypted
   before insertion using `EncryptionManager.encrypt`.
 - This is an additional layer on top of full-file encryption.

 Decryption flow:
 - `DatabaseManager._decrypt` is used to convert encrypted columns back to
   strings for UI display.

 Risks:
 - Decryption failures are silently ignored in some queries, which can hide
   data corruption.

 ## Layer 4: Blob Storage
 - `core/blob_manager.py` decrypts the blob DB into an in-memory SQLite DB,
   then re-encrypts on seal.
 - Individual blobs are encrypted before storage for a second layer.

 Risks:
 - In-memory usage reduces plaintext exposure on disk; large blobs still
   increase RAM pressure during decrypt/serialize cycles.

 ## Layer 5: Session Persistence
 - `core/session_manager.py` stores an encrypted master key in the OS keyring.
 - The session key is derived from hardware ID plus a device secret stored in
   the OS keyring, optionally combined with a PIN-derived key for PIN-gated sessions.
 - AES-256-GCM protects the stored payload.

 Risks:
 - Hardware ID alone is not a strong secret; an attacker with keyring access
   and HWID can decrypt the session.

 ## Layer 6: Backup Encryption
 - Backups are encrypted with AES-256-GCM in `core/backup_manager.py`.
 - Key derivation uses PBKDF2-HMAC-SHA256 over `transfer_key_hash` with `hwid`
   as salt to add work factor for offline guessing.
 - Integrity is checked via a manifest of SHA-256 file hashes.

 Risks:
 - Transfer key entropy should remain high (now 32 hex chars).
 - ZIP extraction uses `extractall` without path validation (zip-slip risk).

 ## End-to-End Flow Summary
 - User credentials -> Argon2id -> master key.
 - Master key -> encryption manager.
 - Vault DB is encrypted at file level, then loaded into memory.
 - Individual fields are encrypted again before insertion.
 - Blobs use a separate encrypted DB with per-blob encryption.
 - Session persistence uses AES-GCM with HWID-derived key (plus optional PIN).
 - Backups use AES-GCM with transfer-key-based derivation and a manifest.

 ## Priority Improvements
 1) Remove world-writable permissions on the vault file.
 2) Avoid plaintext temp DBs for blobs (in-memory or encrypted temp).
 3) Validate backup ZIP paths before extraction.
 4) Increase transfer key entropy and use a KDF with salt.
 5) Strengthen session key derivation with OS-backed secret or user secret.
