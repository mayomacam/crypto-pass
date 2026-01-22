# Crypto Password Manager - Master Task Breakdown



This document tracks the complete lifecycle of the BitMarrow project, from initial foundation to the current advanced security roadmap.



## Phase 1: Planning & Architecture (Completed)

- [x] Create implementation plan with architecture design

- [x] Get user approval on the plan



## Phase 2: Core Implementation (Completed)



### Core Security Module

- [x] Create encryption/decryption utilities using Fernet (initial) and AES-256-GCM (current)

- [x] Implement secure key derivation (PBKDF2/Argon2)

- [x] Create master password hashing system

- [x] Create secure memory zeroing utility (`bytearray` management)



### Database Layer

- [x] Design encrypted SQLite schema

- [x] Implement database initialization with encryption

- [x] Create CRUD operations for password entries

- [x] Create CRUD operations for generated keys



### Password Generation Module

- [x] Standard password generator (customizable length, characters)

- [x] Passphrase generator (word-based)

- [x] PIN generator

- [x] Memorable password generator

- [x] Pattern-based password generator



### Cryptographic Key Generation Module

- [x] RSA key pair generator

- [x] Ed25519 key pair generator  

- [x] AES key generator

- [x] SSH key generator

- [x] X.509 certificate generator

- [x] HMAC key generator



### GUI Application

- [x] Design main window layout (CustomTkinter)

- [x] Master password login screen

- [x] Password vault view (list/search/filter)

- [x] Password generator interface

- [x] Key generator interface

- [x] Stats dashboard

- [x] Password strength meter



### Security Framework

- [x] Clipboard auto-clear

- [x] Session timeout (Fixed threading issues)

- [x] Master password validation

- [x] Secure memory handling



---



## Milestone 1: Core Foundation & Certificate Vault - v1.1.0/v1.2.0 (Completed)

- [x]- **Entropy Check**: Score at least "Good"- **UI Logic**: Standardized `StrengthMeter` and `CTkImage` rendering paths.

- **KeyGen Fix**: Fixed packing order and visibility issues in `KeyGenFrame`.

- **UI Accessibility**: Implemented `ScrollableFrame` for setup and security dialogs.

 error

- [x] **UI Polish**: Implemented ScrollableFrame for setup; Fixed KeyGen options packing

- [x] **Privacy UI**: Implement "Show/Hide" toggles for private keys in Generator & Vault

- [x] **Label Fix**: Standardize "Public Key" vs "Private Key" naming (removed confusing "Secret" suffix)

- [x] **Security Logic**: Enhanced password strength meter with sequence heuristics and "Excellent" (100%) tier scaling

- [x] **DB Upgrade**: Added certificate metadata and expiry schema

- [x] **Versioning**: Established `CHANGELOG.md` and bumped to v1.2.0 (Security Hardened)

- [x] **Cert Logic**: Implemented X.509 parsing and enhanced generation

- [x] **UI**: Launched the dedicated "📜 Key Vault" management interface



---



## Milestone 2: Hardened Security & Performance (Completed)

- [x] **Full DB Encryption**: Implemented AES-256-GCM file-level encrypted containers

- [x] **Hardware-Linked Sessions**: Secure session persistence with Windows Credential Manager

- [x] **Quick Access PIN**: 4-8 digit hardware-bound PIN for rapid unlocking

- [x] **Audit Logging**: Comprehensive internal tracking of security events

- [x] **OWASP 2023 KDF**: Updated Argon2id parameters (64MB, 3 iterations)

- [x] **Schema Migration**: Automatic database upgrades for legacy vault files

- [x] **Settings UI**: Integrated security management console



---



## Milestone 3: Hardened Authentication & Secure Storage (v3.0.0 Completed)

- [x] **Enforced Security**: Mandatory setup of PIN and Everyday Password upon login.

- [x] **Advanced Credentials**: New settings to change Master Password, PIN, and Everyday Password.

- [x] **Secure Blobs**: Created `blobs.db` for encrypted file storage (integrated with Notes).

- [x] **Encrypted Backups**: Implemented `.cpback` migration archives locked with Transfer Key.

- [x] **Configurable Paths**: Added Settings UI for custom data/backup directories.

- [x] **Vault Re-Keying**: Master Password change now triggers full DB re-encryption.



---



## Milestone 4: Critical Audit & Hardening (v4.0.0 Completed)

- [x] **In-Memory DB**: Implemented `sqlite3.deserialize` for RAM-only database operation.

- [x] **Security Audit**: Addressed all findings from `SECURITY_AUDIT.md`.

- [x] **Garbage Collection**: Aggressive `gc.collect` on lock/exit.

- [x] **Session Policy**: Implemented 24h max session duration with configurable slider.

- [x] **Migration**: Moved from temp-file decryption to purely in-memory decryption.



---



## Milestone 5: Security Hardening and Stability (v5.0.0 Completed)
- [x] Vault file permissions hardened during seal.
- [x] Blob DB moved to in-memory deserialize/serialize (no plaintext temp).
- [x] Backup verification/restore with integrity checks and safe extraction.
- [x] Session persistence strengthened with device secret.
- [x] Transfer key entropy increased and backup KDF upgraded.
- [x] Key Vault notes editing and certificate expiry filters.
- [x] Audit log viewer panel and private key import with passphrase support.

## Future Roadmap (Milestone 5)

- [ ] **Auto-Lock Triggers**: Lock on system sleep/lid close.

- [ ] **E2E Cloud Sync**: Secure, client-side encrypted synchronization.

- [ ] **Mobile Companion**: Preliminary research for mobile vault access.



---



## Research Backlog (Proposed) 
- [x] Fix migration history update to use `transfer_key_hash` and `migrated_at` (schema mismatch).
- [x] Restore missing password create function and remove orphaned code in `DatabaseManager`.
- [x] Remove duplicate `_migrate_tables()` call inside `_init_tables()`.
- [x] Standardize UI labels/icons and replace garbled glyph strings in key-related frames.
- [x] Add encrypted private-key import with passphrase prompt (PEM/OpenSSH).
- [x] Add passphrase strength/visibility UI when protecting private keys.
- [x] Expose key/cert notes editing in the Key Vault (notes field already exists).
- [x] Add certificate expiry alerts and filters in Key Vault.
- [x] Add audit log viewer panel for security events.
- [x] Add backup verification + restore workflow with integrity checks.


## Security Remediation Tasks

- [x] Vault file permissions: remove world-writable chmod and enforce restrictive access.

- [x] Blob storage: eliminate plaintext temp DB on disk (use in-memory or encrypted temp).

- [x] Backup restore: validate zip paths before extraction (zip-slip prevention).

- [x] Transfer key strength: increase entropy and use a KDF with salt for backup key derivation.

- [x] Session protection: strengthen session key derivation with OS-backed secret or user secret.



## Documentation & Distribution (Completed)

- [x] Create comprehensive README.md for GitHub

- [x] Create BUILDING.md for standalone executable instructions

- [x] Create .gitignore for security and hygiene

- [x] Finalize project LICENSE (MIT)


