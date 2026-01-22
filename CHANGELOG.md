# Changelog

All notable changes to this project will be documented in this file.

## [5.0.0] - MAJOR SECURITY AND STABILITY RELEASE - 2026-01-19

### Security
- Hardened vault file permissions on seal to avoid world-writable modes.
- Eliminated plaintext temp files for blob storage by using in-memory DB deserialize/serialize.
- Added safe ZIP extraction to prevent path traversal during backup restore.
- Strengthened backup key derivation with PBKDF2-HMAC-SHA256.
- Added device secret to session key derivation to harden persisted sessions.

### Added
- Backup verification and restore workflows with integrity checks.
- Key Vault notes editing.
- Expiry status filtering and alerts for certificates.
- Audit log viewer panel.
- Private key import for PEM/OpenSSH with passphrase prompt.
- Passphrase strength meter and visibility toggle for protected private keys.

### Changed
- Updated documentation to reflect v5 security posture and flows.

## [4.0.0] - MAJOR SECURITY RELEASE - 2026-01-07
**CRITICAL SECURITY UPDATE**: This release changes how the database is handled in memory.
- **SECURITY**: Implemented In-Memory Database Deserialization to prevent unencrypted data from ever touching the disk (`%TEMP%` directory).
- **SECURITY**: Added aggressive garbage collection (`gc.collect()`) on Vault Lock and App Exit to mitigate RAM scraping risks.
- **SECURITY**: Conducted comprehensive internal security audit (see `SECURITY_AUDIT.md`).
- **CHANGED**: Session Policy updated. Persistent sessions (Stay Logged In) now expire after **24 hours**.
- **CHANGED**: Persistent sessions are PIN-Protected. After expiry, Everyday Password is preferred.

## [3.0.0] - 2026-01-06

### Added
- **Enforced Security**: Mandatory setup of PIN and Everyday Password upon login if not already configured.
- **Advanced Credential Management**: New settings options to securely change Master Password, Everyday Password, and PIN.
- **Secure Blob Storage**: Integrated support for encrypted file and image attachments in Notes (`blobs.db`).
- **Encrypted Backups**: Ability to create full vault archives (`.cpback`) encrypted with the Migration Transfer Key.
- **Configurable Storage**: New settings to customize the location of vault data and backup files.
- **Vault Re-Keying**: Changing the Master Password now automatically re-encrypts the entire vault with a new key.

### Changed
- **Settings UI**: Re-organized Settings into a tabbed interface (Credentials, Storage, Migration) for better usability.
- **Login Flow**: Application now checks security status post-login and redirects to settings if setup is incomplete.

## [2.0.0] - 2026-01-06

### Added
- **Hardened Key Wrapping**: Introduced the "Double Password" setup. Your vault can now be unsealed by either a complex Master Password or a more convenient Everyday Password.
- **PIN-Gated Session Persistence**: Persistent sessions now require a PIN or Pattern to unseal, protecting against physical theft of the device.
- **Vault Fingerprinting**: Implemented automated integrity checks during database migrations. Challenging unknown databases with a mandatory mnemonic check.
- **Tiered Auth Logic**: Completely overhauled the unsealing pipeline to support multiple entry points (Master, Everyday, PIN, TOTP).

### Changed
- **Major Security Leap**: Bumped version to 2.0.0 to reflect the fundamental architectural changes in authentication and encryption key management.

## [1.4.0] - 2026-01-06

### Added
- **Full Database Encryption**: Transitioned from field-level to full-file encryption using AES-256-GCM.
- **Hardware-Linked Session Persistence**: Allows users to stay logged in across app restarts, securely bound to the device's unique Hardware ID.
- **Quick Access PIN**: Added a 4-8 digit PIN option for faster unlocking, protected by a hardware-bound key-wrapping mechanism and a 5-strikes security rule.
- **Comprehensive Audit Logging**: Centralized tracking of security-sensitive events (logins, vault modifications, migrations) in an encrypted audit trail.
- **OWASP 2023 KDF Standards**: Updated Argon2id parameters (64MB, 3 iterations, 4 threads) to align with current industry recommendations.
- **Legacy Migration Logic**: Automatic, transparent migration of old unencrypted containers to the new full-file encrypted format.

## [1.3.1] - 2026-01-05

### Added
- **Robust Markdown Engine**: Significantly improved preview rendering for lists, horizontal rules, and inline styling (bold, italic, code).
- **Enhanced Preview Styling**: Added color-coded headers and distinct code block backgrounds for better readability.

### Fixed
- **Database Persistence**: Resolved a critical `AttributeError` in the Password Vault where editing entries could fail due to missing method definitions.
- **Auto-Save Reliability**: Improved note-saving logic to ensure data is committed instantly before switching views.

## [1.3.0] - 2026-01-05

### Added
- **Note-Taker App**: New integrated markdown editor with full encryption and auto-save.
- **Markdown Preview Mode**: High-performance rendering for structured notes with headers and style tags.
- **Smart Password Suggester**: Interactive alternative password candidates based on generation settings.
- **Global Privacy Toggles**: Eye-icon visibility toggles for all password entry fields (Setup, Login, Vault Dialogs).
- **UI Modernization (Phase 2)**: Transitioned from tabbed interface to a premium sidebar-driven desktop layout.
- **Glassmorphism Design**: Updated color palette and card-based system for a more professional feel.

### Fixed
- **CustomTkinter v5.2 Compatibility**: Removed unsupported `checkmark_color` arguments from RadioButtons and CheckBoxes to prevent application crashes.
- **Generator UI Alignment**: Fixed results panel overflow in both Password and Key generators.

## [1.2.0] - 2026-01-02

### Added
- **Hardened Password Policy**: Enforced mandatory 12-character minimum and strict complexity rules.
- **Security Checklist UI**: Real-time visual validation during password setup/changes.
- **Heuristic Strength Analysis**: Password meter now detects and penalizes common sequences ('123'), repetitions ('aaaa'), and common passcodes.
- **Improved Strength Scaling**: Refined the algorithm to reward complex 16-character passwords with a 100% "Excellent" rating.
- **Scrollable Security Dialogs**: Wrapped setup and verification dialogs in scrollable containers for better accessibility on all screen sizes.
- **Mandatory TOTP Verification**: Mandatory 6-digit code verification during MFA setup to prevent lockout.
- **Migration Resilience**: Added fallback logic to handle legacy encoded TOTP keys and provide clear migration instructions via Master Password.
- **Private Key Privacy**: Implemented "Show/Hide" toggles for all generated and saved private keys to prevent accidental exposure (masked by default).
- **UI Standardisation**: Improved labels to explicitly distinguish between Public Keys/Certificates and Private Secrets.
- **UI Overflow**: Fixed "Verify" button being hidden on smaller screens during setup.
- **Key Generation UI**: Fixed packing order in `KeyGenFrame` where options could be hidden.
- **TOTP Cryptographic Fix**: Fixed "Key must be a 32-byte bytearray" crash by standardizing on hex-encoding for the master key wrapper.

## [1.1.0] - 2026-01-01

### Added
- **Certificate Vault**: Full management of X.509 certificates and cryptographic keys.
- **Metadata Parsing**: Support for automatic extraction of Subject, Issuer, and Expiry from certificates.

### Fixed
- **KeyGenFrame Crash**: Resolved `AttributeError` in initialization.
- **SQLite Threading Error**: Fixed `sqlite3.ProgrammingError` using `self.after` timers.
- **UI Render Crashes**: Fixed `TclError` in cross-thread UI operations.

## [1.0.0] - 2026-01-01
- Initial release of BitMarrow.
- Core features: Password Vault, Password Generator, GCM Encryption, TOTP & Mnemonic recovery.
