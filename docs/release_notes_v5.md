# Release Notes - v5.0.0

This release focuses on security hardening, safer backups, and improved key management.

Highlights:
- In-memory blob database handling to eliminate plaintext temp files.
- Safer backup restore with integrity verification and path validation.
- Stronger session persistence key derivation using a device secret.
- Higher-entropy transfer keys and PBKDF2-based backup key derivation.
- Key Vault notes, expiry filters, and private key import with passphrase support.
