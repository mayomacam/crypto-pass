# BitMarrow Authentication Architecture

This document details how authorization and encryption keys are handled in various scenarios.

## 1. Master Key (Root of Trust)
Everything in BitMarrow relies on a **32-byte Master Key**. This key is never stored in plain text. It is used to:
- Encrypt/Decrypt the "Sealed Vault" (the `vault.db` file).
- Initialize the `EncryptionManager` for field-level encryption (historical/migration).

## 2. Authentication Scenarios

### Case A: Master Password (Bootstrapping)
- **Source**: User input (string).
- **Process**: 
  1. Derive a 32-byte key using **Argon2id** (OWASP 2023 params: 64MB, 3 iterations, 4 threads) + a unique 32-byte Salt stored in `master_config`.
  2. The derived bytes ARE the Master Key.
  3. Verify identity by comparing `argon2.hash(password)` against `password_hash` in `master_config`.

### Case B: TOTP Login (Primary Daily Use)
- **Source**: 6-digit code.
- **Process**:
  1. Verify code using `totp_secret` (stored in `master_config`).
  2. If valid, recreate a temporary key: `SHA256(totp_secret_bytes)`.
  3. Decrypt `backup_key` from `master_config` using this temporary key.
  4. The result is the **Master Key**.

### Case C: Session Persistence (Device Link)
- **Source**: Hardware ID + OS Secure Storage.
- **Process**:
  1. Retrieve `Machine GUID` from Windows Registry.
  2. Retrieve or create a device secret stored in the OS keyring.
  3. Derive `Device Key = SHA256(Machine GUID + device_secret)`.
  4. Retrieve encrypted token from **Windows Credential Manager** (`keyring`).
  5. Decrypt token using `Device Key` to get the **Master Key**.
  6. This allows the vault to open without user interaction, but only on the exact same physical machine.

### Case D: PIN Setup (Quick Access - NEW)
- **Source**: 4-8 digit PIN.
- **Process**:
  1. **Storage**: We store `pin_salt`, `pin_hash` (Argon2), and `wrapped_master_key` (Master Key encrypted with `Argon2(PIN + DeviceID + Salt)`).
  2. **Unlocking**: 
     - User enters PIN.
     - We derive the key: `K = Argon2(PIN + DeviceID + Salt)`.
     - We decrypt `wrapped_master_key` using `K`.
     - We compare the result to a known "check value" or simply try to open the database.
  3. **Security**: We enforce a "5-strikes" rule stored in memory/DB. If reached, the `wrapped_master_key` is deleted.

## Summary Table

| Method | Entropy | Resilience | Use Case |
| :--- | :--- | :--- | :--- |
| **Recovery Phrase** | Extremely High (256-bit) | Ultimate | Disaster Recovery / Migration Auth |
| **Master Password** | High (User Set) | Excellent | Administrative Changes / Setup |
| **Everyday Password**| Medium/High | Very Good | Daily Unlocking |
| **TOTP (MFA)** | High (Secret) | Very Good| Login Verification / Action Auth |
| **PIN / Pattern** | Low (Numeric/Visual) | Brute-force local | Quick Unlock (Session Unwrapping) |
| **Hardware ID** | Moderate (Unique) | Device Bound | Session Persistence Locking |
| **Transfer Key** | High (32 hex chars) | Single Use | Cross-Device Migration Auth |
| **Vault Fingerprint**| Moderate (Random) | Integrity | Migration Bypass Defense |

## 3. Vault Re-Keying (Master Password Change)
Changing the Master Password is a critical security operation. It does NOT merely change the access password; it **re-encrypts** the entire vault.

- **Process**:
  1. Decrypt the `vault.db` and old `master_config` using the OLD Master Key.
  2. Generate a NEW Salt and derive a NEW Master Key from the New Password.
  3. Re-encrypt all database containers with the NEW Master Key.
  4. Force-clear any specialized wrapped keys (like PIN/Everyday) because they were wrapped with the old Master Key. They must be re-configured.

## 4. The Defense-in-Depth Layers

### Layer 1: Data at Rest (Full DB Encryption)
The entire `vault.db` is encrypted with **AES-256-GCM**. Without the Master Key, the file is a random blob of bytes. Even table names and metadata are hidden.

### Layer 2: Device Binding (Hardware ID)
Sessions and PINs are cryptographically bound to your **Machine GUID**. If an attacker steals your `vault.db` and your Keyring data and moves them to another PC, they WILL NOT WORK. The Hardware ID mismatch prevents the keys from unwrapping.

### Layer 3: The "Double Password" Shield
By separating the **Master Password** from the **Everyday Password**, we limit exposure. Your Master Password (the key to everything) is only typed during critical changes. Everyday work uses a "Wrapped" version that is easier to manage but still secure.

### Layer 4: Migration Integrity (Fingerprinting)
When you move a database, the application verifies the **Vault Fingerprint** stored in your system's secure storage. If it's a new or "rogue" database, the app enforces a **Mnemonic Challenge** to prove ownership before allowing any data migration.

### Layer 5: Brute-Force Protection
- **PIN**: Wipes after **5 failed attempts**.
- **Everyday Password**: Enforced delay or lockout (planned).
- **Master Password**: Protected by the high cost of Argon2id derivation (slowing down attackers).

## 4. Operational Capabilities (v5.0)

| You CAN | You CANNOT |
| :--- | :--- |
| Stay logged in securely on a single PC. | Move a "Stay Logged In" session to another PC. |
| Move your DB to a new PC using a **Transfer Key**. | Access data on a new PC without the key or mnemonic. |
| Verify and restore encrypted backups with integrity checks. | Restore a backup without the Transfer Key. |
| Use an "Everyday Password" for speed. | Perform admin tasks without the **Master Password**. |
| View your **Migration History** for security audits. | Delete migration logs (permanently archived). |
| Recover from a lost device using the 24-word phrase. | Recover data if both Mnemonic AND Master Pass are lost. |
| Detect if someone replaces your DB with a rogue one. | Bypass the "Mnemonic Challenge" on a rogue DB. |