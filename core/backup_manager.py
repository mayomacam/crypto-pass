"""
Encrypted backup manager for vault migration.
"""
import zipfile
import hashlib
import json
from pathlib import Path

from core.encryption import EncryptionManager

class BackupManager:
    """Handles creation and restoration of encrypted vault backups."""
    
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def create_backup(self, output_path: Path, encryption_manager: EncryptionManager):
        """
        Creates a zip of the data directory and encrypts it.
        The encryption_manager should be initialized with a key derived from the Migration Transfer Key.
        """
        temp_zip = output_path.with_suffix(".tmp.zip")
        
        try:
            # 1. Zip the required files
            manifest = {"version": 1, "files": []}
            with zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
                for file_name in ["vault.db", "blobs.db"]:
                    file_path = self.data_dir / file_name
                    if file_path.exists():
                        file_bytes = file_path.read_bytes()
                        manifest["files"].append({
                            "name": file_name,
                            "size": len(file_bytes),
                            "sha256": hashlib.sha256(file_bytes).hexdigest()
                        })
                        zf.write(file_path, arcname=file_name)
                zf.writestr("manifest.json", json.dumps(manifest))
            
            # 2. Encrypt the zip content
            zip_data = temp_zip.read_bytes()
            encrypted_data = encryption_manager.encrypt_bytes(zip_data)
            
            # 3. Write to final output
            output_path.write_bytes(encrypted_data)
            
            return True
        finally:
            if temp_zip.exists():
                temp_zip.unlink()

    def verify_backup(self, backup_path: Path, encryption_manager: EncryptionManager) -> bool:
        """Verifies a backup by decrypting and checking the manifest hashes."""
        temp_zip = backup_path.with_suffix(".verify.tmp.zip")
        try:
            encrypted_data = backup_path.read_bytes()
            decrypted_data = encryption_manager.decrypt_bytes(encrypted_data)
            temp_zip.write_bytes(decrypted_data)

            with zipfile.ZipFile(temp_zip, 'r') as zf:
                try:
                    manifest_raw = zf.read("manifest.json")
                except KeyError:
                    return False
                manifest = json.loads(manifest_raw.decode("utf-8"))
                for entry in manifest.get("files", []):
                    data = zf.read(entry["name"])
                    if len(data) != entry.get("size"):
                        return False
                    if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                        return False
            return True
        finally:
            if temp_zip.exists():
                temp_zip.unlink()

    def restore_backup(self, backup_path: Path, target_dir: Path, encryption_manager: EncryptionManager):
        """Decrypts and extracts a backup."""
        temp_zip = target_dir / "restore.tmp.zip"
        
        try:
            # 1. Decrypt
            encrypted_data = backup_path.read_bytes()
            decrypted_data = encryption_manager.decrypt_bytes(encrypted_data)
            
            temp_zip.write_bytes(decrypted_data)
            
            # 2. Verify integrity and extract
            with zipfile.ZipFile(temp_zip, 'r') as zf:
                try:
                    manifest_raw = zf.read("manifest.json")
                except KeyError:
                    return False
                manifest = json.loads(manifest_raw.decode("utf-8"))
                for entry in manifest.get("files", []):
                    data = zf.read(entry["name"])
                    if len(data) != entry.get("size"):
                        return False
                    if hashlib.sha256(data).hexdigest() != entry.get("sha256"):
                        return False
                self._safe_extractall(zf, target_dir)
            
            return True
        finally:
            if temp_zip.exists():
                temp_zip.unlink()

    @staticmethod
    def _safe_extractall(zf: zipfile.ZipFile, target_dir: Path) -> None:
        base = target_dir.resolve()
        for member in zf.infolist():
            member_path = (target_dir / member.filename).resolve()
            if base not in member_path.parents and member_path != base:
                raise ValueError("Unsafe backup archive path")
        zf.extractall(target_dir)
