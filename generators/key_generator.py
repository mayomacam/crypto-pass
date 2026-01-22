"""
Cryptographic key generator for secure key pair generation.
Only includes cryptographically secure algorithms.
"""
import secrets
from typing import Tuple, Optional
from enum import Enum
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (
    CertificateBuilder, Name, NameAttribute, random_serial_number
)
from cryptography.x509.oid import NameOID
from cryptography import x509
from datetime import datetime, timedelta
import base64
import hmac
import hashlib


class KeyType(Enum):
    """Types of cryptographic keys that can be generated."""
    RSA = "RSA"
    ED25519 = "Ed25519"
    AES = "AES-256-GCM"
    SSH_ED25519 = "SSH-Ed25519"
    SSH_RSA = "SSH-RSA"
    X509 = "X.509 Certificate"
    HMAC = "HMAC"
    CHACHA20 = "ChaCha20-Poly1305"


@dataclass
class KeyResult:
    """Result of key generation."""
    key_type: KeyType
    public_key: str
    private_key: str
    key_size: int
    additional_info: dict = None


class KeyGenerator:
    """Generates various types of cryptographic keys."""

    def _resolve_encryption(self, passphrase: Optional[str]):
        if passphrase:
            return serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        return serialization.NoEncryption()
    
    def generate(self, key_type: KeyType, **kwargs) -> KeyResult:
        """
        Generate a key of the specified type.
        
        Args:
            key_type: Type of key to generate
            **kwargs: Additional parameters for specific key types
            
        Returns:
            KeyResult with generated key(s)
        """
        generators = {
            KeyType.RSA: self._generate_rsa,
            KeyType.ED25519: self._generate_ed25519,
            KeyType.AES: self._generate_aes,
            KeyType.SSH_ED25519: self._generate_ssh_ed25519,
            KeyType.SSH_RSA: self._generate_ssh_rsa,
            KeyType.X509: self._generate_x509,
            KeyType.HMAC: self._generate_hmac,
            KeyType.CHACHA20: self._generate_chacha20,
        }
        
        generator = generators.get(key_type)
        if not generator:
            raise ValueError(f"Unknown key type: {key_type}")
        
        return generator(**kwargs)
    
    def _generate_rsa(self, key_size: int = 4096, passphrase: Optional[str] = None) -> KeyResult:
        """
        Generate RSA key pair.
        
        Args:
            key_size: 3072 or 4096 bits only
        """
        if key_size not in [3072, 4096]:
            key_size = 4096  # Default to strongest
        
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )
        
        # Serialize private key (PEM format)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._resolve_encryption(passphrase)
        ).decode('utf-8')
        
        # Serialize public key
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.RSA,
            public_key=public_pem,
            private_key=private_pem,
            key_size=key_size,
            additional_info={"private_key_encrypted": bool(passphrase)}
        )
    
    def _generate_ed25519(self, passphrase: Optional[str] = None) -> KeyResult:
        """Generate Ed25519 key pair (256-bit, highly secure)."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._resolve_encryption(passphrase)
        ).decode('utf-8')
        
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.ED25519,
            public_key=public_pem,
            private_key=private_pem,
            key_size=256,
            additional_info={"private_key_encrypted": bool(passphrase)}
        )
    
    def _generate_aes(self, passphrase: Optional[str] = None) -> KeyResult:
        """Generate AES-256-GCM key."""
        key = AESGCM.generate_key(bit_length=256)
        key_b64 = base64.b64encode(key).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.AES,
            public_key="",  # Symmetric key, no public key
            private_key=key_b64,
            key_size=256,
            additional_info={"format": "base64", "algorithm": "AES-256-GCM"}
        )
    
    def _generate_ssh_ed25519(self, passphrase: Optional[str] = None) -> KeyResult:
        """Generate SSH key pair using Ed25519."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        
        # OpenSSH format
        private_ssh = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=self._resolve_encryption(passphrase)
        ).decode('utf-8')
        
        public_ssh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.SSH_ED25519,
            public_key=public_ssh,
            private_key=private_ssh,
            key_size=256,
            additional_info={
                "format": "OpenSSH",
                "private_key_encrypted": bool(passphrase)
            }
        )
    
    def _generate_ssh_rsa(self, key_size: int = 4096, passphrase: Optional[str] = None) -> KeyResult:
        """Generate SSH key pair using RSA-4096."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,  # Always use 4096 for SSH RSA
            backend=default_backend()
        )
        
        private_ssh = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=self._resolve_encryption(passphrase)
        ).decode('utf-8')
        
        public_ssh = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.SSH_RSA,
            public_key=public_ssh,
            private_key=private_ssh,
            key_size=4096,
            additional_info={
                "format": "OpenSSH",
                "private_key_encrypted": bool(passphrase)
            }
        )
    
    def _generate_x509(self, common_name: str = "BitMarrow Self-Signed",
                       validity_days: int = 365,
                       use_ed25519: bool = True,
                       passphrase: Optional[str] = None) -> KeyResult:
        """
        Generate self-signed X.509 certificate.
        
        Args:
            common_name: Certificate common name
            validity_days: Certificate validity in days
            use_ed25519: Use Ed25519 (True) or RSA-4096 (False)
        """
        # Generate key pair
        if use_ed25519:
            private_key = ed25519.Ed25519PrivateKey.generate()
            key_size = 256
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            key_size = 4096
        
        # Build certificate
        subject = issuer = Name([
            NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        cert = (
            CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=validity_days))
            .sign(private_key, None if use_ed25519 else hashes.SHA384())
        )
        
        # Serialize
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
        
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=self._resolve_encryption(passphrase)
        ).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.X509,
            public_key=cert_pem, # This must be BEGIN CERTIFICATE
            private_key=private_pem,
            key_size=key_size,
            additional_info={
                "common_name": common_name,
                "expiry_date": (datetime.utcnow() + timedelta(days=validity_days)).isoformat(),
                "issuer": common_name,
                "serial_number": cert.serial_number,
                "algorithm": "Ed25519" if use_ed25519 else "RSA-4096",
                "private_key_encrypted": bool(passphrase)
            }
        )

    @staticmethod
    def import_private_key(raw_data: bytes, passphrase: Optional[str] = None) -> KeyResult:
        password = passphrase.encode("utf-8") if passphrase else None
        is_ssh = b"BEGIN OPENSSH PRIVATE KEY" in raw_data

        if is_ssh:
            private_key = serialization.load_ssh_private_key(
                raw_data,
                password=password,
                backend=default_backend()
            )
            if isinstance(private_key, rsa.RSAPrivateKey):
                key_type = KeyType.SSH_RSA
                key_size = private_key.key_size
            elif isinstance(private_key, ed25519.Ed25519PrivateKey):
                key_type = KeyType.SSH_ED25519
                key_size = 256
            else:
                raise ValueError("Unsupported SSH private key type")

            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH
            ).decode("utf-8")
            private_key_data = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
            ).decode("utf-8")
            return KeyResult(
                key_type=key_type,
                public_key=public_key,
                private_key=private_key_data,
                key_size=key_size,
                additional_info={"format": "OpenSSH", "private_key_encrypted": bool(passphrase)}
            )

        private_key = serialization.load_pem_private_key(
            raw_data,
            password=password,
            backend=default_backend()
        )
        if isinstance(private_key, rsa.RSAPrivateKey):
            key_type = KeyType.RSA
            key_size = private_key.key_size
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            key_type = KeyType.ED25519
            key_size = 256
        else:
            raise ValueError("Unsupported PEM private key type")

        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        private_key_data = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        ).decode("utf-8")
        return KeyResult(
            key_type=key_type,
            public_key=public_key,
            private_key=private_key_data,
            key_size=key_size,
            additional_info={"format": "PEM", "private_key_encrypted": bool(passphrase)}
        )

    @staticmethod
    def parse_certificate(cert_pem: str) -> dict:
        """
        Parse an X.509 certificate and extract metadata.
        
        Args:
            cert_pem: PEM encoded certificate string
            
        Returns:
            Dictionary with certificate details
        """
        try:
            cert = x509.load_pem_x509_certificate(
                cert_pem.encode('utf-8'), 
                default_backend()
            )
            
            subject = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            common_name = subject[0].value if subject else "Unknown"
            
            issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
            issuer_name = issuer[0].value if issuer else "Unknown"
            
            return {
                "common_name": common_name,
                "issuer": issuer_name,
                "expiry_date": cert.not_valid_after.isoformat(),
                "not_before": cert.not_valid_before.isoformat(),
                "serial_number": cert.serial_number,
                "version": cert.version.name,
                "fingerprint": cert.fingerprint(hashes.SHA256()).hex()
            }
        except Exception as e:
            raise ValueError(f"Failed to parse certificate: {str(e)}")
    
    def _generate_hmac(self, hash_algorithm: str = "SHA-256", passphrase: Optional[str] = None) -> KeyResult:
        """
        Generate HMAC key.
        
        Args:
            hash_algorithm: SHA-256, SHA-384, or SHA-512
        """
        # Key size matches hash output size for security
        key_sizes = {
            "SHA-256": 32,
            "SHA-384": 48,
            "SHA-512": 64
        }
        
        key_size_bytes = key_sizes.get(hash_algorithm, 32)
        key = secrets.token_bytes(key_size_bytes)
        key_b64 = base64.b64encode(key).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.HMAC,
            public_key="",
            private_key=key_b64,
            key_size=key_size_bytes * 8,
            additional_info={"hash_algorithm": hash_algorithm, "format": "base64"}
        )
    
    def _generate_chacha20(self, passphrase: Optional[str] = None) -> KeyResult:
        """Generate ChaCha20-Poly1305 key (256-bit)."""
        key = ChaCha20Poly1305.generate_key()
        key_b64 = base64.b64encode(key).decode('utf-8')
        
        return KeyResult(
            key_type=KeyType.CHACHA20,
            public_key="",
            private_key=key_b64,
            key_size=256,
            additional_info={"format": "base64", "algorithm": "ChaCha20-Poly1305"}
        )
    
    @staticmethod
    def export_to_file(key_result: KeyResult, filepath: str, 
                       export_private: bool = True, export_public: bool = True):
        """
        Export keys to files.
        
        Args:
            key_result: Generated key result
            filepath: Base filepath (without extension)
            export_private: Whether to export private key
            export_public: Whether to export public key
        """
        if export_private and key_result.private_key:
            with open(f"{filepath}_private.pem", 'w') as f:
                f.write(key_result.private_key)
        
        if export_public and key_result.public_key:
            ext = ".pub" if "SSH" in key_result.key_type.value else "_public.pem"
            with open(f"{filepath}{ext}", 'w') as f:
                f.write(key_result.public_key)
# ======= End of File =======
