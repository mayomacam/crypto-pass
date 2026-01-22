"""
TOTP (Time-based One-Time Password) management.
Handles secret generation, QR code data, and verification.
"""
import pyotp
import qrcode
import io
from PIL import Image

class TOTPManager:
    """Manages TOTP authentication."""
    
    @staticmethod
    def generate_secret() -> str:
        """Generates a random 32-character base32 secret."""
        return pyotp.random_base32()
    
    @staticmethod
    def get_provisioning_uri(secret: str, username: str, issuer: str = "BitMarrow") -> str:
        """Returns the provisioning URI for a QR code."""
        return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)
    
    @staticmethod
    def generate_qr_image(uri: str) -> Image.Image:
        """Generates a PIL Image of a QR code from a URI."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        # Convert to RGB to ensure it's a standard PIL Image instance
        return qr.make_image(fill_color="black", back_color="white").convert("RGB")
    
    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        """Verifies a 6-digit TOTP code against a secret."""
        totp = pyotp.TOTP(secret)
        return totp.verify(code)
