"""
Configuration constants for BitMarrow application.
"""
import os
from pathlib import Path

# Application Info
APP_NAME = "BitMarrow"
APP_VERSION = "4.0.0"

# Paths
APP_DIR = Path(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = APP_DIR / "data"
DB_FILE = DATA_DIR / "vault.db"
BLOB_FILE = DATA_DIR / "blobs.db"

# Security Settings (Argon2id - OWASP 2023)
ARGON2_MEMORY_COST = 65536  # 64 MiB
ARGON2_TIME_COST = 3        # Iterations
ARGON2_PARALLELISM = 4      # Threads (Cores)
SALT_LENGTH = 32            # High entropy salt


# Session Settings
SESSION_TIMEOUT_MINUTES = 5
SESSION_LIFETIME_HOURS = 24
CLIPBOARD_CLEAR_SECONDS = 30

# Password Generator Defaults
DEFAULT_PASSWORD_LENGTH = 16
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Key Generation Settings
RSA_KEY_SIZES = [3072, 4096]
DEFAULT_RSA_SIZE = 4096

# Similar character groups for randomization
SIMILAR_CHARS = {
    '0': ['O', 'o'],
    'O': ['0', 'o'],
    'o': ['0', 'O'],
    '1': ['l', 'I', 'i'],
    'l': ['1', 'I', 'i'],
    'I': ['1', 'l', 'i'],
    'i': ['1', 'l', 'I'],
}

# Character sets
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
NUMBERS = "0123456789"
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
BRACKETS = "()[]{}<>"

# UI Theme Colors
COLOR_BG = "#121212"
COLOR_SIDEBAR = "#1a1a1a"
COLOR_ACCENT = "#2ecc71"  # Emerald
COLOR_SURFACE = "#242424"
COLOR_TEXT = "#E0E0E0"
COLOR_TEXT_DIM = "#888888"

