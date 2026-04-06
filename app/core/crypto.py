"""
app/core/crypto.py — AES-256-GCM Encryption Utilities

Provides authenticated encryption for TOTP secrets stored in the database.
AES-GCM provides BOTH confidentiality (AES) AND integrity/authentication (GCM tag).
A tampered ciphertext will raise InvalidTag on decryption — fail-secure behavior.
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag


# Fixed PBKDF2 salt for key derivation.
# Using a fixed salt (not random) is intentional here because:
#   - We need deterministic key derivation from the master key
#   - The master key itself must be high-entropy (from env var)
#   - Multiple salts would require storing them per-secret, adding complexity
_KDF_SALT = b"TDTU-InfoSec-MFA-v1-kdf-salt-2026"
_KDF_ITERATIONS = 600_000   # OWASP 2023 recommendation for PBKDF2-SHA256


def derive_key(master_key: str) -> bytes:
    """
    Derive a 256-bit AES key from a string master key using PBKDF2-SHA256.

    Args:
        master_key: High-entropy string from environment variable.

    Returns:
        32-byte symmetric key for AES-256.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_KDF_SALT,
        iterations=_KDF_ITERATIONS,
    )
    return kdf.derive(master_key.encode("utf-8"))


def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt a string using AES-256-GCM.

    A fresh 96-bit IV is generated for every encryption call using os.urandom().
    IV reuse with GCM is catastrophic (breaks both confidentiality and integrity),
    so we never reuse IVs.

    Args:
        plaintext: String to encrypt (e.g., Base32 TOTP secret).
        key: 32-byte AES key from derive_key().

    Returns:
        Tuple of (ciphertext_with_tag, iv).
        The GCM authentication tag (16 bytes) is appended to ciphertext by cryptography lib.
    """
    iv = os.urandom(12)          # 96-bit IV — NIST SP 800-38D recommended size
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext.encode("utf-8"), associated_data=None)
    return ciphertext, iv


def decrypt(ciphertext: bytes, iv: bytes, key: bytes) -> str:
    """
    Decrypt AES-256-GCM ciphertext.

    If the ciphertext has been tampered with (bit-flip, truncation, etc.),
    AESGCM.decrypt() raises InvalidTag — we propagate this as a ValueError.

    Args:
        ciphertext: Ciphertext + GCM tag (as returned by encrypt()).
        iv: The IV used during encryption.
        key: 32-byte AES key from derive_key().

    Returns:
        Decrypted plaintext string.

    Raises:
        ValueError: If ciphertext integrity check fails (tampered data).
    """
    try:
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext, associated_data=None)
        return plaintext_bytes.decode("utf-8")
    except InvalidTag:
        raise ValueError(
            "Decryption failed: ciphertext integrity check failed. "
            "Data may have been tampered with or the wrong key was used."
        )


def hash_token(token: str) -> str:
    """
    Compute SHA-256 hash of a TOTP token for replay-prevention storage.

    We never store OTP codes in plaintext in the used_tokens table.
    SHA-256 is sufficient here because:
    - OTPs are ephemeral and short-lived (30s validity)
    - We only need exact-match lookup (no need for salted hash)
    - The preimage (the 6-digit code) is already low-entropy, but
      an attacker with DB access learning "this OTP hash" gains nothing
      useful since the OTP is already expired.

    Args:
        token: 6-digit OTP string.

    Returns:
        Hex-encoded SHA-256 digest.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
