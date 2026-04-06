"""
tests/test_totp_engine.py — Unit Tests: TOTP Engine Core Logic
"""

import time
import pytest
import pyotp
from unittest.mock import MagicMock, patch

# We need to test the engine in isolation — mock the database calls
from app.core.crypto import derive_key, encrypt, decrypt, hash_token


class TestCrypto:
    """Test AES-256-GCM encryption utilities."""

    def test_encrypt_decrypt_roundtrip(self):
        key = derive_key("test-master-key-for-unit-tests")
        plaintext = "JBSWY3DPEHPK3PXP"
        ciphertext, iv = encrypt(plaintext, key)
        assert decrypt(ciphertext, iv, key) == plaintext

    def test_different_encryptions_produce_different_iv(self):
        key = derive_key("test-key")
        _, iv1 = encrypt("secret", key)
        _, iv2 = encrypt("secret", key)
        assert iv1 != iv2  # Each call generates fresh IV

    def test_tampered_ciphertext_raises(self):
        key = derive_key("test-key")
        ciphertext, iv = encrypt("secret", key)
        tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]  # flip first bit
        with pytest.raises(ValueError, match="integrity check failed"):
            decrypt(tampered, iv, key)

    def test_wrong_key_raises(self):
        key1 = derive_key("key-one")
        key2 = derive_key("key-two")
        ct, iv = encrypt("secret", key1)
        with pytest.raises(ValueError):
            decrypt(ct, iv, key2)

    def test_hash_token_deterministic(self):
        h1 = hash_token("123456")
        h2 = hash_token("123456")
        assert h1 == h2

    def test_hash_token_different_codes(self):
        assert hash_token("123456") != hash_token("654321")

    def test_hash_token_is_hex_string(self):
        h = hash_token("000000")
        assert len(h) == 64  # SHA-256 = 256 bits = 64 hex chars
        assert all(c in "0123456789abcdef" for c in h)


class TestTOTPVerification:
    """Test TOTP verification logic (without database)."""

    def test_current_valid_code_accepted(self):
        """A freshly generated code should be accepted."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        code = totp.now()
        assert totp.verify(code, valid_window=1)

    def test_old_code_rejected(self):
        """A code from 3+ steps ago should be rejected."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        # Code from 3 steps (90s) ago
        old_time = int(time.time()) - 90
        old_code = totp.at(for_time=old_time)
        assert not totp.verify(old_code, valid_window=1)

    def test_adjacent_window_accepted(self):
        """Code from ±1 step should be accepted with valid_window=1."""
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        prev_time = int(time.time()) - 30
        prev_code = totp.at(for_time=prev_time)
        assert totp.verify(prev_code, valid_window=1)

    def test_qr_uri_format(self):
        import pyotp
        secret = pyotp.random_base32()
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name="test@test.com", issuer_name="TDTU")
        assert uri.startswith("otpauth://totp/")
        # Email may be URL-encoded (@ → %40) in the URI
        assert "test" in uri and "test.com" in uri
        assert secret in uri

    def test_hash_token_uniqueness(self):
        """Different codes must produce different hashes."""
        codes = [f"{i:06d}" for i in range(100)]
        hashes = [hash_token(c) for c in codes]
        assert len(set(hashes)) == 100  # All hashes unique


class TestPasswordHashing:
    """Test Argon2id hashing."""

    def test_correct_password_verifies(self):
        from app.core.auth import hash_password, verify_password
        pwd = "SecurePassword123!"
        hashed = hash_password(pwd)
        assert verify_password(hashed, pwd)

    def test_wrong_password_rejected(self):
        from app.core.auth import hash_password, verify_password
        hashed = hash_password("correct-password")
        assert not verify_password(hashed, "wrong-password")

    def test_hashes_are_unique(self):
        from app.core.auth import hash_password
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2  # Different salts → different hashes

    def test_hash_format(self):
        from app.core.auth import hash_password
        h = hash_password("test")
        assert h.startswith("$argon2id$")

    def test_empty_password_still_works(self):
        from app.core.auth import hash_password, verify_password
        h = hash_password("")
        assert verify_password(h, "")
        assert not verify_password(h, "notempty")
