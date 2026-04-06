"""
app/core/totp_engine.py — RFC 6238 TOTP Engine with Security Hardening

This module implements the core TOTP logic with three security layers:
1. Encrypted secret storage (AES-256-GCM)
2. Replay prevention (SHA-256 token tracking)
3. Clock-skew tolerance (configurable valid_window)
"""

import time
import hmac
import pyotp
import qrcode
import io
import base64

from app.core.crypto import derive_key, encrypt, decrypt, hash_token
from app.models.database import get_db


class TOTPEngine:
    """
    RFC 6238 compliant TOTP engine with security hardening.

    All TOTP secrets are encrypted at rest using AES-256-GCM.
    Token replay is prevented by tracking SHA-256 hashes of used tokens.
    """

    def __init__(self, master_key: str):
        """
        Initialize with a master encryption key.

        Args:
            master_key: High-entropy string from TOTP_MASTER_KEY env var.
                        Internally derived into a 256-bit AES key via PBKDF2.
        """
        self._key = derive_key(master_key)

    # ── Secret Management ──────────────────────────────────────────────────

    def generate_secret(self) -> str:
        """
        Generate a cryptographically secure Base32 TOTP secret.

        Uses os.urandom() internally (via pyotp) as the entropy source.
        32-character Base32 = 160 bits of entropy (well above the 80-bit minimum).

        Returns:
            Base32-encoded secret string (32 characters, uppercase).
        """
        return pyotp.random_base32(length=32)

    def encrypt_secret(self, secret: str) -> tuple[bytes, bytes]:
        """
        Encrypt a TOTP secret for database storage.

        Returns:
            Tuple of (ciphertext_with_gcm_tag, iv).
        """
        return encrypt(secret, self._key)

    def decrypt_secret(self, ciphertext: bytes, iv: bytes) -> str:
        """
        Decrypt a TOTP secret retrieved from the database.

        Raises:
            ValueError: If ciphertext has been tampered with.
        """
        return decrypt(ciphertext, iv, self._key)

    # ── QR Code Generation ─────────────────────────────────────────────────

    def generate_qr_uri(
        self,
        secret: str,
        email: str,
        issuer: str = "TDTU-InfoSec-MFA",
    ) -> str:
        """
        Generate an otpauth:// URI for authenticator app enrollment.

        The URI encodes: algorithm (SHA1), digits (6), period (30s),
        issuer, account name, and secret — all fields required by Google
        Authenticator and Authy.

        Args:
            secret: Base32 TOTP secret.
            email: User's email address (account label in the app).
            issuer: Organization name shown in the authenticator app.

        Returns:
            otpauth://totp/{issuer}:{email}?secret=...&issuer=...
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)

    def generate_qr_image_base64(
        self,
        secret: str,
        email: str,
        issuer: str = "TDTU-InfoSec-MFA",
    ) -> str:
        """
        Generate a QR code image as a Base64-encoded PNG string.

        This allows the QR code to be embedded directly in an HTML <img> tag
        without writing any files to disk.

        Returns:
            Data URI string: "data:image/png;base64,..."
        """
        uri = self.generate_qr_uri(secret, email, issuer)

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=8,
            border=4,
        )
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")
        return f"data:image/png;base64,{b64}"

    # ── TOTP Verification ──────────────────────────────────────────────────

    def verify_totp(
        self,
        secret: str,
        token: str,
        user_id: int,
        valid_window: int = 1,
    ) -> dict:
        """
        Verify a TOTP token with full security checks.

        Security layers applied in order:
        1. Format validation — must be exactly 6 digits
        2. Replay check — reject if this token was already used this time-step
        3. TOTP verification — RFC 6238 check with clock-skew tolerance
        4. Replay registration — mark token as used on success

        Args:
            secret: Base32 TOTP secret (decrypted from DB).
            token: 6-digit code submitted by the user.
            user_id: Used to scope replay-prevention tracking.
            valid_window: Number of time-steps to accept before/after current.
                          Default=1 means ±30s tolerance (RFC 6238 §5.2).

        Returns:
            dict with keys:
                valid (bool): Whether verification succeeded.
                reason (str): Human-readable explanation.
                time_step (int): The time-step at which verification occurred.
        """
        # ── Step 1: Format Validation ──────────────────────────────────────
        if not isinstance(token, str) or not token.isdigit() or len(token) != 6:
            return {
                "valid": False,
                "reason": "Token must be exactly 6 digits.",
                "time_step": None,
            }

        current_step = int(time.time()) // 30

        # ── Step 2: Pre-Verification Replay Check ──────────────────────────
        # Check all time-steps within the acceptance window to prevent
        # replaying a code from an adjacent window.
        token_h = hash_token(token)
        for step_offset in range(-valid_window, valid_window + 1):
            check_step = current_step + step_offset
            if self._is_replayed(user_id, token_h, check_step):
                return {
                    "valid": False,
                    "reason": "This code has already been used. Wait for a new code.",
                    "time_step": check_step,
                }

        # ── Step 3: RFC 6238 TOTP Verification ────────────────────────────
        # pyotp.verify() uses hmac.compare_digest() internally (timing-safe).
        totp = pyotp.TOTP(secret)
        is_valid = totp.verify(token, valid_window=valid_window)

        if not is_valid:
            return {
                "valid": False,
                "reason": "Invalid code. Please check your authenticator app.",
                "time_step": current_step,
            }

        # ── Step 4: Mark Token as Used (Replay Prevention) ─────────────────
        # Determine exactly which time-step matched, then record it.
        matched_step = self._find_matched_step(totp, token, current_step, valid_window)
        self._register_used_token(user_id, token_h, matched_step)

        return {
            "valid": True,
            "reason": "Authentication successful.",
            "time_step": matched_step,
        }

    def _find_matched_step(
        self, totp: pyotp.TOTP, token: str, current_step: int, valid_window: int
    ) -> int:
        """Find which specific time-step the token matched at."""
        for offset in range(-valid_window, valid_window + 1):
            step = current_step + offset
            # Temporarily advance/rewind time to check this step
            at_time = step * 30 + 15                  # midpoint of that window
            if totp.verify(token, for_time=at_time, valid_window=0):
                return step
        return current_step   # fallback

    def _is_replayed(self, user_id: int, token_hash: str, time_step: int) -> bool:
        """Check if this (user, token_hash, time_step) combo was already used."""
        db = get_db()
        row = db.execute(
            "SELECT 1 FROM used_tokens "
            "WHERE user_id = ? AND token_hash = ? AND time_step = ?",
            (user_id, token_hash, time_step),
        ).fetchone()
        return row is not None

    def _register_used_token(
        self, user_id: int, token_hash: str, time_step: int
    ) -> None:
        """Record a used token to prevent future replay."""
        db = get_db()
        try:
            db.execute(
                "INSERT OR IGNORE INTO used_tokens (user_id, token_hash, time_step) "
                "VALUES (?, ?, ?)",
                (user_id, token_hash, time_step),
            )
            db.commit()
        except Exception:
            db.rollback()
            raise

    # ── Maintenance ────────────────────────────────────────────────────────

    def purge_expired_tokens(self, max_age_steps: int = 10) -> int:
        """
        Delete used_tokens records older than max_age_steps time-steps.

        Call this periodically (e.g., daily) to keep the table small.
        With max_age_steps=10, records older than 5 minutes are deleted.

        Returns:
            Number of rows deleted.
        """
        cutoff_step = int(time.time()) // 30 - max_age_steps
        db = get_db()
        cursor = db.execute(
            "DELETE FROM used_tokens WHERE time_step < ?", (cutoff_step,)
        )
        db.commit()
        return cursor.rowcount
