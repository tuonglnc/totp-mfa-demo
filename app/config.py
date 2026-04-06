"""
app/config.py — Application Configuration
Loads settings from environment variables with secure defaults.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env file if present
BASE_DIR = Path(__file__).parent.parent
load_dotenv(BASE_DIR / ".env")


class Config:
    """Base configuration."""

    # ── Flask ──────────────────────────────────────────────────────────────
    SECRET_KEY: str = os.environ.get("SECRET_KEY", os.urandom(32).hex())
    DEBUG: bool = False
    TESTING: bool = False

    # ── Database ───────────────────────────────────────────────────────────
    DATABASE_PATH: str = os.environ.get(
        "DATABASE_PATH",
        str(BASE_DIR / "database" / "mfa_demo.db"),
    )
    SCHEMA_PATH: str = str(BASE_DIR / "database" / "schema.sql")

    # ── TOTP ───────────────────────────────────────────────────────────────
    TOTP_MASTER_KEY: str = os.environ.get("TOTP_MASTER_KEY", os.urandom(32).hex())
    TOTP_ISSUER: str = os.environ.get("TOTP_ISSUER", "TDTU-InfoSec-MFA")
    TOTP_VALID_WINDOW: int = 1          # ±1 time-step (±30s) — RFC 6238 §5.2
    TOTP_PERIOD: int = 30               # seconds per OTP window

    # ── Rate Limiting ──────────────────────────────────────────────────────
    RATELIMIT_DEFAULT: str = "200 per day;50 per hour"
    RATELIMIT_STORAGE_URI: str = "memory://"
    TOTP_MAX_ATTEMPTS_WINDOW: int = int(
        os.environ.get("TOTP_MAX_ATTEMPTS_PER_WINDOW", "5")
    )

    # ── Account Lockout ────────────────────────────────────────────────────
    LOCKOUT_TIER1_ATTEMPTS: int = int(os.environ.get("LOCKOUT_TIER1_ATTEMPTS", "5"))
    LOCKOUT_TIER1_MINUTES: int = int(os.environ.get("LOCKOUT_TIER1_MINUTES", "15"))
    LOCKOUT_TIER2_ATTEMPTS: int = int(os.environ.get("LOCKOUT_TIER2_ATTEMPTS", "10"))
    LOCKOUT_TIER2_MINUTES: int = int(os.environ.get("LOCKOUT_TIER2_MINUTES", "60"))
    LOCKOUT_TIER3_ATTEMPTS: int = int(os.environ.get("LOCKOUT_TIER3_ATTEMPTS", "20"))
    LOCKOUT_TIER3_HOURS: int = int(os.environ.get("LOCKOUT_TIER3_HOURS", "24"))

    # ── WTForms / CSRF ─────────────────────────────────────────────────────
    WTF_CSRF_ENABLED: bool = True
    WTF_CSRF_TIME_LIMIT: int = 3600     # 1 hour

    # ── Session ────────────────────────────────────────────────────────────
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: int = 3600   # 1 hour

    # ── Pending 2FA Session TTL ────────────────────────────────────────────
    PENDING_2FA_TTL: int = 300               # 5 minutes to complete TOTP step


class DevelopmentConfig(Config):
    DEBUG = True
    WTF_CSRF_ENABLED = False             # Disable CSRF in dev for easier API testing


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True        # HTTPS only in prod


config_map = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def get_config() -> Config:
    env = os.environ.get("FLASK_ENV", "development")
    return config_map.get(env, DevelopmentConfig)
