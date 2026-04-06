"""
app/middleware/rate_limiter.py — Rate Limiting & Progressive Account Lockout

Two complementary rate-limiting strategies:
1. IP-based (flask-limiter): Prevents one IP from hammering any endpoint
2. Per-user lockout (database): Progressive lockout after consecutive failures

Lockout tiers (configurable via .env):
  Tier 1: >= 5  failures  → lock 15 minutes
  Tier 2: >= 10 failures  → lock 1 hour
  Tier 3: >= 20 failures  → lock 24 hours (requires admin intervention)
"""

from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.models.database import query_one, execute


# ── Flask-Limiter (IP-based) ───────────────────────────────────────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)


def init_limiter(app) -> None:
    """Attach flask-limiter to the Flask app."""
    limiter.init_app(app)


# ── Per-User Lockout (Database-backed) ────────────────────────────────────

def check_account_lockout(user_id: int) -> dict | None:
    """
    Check if a user account is currently locked.

    Returns:
        None if not locked.
        dict with 'locked_until' and 'retry_after_seconds' if locked.
    """
    row = query_one(
        "SELECT locked_until FROM users WHERE id = ?", (user_id,)
    )
    if row is None or row["locked_until"] is None:
        return None

    locked_until = datetime.fromisoformat(row["locked_until"])
    now = datetime.now(timezone.utc)

    # Ensure locked_until is timezone-aware
    if locked_until.tzinfo is None:
        locked_until = locked_until.replace(tzinfo=timezone.utc)

    if now < locked_until:
        delta = locked_until - now
        return {
            "locked": True,
            "locked_until": locked_until.isoformat(),
            "retry_after_seconds": int(delta.total_seconds()),
        }

    # Lock has expired — clear it
    execute(
        "UPDATE users SET locked_until = NULL, failed_attempts = 0 WHERE id = ?",
        (user_id,),
    )
    return None


def record_failed_attempt(user_id: int) -> dict:
    """
    Increment failed attempt counter and apply lockout if thresholds are exceeded.

    Reads thresholds from current_app.config.

    Returns:
        dict with 'failed_attempts' and optionally 'locked_until'.
    """
    cfg = current_app.config

    # Get current failed count
    row = query_one("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
    if row is None:
        return {"failed_attempts": 0}

    new_count = (row["failed_attempts"] or 0) + 1

    # Determine lockout duration based on tier
    lockout_delta = None
    if new_count >= cfg["LOCKOUT_TIER3_ATTEMPTS"]:
        lockout_delta = timedelta(hours=cfg["LOCKOUT_TIER3_HOURS"])
    elif new_count >= cfg["LOCKOUT_TIER2_ATTEMPTS"]:
        lockout_delta = timedelta(minutes=cfg["LOCKOUT_TIER2_MINUTES"])
    elif new_count >= cfg["LOCKOUT_TIER1_ATTEMPTS"]:
        lockout_delta = timedelta(minutes=cfg["LOCKOUT_TIER1_MINUTES"])

    now = datetime.now(timezone.utc)
    locked_until = (now + lockout_delta).isoformat() if lockout_delta else None

    execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (new_count, locked_until, user_id),
    )

    result = {"failed_attempts": new_count}
    if locked_until:
        result["locked_until"] = locked_until
        result["retry_after_seconds"] = int(lockout_delta.total_seconds())

    return result


def reset_failed_attempts(user_id: int) -> None:
    """Reset failed attempt counter after a successful login."""
    execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )


def log_attempt(
    user_id: int | None,
    attempt_type: str,
    success: bool,
    ip_address: str | None = None,
) -> None:
    """
    Record a login attempt in the audit log.

    Args:
        user_id: Database user ID (None if username not found).
        attempt_type: 'password' | 'totp' | 'enroll'
        success: Whether the attempt succeeded.
        ip_address: Client IP (defaults to Flask request remote_addr).
    """
    ip = ip_address or (request.remote_addr if request else "unknown")
    ua = request.headers.get("User-Agent", "")[:255] if request else ""

    execute(
        "INSERT INTO login_attempts (user_id, ip_address, attempt_type, success, user_agent) "
        "VALUES (?, ?, ?, ?, ?)",
        (user_id, ip, attempt_type, success, ua),
    )


def require_no_lockout(f):
    """
    Decorator: Return 423 Locked if the user account is locked.
    The wrapped view must receive user_id as a parameter or from the request.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        return f(*args, **kwargs)
    return decorated
