"""
app/routes/auth_routes.py — Authentication API Endpoints

All API endpoints return JSON. The two-phase auth flow is:
  Phase 1: POST /api/login   → validates password → returns pending_session_token
  Phase 2: POST /api/verify-totp → validates TOTP → upgrades session → sets cookie
"""

import uuid
import time
from datetime import datetime, timedelta, timezone
from flask import Blueprint, request, jsonify, session, current_app

from app.core.auth import verify_password, hash_password, check_needs_rehash
from app.core.totp_engine import TOTPEngine
from app.models.database import query_one, query_all, execute
from app.middleware.rate_limiter import (
    limiter,
    check_account_lockout,
    record_failed_attempt,
    reset_failed_attempts,
    log_attempt,
)

auth_bp = Blueprint("auth", __name__, url_prefix="/api")

# In-memory store for pending 2FA sessions (session_token → {user_id, expires_at})
# In production, use Redis. For this demo, in-memory is sufficient.
_pending_2fa: dict[str, dict] = {}


def _get_engine() -> TOTPEngine:
    return TOTPEngine(current_app.config["TOTP_MASTER_KEY"])


def _clean_pending_sessions() -> None:
    """Remove expired pending 2FA sessions."""
    now = time.time()
    expired = [k for k, v in _pending_2fa.items() if v["expires_at"] < now]
    for k in expired:
        del _pending_2fa[k]


# ── Register ───────────────────────────────────────────────────────────────

@auth_bp.route("/register", methods=["POST"])
@limiter.limit("5 per minute")
def register():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""

    # Basic validation
    if not username or len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters."}), 400
    if not email or "@" not in email:
        return jsonify({"error": "Valid email is required."}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters."}), 400

    # Check uniqueness
    if query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
        return jsonify({"error": "Username already taken."}), 409
    if query_one("SELECT 1 FROM users WHERE email = ?", (email,)):
        return jsonify({"error": "Email already registered."}), 409

    # Hash password and create user
    password_hash = hash_password(password)
    cursor = execute(
        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
        (username, email, password_hash),
    )
    user_id = cursor.lastrowid

    return jsonify({
        "success": True,
        "message": "Account created successfully.",
        "user_id": user_id,
        "next": "/enroll-2fa",
    }), 201


# ── Login (Phase 1: Password) ──────────────────────────────────────────────

@auth_bp.route("/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # Fetch user
    user = query_one(
        "SELECT id, password_hash, is_2fa_enabled, locked_until, failed_attempts "
        "FROM users WHERE username = ?",
        (username,),
    )

    # Constant-time: always run verify even if user not found (prevent timing attack)
    dummy_hash = "$argon2id$v=19$m=19456,t=2,p=1$dummydummydummy$dummydummydummydummy"
    hash_to_check = user["password_hash"] if user else dummy_hash
    is_valid = verify_password(hash_to_check, password)

    if not user or not is_valid:
        if user:
            lockout_info = record_failed_attempt(user["id"])
            log_attempt(user["id"], "password", False)
            if "locked_until" in lockout_info:
                return jsonify({
                    "error": "Too many failed attempts. Account locked.",
                    "retry_after_seconds": lockout_info["retry_after_seconds"],
                }), 423
        else:
            log_attempt(None, "password", False)
        return jsonify({"error": "Invalid username or password."}), 401

    # Check account lockout
    lockout = check_account_lockout(user["id"])
    if lockout:
        return jsonify({
            "error": "Account is temporarily locked.",
            "retry_after_seconds": lockout["retry_after_seconds"],
            "locked_until": lockout["locked_until"],
        }), 423

    # Re-hash if parameters are outdated
    if check_needs_rehash(user["password_hash"]):
        new_hash = hash_password(password)
        execute("UPDATE users SET password_hash = ? WHERE id = ?", (new_hash, user["id"]))

    log_attempt(user["id"], "password", True)

    # If 2FA not enabled — log in directly
    if not user["is_2fa_enabled"]:
        reset_failed_attempts(user["id"])
        session["user_id"] = user["id"]
        session["authenticated"] = True
        session.permanent = True
        return jsonify({
            "success": True,
            "requires_2fa": False,
            "redirect": "/dashboard",
        }), 200

    # 2FA required — issue pending session token
    _clean_pending_sessions()
    pending_token = str(uuid.uuid4())
    _pending_2fa[pending_token] = {
        "user_id": user["id"],
        "expires_at": time.time() + current_app.config["PENDING_2FA_TTL"],
    }

    return jsonify({
        "success": True,
        "requires_2fa": True,
        "session_token": pending_token,
        "expires_in": current_app.config["PENDING_2FA_TTL"],
    }), 200


# ── Verify TOTP (Phase 2) ──────────────────────────────────────────────────

@auth_bp.route("/verify-totp", methods=["POST"])
@limiter.limit("20 per minute")
def verify_totp():
    data = request.get_json(silent=True) or {}
    session_token = data.get("session_token") or ""
    totp_code = data.get("totp_code") or ""

    # Validate pending session
    _clean_pending_sessions()
    pending = _pending_2fa.get(session_token)
    if not pending or pending["expires_at"] < time.time():
        return jsonify({"error": "Session expired or invalid. Please log in again."}), 401

    user_id = pending["user_id"]

    # Check account lockout
    lockout = check_account_lockout(user_id)
    if lockout:
        return jsonify({
            "error": "Account is temporarily locked.",
            "retry_after_seconds": lockout["retry_after_seconds"],
        }), 423

    # Fetch encrypted TOTP secret
    secret_row = query_one(
        "SELECT encrypted_secret, encryption_iv FROM totp_secrets WHERE user_id = ?",
        (user_id,),
    )
    if not secret_row:
        return jsonify({"error": "2FA not configured for this account."}), 400

    # Decrypt secret
    try:
        engine = _get_engine()
        secret = engine.decrypt_secret(
            bytes(secret_row["encrypted_secret"]),
            bytes(secret_row["encryption_iv"]),
        )
    except ValueError:
        return jsonify({"error": "Internal security error. Contact administrator."}), 500

    # Verify TOTP (includes replay check)
    result = engine.verify_totp(
        secret=secret,
        token=totp_code,
        user_id=user_id,
        valid_window=current_app.config["TOTP_VALID_WINDOW"],
    )

    if not result["valid"]:
        lockout_info = record_failed_attempt(user_id)
        log_attempt(user_id, "totp", False)

        response = {
            "error": result["reason"],
            "failed_attempts": lockout_info.get("failed_attempts", 0),
        }
        if "locked_until" in lockout_info:
            response["retry_after_seconds"] = lockout_info["retry_after_seconds"]
            log_attempt(user_id, "totp", False)
            return jsonify(response), 423

        return jsonify(response), 401

    # Success — consume pending session, establish full session
    del _pending_2fa[session_token]
    reset_failed_attempts(user_id)
    log_attempt(user_id, "totp", True)

    session["user_id"] = user_id
    session["authenticated"] = True
    session.permanent = True

    return jsonify({
        "success": True,
        "message": "Authentication successful.",
        "redirect": "/dashboard",
    }), 200


# ── Enroll 2FA ─────────────────────────────────────────────────────────────

@auth_bp.route("/enroll-2fa", methods=["POST"])
@limiter.limit("3 per minute")
def enroll_2fa():
    if not session.get("user_id") and not request.get_json(silent=True, force=True).get("user_id"):
        return jsonify({"error": "Authentication required."}), 401

    data = request.get_json(silent=True) or {}
    user_id = session.get("user_id") or data.get("user_id")

    user = query_one("SELECT id, email, username FROM users WHERE id = ?", (user_id,))
    if not user:
        return jsonify({"error": "User not found."}), 404

    engine = _get_engine()
    secret = engine.generate_secret()
    qr_image = engine.generate_qr_image_base64(
        secret, user["email"], current_app.config["TOTP_ISSUER"]
    )
    uri = engine.generate_qr_uri(
        secret, user["email"], current_app.config["TOTP_ISSUER"]
    )

    # Store secret in session temporarily until enrollment is confirmed
    session["enrolling_secret"] = secret
    session["enrolling_user_id"] = user_id

    return jsonify({
        "success": True,
        "qr_image": qr_image,
        "manual_secret": secret,
        "uri": uri,
        "issuer": current_app.config["TOTP_ISSUER"],
        "email": user["email"],
    }), 200


# ── Confirm 2FA Enrollment ─────────────────────────────────────────────────

@auth_bp.route("/confirm-2fa", methods=["POST"])
@limiter.limit("5 per minute")
def confirm_2fa():
    data = request.get_json(silent=True) or {}
    totp_code = data.get("totp_code") or ""
    user_id = session.get("enrolling_user_id") or data.get("user_id")
    secret = session.get("enrolling_secret") or data.get("secret")

    if not user_id or not secret:
        return jsonify({"error": "Enrollment session expired. Please start over."}), 400

    engine = _get_engine()
    result = engine.verify_totp(
        secret=secret,
        token=totp_code,
        user_id=user_id,
        valid_window=1,
    )

    if not result["valid"]:
        return jsonify({"error": result["reason"]}), 401

    # Encrypt and store the secret
    ciphertext, iv = engine.encrypt_secret(secret)
    execute(
        "INSERT OR REPLACE INTO totp_secrets (user_id, encrypted_secret, encryption_iv) "
        "VALUES (?, ?, ?)",
        (user_id, ciphertext, iv),
    )
    execute(
        "UPDATE users SET is_2fa_enabled = 1 WHERE id = ?", (user_id,)
    )

    # Clear enrollment session data
    session.pop("enrolling_secret", None)
    session.pop("enrolling_user_id", None)
    session["user_id"] = user_id
    session["authenticated"] = True
    session.permanent = True

    log_attempt(user_id, "enroll", True)

    return jsonify({
        "success": True,
        "message": "2FA successfully enabled for your account.",
        "redirect": "/dashboard",
    }), 200


# ── Logout ─────────────────────────────────────────────────────────────────

@auth_bp.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "redirect": "/login"}), 200


# ── Status ─────────────────────────────────────────────────────────────────

@auth_bp.route("/status", methods=["GET"])
@limiter.limit("30 per minute")
def status():
    user_id = session.get("user_id")
    authenticated = session.get("authenticated", False)

    if not user_id or not authenticated:
        return jsonify({"authenticated": False}), 200

    user = query_one(
        "SELECT username, email, is_2fa_enabled, created_at FROM users WHERE id = ?",
        (user_id,),
    )
    if not user:
        session.clear()
        return jsonify({"authenticated": False}), 200

    return jsonify({
        "authenticated": True,
        "user": {
            "id": user_id,
            "username": user["username"],
            "email": user["email"],
            "is_2fa_enabled": bool(user["is_2fa_enabled"]),
            "created_at": user["created_at"],
        },
    }), 200


# ── Login History ──────────────────────────────────────────────────────────

@auth_bp.route("/login-history", methods=["GET"])
def login_history():
    user_id = session.get("user_id")
    if not user_id or not session.get("authenticated"):
        return jsonify({"error": "Authentication required."}), 401

    rows = query_all(
        "SELECT attempt_type, success, ip_address, attempted_at "
        "FROM login_attempts WHERE user_id = ? "
        "ORDER BY attempted_at DESC LIMIT 20",
        (user_id,),
    )

    return jsonify({
        "history": [
            {
                "type": r["attempt_type"],
                "success": bool(r["success"]),
                "ip": r["ip_address"],
                "at": r["attempted_at"],
            }
            for r in rows
        ]
    }), 200
