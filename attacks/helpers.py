#!/usr/bin/env python3
"""
attacks/helpers.py — Shared utilities for TOTP attack demo scripts.

Provides:
  - setup_2fa_user(): auto-create user, enroll 2FA, return session_token + secret
  - get_fresh_session(): login to get a new pending 2FA session token
  - print_header(), time_step_info(): display helpers
"""

import sys
import os
import time
import requests
import pyotp
from datetime import datetime

# Ensure helpers can be imported when running scripts from project root
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

DEFAULT_TARGET = "http://localhost:5000"
DEFAULT_PASSWORD = "TestPass123!"


def print_header(title: str, target: str):
    print(f"\n{'=' * 65}")
    print(f"  {title}")
    print(f"{'=' * 65}")
    print(f"  Target: {target}")
    print(f"  Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  WARNING: Educational purpose only - test only on YOUR OWN system!\n")


def time_step_info() -> tuple[int, int]:
    """Return (current_time_step, seconds_remaining_in_this_window)."""
    now = int(time.time())
    return now // 30, 30 - (now % 30)


def wait_for_fresh_window(min_remaining: int = 20):
    """Sleep until a new TOTP window starts (to avoid enrollment code conflicts)."""
    _, remaining = time_step_info()
    if remaining < min_remaining:
        wait = remaining + 1
        print(f"  [*] Waiting {wait}s for next TOTP window (avoid enrollment code conflict)...")
        time.sleep(wait)


def setup_2fa_user(
    base_url: str,
    username: str,
    password: str = DEFAULT_PASSWORD,
) -> tuple[str | None, str | None]:
    """
    Create a user, enroll TOTP 2FA, and return a pending session token + secret.

    Flow:
      1. POST /api/register   - create account
      2. POST /api/login      - authenticate (no 2FA yet, sets Flask session cookie)
      3. POST /api/enroll-2fa - generate TOTP secret + QR
      4. POST /api/confirm-2fa - verify first TOTP code, enable 2FA
      5. POST /api/login      - re-login (now requires 2FA -> pending session token)

    Returns:
        (session_token, secret) on success, (None, None) on failure.
    """
    s = requests.Session()

    # 1. Register (ignore 409 = already exists)
    r = s.post(f"{base_url}/api/register", json={
        "username": username,
        "email": f"{username}@test.local",
        "password": password,
    })
    if r.status_code not in (201, 409):
        print(f"  [!] Register failed (HTTP {r.status_code}): {r.text}")
        return None, None
    print(f"  [+] User '{username}' registered")

    # 2. Login - Phase 1 (password only, no 2FA yet -> Flask session cookie set)
    r = s.post(f"{base_url}/api/login", json={
        "username": username,
        "password": password,
    })
    data = r.json()

    if data.get("requires_2fa"):
        print("  [!] User already has 2FA from a previous run.")
        print("      Use a different username or delete the database.")
        return None, None

    # 3. Enroll 2FA (Flask session has user_id from step 2)
    r = s.post(f"{base_url}/api/enroll-2fa")
    if r.status_code != 200:
        print(f"  [!] Enroll-2FA failed (HTTP {r.status_code}): {r.text}")
        return None, None

    secret = r.json()["manual_secret"]
    print(f"  [+] TOTP secret generated: {secret[:12]}...")

    # 4. Confirm enrollment with a valid TOTP code
    code = pyotp.TOTP(secret).now()
    r = s.post(f"{base_url}/api/confirm-2fa", json={"totp_code": code})
    if r.status_code != 200:
        print(f"  [!] Confirm-2FA failed (HTTP {r.status_code}): {r.text}")
        return None, None
    print(f"  [+] 2FA confirmed (code: {code})")

    # 5. Re-login - now 2FA is enabled, get pending session token
    r = s.post(f"{base_url}/api/login", json={
        "username": username,
        "password": password,
    })
    data = r.json()

    if not data.get("requires_2fa"):
        print("  [!] Login did not require 2FA after enrollment")
        return None, None

    session_token = data["session_token"]
    print(f"  [+] Pending 2FA session: {session_token[:12]}...")
    return session_token, secret


def get_fresh_session(
    base_url: str,
    username: str,
    password: str = DEFAULT_PASSWORD,
) -> str | None:
    """
    Log in and return a new pending 2FA session token.

    Used by attack scripts that need a fresh session for each test case
    (e.g., replay attack needs a new session per attempt).

    Returns:
        session_token string, or None if login failed.
    """
    r = requests.post(f"{base_url}/api/login", json={
        "username": username,
        "password": password,
    })
    data = r.json()
    if data.get("requires_2fa"):
        return data["session_token"]
    if data.get("error"):
        print(f"  [!] Login failed: {data['error']}")
    return None
