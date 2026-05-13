#!/usr/bin/env python3
"""
attacks/attack_clock_skew.py — Scenario 3: Clock Skew / Drift Analysis
=======================================================================
Systematically test TOTP verification at various clock offsets to map
the system's acceptance window and determine boundary behavior.

Simulates what happens when a user's phone clock drifts from the server's
clock -- a common real-world scenario with:
  - Phones in airplane mode (no NTP sync)
  - Old devices with poor clock accuracy
  - Server VMs with clock drift
  - Timezone misconfigurations

Defense demonstrated:
  - Configurable valid_window (default: 1 = +-30s tolerance)
  - Replay prevention still works across window boundaries
  - Progressive account lockout prevents systematic probing

Key insight (session lifecycle):
  A pending session token is only consumed on SUCCESSFUL verification.
  Failed verifications leave the token intact. So we can reuse one
  session for all rejected codes, and only need new sessions for
  accepted codes (max 3 with valid_window=1).

Usage:
    python attacks/attack_clock_skew.py
    python attacks/attack_clock_skew.py --range 120 --step 30
"""

import argparse
import time
import hmac
import hashlib
import struct
import base64
import requests
import pyotp

from helpers import (
    DEFAULT_TARGET,
    DEFAULT_PASSWORD,
    print_header,
    setup_2fa_user,
    get_fresh_session,
    time_step_info,
)


def generate_totp_at_offset(secret: str, offset_seconds: int) -> tuple[str, int]:
    """
    Generate a TOTP code as if the client clock is offset by N seconds.

    Manually implements RFC 6238 TOTP (HOTP over time) to simulate
    a client whose clock is ahead (+) or behind (-) the server.

    Returns:
        (6-digit OTP string, time_step_used)
    """
    client_time = int(time.time()) + offset_seconds
    client_step = client_time // 30

    counter_bytes = struct.pack(">Q", client_step)
    key = base64.b32decode(secret)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    otp = f"{code_int % 1_000_000:06d}"

    return otp, client_step


def run_clock_skew_analysis(
    base_url: str,
    username: str,
    secret: str,
    test_range: int = 90,
    step_size: int = 30,
) -> dict:
    """
    Test TOTP verification at offsets from -test_range to +test_range seconds.

    Smart session management:
      - One session for all rejected codes (not consumed on failure)
      - New session only needed after each accepted code (consumed on success)
      - With valid_window=1, max 3 new sessions needed (offsets -30, 0, +30)
    """
    current_step, remaining = time_step_info()

    print(f"\n{'=' * 60}")
    print("  SCENARIO 3: Clock Skew / Drift Analysis")
    print(f"{'=' * 60}")
    print(f"  Testing offsets: -{test_range}s to +{test_range}s (step: {step_size}s)")
    print(f"  Server time step: {current_step}")
    print(f"  Window remaining: {remaining}s")
    print()

    results = {
        "test_range": test_range,
        "step_size": step_size,
        "data_points": [],
        "accepted_offsets": [],
        "rejected_offsets": [],
        "account_locked": False,
    }

    offsets = list(range(-test_range, test_range + 1, step_size))
    seen_codes = set()
    session_token = None
    failed_since_last_success = 0

    print(f"  {'Offset':>8} | {'Step':>6} | {'OTP':>8} | {'Result':>14} | HTTP")
    print(f"  {'-' * 8}-+-{'-' * 6}-+-{'-' * 8}-+-{'-' * 14}-+-----")

    for offset in offsets:
        if results["account_locked"]:
            print(f"  {offset:>+8}s | {'---':>6} | {'---':>8} | {'LOCKED':>14} | 423")
            results["data_points"].append({
                "offset": offset, "accepted": False, "http_status": 423, "reason": "locked",
            })
            continue

        otp, client_step = generate_totp_at_offset(secret, offset)
        steps_off = client_step - current_step

        # Skip duplicate codes (e.g., offset -15s and 0s produce same code)
        if otp in seen_codes:
            print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'DUPLICATE':>14} | ---")
            results["data_points"].append({
                "offset": offset, "accepted": False, "http_status": None,
                "reason": "duplicate_code",
            })
            continue
        seen_codes.add(otp)

        # Get fresh session if we don't have one
        if session_token is None:
            session_token = get_fresh_session(base_url, username)
            if not session_token:
                print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'NO SESSION':>14} | ---")
                break

        try:
            r = requests.post(
                f"{base_url}/api/verify-totp",
                json={"session_token": session_token, "totp_code": otp},
                timeout=5,
            )
        except requests.RequestException as e:
            print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'ERROR':>14} | ---")
            break

        status = r.status_code

        if status == 200:
            print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'ACCEPTED':>14} | 200")
            results["accepted_offsets"].append(offset)
            results["data_points"].append({
                "offset": offset, "step": client_step, "otp": otp,
                "accepted": True, "http_status": 200,
            })
            session_token = None  # consumed, need fresh one next time
            failed_since_last_success = 0

        elif status == 423:
            print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'ACCOUNT LOCKED':>14} | 423")
            results["account_locked"] = True
            results["data_points"].append({
                "offset": offset, "step": client_step, "otp": otp,
                "accepted": False, "http_status": 423, "reason": "locked",
            })

        elif status == 429:
            print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'RATE LIMITED':>14} | 429")
            results["data_points"].append({
                "offset": offset, "step": client_step, "otp": otp,
                "accepted": False, "http_status": 429, "reason": "rate_limited",
            })
            time.sleep(2)  # brief pause for rate limit

        else:
            print(f"  {offset:>+8}s | {steps_off:>+6} | {otp:>8} | {'REJECTED':>14} | {status}")
            results["rejected_offsets"].append(offset)
            results["data_points"].append({
                "offset": offset, "step": client_step, "otp": otp,
                "accepted": False, "http_status": status,
            })
            failed_since_last_success += 1
            # session_token still valid (not consumed on failure)

        time.sleep(0.3)  # small delay between requests

    return results


def print_analysis(results: dict):
    accepted = results["accepted_offsets"]
    rejected = results["rejected_offsets"]

    print(f"\n{'=' * 60}")
    print("  CLOCK SKEW ANALYSIS RESULTS")
    print(f"{'=' * 60}")

    if accepted:
        min_a, max_a = min(accepted), max(accepted)
        print(f"  Accepted offset range: {min_a:+d}s to {max_a:+d}s")
        print(f"    Equivalent time steps: {min_a // 30:+d} to {max_a // 30:+d}")
        print(f"    Total accepted range: {max_a - min_a}s")
        print(f"    Active valid codes: {len(accepted)}")
    else:
        print("  No offsets were accepted")

    real_rejected = [r["offset"] for r in results["data_points"]
                     if not r["accepted"] and r.get("http_status") == 401]
    print(f"\n  Total tested:    {len(results['data_points'])}")
    print(f"  Accepted:        {len(accepted)}")
    print(f"  Rejected:        {len(real_rejected)}")
    print(f"  Account locked:  {results['account_locked']}")

    print(f"""
  Security Trade-off Table:
  +-------------+---------------+----------------+------------------------+
  | valid_window| Tolerance     | Active Codes   | P(brute per window)    |
  +-------------+---------------+----------------+------------------------+
  | 0           | +-0s (exact)  | 1 code         | 1/1,000,000 = 0.0001%  |
  | 1 (default) | +-30s         | 3 codes        | 3/1,000,000 = 0.0003%  |
  | 2           | +-60s         | 5 codes        | 5/1,000,000 = 0.0005%  |
  | 3           | +-90s         | 7 codes        | 7/1,000,000 = 0.0007%  |
  +-------------+---------------+----------------+------------------------+

  RECOMMENDATION: valid_window=1 (this system's configuration)
    - Handles normal NTP drift (phones sync within +-5s)
    - Only 3 codes valid simultaneously (negligible security impact)
    - RFC 6238 section 5.2 recommended default
    - Usable even if user's phone drifts up to +-30s

  Real-World Causes of Clock Skew:
    - NTP failure/unavailable: Server or phone loses NTP sync
    - Airplane mode: Phone doesn't sync for extended periods
    - Old hardware: Battery-backed RTCs drift ~1-2 min/month
    - VM clock drift: Hypervisor pausing causes time jumps
    - Timezone misconfiguration: Off-by-one-hour if misconfigured
""")


def main():
    parser = argparse.ArgumentParser(description="TOTP Clock Skew Analysis Tool")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Server URL")
    parser.add_argument("--range", type=int, default=90,
                        help="Max clock offset in seconds (default: 90)")
    parser.add_argument("--step", type=int, default=30,
                        help="Offset increment in seconds (default: 30)")
    args = parser.parse_args()

    print_header("Scenario 3: TOTP Clock Skew Analysis", args.target)

    ts = int(time.time())
    username = f"cs_victim_{ts % 100000}"

    print(f"--- Setting up target user: {username} ---")
    session_token, secret = setup_2fa_user(args.target, username)

    if not session_token or not secret:
        print("\n[!] Setup failed. Make sure the server is running.")
        return

    results = run_clock_skew_analysis(
        args.target,
        username,
        secret,
        test_range=args.range,
        step_size=args.step,
    )
    print_analysis(results)


if __name__ == "__main__":
    main()
