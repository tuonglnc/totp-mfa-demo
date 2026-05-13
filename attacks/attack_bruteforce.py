#!/usr/bin/env python3
"""
attacks/attack_bruteforce.py — Scenario 1: Brute-Force Attack Simulator
========================================================================
Demonstrates that rate-limiting and progressive account lockout effectively
prevent brute-force enumeration of the 6-digit OTP keyspace.

Attack premise:
  An attacker who has obtained the victim's username/password (via phishing,
  credential stuffing, or breach) tries to guess the 6-digit TOTP code by
  sending many attempts within the 30-second validity window.

Defense demonstrated:
  - IP-based rate limiting (flask-limiter): 20 req/min on /api/verify-totp
  - Per-user account lockout: 5 failures -> 15 min lock (progressive tiers)

Usage:
    python attacks/attack_bruteforce.py
    python attacks/attack_bruteforce.py --mode all
    python attacks/attack_bruteforce.py --mode parallel --threads 10
"""

import argparse
import time
import random
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

from helpers import (
    DEFAULT_TARGET,
    DEFAULT_PASSWORD,
    print_header,
    setup_2fa_user,
)


# ── Mode 1: Sequential Brute-Force ───────────────────────────────────────

def bruteforce_sequential(base_url: str, session_token: str, max_attempts: int = 50) -> dict:
    """
    Try OTP codes 000000, 000001, 000002, ... in order.

    Expected: Server blocks after 5 failed attempts (account lockout Tier 1).
    """
    print(f"\n{'=' * 60}")
    print("  SCENARIO 1A: Sequential Brute-Force")
    print(f"  Trying codes 000000 to {max_attempts - 1:06d}")
    print(f"{'=' * 60}")

    results = {
        "mode": "sequential",
        "total_attempts": 0,
        "rate_limited_at": None,
        "locked_at": None,
        "cracked": False,
        "cracked_code": None,
        "status_distribution": {},
        "start_time": time.time(),
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
            print(f"  [!] Request error: {e}")
            break

        results["total_attempts"] += 1
        status = r.status_code
        results["status_distribution"][status] = results["status_distribution"].get(status, 0) + 1

        if results["total_attempts"] % 10 == 0 or status != 401:
            print(f"  [{results['total_attempts']:>4}] OTP={otp} -> HTTP {status}")

        if status == 429:
            results["rate_limited_at"] = results["total_attempts"]
            print(f"\n  [!] RATE LIMITED after {results['total_attempts']} attempts!")
            print(f"      {r.json()}")
            break
        elif status == 423:
            results["locked_at"] = results["total_attempts"]
            data = r.json()
            print(f"\n  [!] ACCOUNT LOCKED after {results['total_attempts']} attempts!")
            print(f"      Retry after: {data.get('retry_after_seconds', '?')}s")
            break
        elif status == 200:
            results["cracked"] = True
            results["cracked_code"] = otp
            print(f"\n  [!] CODE CRACKED: {otp} (attempt #{results['total_attempts']})")
            break

    results["elapsed"] = time.time() - results["start_time"]
    return results


# ── Mode 2: Random Brute-Force ────────────────────────────────────────────

def bruteforce_random(base_url: str, session_token: str, max_attempts: int = 50) -> dict:
    """
    Try random OTP codes to simulate a smarter attacker avoiding patterns.
    """
    print(f"\n{'=' * 60}")
    print("  SCENARIO 1B: Random Brute-Force")
    print(f"{'=' * 60}")

    results = {
        "mode": "random",
        "total_attempts": 0,
        "rate_limited_at": None,
        "locked_at": None,
        "cracked": False,
        "status_distribution": {},
        "start_time": time.time(),
    }

    tried = set()
    while results["total_attempts"] < max_attempts:
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
        results["status_distribution"][status] = results["status_distribution"].get(status, 0) + 1

        if results["total_attempts"] <= 5 or status != 401:
            print(f"  [{results['total_attempts']:>4}] OTP={otp} -> HTTP {status}")

        if status in (429, 423):
            key = "rate_limited_at" if status == 429 else "locked_at"
            results[key] = results["total_attempts"]
            label = "RATE LIMITED" if status == 429 else "LOCKED"
            print(f"\n  [!] {label} (HTTP {status}) after {results['total_attempts']} attempts")
            break
        elif status == 200:
            results["cracked"] = True
            results["cracked_code"] = otp
            print(f"\n  [!] CODE CRACKED: {otp}")
            break

    results["elapsed"] = time.time() - results["start_time"]
    return results


# ── Mode 3: Parallel Brute-Force ─────────────────────────────────────────

def bruteforce_parallel(base_url: str, session_token: str,
                        max_attempts: int = 50, threads: int = 5) -> dict:
    """
    Fire multiple concurrent requests to test if parallelism bypasses rate limits.
    Account lockout is per-user, so parallel threads share the same lockout counter.
    """
    print(f"\n{'=' * 60}")
    print(f"  SCENARIO 1C: Parallel Brute-Force ({threads} threads)")
    print(f"{'=' * 60}")

    results = {
        "mode": "parallel",
        "threads": threads,
        "total_attempts": 0,
        "rate_limited_at": None,
        "locked_at": None,
        "cracked": False,
        "status_distribution": {},
        "start_time": time.time(),
    }

    codes = [f"{i:06d}" for i in range(max_attempts)]

    def try_code(otp: str) -> tuple[str, int]:
        try:
            r = requests.post(
                f"{base_url}/api/verify-totp",
                json={"session_token": session_token, "totp_code": otp},
                timeout=5,
            )
            return otp, r.status_code
        except Exception:
            return otp, -1

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(try_code, c): c for c in codes}
        for future in as_completed(futures):
            otp, status = future.result()
            results["total_attempts"] += 1
            results["status_distribution"][status] = results["status_distribution"].get(status, 0) + 1

            if results["total_attempts"] <= 20 or status != 401:
                print(f"  [{results['total_attempts']:>4}] OTP={otp} -> HTTP {status}")

            if status == 429 and not results["rate_limited_at"]:
                results["rate_limited_at"] = results["total_attempts"]
            elif status == 423 and not results["locked_at"]:
                results["locked_at"] = results["total_attempts"]
            elif status == 200:
                results["cracked"] = True
                results["cracked_code"] = otp

    results["elapsed"] = time.time() - results["start_time"]
    return results


# ── Analysis ──────────────────────────────────────────────────────────────

def print_analysis(results: dict):
    print(f"\n{'=' * 60}")
    print("  ATTACK ANALYSIS")
    print(f"{'=' * 60}")
    print(f"  Mode:           {results['mode']}")
    if results.get("threads"):
        print(f"  Threads:        {results['threads']}")
    print(f"  Total attempts: {results['total_attempts']}")
    elapsed = results.get("elapsed", 0)
    print(f"  Elapsed:        {elapsed:.2f}s")
    rate = results["total_attempts"] / max(elapsed, 0.001)
    print(f"  Rate:           {rate:.1f} req/s")

    print(f"\n  Outcome:")
    if results.get("cracked"):
        print(f"    [VULNERABLE] Code cracked: {results['cracked_code']}")
    elif results.get("locked_at"):
        print(f"    [PROTECTED]  Account locked after {results['locked_at']} attempts")
    elif results.get("rate_limited_at"):
        print(f"    [PROTECTED]  Rate limited after {results['rate_limited_at']} attempts")
    else:
        print(f"    Attack stopped before triggering defense")

    if results.get("status_distribution"):
        print(f"\n  HTTP Status Distribution:")
        for code, count in sorted(results["status_distribution"].items()):
            label = {
                200: "OK", 401: "Unauthorized",
                423: "Locked", 429: "Rate Limited"
            }.get(int(code), "Other")
            print(f"    HTTP {code} ({label}): {count}x")

    block = results.get("rate_limited_at") or results.get("locked_at") or results["total_attempts"]
    rps = results["total_attempts"] / max(elapsed, 0.001)
    print(f"\n  Mathematical Analysis:")
    print(f"    OTP keyspace:           1,000,000 (6 digits)")
    print(f"    Attempts before block:  {block}")
    print(f"    P(guess in 30s window) = {min(1.0, rps * 30 / 1_000_000):.6%}")
    print(f"    P(guess before lockout) = {block / 1_000_000:.6%}")
    windows = 1_000_000 / max(block, 1)
    print(f"    Windows needed to scan: {windows:,.0f}")
    print(f"    Expected time to crack: {windows * 30 / 86400:.1f} days")


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="TOTP Brute-Force Attack Simulator")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Server URL")
    parser.add_argument("--mode", choices=["sequential", "random", "parallel", "all"],
                        default="sequential")
    parser.add_argument("--max-attempts", type=int, default=50)
    parser.add_argument("--threads", type=int, default=5)
    args = parser.parse_args()

    print_header("Scenario 1: TOTP Brute-Force Attack", args.target)

    ts = int(time.time())
    base_username = f"bf_victim_{ts % 100000}"

    if args.mode in ("sequential", "all"):
        print(f"\n--- Setting up target user: {base_username} ---")
        session_token, _ = setup_2fa_user(args.target, base_username)
        if session_token:
            r = bruteforce_sequential(args.target, session_token, args.max_attempts)
            print_analysis(r)

    if args.mode in ("random", "all"):
        uname_r = f"{base_username}_r"
        print(f"\n--- Setting up target user: {uname_r} ---")
        session_token, _ = setup_2fa_user(args.target, uname_r)
        if session_token:
            r = bruteforce_random(args.target, session_token, args.max_attempts)
            print_analysis(r)

    if args.mode in ("parallel", "all"):
        uname_p = f"{base_username}_p"
        print(f"\n--- Setting up target user: {uname_p} ---")
        session_token, _ = setup_2fa_user(args.target, uname_p)
        if session_token:
            r = bruteforce_parallel(args.target, session_token, args.max_attempts, args.threads)
            print_analysis(r)

    print(f"\n{'=' * 60}")
    print("  CONCLUSION")
    print(f"{'=' * 60}")
    print("""
  Brute-force TOTP is NOT feasible when defenses are active:

  1. RATE LIMITING (flask-limiter)
     - 20 requests/minute on /api/verify-totp
     - Prevents high-speed enumeration
     - Even at max rate, scanning 1M codes takes 34+ days

  2. ACCOUNT LOCKOUT (progressive tiers)
     - 5 failures  -> 15 min lock
     - 10 failures -> 1 hour lock
     - 20 failures -> 24 hour lock (admin intervention)
     - Attacker can only try 4 codes before lockout

  3. COMBINED EFFECT
     - Attacker gets 4 guesses per 15 minutes
     - P(success) = 4/1,000,000 = 0.0004% per attempt
     - Time to 50% probability: ~10 years
""")


if __name__ == "__main__":
    main()
