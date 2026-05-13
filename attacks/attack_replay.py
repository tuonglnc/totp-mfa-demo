#!/usr/bin/env python3
"""
attacks/attack_replay.py — Scenario 2: Token Replay Attack Simulator
=====================================================================
Demonstrates that a valid OTP cannot be reused, even within the same
30-second time window.

Attack premise:
  1. Attacker observes/steals a valid OTP (shoulder-surfing, MITM, phishing)
  2. Legitimate user authenticates with that OTP
  3. Attacker tries to reuse the same OTP immediately after

Defense demonstrated:
  - Replay prevention via used_tokens table (SHA-256 hash tracking)
  - UNIQUE INDEX on (user_id, token_hash, time_step) prevents duplicates
  - Pre-verification replay check scans all steps within valid_window

Key insight (why we need fresh sessions per test):
  After a successful /api/verify-totp, the server DELETES the pending
  session token. So to test replay, each attempt needs its own fresh
  session obtained via /api/login.

Usage:
    python attacks/attack_replay.py
    python attacks/attack_replay.py --target http://localhost:5000
"""

import argparse
import time
import requests
import pyotp

from helpers import (
    DEFAULT_TARGET,
    DEFAULT_PASSWORD,
    print_header,
    setup_2fa_user,
    get_fresh_session,
    wait_for_fresh_window,
    time_step_info,
)


def run_replay_tests(base_url: str, username: str, secret: str) -> dict:
    """
    Run 4 replay attack tests, each with a fresh session token.

    Tests:
      1. First use (legitimate)    -> EXPECTED: 200 OK
      2. Immediate replay          -> EXPECTED: 401 "already used"
      3. Delayed replay (5s later) -> EXPECTED: 401 "already used"
      4. Adjacent window code      -> EXPECTED: 200 OK (different, unused code)
    """
    totp = pyotp.TOTP(secret)
    step, remaining = time_step_info()

    print(f"\n{'=' * 60}")
    print("  SCENARIO 2: Token Replay Attack Tests")
    print(f"{'=' * 60}")
    print(f"  Current OTP:  {totp.now()}")
    print(f"  Time step:    {step}")
    print(f"  Window ends:  {remaining}s remaining")
    print()

    # Wait for fresh window if < 20s remaining to avoid mid-test expiry
    if remaining < 20:
        wait = remaining + 1
        print(f"  [*] Waiting {wait}s for fresh TOTP window...")
        time.sleep(wait)
        step, remaining = time_step_info()

    current_code = totp.now()
    next_code = totp.at(for_time=int(time.time()) + 30)  # code for next time step

    results = {
        "tests": [],
        "verdict": None,
    }

    def do_test(test_name: str, code: str, delay: float = 0) -> dict:
        if delay > 0:
            print(f"  [{test_name}] Waiting {delay}s...")
            time.sleep(delay)

        # Get a FRESH session token for each test
        session_token = get_fresh_session(base_url, username)
        if not session_token:
            print(f"  [{test_name}] FAILED to get session token")
            return {"test": test_name, "status": -1, "success": False}

        print(f"  [{test_name}] Code: {code}")
        r = requests.post(
            f"{base_url}/api/verify-totp",
            json={"session_token": session_token, "totp_code": code},
            timeout=5,
        )
        data = r.json()
        success = r.status_code == 200
        icon = "OK" if success else "BLOCKED"
        msg = data.get("message") or data.get("error", "")
        print(f"  [{test_name}] -> HTTP {r.status_code} [{icon}] {msg}")

        result = {
            "test": test_name,
            "code": code,
            "http_status": r.status_code,
            "success": success,
            "message": msg,
        }
        results["tests"].append(result)
        return result

    # ── Test 1: Legitimate first use ────────────────────────────────────
    print("  TEST 1: First Use (Legitimate Authentication)")
    t1 = do_test("First Use", current_code)
    if not t1["success"]:
        print(f"\n  [!] First use failed - cannot test replay.")
        print(f"      Possible causes: code expired, account locked, wrong secret.")
        results["verdict"] = "SETUP_FAILED"
        return results

    # ── Test 2: Immediate replay ────────────────────────────────────────
    print("\n  TEST 2: Immediate Replay (Same Code, New Session)")
    t2 = do_test("Immediate Replay", current_code)

    # ── Test 3: Delayed replay ──────────────────────────────────────────
    print("\n  TEST 3: Delayed Replay (Same Code, 5s Later)")
    t3 = do_test("Delayed Replay", current_code, delay=5)

    # ── Test 4: Adjacent window code (different, unused) ────────────────
    print("\n  TEST 4: Adjacent Window Code (Different, Unused Code)")
    print(f"  [*] Using code from next time step: {next_code}")
    t4 = do_test("Adjacent Window", next_code)

    # ── Verdict ─────────────────────────────────────────────────────────
    replay_blocked = not t2["success"] and not t3["success"]
    new_code_accepted = t4["success"]

    if replay_blocked and new_code_accepted:
        results["verdict"] = "SECURE"
    elif not replay_blocked:
        results["verdict"] = "VULNERABLE"
    else:
        results["verdict"] = "PARTIAL"

    return results


def print_analysis(results: dict):
    print(f"\n{'=' * 60}")
    print("  REPLAY ATTACK ANALYSIS")
    print(f"{'=' * 60}")

    for t in results["tests"]:
        icon = "[OK]" if t["success"] else "[BLOCKED]"
        print(f"  {t['test']:25s} Code: {t['code']}  HTTP {t['http_status']} {icon}")
        print(f"  {'':25s} {t['message']}")
        print()

    verdict = results.get("verdict", "UNKNOWN")
    verdict_map = {
        "SECURE": "SECURE - Replay attacks are fully blocked",
        "VULNERABLE": "VULNERABLE - Replay prevention is NOT working",
        "PARTIAL": "PARTIAL - Some tests passed, some failed",
        "SETUP_FAILED": "SETUP FAILED - Could not run tests",
    }
    print(f"  Verdict: {verdict_map.get(verdict, verdict)}")

    if verdict == "SECURE":
        print("""
  HOW REPLAY PREVENTION WORKS:

  1. Pre-verification check
     When a TOTP code is submitted, the server FIRST checks the used_tokens
     table BEFORE doing any crypto verification. This is O(1) via the
     UNIQUE INDEX on (user_id, token_hash, time_step).

  2. Token hashing
     The server stores SHA-256(code), never the plaintext code.
     An attacker with DB read access cannot recover used OTPs.

  3. Multi-step scanning
     The replay check scans ALL time steps within valid_window (default: +-1).
     This prevents replaying a code from an adjacent 30s window.

  4. Database-level enforcement
     The UNIQUE INDEX ensures that even under race conditions (two requests
     with the same code arriving simultaneously), only one can succeed.
     The second INSERT OR IGNORE silently fails.

  Code flow (totp_engine.py:verify_totp):
     Format check -> Replay check -> TOTP verify -> Register used token
""")


def main():
    parser = argparse.ArgumentParser(description="TOTP Replay Attack Simulator")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="Server URL")
    args = parser.parse_args()

    print_header("Scenario 2: TOTP Replay Attack", args.target)

    ts = int(time.time())
    username = f"rp_victim_{ts % 100000}"

    print(f"--- Setting up target user: {username} ---")
    session_token, secret = setup_2fa_user(args.target, username)

    if not session_token or not secret:
        print("\n[!] Setup failed. Make sure the server is running.")
        return

    # Wait for fresh window so enrollment code doesn't conflict with test code
    wait_for_fresh_window(min_remaining=22)

    results = run_replay_tests(args.target, username, secret)
    print_analysis(results)


if __name__ == "__main__":
    main()
