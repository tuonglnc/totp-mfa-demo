#!/usr/bin/env python3
"""
attacks/attack_replay.py — Scenario 2: Token Replay Attack Simulator
=====================================================================
Purpose: Demonstrate that a valid OTP cannot be used twice,
even within the same 30-second time window.

Attack scenario:
  1. Attacker observes/steals a valid OTP (via MITM, shoulder-surfing, etc.)
  2. Legitimate user authenticates with that OTP
  3. Attacker tries to reuse the same OTP immediately after

⚠️  Educational Purpose Only. Test only against YOUR OWN system.

Usage:
    python attacks/attack_replay.py --target http://localhost:5000 --secret JBSWY3DPEHPK3PXP
"""

import argparse
import time
import pyotp
import requests
from datetime import datetime


TARGET_URL = "http://localhost:5000"


def get_current_time_step() -> int:
    return int(time.time()) // 30


def seconds_remaining_in_window() -> int:
    return 30 - (int(time.time()) % 30)


def run_replay_tests(base_url: str, session_token: str, secret: str) -> dict:
    """
    Run the complete replay attack test suite.

    Tests:
    1. First use (legitimate authentication) — should SUCCEED
    2. Immediate replay — should FAIL
    3. 5-second delayed replay (same window) — should FAIL
    4. Adjacent window code replay (if window ≥ 1) — should FAIL if already used
    """
    totp = pyotp.TOTP(secret)
    current_code = totp.now()
    step = get_current_time_step()
    remaining = seconds_remaining_in_window()

    print(f"\n{'='*60}")
    print("SCENARIO 2: Token Replay Attack Tests")
    print(f"{'='*60}")
    print(f"Current OTP code:  {current_code}")
    print(f"Current time step: {step}")
    print(f"Time remaining:    {remaining}s in this window")
    print()

    results = {
        "secret": secret[:8] + "...",
        "code": current_code,
        "time_step": step,
        "tests": [],
        "verdict": None,
    }

    def do_request(test_name: str, code: str, delay_before: float = 0) -> dict:
        if delay_before > 0:
            print(f"  [{test_name}] Waiting {delay_before}s before submitting...")
            time.sleep(delay_before)

        print(f"  [{test_name}] Submitting code: {code}")
        r = requests.post(
            f"{base_url}/api/verify-totp",
            json={"session_token": session_token, "totp_code": code},
            timeout=5,
        )
        data = r.json()
        result = {
            "test": test_name,
            "code": code,
            "http_status": r.status_code,
            "response": data,
            "success": r.status_code == 200,
        }
        status_icon = "✅" if r.status_code == 200 else "❌"
        print(f"    → HTTP {r.status_code} {status_icon}: {data.get('message') or data.get('error', '')}")
        results["tests"].append(result)
        return result

    # Test 1: Legitimate first use
    print("TEST 1: First Use (Legitimate Authentication)")
    t1 = do_request("First Use", current_code)

    if not t1["success"]:
        print(f"\n[!] First use failed — cannot test replay. "
              f"Check session token validity and secret correctness.")
        results["verdict"] = "SETUP_FAILED"
        return results

    # Test 2: Immediate replay
    print("\nTEST 2: Immediate Replay (Same Code, ~0s After First Use)")
    t2 = do_request("Immediate Replay", current_code)

    # Test 3: 5-second delayed replay
    print("\nTEST 3: Delayed Replay (Same Code, 5s After First Use)")
    t3 = do_request("Delayed Replay (5s)", current_code, delay_before=5)

    # Test 4: Cross-window check — use code from immediately adjacent step
    print("\nTEST 4: Adjacent Window Code (Different Code, Same Window Tolerance)")
    # Generate code for t-1 step (should still be valid with window=1, but won't be replayed)
    prev_step_time = (step - 1) * 30 + 15
    prev_code = totp.at(for_time=prev_step_time)
    t4 = do_request("Adjacent Window Code", prev_code)

    # Verdict
    replay1_blocked = not t2["success"]
    replay2_blocked = not t3["success"]
    all_blocked = replay1_blocked and replay2_blocked

    if all_blocked:
        results["verdict"] = "SECURE"
        print(f"\n✅ VERDICT: SECURE — Replay attacks are blocked!")
    else:
        results["verdict"] = "VULNERABLE"
        issues = []
        if not replay1_blocked: issues.append("immediate replay succeeded")
        if not replay2_blocked: issues.append("delayed replay succeeded")
        print(f"\n❌ VERDICT: VULNERABLE — {', '.join(issues)}")

    return results


def print_analysis(results: dict):
    print(f"\n{'='*60}")
    print("REPLAY ATTACK ANALYSIS")
    print(f"{'='*60}")

    for i, test in enumerate(results["tests"], 1):
        icon = "✅" if test["success"] else "❌"
        blocked = "" if test["success"] else " [BLOCKED]"
        print(f"  Test {i}: {test['test']}")
        print(f"    Code:   {test['code']}")
        print(f"    Status: HTTP {test['http_status']} {icon}{blocked}")
        print(f"    Msg:    {test['response'].get('message') or test['response'].get('error', '')}")
        print()

    print(f"Overall Verdict: {results['verdict']}")
    print()

    print("Security Mechanism Explanation:")
    print("""
  REPLAY PREVENTION DESIGN:
  ─────────────────────────
  When a TOTP code is verified successfully:
  1. The server computes SHA-256(code) → token_hash
  2. Records (user_id, token_hash, time_step) in used_tokens table
  3. A UNIQUE INDEX on (user_id, token_hash, time_step) prevents duplicates
  4. On any future verification attempt, the same (user_id, token_hash, time_step)
     is looked up BEFORE cryptographic verification
  5. If found → 401 "Already used" (replay detected)

  WHY HASH THE CODE?
  ─────────────────
  We store SHA-256(code) rather than the plaintext code because:
  - An attacker with DB read access should not learn what OTPs were used
  - SHA-256 provides sufficient security for short-lived ephemeral values
  - Lookup is still O(1) with the UNIQUE INDEX
    """)


def main():
    parser = argparse.ArgumentParser(description="TOTP Replay Attack Simulator")
    parser.add_argument("--target", default="http://localhost:5000")
    parser.add_argument("--session-token", required=True,
                        help="Pending 2FA session token from /api/login")
    parser.add_argument("--secret", required=True,
                        help="TOTP Base32 secret (visible during enrollment)")
    args = parser.parse_args()

    print(f"🎭 TOTP Replay Attack Simulator")
    print(f"   Target:  {args.target}")
    print(f"   Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n⚠️  Educational purpose only — test only on YOUR OWN system!")

    results = run_replay_tests(args.target, args.session_token, args.secret)
    print_analysis(results)


if __name__ == "__main__":
    main()
