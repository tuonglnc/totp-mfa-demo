#!/usr/bin/env python3
"""
attacks/attack_clock_skew.py — Scenario 3: Clock Skew / Drift Analysis
=======================================================================
Purpose: Systematically test TOTP verification at various clock offsets
to map the system's acceptance window and determine boundary behavior.

Simulates what happens when a user's phone clock drifts from the server's
clock — a common real-world scenario with:
  - Phones in airplane mode (no NTP sync)
  - Old devices with poor clock accuracy
  - Server VMs with clock drift
  - Timezone misconfigurations

⚠️  Educational Purpose Only. Test only against YOUR OWN system.

Usage:
    python attacks/attack_clock_skew.py --target http://localhost:5000 --secret YOURSECRET
"""

import argparse
import time
import hmac
import hashlib
import struct
import base64
import requests
import pyotp
from datetime import datetime


TARGET_URL = "http://localhost:5000"


def generate_totp_at_offset(secret: str, offset_seconds: int) -> tuple[str, int]:
    """
    Generate a TOTP code as if the client's clock is offset by N seconds.

    This manually computes HOTP at a specific time counter, simulating
    a client whose clock is ahead (+) or behind (-) the server's clock.

    This is the exact same algorithm used in our totp_manual.py prototype,
    now applied to arbitrary time offsets.

    Args:
        secret: Base32 TOTP secret.
        offset_seconds: Clock offset in seconds (+ = client ahead, - = client behind).

    Returns:
        Tuple of (6-digit OTP string, time_step_used).
    """
    client_time = int(time.time()) + offset_seconds
    client_step = client_time // 30

    # RFC 4226 / RFC 6238 TOTP algorithm
    counter_bytes = struct.pack(">Q", client_step)
    key = base64.b32decode(secret)
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation
    offset = hmac_hash[-1] & 0x0F
    code_int = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    otp = f"{code_int % 1_000_000:06d}"

    return otp, client_step


def run_clock_skew_analysis(
    base_url: str,
    session_token: str,
    secret: str,
    test_range: int = 180,
    step_size: int = 15,
) -> dict:
    """
    Test TOTP verification at offsets from -test_range to +test_range seconds.

    Args:
        base_url: Target server URL.
        session_token: Pending 2FA session token.
        secret: TOTP Base32 secret.
        test_range: Maximum offset to test (seconds), default ±180s.
        step_size: Offset increment (seconds), default 15s.

    Returns:
        Analysis results dict.
    """
    print(f"\n{'='*60}")
    print("SCENARIO 3: Clock Skew / Drift Analysis")
    print(f"{'='*60}")
    print(f"Testing offsets: -{test_range}s to +{test_range}s (step: {step_size}s)")
    print(f"Server time:     {datetime.fromtimestamp(int(time.time())).strftime('%H:%M:%S')}")
    print(f"Current step:    {int(time.time()) // 30}")
    print()

    results = {
        "test_range": test_range,
        "step_size": step_size,
        "server_time": int(time.time()),
        "current_step": int(time.time()) // 30,
        "data_points": [],
        "accepted_offsets": [],
        "rejected_offsets": [],
        "acceptance_window_seconds": None,
    }

    print(f"{'Offset':>8} | {'Steps':>6} | {'OTP':>8} | {'Result':>12} | HTTP")
    print(f"{'-'*8}-+-{'-'*6}-+-{'-'*8}-+-{'-'*12}-+-----")

    offsets = range(-test_range, test_range + 1, step_size)

    for offset in offsets:
        otp, client_step = generate_totp_at_offset(secret, offset)
        steps_off = (client_step - results["current_step"])

        try:
            r = requests.post(
                f"{base_url}/api/verify-totp",
                json={"session_token": session_token, "totp_code": otp},
                timeout=5,
            )

            accepted = r.status_code == 200
            result_label = "✅ ACCEPTED" if accepted else "❌ REJECTED"
            if r.status_code == 423:
                result_label = "🔒 LOCKED"
            elif r.status_code == 429:
                result_label = "⏸ RATE-LIM"

            print(f"{offset:>+8}s | {steps_off:>+6} | {otp:>8} | {result_label:>12} | {r.status_code}")

            point = {
                "offset_seconds": offset,
                "offset_steps": steps_off,
                "otp": otp,
                "time_step": client_step,
                "accepted": accepted,
                "http_status": r.status_code,
            }
            results["data_points"].append(point)

            if accepted:
                results["accepted_offsets"].append(offset)
            else:
                results["rejected_offsets"].append(offset)

        except requests.RequestException as e:
            print(f"{offset:>+8}s | {steps_off:>+6} | {otp:>8} | ERROR        | --- ({e})")

        # Small delay to avoid triggering rate limiting
        time.sleep(0.3)

    # Compute effective acceptance window
    if results["accepted_offsets"]:
        min_off = min(results["accepted_offsets"])
        max_off = max(results["accepted_offsets"])
        results["acceptance_window_seconds"] = (min_off, max_off)

    return results


def print_analysis(results: dict):
    print(f"\n{'='*60}")
    print("CLOCK SKEW ANALYSIS RESULTS")
    print(f"{'='*60}")

    accepted = results["accepted_offsets"]
    rejected = results["rejected_offsets"]

    if accepted:
        min_a, max_a = min(accepted), max(accepted)
        print(f"Accepted offset range: {min_a:+d}s to {max_a:+d}s")
        print(f"  Equivalent time steps: {min_a//30:+d} to {max_a//30:+d}")
        print(f"  Total accepted range: {max_a - min_a}s")
    else:
        print("❌ No offsets were accepted (all rejected or blocked)")

    print(f"\nTotal tested:   {len(results['data_points'])}")
    print(f"Accepted:       {len(accepted)}")
    print(f"Rejected:       {len(rejected)}")

    print(f"""
Security Trade-off Analysis:
┌──────────────┬────────────────┬──────────────────┬───────────────────────┐
│ valid_window │ Tolerance      │ Active Codes     │ P(brute-force guess)  │
├──────────────┼────────────────┼──────────────────┼───────────────────────┤
│ 0            │ ±0s (exact)    │ 1 code           │ 1/1,000,000 = 0.0001% │
│ 1 (default)  │ ±30s           │ 3 codes          │ 3/1,000,000 = 0.0003% │
│ 2            │ ±60s           │ 5 codes          │ 5/1,000,000 = 0.0005% │
│ 3            │ ±90s           │ 7 codes          │ 7/1,000,000 = 0.0007% │
└──────────────┴────────────────┴──────────────────┴───────────────────────┘

RECOMMENDATION: valid_window=1 (this system's configuration)
  ✅ Handles normal NTP drift (phones sync within ±5s)
  ✅ Only 3 codes valid simultaneously (negligible security impact)
  ✅ RFC 6238 §5.2 recommended default
  ✅ Usable even if user's phone drifts up to ±30s
    """)

    print("Real-World Causes of Clock Skew:")
    causes = [
        ("NTP failure/unavailable", "Server or phone loses NTP sync"),
        ("Airplane mode", "Phone doesn't sync for extended periods"),
        ("Old hardware", "Battery-backed RTCs drift ~1-2 min/month"),
        ("VM clock drift", "Hypervisor pausing causes time jumps"),
        ("Daylight saving (DST)", "Off-by-one-hour if misconfigured"),
    ]
    for cause, desc in causes:
        print(f"  • {cause}: {desc}")


def compare_with_pyotp(secret: str):
    """Side-by-side comparison of our manual implementation vs pyotp."""
    print(f"\n{'='*60}")
    print("VERIFICATION: Manual RFC 6238 vs pyotp Library")
    print(f"{'='*60}")
    totp = pyotp.TOTP(secret)

    print(f"{'Offset':>8} | {'Our Code':>10} | {'pyotp Code':>10} | Match")
    print(f"{'-'*8}-+-{'-'*10}-+-{'-'*10}-+------")

    for offset in range(-60, 61, 15):
        our_code, _ = generate_totp_at_offset(secret, offset)
        client_time = int(time.time()) + offset
        pyotp_code = totp.at(for_time=client_time)
        match = "✅" if our_code == pyotp_code else "❌ MISMATCH"
        print(f"{offset:>+8}s | {our_code:>10} | {pyotp_code:>10} | {match}")


def main():
    parser = argparse.ArgumentParser(description="TOTP Clock Skew Analysis Tool")
    parser.add_argument("--target", default="http://localhost:5000")
    parser.add_argument("--session-token", required=True,
                        help="Pending 2FA session token from /api/login")
    parser.add_argument("--secret", required=True,
                        help="TOTP Base32 secret")
    parser.add_argument("--range", type=int, default=180,
                        help="Max clock offset to test in seconds (default: 180)")
    parser.add_argument("--step", type=int, default=15,
                        help="Step size in seconds (default: 15)")
    parser.add_argument("--verify-impl", action="store_true",
                        help="Compare manual RFC 6238 impl vs pyotp")
    args = parser.parse_args()

    print(f"🕐 TOTP Clock Skew Analysis Tool")
    print(f"   Target:  {args.target}")
    print(f"   Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n⚠️  Educational purpose only — test only on YOUR OWN system!")

    if args.verify_impl:
        compare_with_pyotp(args.secret)

    results = run_clock_skew_analysis(
        args.target,
        args.session_token,
        args.secret,
        test_range=args.range,
        step_size=args.step,
    )
    print_analysis(results)


if __name__ == "__main__":
    main()
