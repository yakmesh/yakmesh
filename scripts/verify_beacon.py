#!/usr/bin/env python3
"""
YAKMESH Paranoid Entropy Beacon — Client Verification Script (Python)

Exercises all public endpoints and performs client-side verification
exactly as specified in the grok report:
  1. Signature verification (ML-DSA-65 via server-side endpoint)
  2. Chain link check (previous_signature continuity)
  3. Freshness / timing validation

Usage:
  python3 scripts/verify_beacon.py [BASE_URL]
  python3 scripts/verify_beacon.py https://time.yakmesh.dev

Exit codes:
  0 = all checks passed
  1 = one or more checks failed
"""

import sys
import json
import time
import urllib.request
import urllib.error

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:3080"
FRESHNESS_SEC = 120

exit_code = 0
info = None
latest = None
previous_pulse = None


def fail(msg):
    global exit_code
    print(f"  ✗ {msg}", file=sys.stderr)
    exit_code = 1


def pass_(msg):
    print(f"  ✓ {msg}")


def get_json(path, data=None):
    url = f"{BASE}{path}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8") if data else None,
        headers={"Content-Type": "application/json"} if data else {},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def assert_field(obj, field, field_type, ctx):
    if field not in obj or obj[field] is None:
        fail(f"{ctx}: missing {field}")
        return False
    if field_type == "string" and not isinstance(obj[field], str):
        fail(f"{ctx}: {field} should be string")
        return False
    if field_type == "number" and not isinstance(obj[field], (int, float)):
        fail(f"{ctx}: {field} should be number")
        return False
    return True


# ─── 1. /info ───
print("\n📡 /info")
try:
    info = get_json("/info")
    pass_(f"node_id: {info['node_id']}")
    pass_(f"period: {info['period']}s")
    assert_field(info, "public_key", "string", "/info")
    assert_field(info, "next_expected", "number", "/info")
    assert_field(info, "total_pulses", "number", "/info")
    pass_(f"total_pulses: {info['total_pulses']}")
except Exception as e:
    fail(f"/info: {e}")
    sys.exit(1)

if info["total_pulses"] == 0:
    print("\n⚠️  No pulses yet. Node is still booting or has no peers.")
    print("   Wait for the first Commit-Reveal round to complete.")
    sys.exit(0)

# ─── 2. /public/latest ───
print("\n📡 /public/latest")
try:
    latest = get_json("/public/latest")
    pass_(f"round #{latest['round']}")
    assert_field(latest, "randomness", "string", "latest pulse")
    assert_field(latest, "timestamp", "number", "latest pulse")
    assert_field(latest, "signature", "string", "latest pulse")
    assert_field(latest, "public_key", "string", "latest pulse")
    assert_field(latest, "node_id", "string", "latest pulse")

    if len(latest["randomness"]) >= 64:
        pass_(f"randomness length: {len(latest['randomness'])} hex chars (≥ 256 bits)")
    else:
        fail(f"randomness too short: {len(latest['randomness'])} hex chars")
except Exception as e:
    fail(f"/public/latest: {e}")
    sys.exit(1)

# ─── 3. /public/{round} ───
print(f"\n📡 /public/{latest['round']}")
try:
    by_round = get_json(f"/public/{latest['round']}")
    if by_round["round"] == latest["round"]:
        pass_("round matches")
    else:
        fail(f"round mismatch")
    if by_round["randomness"] == latest["randomness"]:
        pass_("randomness matches")
    else:
        fail("randomness mismatch")
except Exception as e:
    fail(f"/public/{{round}}: {e}")

# ─── 4. /public (history) ───
print("\n📡 /public?limit=5")
try:
    history = get_json("/public?limit=5")
    if isinstance(history.get("pulses"), list):
        pass_(f"returned {len(history['pulses'])} pulses")
    else:
        fail("history.pulses is not a list")
    if history.get("limit") == 5:
        pass_("limit parameter respected")
    else:
        fail(f"limit not respected: got {history.get('limit')}")
except Exception as e:
    fail(f"/public: {e}")

# ─── 5. Chain link check ───
print("\n🔗 Chain link check")
if (
    latest["round"] > 1
    and info.get("first_round")
    and latest["round"] > info["first_round"]
):
    try:
        previous_pulse = get_json(f"/public/{latest['round'] - 1}")
        if latest["previous_signature"] == previous_pulse["signature"]:
            pass_(
                f"chain link: previous_signature matches round {latest['round'] - 1}"
            )
        else:
            fail("chain link broken")
    except Exception as e:
        fail(f"chain check: {e}")
elif latest["round"] == info.get("first_round"):
    pass_("genesis pulse — no previous_signature expected")
else:
    pass_("skipping chain check")

# ─── 6. Freshness check ───
print("\n⏱️  Freshness check")
now = int(time.time())
age = now - latest["timestamp"]
if age <= FRESHNESS_SEC:
    pass_(f"pulse age: {age}s (≤ {FRESHNESS_SEC}s)")
else:
    fail(f"pulse stale: {age}s old (threshold {FRESHNESS_SEC}s)")
    print("   Note: timestamp is AGUWA-synchronized time, not wall clock.")
    print("   If AGUWA has large offset, adjust freshness threshold accordingly.")

# ─── 7. Server-side signature verification ───
print("\n🔐 Server-side verify (/public/verify)")
try:
    verify_result = get_json(
        "/public/verify",
        data={
            "round": latest["round"],
            "randomness": latest["randomness"],
            "timestamp": latest["timestamp"],
            "previous_signature": latest.get("previous_signature"),
            "signature": latest["signature"],
            "public_key": latest["public_key"],
        },
    )
    if verify_result.get("valid") is True:
        pass_("server confirms signature valid")
    else:
        fail("server reports signature INVALID")
except Exception as e:
    fail(f"/public/verify: {e}")

# ─── 8. Cross-node check ───
if (
    latest.get("public_key")
    and info.get("public_key")
    and latest["public_key"] != info["public_key"]
):
    print("\n⚠️  Pulse public_key differs from /info public_key")
    print("   This pulse may be from a different node in the mesh.")

# ─── Summary ───
print("\n========================================")
if exit_code == 0:
    print("✅ All beacon checks passed")
else:
    print("❌ Some beacon checks failed")
print(f"   Node: {info['node_id']}")
print(f"   Pulses: {info['total_pulses']}")
print(f"   Latest: round #{latest.get('round', 'N/A')}")
print("========================================\n")

sys.exit(exit_code)
