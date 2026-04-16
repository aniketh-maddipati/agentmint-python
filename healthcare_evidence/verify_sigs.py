#!/usr/bin/env python3
"""Verify Ed25519 signatures and hash chains. Requires: pip install pynacl"""
import base64, hashlib, json, sys
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("  Install pynacl: pip install pynacl"); sys.exit(1)

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

here = Path(__file__).parent
pk = here / "public_key.pem"
if not pk.exists():
    print("  No public_key.pem"); sys.exit(1)

b64 = "".join(pk.read_text().strip().split("\n")[1:-1])
vk = VerifyKey(base64.b64decode(b64)[12:])

sig_ok = sig_fail = chain_ok = chain_fail = hash_ok = hash_fail = 0
chain_heads = {}  # plan_id -> prev hash (per-plan chains)

for f in sorted((here / "evidence").glob("*.json")):
    r = json.loads(f.read_text())
    sig_hex = r.pop("signature")
    r.pop("timestamp", None)
    payload = canonical(r)

    # Signature
    try:
        vk.verify(payload, bytes.fromhex(sig_hex))
        s = "\u2713"
        sig_ok += 1
    except (BadSignatureError, ValueError):
        s = "\u2717 FAIL"
        sig_fail += 1

    # Chain (per-plan — each plan has its own hash chain)
    plan_id = r.get("plan_id", "")
    expected = chain_heads.get(plan_id)
    got = r.get("previous_receipt_hash")
    if got == expected:
        ch = "\u2713"
        chain_ok += 1
    else:
        ch = "\u2717 BREAK"
        chain_fail += 1

    # Evidence hash
    ev = r.get("evidence")
    ev_hash = r.get("evidence_hash_sha512", "")
    if ev and hashlib.sha512(canonical(ev)).hexdigest() == ev_hash:
        h = "\u2713"
        hash_ok += 1
    elif ev:
        h = "\u2717 MISMATCH"
        hash_fail += 1
    else:
        h = "-"

    agent = r.get("agent", "")
    tag = "in policy" if r.get("in_policy") else "BLOCKED"
    short = r.get("id", "")[:8]
    action = r.get("action", "")
    extra = f"  [{agent}]" if agent not in ("claims-agent",) else ""
    print(f"  sig:{s}  chain:{ch}  hash:{h}   {short}  {action}  ({tag}){extra}")

    # Advance chain head for this plan
    signed = canonical({**r, "signature": sig_hex})
    chain_heads[plan_id] = hashlib.sha256(signed).hexdigest()

total = sig_ok + sig_fail
print(f"\n  Signatures:  {sig_ok}/{total} verified")
print(f"  Chain links: {chain_ok}/{total} verified")
print(f"  Hash checks: {hash_ok}/{hash_ok + hash_fail} verified")
sys.exit(1 if (sig_fail or chain_fail or hash_fail) else 0)
