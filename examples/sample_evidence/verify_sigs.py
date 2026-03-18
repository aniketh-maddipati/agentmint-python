#!/usr/bin/env python3
"""Verify Ed25519 signatures on all receipts. Requires: pip install pynacl"""
import json, sys, base64
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("Install pynacl: pip install pynacl")
    sys.exit(1)

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

def load_pem_public_key(path):
    lines = path.read_text().strip().split("\n")
    b64 = "".join(lines[1:-1])
    der = base64.b64decode(b64)
    # SPKI prefix is 12 bytes, Ed25519 key is last 32
    return VerifyKey(der[12:])

here = Path(__file__).parent
pk_path = here / "public_key.pem"
if not pk_path.exists():
    print("No public_key.pem found"); sys.exit(1)

vk = load_pem_public_key(pk_path)
ok = fail = 0

for rfile in sorted((here / "receipts").glob("*.json")):
    receipt = json.loads(rfile.read_text())
    sig = bytes.fromhex(receipt["signature"])
    # Reconstruct signable dict (everything except signature and timestamp)
    signable = {k: v for k, v in receipt.items() if k not in ("signature", "timestamp")}
    try:
        vk.verify(canonical(signable), sig)
        status = "✓"
        ok += 1
    except BadSignatureError:
        status = "✗ FAILED"
        fail += 1
    tag = "in policy" if receipt.get("in_policy") else "VIOLATION"
    print(f"  {status}  {receipt['id'][:8]}  {receipt['action']}  ({tag})")

print(f"\nSignatures: {ok} verified, {fail} failed")
sys.exit(1 if fail else 0)
