#!/usr/bin/env python3
"""
verify_all.py — Single-command evidence verification.

Replaces VERIFY.sh + verify_sigs.py with one script, one verdict.
Workpaper-ready output. Exception-first reporting.

Place this inside an unzipped evidence package and run:
    python3 verify_all.py

Requires: pip install pynacl
No AgentMint software or account needed.
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("Requires: pip install pynacl")
    sys.exit(1)


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def load_pem_public_key(path):
    lines = path.read_text().strip().split("\n")
    b64 = "".join(lines[1:-1])
    der = base64.b64decode(b64)
    return VerifyKey(der[12:])  # SPKI prefix is 12 bytes


def main():
    here = Path(__file__).parent

    # ── Load public key ───────────────────────────────
    pk_path = here / "public_key.pem"
    if not pk_path.exists():
        print("ERROR: public_key.pem not found")
        sys.exit(1)
    vk = load_pem_public_key(pk_path)
    key_id = hashlib.sha256(bytes(vk)).hexdigest()[:16]

    # ── Load plan ─────────────────────────────────────
    plan_path = here / "plan.json"
    plan = json.loads(plan_path.read_text()) if plan_path.exists() else None

    # ── Load receipts ─────────────────────────────────
    receipts_dir = here / "receipts"
    if not receipts_dir.exists():
        print("ERROR: receipts/ directory not found")
        sys.exit(1)

    receipt_files = sorted(receipts_dir.glob("*.json"))
    if not receipt_files:
        print("ERROR: no receipt JSON files found")
        sys.exit(1)

    # ── Verify ────────────────────────────────────────
    results = []
    exceptions = []
    chain_hashes = []

    print()
    print("  AGENTMINT EVIDENCE VERIFICATION")
    print("  ================================")
    print()

    # Verify plan signature
    if plan:
        sig = bytes.fromhex(plan["signature"])
        signable = {k: v for k, v in plan.items() if k != "signature"}
        try:
            vk.verify(canonical(signable), sig)
            plan_ok = True
        except BadSignatureError:
            plan_ok = False
        status = "OK" if plan_ok else "FAILED"
        print(f"  Plan {plan.get('id', '?')[:8]}  signature: {status}")
        print(f"    user:       {plan.get('user', '?')}")
        print(f"    scope:      {len(plan.get('scope', []))} tools")
        print(f"    delegates:  {plan.get('delegates_to', [])}")
        print(f"    TTL:        {plan.get('issued_at', '?')} → {plan.get('expires_at', '?')}")
        if not plan_ok:
            exceptions.append(("plan", plan.get("id", "?")[:8], "SIGNATURE INVALID"))
        print()

    # Verify each receipt
    for rfile in receipt_files:
        receipt = json.loads(rfile.read_text())
        rid = receipt.get("id", "?")[:8]
        action = receipt.get("action", "?")
        agent = receipt.get("agent", "?")
        in_policy = receipt.get("in_policy", None)
        policy_reason = receipt.get("policy_reason", "")

        # Signature check
        sig = bytes.fromhex(receipt["signature"])
        signable = {k: v for k, v in receipt.items()
                    if k not in ("signature", "timestamp")}
        try:
            vk.verify(canonical(signable), sig)
            sig_ok = True
        except BadSignatureError:
            sig_ok = False

        # Evidence hash check
        evidence = receipt.get("evidence", {})
        evidence_hash = receipt.get("evidence_hash_sha512", "")
        recomputed = hashlib.sha512(canonical(evidence)).hexdigest()
        hash_ok = recomputed == evidence_hash

        # Chain hash (collect for chain verification)
        chain_hashes.append({
            "id": receipt.get("id"),
            "previous_receipt_hash": receipt.get("previous_receipt_hash"),
            "signed_payload": canonical({**signable, "signature": receipt["signature"]}),
        })

        # Key ID check
        receipt_key_id = receipt.get("key_id", "")
        key_match = receipt_key_id == key_id

        # Record result
        row = {
            "id": rid, "action": action, "agent": agent,
            "in_policy": in_policy, "sig_ok": sig_ok,
            "hash_ok": hash_ok, "key_match": key_match,
        }
        results.append(row)

        if not in_policy:
            exceptions.append((rid, action, f"OUT OF POLICY: {policy_reason}"))
        if not sig_ok:
            exceptions.append((rid, action, "SIGNATURE INVALID"))
        if not hash_ok:
            exceptions.append((rid, action, "EVIDENCE HASH MISMATCH"))
        if not key_match:
            exceptions.append((rid, action, f"KEY MISMATCH: {receipt_key_id} != {key_id}"))

    # Chain verification
    chain_valid = True
    chain_break = None
    prev_hash = None
    for i, ch in enumerate(chain_hashes):
        if ch["previous_receipt_hash"] != prev_hash:
            chain_valid = False
            chain_break = i
            break
        prev_hash = hashlib.sha256(ch["signed_payload"]).hexdigest()

    if not chain_valid:
        exceptions.append(("chain", f"index {chain_break}", "CHAIN INTEGRITY BROKEN"))

    # ── EXCEPTIONS (first) ────────────────────────────
    if exceptions:
        print("  EXCEPTIONS")
        print("  ----------")
        for src, detail, msg in exceptions:
            print(f"  ✗  {src:<10s} {detail:<34s} {msg}")
        print()

    # ── RECEIPT TABLE (workpaper-ready) ───────────────
    print(f"  {'ID':<10s} {'Action':<32s} {'Agent':<14s} {'Policy':<10s} {'Sig':<6s} {'Hash':<6s} {'Key':<6s}")
    print(f"  {'─'*10} {'─'*32} {'─'*14} {'─'*10} {'─'*6} {'─'*6} {'─'*6}")
    for r in results:
        policy = "ALLOW" if r["in_policy"] else "DENY"
        sig = "OK" if r["sig_ok"] else "FAIL"
        hsh = "OK" if r["hash_ok"] else "FAIL"
        key = "OK" if r["key_match"] else "FAIL"
        print(f"  {r['id']:<10s} {r['action']:<32s} {r['agent']:<14s} {policy:<10s} {sig:<6s} {hsh:<6s} {key:<6s}")

    # ── SUMMARY ───────────────────────────────────────
    total = len(results)
    sig_pass = sum(1 for r in results if r["sig_ok"])
    hash_pass = sum(1 for r in results if r["hash_ok"])
    key_pass = sum(1 for r in results if r["key_match"])
    policy_deny = sum(1 for r in results if not r["in_policy"])

    print()
    print(f"  SUMMARY")
    print(f"  -------")
    print(f"  Receipts:    {total}")
    print(f"  Signatures:  {sig_pass}/{total} valid")
    print(f"  Hashes:      {hash_pass}/{total} valid")
    print(f"  Key IDs:     {key_pass}/{total} match public_key.pem")
    print(f"  Chain:       {'INTACT' if chain_valid else 'BROKEN at index ' + str(chain_break)}")
    print(f"  Policy:      {total - policy_deny} allowed, {policy_deny} denied")
    print(f"  Exceptions:  {len(exceptions)}")
    print()

    # ── VERDICT ───────────────────────────────────────
    all_ok = sig_pass == total and hash_pass == total and key_pass == total and chain_valid
    if all_ok and not any(e[2].startswith("SIGNATURE") or e[2].startswith("EVIDENCE") or e[2].startswith("CHAIN") for e in exceptions):
        print(f"  VERDICT: PASS — all signatures valid, chain intact, hashes match")
    else:
        print(f"  VERDICT: FAIL — see exceptions above")

    print()
    print(f"  key_id:      {key_id}")
    print(f"  verified_by: verify_all.py (pynacl + hashlib, no vendor software)")
    print()

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
