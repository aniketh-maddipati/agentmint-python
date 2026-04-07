#!/usr/bin/env python3
"""Verify Ed25519 signatures, per-plan SHA-256 chains, and hash commitments.
Requires: openssl (for sigs). No AgentMint installation needed."""

from __future__ import annotations
import hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path

UNSIGNED = {"signature", "timestamp", "output"}

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

def signable(r):
    return {k: v for k, v in r.items() if k not in UNSIGNED}

def verify_ed25519(pub, payload, sig_hex):
    with tempfile.TemporaryDirectory() as td:
        pf, sf = os.path.join(td, "p"), os.path.join(td, "s")
        with open(pf, "wb") as f: f.write(payload)
        with open(sf, "wb") as f: f.write(bytes.fromhex(sig_hex))
        r = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin",
             "-inkey", pub, "-rawin", "-sigfile", sf, "-in", pf],
            capture_output=True, text=True)
        return "Verified Successfully" in r.stdout

def main():
    here = Path(__file__).parent
    pub = str(here / "public_key.pem")
    if not (here / "public_key.pem").exists():
        print("ERROR: public_key.pem not found"); sys.exit(1)

    sig_ok = sig_fail = 0

    # Verify plans
    for pf in sorted(here.glob("plan-*.json")):
        p = json.loads(pf.read_text())
        if "signature" not in p: continue
        # Exclude parent_plan_id from sig check (injected post-signing)
        ps = {k: v for k, v in p.items() if k not in ("signature", "parent_plan_id")}
        if verify_ed25519(pub, canonical(ps), p["signature"]):
            pid = p.get("parent_plan_id")
            extra = " (parent: %s)" % pid[:8] if pid else ""
            print("  sig:✓  plan  %s  %s%s" % (p["id"][:8], p.get("action", ""), extra))
            sig_ok += 1
        else:
            print("  sig:✗  plan  %s  SIG FAILED" % p["id"][:8])
            sig_fail += 1

    chain_ok = chain_fail = hash_ok = hash_fail = 0
    chain_prev = {}

    for rf in sorted((here / "evidence").glob("*.json")):
        r = json.loads(rf.read_text())
        sig = r["signature"]
        sd = signable(r)
        sid = r["id"][:8]
        pid = r.get("plan_id", "unknown")
        c = []

        if verify_ed25519(pub, canonical(sd), sig):
            c.append("sig:✓"); sig_ok += 1
        else:
            c.append("sig:✗"); sig_fail += 1

        expected_prev = chain_prev.get(pid)
        actual_prev = r.get("previous_receipt_hash")
        if actual_prev == expected_prev:
            c.append("chain:✓"); chain_ok += 1
        else:
            c.append("chain:✗"); chain_fail += 1

        ev = r.get("evidence")
        eh = r.get("evidence_hash_sha512", "")
        if ev and eh:
            if hashlib.sha512(canonical(ev)).hexdigest() == eh:
                c.append("evidence:✓"); hash_ok += 1
            else:
                c.append("evidence:✗"); hash_fail += 1

        out = r.get("output")
        oh = r.get("output_hash")
        if out is not None and oh is not None:
            if hashlib.sha256(canonical(out)).hexdigest() == oh:
                c.append("output:✓"); hash_ok += 1
            else:
                c.append("output:✗"); hash_fail += 1
        elif oh and out is None:
            if oh == hashlib.sha256(b"").hexdigest():
                c.append("output:✓(blocked)"); hash_ok += 1
            else:
                c.append("output:✗"); hash_fail += 1
        else:
            c.append("output:—"); hash_ok += 1

        chain_prev[pid] = hashlib.sha256(
            canonical(dict(**sd, signature=sig))).hexdigest()

        tag = "in policy" if r.get("in_policy") else "BLOCKED"
        print("  %s  %s  %s  (%s)" % ("  ".join(c), sid, r["action"], tag))

    ts = sig_ok + sig_fail
    tc = chain_ok + chain_fail
    th = hash_ok + hash_fail
    print()
    print("  Signatures:  %d/%d verified" % (sig_ok, ts))
    print("  Chain links: %d/%d verified" % (chain_ok, tc))
    print("  Hash checks: %d/%d verified" % (hash_ok, th))
    print("  Chains:      %d plan(s)" % len(chain_prev))
    sys.exit(1 if sig_fail or chain_fail or hash_fail else 0)

if __name__ == "__main__":
    main()
