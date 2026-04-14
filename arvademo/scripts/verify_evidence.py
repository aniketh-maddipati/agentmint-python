#!/usr/bin/env python3
"""
Verify AgentMint evidence package -- signatures, chain, hashes.

Requires: openssl (system)
Does NOT require AgentMint installed. No vendor account. No network calls.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

UNSIGNED = {"signature", "timestamp", "output"}

G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; C = "\033[36m"
W = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def signable(r):
    return {k: v for k, v in r.items() if k not in UNSIGNED}


def verify_ed25519(pub_pem, payload, sig_hex):
    """Verify Ed25519 signature using openssl."""
    try:
        with tempfile.TemporaryDirectory() as td:
            pf = os.path.join(td, "payload")
            sf = os.path.join(td, "sig")
            with open(pf, "wb") as f:
                f.write(payload)
            with open(sf, "wb") as f:
                f.write(bytes.fromhex(sig_hex))
            r = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin",
                 "-inkey", pub_pem, "-rawin", "-sigfile", sf, "-in", pf],
                capture_output=True, text=True, timeout=10)
            return "Verified Successfully" in r.stdout
    except Exception:
        return False


def main():
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        edir = Path(__file__).resolve().parent.parent / "evidence"
        zips = sorted(edir.glob("agentmint_evidence_*.zip"))
        if not zips:
            print("  %sNo evidence found. Run: python3 arvademo/run_demo.py%s" % (R, W))
            sys.exit(1)
        target = zips[-1]

    if target.suffix == ".zip":
        extract = target.parent / "extracted"
        extract.mkdir(exist_ok=True)
        with zipfile.ZipFile(target, "r") as zf:
            zf.extractall(extract)
        here = extract
    else:
        here = target

    pub = here / "public_key.pem"
    if not pub.exists():
        print("  %sNo public_key.pem in %s%s" % (R, here, W))
        sys.exit(1)

    print("\n%s%s%s" % (BOLD, "=" * 78, W))
    print("%s  AgentMint Evidence Verification%s" % (BOLD, W))
    print("=" * 78 + "\n")

    sig_ok = sig_fail = 0

    # -- Plans --
    for pf in sorted(here.glob("plan*.json")):
        p = json.loads(pf.read_text())
        if "signature" not in p:
            continue
        ps = {k: v for k, v in p.items() if k not in ("signature", "parent_plan_id")}
        if verify_ed25519(str(pub), canonical(ps), p["signature"]):
            sig_ok += 1
            print("  %s+%s plan %s...  %s" % (G, W, p["id"][:12], p.get("action", "")))
        else:
            sig_fail += 1
            print("  %sX%s plan %s...  SIG FAILED" % (R, W, p["id"][:12]))

    # -- Receipts --
    rdir = here / "receipts"
    if not rdir.exists():
        rdir = here / "evidence"
    files = sorted(rdir.glob("*.json"))
    total = len(files)

    chain_ok = chain_fail = hash_ok = hash_fail = 0
    chain_prev = {}
    sample_interval = max(1, total // 20)

    print("\n  %sReceipts (%d)%s\n" % (BOLD, total, W))

    for idx, rf in enumerate(files):
        r = json.loads(rf.read_text())
        sig = r["signature"]
        sd = signable(r)
        pid = r.get("plan_id", "?")
        checks = []

        if verify_ed25519(str(pub), canonical(sd), sig):
            checks.append("%ssig:+%s" % (G, W)); sig_ok += 1
        else:
            checks.append("%ssig:X%s" % (R, W)); sig_fail += 1

        expected = chain_prev.get(pid)
        actual = r.get("previous_receipt_hash")
        if actual == expected:
            checks.append("%schain:+%s" % (G, W)); chain_ok += 1
        else:
            checks.append("%schain:X%s" % (R, W)); chain_fail += 1

        ev = r.get("evidence")
        eh = r.get("evidence_hash_sha512", "")
        if ev and eh:
            if hashlib.sha512(canonical(ev)).hexdigest() == eh:
                checks.append("%shash:+%s" % (G, W)); hash_ok += 1
            else:
                checks.append("%shash:X%s" % (R, W)); hash_fail += 1

        chain_prev[pid] = hashlib.sha256(
            canonical(dict(**sd, signature=sig))).hexdigest()

        tag = "%s+%s" % (G, W) if r.get("in_policy") else "%sBLOCKED%s" % (R, W)
        if idx % sample_interval == 0 or not r.get("in_policy"):
            act = r["action"][:40]
            print("  %s  %s  %-40s  %s" % ("  ".join(checks), r["id"][:8], act, tag))

    total_fail = sig_fail + chain_fail + hash_fail

    print("\n%s%s%s" % (BOLD, "=" * 78, W))
    print("%s  VERIFICATION SUMMARY%s" % (BOLD, W))
    print("=" * 78 + "\n")
    print("  Notary signatures:  %s%d%s/%d" % (G, sig_ok, W, sig_ok + sig_fail))
    print("  Chain links:        %s%d%s/%d" % (G, chain_ok, W, chain_ok + chain_fail))
    print("  Evidence hashes:    %s%d%s/%d" % (G, hash_ok, W, hash_ok + hash_fail))
    print()
    print("  %sTrust Model%s" % (BOLD, W))
    print("  Notary and Agent are independent keypairs.")
    print("  Compromising one does not forge the other.")
    print()

    if total_fail:
        print("  %sX %d verification(s) FAILED%s\n" % (R, total_fail, W))
    else:
        print("  %s+ ALL VERIFICATIONS PASSED%s\n" % (G, W))

    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
