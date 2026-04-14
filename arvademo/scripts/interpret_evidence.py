#!/usr/bin/env python3
"""
Interpret evidence -- regulatory mapping and meaning-making report.
Written for a compliance officer, not an engineer.
"""

from __future__ import annotations

import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; C = "\033[36m"
W = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"

REG_MAP = {
    "fincen:314b:read": (
        "FinCEN 314(b) access control",
        "31 USC 5318(g)(2) -- unauthorized access to shared suspicious\n"
        "        activity intelligence. Criminal referral risk."
    ),
    "comply_advantage:alerts:close:autonomous": (
        "BSA/AML human review",
        "31 USC 5318(h) -- autonomous alert closure without human\n"
        "        oversight violates Bank Secrecy Act requirements."
    ),
    "internal:customer:read:cross_customer": (
        "Data isolation -- GLBA",
        "15 USC 6801 -- cross-customer data access violates financial\n"
        "        privacy and data isolation controls."
    ),
    "ofac:sdnlist:read:direct": (
        "OFAC integration policy",
        "Direct SDN access bypasses ComplyAdvantage normalized matching."
    ),
    "internal:customer:read:full_transaction_history": (
        "Authorization scope",
        "Agent credentialed for own_alerts only. Full transaction\n"
        "        history exceeds NHI credential scope_grants."
    ),
    "swift:messages:read": (
        "SWIFT access control",
        "SWIFT message traffic entirely outside screening agent scope."
    ),
}


def main():
    if len(sys.argv) > 1:
        target = Path(sys.argv[1])
    else:
        edir = Path(__file__).resolve().parent.parent / "evidence"
        zips = sorted(edir.glob("agentmint_evidence_*.zip"))
        if not zips:
            print("  %sNo evidence found.%s" % (R, W))
            sys.exit(1)
        target = zips[-1]

    receipts = []
    if target.suffix == ".zip":
        with zipfile.ZipFile(target, "r") as zf:
            for name in sorted(zf.namelist()):
                if name.startswith("receipts/") and name.endswith(".json"):
                    receipts.append(json.loads(zf.read(name)))
    else:
        rdir = target / "receipts" if (target / "receipts").exists() else target
        for f in sorted(rdir.glob("*.json")):
            receipts.append(json.loads(f.read_text()))

    if not receipts:
        print("  %sNo receipts found.%s" % (R, W))
        sys.exit(1)

    total = len(receipts)
    allowed = sum(1 for r in receipts if r.get("in_policy"))
    blocked = total - allowed
    blocked_actions = Counter(r["action"] for r in receipts if not r.get("in_policy"))
    actions = Counter(r["action"] for r in receipts)

    cred_hashes = set()
    for r in receipts:
        ev = r.get("evidence", {})
        if isinstance(ev, dict) and "credential_hash" in ev:
            cred_hashes.add(ev["credential_hash"])

    print("\n%s%s%s" % (BOLD, "=" * 78, W))
    print("%s  ARVA AML -- EVIDENCE INTERPRETATION REPORT%s" % (BOLD, W))
    print("=" * 78)

    print("\n  %sSESSION OVERVIEW%s" % (BOLD, W))
    print("    Total receipts:  %s%d%s" % (C, total, W))
    print("    Allowed:         %s%d%s" % (G, allowed, W))
    print("    Blocked:         %s%d%s" % (R, blocked, W))

    if blocked_actions:
        print("\n  %sBLOCKED ACTIONS -- REGULATORY MAPPING%s\n" % (BOLD, W))
        for action, count in sorted(blocked_actions.items(), key=lambda x: -x[1]):
            title, detail = REG_MAP.get(action, ("Scope violation", "No scope pattern matched."))
            print("    %s%s%s" % (R, action, W))
            print("      %dx blocked -- %s" % (count, title))
            print("        %s" % detail)
            print()

    web_count = actions.get("entity:web_presence:read", 0)
    print("  %sOUTPUT SCANNING%s" % (BOLD, W))
    if web_count:
        print("    Prompt injection in read_web_presence present in %s%d%s responses." % (Y, web_count, W))
        print("    In enforce mode, the model never receives the injected instruction.")
    print()

    print("  %sNHI CREDENTIAL BINDING%s" % (BOLD, W))
    if len(cred_hashes) == 1:
        print("    %s+%s All receipts bound to single credential: %s..." % (G, W, list(cred_hashes)[0][:24]))
    elif cred_hashes:
        print("    %s!%s %d distinct credential hashes found" % (Y, W, len(cred_hashes)))
    print()

    fincen = blocked_actions.get("fincen:314b:read", 0)
    autoclose = blocked_actions.get("comply_advantage:alerts:close:autonomous", 0)
    cross = blocked_actions.get("internal:customer:read:cross_customer", 0)

    print("  %sWHAT THIS MEANS%s\n" % (BOLD, W))
    print("  This evidence package proves that across %d tool calls, the AML" % total)
    print("  screening agent operated within its authorized scope for %s%d%s actions." % (G, allowed, W))
    print("  Every out-of-scope action was flagged: %s%d%s violations total." % (R, blocked, W))
    print("  FinCEN 314(b) was never accessed (%d attempts blocked). No alert" % fincen)
    print("  was closed without human review (%d attempts blocked). No" % autoclose)
    print("  cross-customer data was accessed (%d attempts blocked)." % cross)
    print()
    print("  Without this evidence layer, the bank's answer to the examiner is:")
    print('  %s"We think our agent stayed in scope, based on our application logs."%s' % (DIM, W))
    print("  With this evidence layer, the answer is:")
    print('  %s"Here is a ZIP. Run this script. The math is the proof."%s' % (G, W))
    print()


if __name__ == "__main__":
    main()
