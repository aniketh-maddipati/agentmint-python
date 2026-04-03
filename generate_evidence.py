#!/usr/bin/env python3
"""
Generate AIUC-1 evidence package. Real Ed25519 signatures, SHA-256 hash chains.
Uses the actual Notary class — receipts match NotarisedReceipt.to_dict() exactly.

Run:    uv run python3 generate_evidence.py
Output: agentmint_evidence/
Verify: cd agentmint_evidence && bash VERIFY.sh
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

from agentmint.notary import (
    Notary,
    NotarisedReceipt,
    PlanReceipt,
    _public_key_pem,
    verify_chain,
)

# ── Config ────────────────────────────────────────────────

OUTPUT_DIR = Path(__file__).parent / "agentmint_evidence"

PLAN_USER = "claims-supervisor@clinic.example.com"
PLAN_ACTION = "daily-claims-batch"
PLAN_SCOPE = ["read:patient:*", "check:insurance:*", "submit:claim:*", "write:summary:*"]
PLAN_CHECKPOINTS = ["appeal:*"]
PLAN_DELEGATES = ["claims-agent"]

# ── Scenario ──────────────────────────────────────────────

SCENARIO = [
    {
        "seq": "001",
        "action": "read:patient:PT-4821",
        "agent": "claims-agent",
        "evidence": {"tool": "read-patient", "patient_id": "PT-4821",
                     "fields_accessed": ["name", "dob", "insurance_id"]},
        "output": {"patient_id": "PT-4821", "name": "Margaret Chen",
                   "dob": "1958-03-14", "insurance_id": "BCBS-IL-98301"},
        "reasoning": "Patient PT-4821 is listed in today's claims batch; "
                     "reading demographics to verify identity before claim submission.",
    },
    {
        "seq": "002",
        "action": "check:insurance:BCBS-IL-98301",
        "agent": "claims-agent",
        "evidence": {"tool": "check-insurance", "insurance_id": "BCBS-IL-98301",
                     "check_type": "eligibility"},
        "output": {"eligible": True, "plan_type": "PPO",
                   "copay_pct": 20, "deductible_remaining": 450.00},
        "reasoning": "Insurance eligibility must be confirmed before "
                     "submitting claim CLM-9920 for patient PT-4821.",
    },
    {
        "seq": "003",
        "action": "submit:claim:CLM-9920",
        "agent": "claims-agent",
        "evidence": {"tool": "submit-claim", "claim_id": "CLM-9920",
                     "cpt_codes": ["99213", "85025"], "total_charge": 284.00},
        "output": {"claim_id": "CLM-9920", "status": "submitted",
                   "estimated_payment": 227.20, "payer_reference": "BCBS-2026-04-7821"},
        "reasoning": "Patient identity and insurance verified; "
                     "submitting claim CLM-9920 with CPT codes 99213 and 85025.",
    },
    {
        "seq": "004",
        "action": "appeal:claim:CLM-9920",
        "agent": "claims-agent",
        "evidence": {"tool": "appeal-blocked", "claim_id": "CLM-9920",
                     "denial_code": "CO-50", "attempted": True},
        "output": None,
        "reasoning": "Claim CLM-9920 was denied by payer with code CO-50; "
                     "attempting to file appeal for medical necessity review.",
    },
    {
        "seq": "005",
        "action": "write:summary:daily-batch",
        "agent": "claims-agent",
        "use_child_plan": True,  # Delegated child plan with write:summary:* scope
        "evidence": {"tool": "write-summary-delegated", "batch_date": "2026-04-02",
                     "claims_processed": 1, "appeals_blocked": 1,
                     "delegated_by": PLAN_USER},
        "output": {"note_id": "NOTE-2026-04-02-DEL", "word_count": 312,
                   "status": "saved", "scope": "write:summary:*"},
        "reasoning": "Supervisor delegated summary-write scope to claims-agent; "
                     "writing session summary under narrowed child plan.",
    },
    {
        "seq": "006",
        "action": "write:summary:daily-batch",
        "agent": "claims-agent",
        "evidence": {"tool": "write-summary", "batch_date": "2026-04-02",
                     "claims_processed": 1, "appeals_filed": 0},
        "output": {"note_id": "NOTE-2026-04-02-001", "word_count": 247,
                   "status": "saved"},
        "reasoning": "All actions complete for today's batch; "
                     "writing session summary with claims processed and outcomes.",
    },
]

# ── File writers ──────────────────────────────────────────

def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def write_text(path, text):
    path.write_text(text)


# ── VERIFY.sh ─────────────────────────────────────────────

def build_verify_sh(receipts, plan):
    lines = [
        "#!/bin/bash",
        "# AgentMint AIUC-1 Evidence Verification",
        'set -euo pipefail',
        'cd "$(dirname "$0")"',
        "",
        'echo "════════════════════════════════════════════════════════"',
        'echo "  AgentMint AIUC-1 Evidence Verification"',
        'echo "════════════════════════════════════════════════════════"',
        'echo ""',
        'echo "Plan %s — %s"' % (plan.id[:8], plan.user),
        'echo "Scope: %s"' % ", ".join(plan.scope),
        'echo ""',
    ]
    for r in receipts:
        m = "✓" if r.in_policy else "✗"
        lines.append('echo "  %s %s  %s"' % (m, r.id[:8], r.action))
        if not r.in_policy:
            lines.append('echo "    ⚠ %s"' % r.policy_reason)
    lines += ['echo ""', 'echo "── Cryptographic Verification ──"',
              'python3 verify_sigs.py', 'exit $?']
    return "\n".join(lines) + "\n"


# ── verify_sigs.py (shipped in evidence package) ─────────

VERIFY_SIGS_PY = (
    "#!/usr/bin/env python3\n"
    "# Verify Ed25519 signatures, per-plan SHA-256 chains, and hash commitments.\n"
    "# No deps beyond stdlib + openssl.\n"
)
VERIFY_SIGS_PY += r'''
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

UNSIGNED = {"signature", "timestamp", "output"}


def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def signable(r):
    return {k: v for k, v in r.items() if k not in UNSIGNED}


def verify_ed25519(pub, payload, sig_hex):
    with tempfile.TemporaryDirectory() as td:
        pf = os.path.join(td, "p")
        sf = os.path.join(td, "s")
        with open(pf, "wb") as f:
            f.write(payload)
        with open(sf, "wb") as f:
            f.write(bytes.fromhex(sig_hex))
        r = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-pubin",
             "-inkey", pub, "-rawin", "-sigfile", sf, "-in", pf],
            capture_output=True, text=True,
        )
        return "Verified Successfully" in r.stdout


def main():
    here = Path(__file__).parent
    pub = str(here / "public_key.pem")
    if not (here / "public_key.pem").exists():
        print("ERROR: public_key.pem not found")
        sys.exit(1)

    # Verify all plan files
    sig_ok = sig_fail = 0
    for pf in sorted(here.glob("*plan*.json")):
        if pf.name == "receipt_index.json":
            continue
        p = json.loads(pf.read_text())
        if "signature" not in p:
            continue
        ps = {k: v for k, v in p.items() if k != "signature"}
        if verify_ed25519(pub, canonical(ps), p["signature"]):
            print("  sig:✓  plan  %s  %s" % (p["id"][:8], p.get("action", "")))
            sig_ok += 1
        else:
            print("  sig:✗  plan  %s  SIG FAILED" % p["id"][:8])
            sig_fail += 1

    chain_ok = chain_fail = hash_ok = hash_fail = 0
    # Chains are per-plan — track previous hash per plan_id
    chain_prev = {}

    for rf in sorted((here / "receipts").glob("*.json")):
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

        # Chain check — per plan_id
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
        else:
            c.append("output:—" if out is None else "output:✓")
            hash_ok += 1

        # Advance chain for this plan
        chain_prev[pid] = hashlib.sha256(canonical(dict(**sd, signature=sig))).hexdigest()
        tag = "in policy" if r.get("in_policy") else "VIOLATION"
        print("  %s  %s  %s  (%s)" % ("  ".join(c), sid, r["action"], tag))

    ts = sig_ok + sig_fail
    tc = chain_ok + chain_fail
    th = hash_ok + hash_fail
    print()
    print("  Signatures:  %d/%d verified" % (sig_ok, ts))
    print("  Chain links: %d/%d verified" % (chain_ok, tc))
    print("  Hash checks: %d/%d verified (evidence + output)" % (hash_ok, th))
    print("  Chains:      %d plan(s)" % len(chain_prev))
    sys.exit(1 if sig_fail or chain_fail or hash_fail else 0)


if __name__ == "__main__":
    main()
'''

# ── Docs ──────────────────────────────────────────────────

E015_CONTROL_MAP = """# E015 — Log Model Activity: Control Mapping

## Receipt Fields → Control Requirements

| Requirement | Status | Receipt Field | Notes |
|---|---|---|---|
| Action logged | ✓ | `action`, `observed_at` | Every tool call with UTC timestamp |
| Agent identity | ✓ | `agent`, `agent_key_id` | Name + optional co-signing key |
| Policy evaluation | ✓ | `in_policy`, `policy_reason` | Binary verdict + reason |
| Evidence integrity | ✓ | `evidence_hash_sha512` | SHA-512 of evidence dict |
| Tool output data | ✓ | `output_hash` | SHA-256 of tool output. Omitted on blocked actions. Raw output as unsigned display field. |
| Agent reasoning | ✓ | `reasoning_hash` | SHA-256 of reasoning text. Raw text never in receipt — privacy-preserving. |
| Signature | ✓ | `signature` | Ed25519 covers all signable fields |
| Chain integrity | ✓ | `previous_receipt_hash` | SHA-256 hash chain |
| Policy version | ✓ | `policy_hash` | SHA-256 of scope + checkpoints + delegates |
| Human approval | ✓ | `plan_signature` | Plan signed by human |

## Honest Gaps

| Gap | Notes |
|---|---|
| Storage retention | Deployment decision — library produces receipts, retention is infrastructure |
| RFC 3161 timestamps | Package uses `enable_timestamp=False`. Production uses TSA. |
| Adversarial testing | Receipt 004 shows checkpoint enforcement. Full testing in library's 251-test suite. |
"""

TRUST_MODEL = """# Trust Model

## Proves

1. **Integrity** — Ed25519 signed. Any change invalidates signature.
2. **Ordering** — SHA-256 hash chain. Insert/delete/reorder breaks chain.
3. **Policy** — Each receipt records in-policy verdict and reason.
4. **Evidence** — SHA-512 of evidence dict in signed payload.
5. **Output** — SHA-256 of tool output (`output_hash`). Raw output may contain PHI — only hash is signed.
6. **Reasoning** — SHA-256 of agent reasoning (`reasoning_hash`). Raw text is private — proves reasoning existed without exposing chain-of-thought.
7. **Human approval** — Plan signature carried into every receipt.
8. **Delegation** — Child plan created via `delegate_to_agent()` with intersected scope. Checkpoints propagate — delegation cannot bypass organizational policy. Delegation tree in receipt_index.json.

## Does NOT Prove

1. **Agent identity** — `agent` is asserted, not cryptographically proven.
2. **Time** — `observed_at` is self-reported. Production uses RFC 3161 TSA.
3. **Completeness** — Cannot prove nothing was omitted.

## Verify

```bash
bash VERIFY.sh
```

No AgentMint software required. Only openssl and python3.
"""

README = """# AgentMint AIUC-1 Evidence Package

## Verify

```bash
bash VERIFY.sh
```

Requires `openssl` and `python3`. No AgentMint installation needed.

## Scenario

Healthcare claims processing — 6 receipts across parent and child plans.

1. **001** Read patient — in-policy (parent plan)
2. **002** Check insurance — in-policy (parent plan)
3. **003** Submit claim — in-policy (parent plan)
4. **004** Attempt appeal — **blocked by checkpoint** (parent plan)
5. **005** Write summary via delegated child plan — in-policy (narrowed scope)
6. **006** Write summary — in-policy (parent plan)

Receipt 004 demonstrates checkpoint enforcement: the agent attempted an action
matching `appeal:*`, was blocked, and the denial was signed into the chain.
Checkpoints propagate through delegation by design — they represent
organizational policy that sub-delegation cannot bypass.

Receipt 005 demonstrates delegation: supervisor created a child plan with
`write:summary:*` scope via `delegate_to_agent()`. The child plan's scope is
the intersection of parent scope and requested scope. The receipt is under a
different `plan_id` with a different `policy_hash`.

## Key Fields

**`output_hash`** — SHA-256 of tool output. Present when action executed. Omitted on blocked. Raw output as unsigned display field.

**`reasoning_hash`** — SHA-256 of agent reasoning. Present on all receipts. Raw text never in receipt.
"""


# ── Main ──────────────────────────────────────────────────

def main():
    print("AgentMint AIUC-1 Evidence Generator")
    print("=" * 56)

    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)
    (OUTPUT_DIR / "receipts").mkdir()

    notary = Notary()
    print("  Key ID:  %s" % notary.key_id)

    plan = notary.create_plan(
        user=PLAN_USER, action=PLAN_ACTION,
        scope=PLAN_SCOPE, checkpoints=PLAN_CHECKPOINTS,
        delegates_to=PLAN_DELEGATES, ttl_seconds=3600,
    )
    print("  Plan:    %s — %s" % (plan.short_id, plan.user))

    # Supervisor delegates a child plan with narrowed scope (write:summary:* only).
    # Demonstrates scope intersection: child can only write summaries, not read
    # patients or submit claims. Checkpoints propagate — by design, they
    # represent organizational policy that delegation cannot bypass.
    child_plan = notary.delegate_to_agent(
        plan, "claims-agent",
        requested_scope=["write:summary:*"],
    )
    print("  Child:   %s — delegated write:summary:* scope" % child_plan.short_id)
    print()

    receipts = []
    plans_used = []
    for entry in SCENARIO:
        # Receipt 005 uses the child plan; all others use the parent plan
        active_plan = child_plan if entry.get("use_child_plan") else plan

        receipt = notary.notarise(
            action=entry["action"], agent=entry["agent"], plan=active_plan,
            evidence=entry["evidence"], enable_timestamp=False,
            output=entry.get("output"), reasoning=entry.get("reasoning"),
        )
        receipts.append(receipt)
        plans_used.append(active_plan)
        oh = "✓" if receipt.output_hash else "—"
        rh = "✓" if receipt.reasoning_hash else "—"
        m = "✓" if receipt.in_policy else "✗"
        tag = " (child plan)" if entry.get("use_child_plan") else ""
        print("  %s %s %-35s  oh=%s  rh=%s%s" % (
            m, entry["seq"], entry["action"], oh, rh, tag))

    # Verify chains per-plan (chains are per-plan, not global)
    parent_receipts = [r for r, p in zip(receipts, plans_used) if p is plan]
    child_receipts = [r for r, p in zip(receipts, plans_used) if p is child_plan]

    parent_chain = verify_chain(parent_receipts)
    assert parent_chain.valid, "Parent chain broken at %s" % parent_chain.break_at_index
    child_chain = verify_chain(child_receipts)
    assert child_chain.valid, "Child chain broken at %s" % child_chain.break_at_index

    # Write plans (parent + child)
    write_json(OUTPUT_DIR / "plan.json", plan.to_dict())
    write_json(OUTPUT_DIR / "child_plan.json", child_plan.to_dict())

    # Write receipts with unsigned output display field
    for i, (receipt, entry) in enumerate(zip(receipts, SCENARIO)):
        rd = receipt.to_dict()
        if entry.get("output") is not None:
            rd["output"] = entry["output"]
        write_json(OUTPUT_DIR / "receipts" / ("%03d_%s.json" % (i, receipt.id)), rd)

    # Write index
    from datetime import datetime, timezone
    ic = sum(1 for r in receipts if r.in_policy)
    write_json(OUTPUT_DIR / "receipt_index.json", {
        "package_created": datetime.now(timezone.utc).isoformat(),
        "plan_id": plan.id, "plan_user": plan.user, "key_id": plan.key_id,
        "child_plan_id": child_plan.id,
        "total_receipts": len(receipts),
        "in_policy_count": ic, "out_of_policy_count": len(receipts) - ic,
        "aiuc_controls": ["E015", "D003", "B001"],
        "delegation_tree": notary.audit_tree(plan.id),
        "receipts": [{
            "receipt_id": r.id, "short_id": r.short_id,
            "action": r.action, "agent": r.agent,
            "in_policy": r.in_policy, "policy_reason": r.policy_reason,
            "observed_at": r.observed_at,
            "previous_receipt_hash": r.previous_receipt_hash,
            "output_hash": r.output_hash or "",
            "reasoning_hash": r.reasoning_hash,
            "plan_id": r.plan_id,
        } for r in receipts],
    })

    # Write remaining files
    write_text(OUTPUT_DIR / "public_key.pem", _public_key_pem(notary.verify_key))
    vsh = OUTPUT_DIR / "VERIFY.sh"
    write_text(vsh, build_verify_sh(receipts, plan))
    os.chmod(vsh, 0o755)
    vpy = OUTPUT_DIR / "verify_sigs.py"
    write_text(vpy, VERIFY_SIGS_PY)
    os.chmod(vpy, 0o755)
    write_text(OUTPUT_DIR / "E015_CONTROL_MAP.md", E015_CONTROL_MAP)
    write_text(OUTPUT_DIR / "TRUST_MODEL.md", TRUST_MODEL)
    write_text(OUTPUT_DIR / "README.md", README)

    print()
    print("  Output:  %s/" % OUTPUT_DIR)
    print("  Chains:  parent=%d links (root=%s...), child=%d links" % (
        parent_chain.length, parent_chain.root_hash[:16], child_chain.length))
    print("  Receipts: %d (%d in-policy, %d violations)" % (
        len(receipts), ic, len(receipts) - ic))
    print("  Delegation: parent %s → child %s" % (plan.short_id, child_plan.short_id))
    print("  Verify:  cd %s && bash VERIFY.sh" % OUTPUT_DIR)


if __name__ == "__main__":
    main()
