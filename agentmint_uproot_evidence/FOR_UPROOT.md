# AgentMint Evidence Package

Every AI agent action gets a signed receipt. This package has six of them.

Run verification (requires openssl + python3, no AgentMint install):

    bash VERIFY.sh
    python3 verify_sigs.py

---

## What's in here

### Plans — human authorization

A supervisor creates a [plan](plan-001.json) that defines what the agent is allowed to do:

```json
{
  "user": "claims-supervisor@clinic.example.com",
  "scope": ["read:patient:*", "check:insurance:*", "submit:claim:*", "appeal:*", "write:summary:*"],
  "checkpoints": ["appeal:*"],
  "delegates_to": ["claude-sonnet-4-6"],
  "signature": "21b60330..."
}
```

`scope` — what actions are permitted. `checkpoints` — what actions require human approval before execution. `delegates_to` — which agent identity is authorized. The whole thing is Ed25519-signed. Change one byte, signature breaks.

### Receipts — what the agent actually did

Every tool call produces a signed receipt in [evidence/](evidence/). Here's [001-read-patient.json](evidence/001-read-patient.json):

```json
{
  "agent": "claude-sonnet-4-6",
  "action": "read:patient:PT-4821",
  "in_policy": true,
  "policy_reason": "matched scope read:patient:*",
  "evidence_hash_sha512": "164711fa...",
  "policy_hash": "c4ed6679...",
  "previous_receipt_hash": null,
  "signature": "e2fc2ba7..."
}
```

Every receipt records: what action was taken, whether it was in policy, why, a hash of the evidence, a hash of the policy that was active, a link to the previous receipt in the chain, and an Ed25519 signature over all of it.

### The chain — tamper evidence

Each receipt includes `previous_receipt_hash` — the SHA-256 hash of the prior receipt's signed payload. Insert, delete, or reorder a receipt and the chain breaks. `verify_sigs.py` checks every link.

---

## The sequence that matters

Six receipts. Five pass. One gets blocked. Then a human intervenes.

| # | Action | Policy | File |
|---|---|---|---|
| 001 | `read:patient:PT-4821` | ✓ in scope | [001-read-patient.json](evidence/001-read-patient.json) |
| 002 | `check:insurance:BCBS-IL-98301` | ✓ in scope | [002-check-insurance.json](evidence/002-check-insurance.json) |
| 003 | `submit:claim:CLM-9920` | ✓ in scope | [003-submit-claim.json](evidence/003-submit-claim.json) |
| 004 | `appeal:claim:CLM-9920` | **✗ blocked** | [004-appeal-blocked.json](evidence/004-appeal-blocked.json) |
| 005 | `appeal:claim:CLM-9920` | ✓ re-approved | [005-appeal-approved.json](evidence/005-appeal-approved.json) |
| 006 | `write:summary:2026-04-03` | ✓ in scope | [006-write-summary.json](evidence/006-write-summary.json) |

**What happened at 004:** The agent tried to appeal a denied claim. The plan's `checkpoints` list includes `appeal:*`, so the action was blocked. `in_policy: false`. `output: null`. The agent did not execute the appeal. The receipt still gets signed — you have tamper-evident proof the system caught it.

**What happened between 004 and 005:** A human supervisor issued [plan-002.json](plan-002.json) — a narrower plan scoped to exactly `appeal:claim:CLM-9920`. It traces back to the original plan via `parent_plan_id`. The scope is a strict subset. The checkpoints are empty (supervisor explicitly approved this one action).

**What happened at 005:** The agent re-executed the appeal under plan-002. `in_policy: true`. Different `plan_id`. Different `policy_hash`. The appeal went through. Output recorded.

This three-file sequence — block, amend, re-approve — is the human-in-the-loop evidence that auditors can't get today.

---

## What verification proves

`python3 verify_sigs.py` checks three things on every receipt:

1. **Signature** — Ed25519 over the canonical JSON. Proves nothing was modified after signing.
2. **Chain** — `previous_receipt_hash` matches SHA-256 of prior receipt. Proves no insertions, deletions, or reordering.
3. **Hashes** — `evidence_hash_sha512` matches the evidence dict. `output_hash` matches the output. Proves the evidence is what was observed at signing time.

A clean run:

```
  sig:✓  chain:✓  evidence:✓  output:✓  9ee4aed5  read:patient:PT-4821        (in policy)
  sig:✓  chain:✓  evidence:✓  output:✓  b6273157  check:insurance:BCBS-IL-98301 (in policy)
  sig:✓  chain:✓  evidence:✓  output:✓  b3719ce0  submit:claim:CLM-9920        (in policy)
  sig:✓  chain:✓  evidence:✓  output:—  6b0dfbae  appeal:claim:CLM-9920        (BLOCKED)
  sig:✓  chain:✓  evidence:✓  output:✓  6adc1877  appeal:claim:CLM-9920        (in policy)
  sig:✓  chain:✓  evidence:✓  output:✓  538feb54  write:summary:2026-04-03     (in policy)

  Signatures:  8/8 verified
  Chain links: 6/6 verified
  Hash checks: 11/11 verified
```

No vendor software. No API calls. Just openssl and python3.

---

## Why this is better than what auditors get today

| Today | With AgentMint receipts |
|---|---|
| Application logs — mutable, no integrity guarantee | Ed25519 signed — tamper breaks the signature |
| Screenshot evidence — point-in-time, no chain | Hash-chained — covers the full session |
| "The agent is authorized" — asserted, not proven | Plan + receipt — cryptographic proof of authorization |
| No violation evidence — you only see what worked | Blocked actions are signed too — you see what was caught |
| Evidence hunting takes days | Pre-structured, pre-mapped — [workpaper](WORKPAPER_TEMPLATE.md) covers 6 controls in ~37 min |
| One format per framework | One receipt maps to SOC 2 CC6/CC7/CC8, ISO 42001 A.6/A.7/A.8, AIUC-1 D003/E015 |

---

## What I want to know from you

Following up from our call on SOC 2 evidence for agent actions — this is the working implementation.

I'm building this to be the reference evidence format for AIUC-1 agent assessments — something any agent vendor can adopt and any auditor can assess with a standard workpaper. The assessors who shape it now define what "good evidence" looks like for the industry.

1. **What's missing?** What fields, metadata, or context would you need to see in a receipt to accept it as audit evidence?
2. **What would you reject?** What about this format wouldn't pass your review?
3. **Does the [workpaper template](WORKPAPER_TEMPLATE.md) fit how your team actually works?**

If it holds up, I'd like to do a pilot: instrument one agent workflow on your next AI-heavy client, deliver the evidence pack, your team runs the assessment alongside their current method. If it doesn't save time, we stop.

20 minutes to walk through it.

---

*Built by Aniketh Maddipati · [github.com/aniketh-maddipati/agentmint-python](https://github.com/aniketh-maddipati/agentmint-python)*
*Contributing to OWASP Agentic AI Security Initiative with Ken Huang*
