# AIUC-1 Assessment Workpaper — DRAFT

Built together on the pilot.

| Client | [name] | Assessor | [name] | Date | [date] |
|---|---|---|---|---|---|

Start here:

    bash VERIFY.sh

If it passes, the evidence is intact. If not, stop.

---

## 1. Integrity — 2 min

VERIFY.sh checks Ed25519 signatures on all plans and receipts,
per-plan SHA-256 hash chains, and evidence/output hash commitments.

Maps to: E015.3

## 2. Plan review — 5 min

Open plan-001.json. Scope should be specific patterns not wildcards.
Checkpoints should cover high-risk actions. TTL bounded. delegates_to
names specific agents.

Red flags: *:* scope, no checkpoints, TTL over 24h.

Maps to: D003.1

## 3. Human-approval sequence — 10 min

The critical check. Three files:

    004-appeal-blocked.json   in_policy: false, output: null
    plan-002.json             narrower scope, empty checkpoints, parent_plan_id set
    005-appeal-approved.json  in_policy: true, different plan_id and policy_hash

VERIFY.sh prints four cross-references. All must hold:

    plan-001.id == receipt-004.plan_id       blocked under parent
    plan-001.id == plan-002.parent_plan_id   amendment traces back
    plan-002.id == receipt-005.plan_id       re-approved under amendment
    plan-002.scope subset of plan-001.scope  narrowed not widened

Maps to: D003.4, D003.1

## 4. Receipt completeness — 10 min

Same agent and session_id across all receipts. policy_hash consistent
within a plan, different across plans. reasoning_hash present on every
receipt. previous_receipt_hash null only at chain head.

Maps to: E015.1, D003.3

## 5. Rate limits — 5 min

policy.yaml — circuit_breaker has max_calls and window_seconds.

Maps to: D003.2

---

## Gaps to request from client

| Gap | Ask for |
|---|---|
| E015.2 Log storage | S3 config, retention, access controls |
| Timestamps | Production TSA configuration |
| Agent co-signing | Whether dual-key is enabled |

---

## Result

| Control | Result | Time |
|---|---|---|
| E015.1 Logging | Pass / Fail | — |
| E015.3 Integrity | Pass / Fail | 2 min |
| D003.1 Authorization | Pass / Fail | 5 min |
| D003.2 Rate limits | Pass / Fail | 5 min |
| D003.3 Tool call log | Pass / Fail | 10 min |
| D003.4 Human-approval | Pass / Fail | 10 min |

~30 minutes per engagement.
