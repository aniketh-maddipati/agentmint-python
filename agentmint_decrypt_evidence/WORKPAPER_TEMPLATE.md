# AI Agent Evidence Assessment Workpaper — DRAFT

Built together on the pilot. SOC 2 + ISO 42001 + AIUC-1.

| Client | [name] | Assessor | [name] | Date | [date] |
|---|---|---|---|---|---|

Start here:

    bash VERIFY.sh            # RFC 3161 timestamps
    python3 verify_sigs.py    # Ed25519 signatures

If both pass, evidence integrity is confirmed. If not, stop.

---

## 1. Evidence Integrity — 2 min

VERIFY.sh checks RFC 3161 timestamps via openssl.
verify_sigs.py checks Ed25519 signatures and SHA-256 chain hashes.

| Check | Expected | Actual | Pass/Fail |
|---|---|---|---|
| All signatures valid | ✓ on all receipts | | |
| Chain integrity | No breaks | | |
| Timestamps verify | ✓ against FreeTSA CA | | |

Maps to: CC7.2 (monitoring), CC8.1 (integrity), ISO 42001 Clause 7.5, Clause 9.1, AIUC-1 E015.3

---

## 2. Plan Authorization Review — 5 min

Open plan-001.json.

| Check | What to look for | Actual | Pass/Fail |
|---|---|---|---|
| Scope specificity | Specific patterns (e.g., `read:patient:*`), NOT `*:*` | | |
| Checkpoint coverage | High-risk actions listed (e.g., `appeal:*`) | | |
| TTL bounded | Reasonable expiry, not open-ended | | |
| Delegates named | `delegates_to` lists specific agent identities | | |
| Signed by human | `user` field identifies the human approver | | |

Red flags: `*:*` scope, no checkpoints, TTL >24h, empty delegates_to.

Maps to: CC6.1 (logical access), CC6.2 (prior authorization), ISO 42001 A.6.2.3, A.8.4, AIUC-1 D003.1

---

## 3. Human-Approval Sequence — 10 min

The critical check. Three files show block → human review → re-authorization:

    004-appeal-blocked.json   in_policy: false, output: null
    plan-002.json             narrower scope, parent traces to plan-001
    005-appeal-approved.json  in_policy: true, different plan_id

| Cross-reference | Expected | Actual | Pass/Fail |
|---|---|---|---|
| plan-001.id == receipt-004.plan_id | Blocked under parent plan | | |
| plan-001.id == plan-002.parent_plan_id | Amendment traces back | | |
| plan-002.id == receipt-005.plan_id | Re-approved under amendment | | |
| plan-002.scope ⊆ plan-001.scope | Narrowed, not widened | | |
| receipt-004.output == null | Action was actually blocked | | |
| receipt-005.policy_hash ≠ receipt-004.policy_hash | Different policy | | |

Maps to: CC6.1 (authorization), CC7.2 (anomaly escalation), ISO 42001 A.8.3 (human oversight), AIUC-1 D003.4

---

## 4. Receipt Completeness — 10 min

Walk the full chain:

| Check | Expected | Actual | Pass/Fail |
|---|---|---|---|
| Same `agent` across all receipts | Consistent identity | | |
| Same `session_id` across chain | Single session | | |
| `policy_hash` consistent within plan | Same policy per plan | | |
| `policy_hash` differs across plans | Policy actually changed | | |
| `reasoning_hash` present | Agent rationale captured | | |
| `previous_receipt_hash` null only at head | Chain starts clean | | |
| `session_trajectory` grows monotonically | Trajectory accumulates | | |

Maps to: CC7.1 (system monitoring), CC7.3 (event evaluation), ISO 42001 A.6.2.6, A.6.2.8, AIUC-1 E015.1

---

## 5. Rate Limiting — 5 min

Open policy.yaml. Confirm circuit_breaker configuration:

| Check | Expected | Actual | Pass/Fail |
|---|---|---|---|
| `max_calls` defined | Reasonable limit | | |
| `window_seconds` defined | Bounded time window | | |
| Three states documented | closed → half_open → open | | |

Maps to: CC6.3 (least privilege), ISO 42001 A.6.2.6, AIUC-1 D003.2

---

## 6. Scope Violation Handling — 5 min

If present, check any receipt where `in_policy: false`:

| Check | Expected | Actual | Pass/Fail |
|---|---|---|---|
| `output` is null on blocked receipt | Action was prevented | | |
| `policy_reason` explains why | Specific reason given | | |
| Violation still signed | Evidence of violation is tamper-proof | | |

Maps to: CC7.2 (anomaly detection), ISO 42001 A.10.2 (nonconformity), AIUC-1 D003

---

## Gaps to Request from Client

| Gap | What to ask for | Framework |
|---|---|---|
| E015.2 Log storage | S3/GCS config, retention policy, access controls | AIUC-1 |
| B001 Adversarial testing | Pen test results, red team exercises | AIUC-1 |
| Timestamps | Production TSA configuration (if not FreeTSA) | SOC 2, ISO 42001 |
| Agent co-signing | Whether dual-key (notary + agent) is enabled | SOC 2 CC6.1 |
| Data retention | How long evidence packages are stored | ISO 42001 Clause 7.5 |
| Incident response | Process when violations are escalated | ISO 42001 A.10.2 |

---

## Summary

| Control | Framework(s) | Result | Time |
|---|---|---|---|
| Evidence integrity | CC7.2, CC8.1, Clause 7.5/9.1, E015.3 | Pass / Fail | 2 min |
| Plan authorization | CC6.1, CC6.2, A.6.2.3, A.8.4, D003.1 | Pass / Fail | 5 min |
| Human-approval | CC6.1, CC7.2, A.8.3, D003.4 | Pass / Fail | 10 min |
| Receipt completeness | CC7.1, CC7.3, A.6.2.6, A.6.2.8, E015.1 | Pass / Fail | 10 min |
| Rate limiting | CC6.3, A.6.2.6, D003.2 | Pass / Fail | 5 min |
| Violation handling | CC7.2, A.10.2, D003 | Pass / Fail | 5 min |

**Estimated total: ~37 minutes per engagement.**
