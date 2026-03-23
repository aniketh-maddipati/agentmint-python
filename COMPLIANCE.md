# Compliance Mapping

How AgentMint receipt fields and runtime controls map to regulatory frameworks.

## SOC 2 Trust Services Criteria

### CC6.1 — Logical and Physical Access Controls

| AgentMint Feature | Evidence |
|---|---|
| Scoped delegation (`scope` in plan) | Only explicitly authorised actions proceed. Receipt proves scope was checked. |
| Checkpoint enforcement | Sensitive actions require explicit human approval before execution. |
| Circuit breaker | Per-agent rate limits prevent runaway access patterns. |
| `original_approver` on receipt | Every action traces back to the human who authorised the plan. |
| `key_id` on receipt | Signing key is identified, supporting key rotation and revocation. |

### CC7.2 — Monitoring of System Components

| AgentMint Feature | Evidence |
|---|---|
| Receipt chain (`previous_receipt_hash`) | Immutable, hash-linked audit trail of every action. |
| FileSink (JSONL) | Real-time append-only log compatible with SIEM ingestion. |
| `evidence_hash` (SHA-512) | Tamper-evident hash of action evidence at time of signing. |
| `policy_hash` on receipt | Captures exact policy state at decision time. |
| Session trajectory | Rolling window of recent agent actions within a session. |

### CC8.1 — Change Management

| AgentMint Feature | Evidence |
|---|---|
| `policy_hash` on receipt | SHA-256 of canonical policy (scope + checkpoints + delegates_to). Any policy change produces a different hash. |
| Plan signature (Ed25519) | Plan content is signed at approval time. Modifications invalidate the signature. |
| Evidence export (zip) | Self-contained verification package with VERIFY.sh script. |

### PI1.1 — Privacy Criteria

| AgentMint Feature | Evidence |
|---|---|
| Shield module (PII scanning) | SSN, email, phone, credit card detection before action execution. |
| Shield redaction | PII matches are heavily redacted in threat previews. |
| Scope enforcement | Agents cannot access data outside their approved scope. |

---

## NIST AI Risk Management Framework (AI RMF 1.0)

### MAP 1.1 — Intended purpose and context of use

| AgentMint Feature | Mapping |
|---|---|
| Plan issuance with `action` description | Documents the intended purpose of each agent action. |
| `scope` definition | Explicitly bounds the context of permitted operations. |
| `delegates_to` list | Names authorised agents, preventing unauthorised use. |
| Reasoning capture (`reasoning_hash`) | Records the agent's stated rationale at decision time. |

### MEASURE 2.3 — AI system performance monitoring

| AgentMint Feature | Mapping |
|---|---|
| Receipt chain | Continuous log of every action with pass/fail status. |
| `in_policy` field | Binary indicator of whether each action was within approved bounds. |
| Circuit breaker state | Quantitative measure of agent activity rate. |
| Session counters | Per-pattern action counts within a session. |
| FileSink logs | Machine-parseable performance data for trend analysis. |

### MANAGE 3.1 — Risks are responded to

| AgentMint Feature | Mapping |
|---|---|
| Circuit breaker (open state) | Automatic blocking when agent exceeds rate thresholds. |
| Checkpoint enforcement | Human escalation for sensitive action categories. |
| Shield blocking | Automatic rejection when content matches threat patterns. |
| Session escalation | Configurable deny/escalate thresholds per action pattern. |
| Scope intersection (delegation) | Child agents receive only the intersection of parent permissions. |

### GOVERN 1.1 — Policies and procedures

| AgentMint Feature | Mapping |
|---|---|
| `policy_hash` | Cryptographic proof of which policy was in effect. |
| Plan signature | Non-repudiation of policy approval. |
| `original_approver` | Attribution to the human who set the policy. |
| Evidence export | Auditor-friendly package for policy review. |

---

## HIPAA (45 CFR Part 164)

### 164.312(a)(1) — Access Control

| AgentMint Feature | Evidence |
|---|---|
| Scoped delegation | Technical enforcement of minimum necessary access. |
| Checkpoint patterns | PHI access patterns can require explicit approval. |
| Circuit breaker | Prevents bulk data access by rate-limiting agents. |
| `delegates_to` | Only named agents can act under a plan. |

### 164.312(b) — Audit Controls

| AgentMint Feature | Evidence |
|---|---|
| Receipt chain | Hardware-independent audit trail with hash linking. |
| RFC 3161 timestamps | Third-party timestamp authority proves when actions occurred. |
| FileSink | JSONL log suitable for audit retention requirements. |
| Evidence export | Self-contained verification for compliance audits. |

### 164.312(c)(1) — Integrity

| AgentMint Feature | Evidence |
|---|---|
| Ed25519 signatures | Receipts are cryptographically signed; tampering is detectable. |
| `evidence_hash` (SHA-512) | Integrity verification of action evidence. |
| `output_hash` | Integrity verification of tool output. |
| `previous_receipt_hash` | Chain linking detects insertion or deletion of records. |

### 164.312(d) — Person or Entity Authentication

| AgentMint Feature | Evidence |
|---|---|
| `original_approver` | Human identity tied to plan authorisation. |
| `key_id` | Cryptographic key identity for signing entity. |
| Agent co-signatures | Agents can provide their own key-based attestation. |
| Plan verification | `verify_plan()` confirms human signature is valid. |

### 164.312(e)(1) — Transmission Security

| AgentMint Feature | Evidence |
|---|---|
| Shield module | Scans tool inputs and outputs for PII before transmission. |
| Shield blocking | Prevents exfiltration of detected secrets and PII. |

---

## EU AI Act — Article 12 (Record-keeping)

Article 12 requires high-risk AI systems to include logging capabilities that enable monitoring of the system's operation throughout its lifecycle.

### 12.1 — Automatic recording of events

| AgentMint Feature | Mapping |
|---|---|
| Receipt chain | Every agent action is automatically recorded with unique ID, timestamp, agent, action, and outcome. |
| FileSink | Continuous JSONL logging of all notarised events. |
| Session trajectory | Rolling window captures operational context. |

### 12.2 — Traceability of system operation

| AgentMint Feature | Mapping |
|---|---|
| `plan_id` to `receipt_id` chain | Full traceability from human approval to individual actions. |
| `parent_plan_id` (delegation) | Multi-agent chains are fully traceable. |
| `previous_receipt_hash` | Hash linking provides tamper-evident ordering. |
| RFC 3161 timestamps | Third-party time proof for each event. |

### 12.3 — Level of detail appropriate to intended purpose

| AgentMint Feature | Mapping |
|---|---|
| `evidence` dict on receipt | Captures action-specific context (tool args, results). |
| `reasoning_hash` | Links to agent's stated rationale without storing full text in receipt. |
| `output_hash` | Captures tool output integrity without duplicating content. |
| `policy_hash` | Records exact policy version at decision time. |

### 12.4 — Logging for post-market monitoring

| AgentMint Feature | Mapping |
|---|---|
| Evidence export (zip) | Offline-verifiable package for regulatory submission. |
| VERIFY.sh + verify_sigs.py | Independent verification without AgentMint installation. |
| SIEM-compatible fields | Standard field names for integration with monitoring infrastructure. |

---

## Field Reference

Quick lookup: which receipt field maps to which framework requirement.

| Receipt Field | SOC 2 | NIST AI RMF | HIPAA | EU AI Act Art. 12 |
|---|---|---|---|---|
| `id` | CC7.2 | MEASURE 2.3 | 164.312(b) | 12.1 |
| `plan_id` | CC7.2 | MAP 1.1 | 164.312(b) | 12.2 |
| `agent` | CC6.1 | MAP 1.1 | 164.312(d) | 12.1 |
| `action` | CC6.1 | MAP 1.1 | 164.312(a) | 12.1 |
| `in_policy` | CC7.2 | MEASURE 2.3 | 164.312(b) | 12.1 |
| `policy_reason` | CC7.2 | MANAGE 3.1 | 164.312(b) | 12.3 |
| `signature` | CC8.1 | GOVERN 1.1 | 164.312(c) | 12.2 |
| `previous_receipt_hash` | CC7.2 | MEASURE 2.3 | 164.312(c) | 12.2 |
| `evidence_hash` | CC7.2 | MEASURE 2.3 | 164.312(c) | 12.3 |
| `key_id` | CC6.1 | GOVERN 1.1 | 164.312(d) | 12.2 |
| `original_approver` | CC6.1 | GOVERN 1.1 | 164.312(d) | 12.2 |
| `policy_hash` | CC8.1 | GOVERN 1.1 | — | 12.4 |
| `output_hash` | CC7.2 | MEASURE 2.3 | 164.312(c) | 12.3 |
| `reasoning_hash` | — | MAP 1.1 | — | 12.3 |
| `session_id` | CC7.2 | MEASURE 2.3 | 164.312(b) | 12.1 |
| `session_trajectory` | CC7.2 | MEASURE 2.3 | — | 12.4 |
