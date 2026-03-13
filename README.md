# AgentMint

**Open‑source agent identity gateway and AIUC‑1 evidence engine.**

AIUC‑1, IBM’s AI Risk Atlas, and similar frameworks now tell you *which* controls you need for AI agents. AgentMint proves *what your agents actually did* against those controls, with cryptographic receipts you can verify independently.

Every agent becomes a first‑class identity with least‑privilege policies, and every action emits a tamper‑evident, AIUC‑1‑tagged receipt — generated passively, verified with OpenSSL alone.

**[One‑Pager](https://aniketh-maddipati.github.io/agentmint-python/)**  

---

## What it does

AgentMint has two core jobs:

1. **Agent identity & least‑privilege (Gatekeeper).**
  - Issue scoped “plans” to agents: which tools/APIs/resources they can touch and under what conditions.  
  - Enforce checkpoints and replay protection *before* high‑risk actions.
2. **Cryptographic receipts for every action (Notary).**
  - After the call returns, AgentMint evaluates policy, signs a receipt, timestamps it with an independent TSA, and tags it with AIUC‑1 controls
  - ~400ms overhead, never in the call path, no new availability dependency.

Three anchors per receipt:

- **Ed25519 signature** – any modification breaks it immediately.  
- **RFC 3161 timestamp** – independent authority; backdating is impossible.  
- **Commitment hashes** – receipts contain hashes, not content, so nothing sensitive leaves your environment.

---

## Architecture

AgentMint has two layers that coexist:

**Gatekeeper (`core.py`)** — Authorization *before* the action. Scoped delegation, checkpoints, replay protection. “Should this agent be allowed to do this right now?”

**Notary (`notary.py`)** — Evidence *after* the action. Passive receipt generation, policy evaluation, Ed25519 signing, RFC 3161 timestamping, AIUC‑1 control tagging. “Prove this agent did this, under this policy, at this time.”

```text
agentmint/
├── core.py            # Gatekeeper: scoped delegation, checkpoints, replay protection
├── notary.py          # Notary: passive receipt generation, policy evaluation
├── anchor.py          # RFC 3161 timestamping (FreeTSA + DigiCert fallback)
├── commitment.py      # SHA-256 commitment scheme (hash-only receipts)
├── batch.py           # Batch mode: scenario loading, execution, aggregation
├── export.py          # Evidence ZIP packaging
├── keystore.py        # Ed25519 key persistence
├── receipt_store.py   # JSONL append-only receipt persistence
├── types.py           # Data types and enums
├── errors.py          # Exception hierarchy
├── console.py         # Terminal output formatting
└── decorator.py       # @require_receipt decorator
```

System view:

```text
Agent → Identity Gateway (Gatekeeper) → Tools / APIs
                      ↓
          Cryptographic Notary (Notary)
                      ↓
     Receipts → Evidence package → Auditors / GRC / AIUC‑1 / IBM tooling
```

---

## How AgentMint does agent IAM

AgentMint treats every AI agent as a first‑class **non‑human identity (NHI)** with its own scope, owner, and audit trail, instead of hiding agents behind shared API keys or generic service accounts.
### 1. Issuing agent identities and plans

At the IAM layer, AgentMint issues a **plan** to each agent:

- A unique `agent_id` that represents that specific agent.  
- A **scope**: which tools/APIs/resources it can touch (e.g. `tts:standard`, `read:public:`*).  
- A **delegation chain**: who delegated authority to this agent (`user`, service, or higher‑level agent).  
- **Constraints**: actions that require a checkpoint (human approval, higher‑trust agent) before they’re allowed.

```python
from agentmint import AgentMint

mint = AgentMint()

plan = mint.issue_plan(
    action="file-analysis",
    user="manager@company.com",             # human / principal
    scope=["read:public:*", "write:summary:*"],
    delegates_to=["claude-sonnet-4-20250514"],
    requires_checkpoint=["read:secret:*", "delete:*"],
)
```

This is effectively **agent provisioning + least‑privilege policy** in one object.

### 2. Enforcing least‑privilege per action

Whenever an agent wants to do something, Gatekeeper is called before the action:

```python
result = mint.delegate(plan, "claude-sonnet-4-20250514", "read:public:report.txt")
if result.ok:
    ...
```

On each call, Gatekeeper:

- Verifies the agent identity (`agent_id`) against the `delegates_to` list.  
- Checks the requested operation (`"read:public:report.txt"`) against the **scope**; if it’s out of scope, it is blocked or marked as a violation.  
- Enforces **checkpoints** for high‑risk actions (e.g. `read:secret:`*), so those cannot execute without additional approval.  
- Adds **replay protection**, so a captured plan cannot be reused indefinitely.

This yields **per‑agent, per‑action authorization**, rather than “this API key can do everything forever.”

### 3. Binding IAM decisions to cryptographic receipts

After the action runs, the Notary layer turns the IAM decision into a verifiable receipt:

- Copies the identity context (`agent_id`, `user`, `policy_id`, `policy_version`).  
- Records whether the action was **in policy** or a **violation**, plus `violation_type`.  
- Signs the receipt with Ed25519 and anchors it with an RFC 3161 timestamp.  
- Commits to sensitive content and logs via hashes only.

Your IAM decisions are no longer just runtime checks; they’re **persisted as tamper‑evident evidence** you can show auditors, insurers, or platforms like AIUC‑1 / IBM Risk Atlas.

Short why:  

> AgentMint gives AI agents real IAM: every agent gets a unique identity, a scoped plan of what it’s allowed to do, and checkpoints for high‑risk actions. Instead of spraying shared API keys across agents, you enforce least‑privilege on every call and then turn each decision into a signed, timestamped receipt. The result is agent IAM that your security team can reason about and your auditors can verify independently.

---

## Demo — real APIs, no mocks

```bash
$ python -m agentmint.batch scenarios/elevenlabs_quarterly.yaml

Loading scenarios... 4 scenarios, 80 executions
Running against live APIs...

✓ tts:standard     ElevenLabs TTS           [in-policy]    E015,D003,B001
✗ voice:clone      Clone attempt → 401      [VIOLATION]    E015,D004,E010
✓ tts:standard     Claude + clean doc       [in-policy]    E015,D003,B001
✗ tts:standard     Prompt injection caught  [VIOLATION]    E015,D004,B001

Receipts: 80 | In-policy: 68 | Violations: 12
Evidence: agentmint_evidence_20260307.zip

$ bash VERIFY.sh
|Receipts verified: 80/80 · Violations flagged: 12 · All signatures valid
```

---

## Receipt schema (v0.2)

```json
{
  "receipt_id": "a1f7e3d2-8b4c-4e91-a6f0-3c9d5e2b1a08",
  "schema_version": "0.2",
  "action": "tts:standard",
  "in_policy": true,
  "violation_type": null,
  "issued_at": "2026-03-06T04:08:45.221Z",
  "api_provider": "ElevenLabs",
  "api_endpoint": "/v1/text-to-speech/{voice_id}",
  "agent_id": "elevenlabs-demo-agent",
  "policy_id": "elevenlabs-voice-policy-v2.3",
  "policy_version": "2.3",
  "architecture_ref": "arch-doc-2026Q1",
  "aiuc1_controls": ["E015", "D003", "B001"],
  "batch_id": null,
  "anchored": true,
  "signature_ed25519": "e4a9b2c1d7f3...",
  "tsr_token_ref": "receipt_001.tsr",
  "content_hash": "sha256:7f83b165...",
  "source_log_hash": "sha256:2c26b46b..."
}
```

---

## AIUC‑1 control mapping (examples)

AgentMint doesn’t define controls; it **implements and evidences** them. AIUC‑1 plus IBM’s Risk Atlas / Nexus tell you which controls to apply; AgentMint emits receipts that prove how your agents behaved against those controls in production.


| Receipt Field          | AIUC‑1 Control(s) | What It Proves in Practice                                                                |
| ---------------------- | ----------------- | ----------------------------------------------------------------------------------------- |
| `action` + `in_policy` | E015              | Every agent action is logged with a clear “in‑policy / violation” outcome.                |
| `violation_type`       | D004              | Unauthorized / unsafe tool calls are detected, classified, and recorded.                  |
| `signature_ed25519`    | B001, B006        | Evidence is tamper‑evident and independently verifiable; any change breaks the signature. |
| `content_hash`         | D003              | Tool/LLM content is committed without exposing it, enabling safe cross‑checking.          |
| `source_log_hash`      | B006              | Ties receipts to provider logs, enabling forensic correlation for incidents.              |
| `tsr_token_ref`        | E010              | Independent timestamp shows evidence existed at the time, not back‑filled later.          |
| `policy_id` + version  | E007              | Every action is tied to the exact policy and version in force when it ran.                |
| `architecture_ref`     | E005              | Links runtime evidence back to documented architecture and data‑flow.                     |
| `agent_id`             | B005/B007         | Which agent identity acted, traceable through your IAM / access control chain.            |


---

## Evidence package

Agent certifications like AIUC‑1 expect continuous, control‑aligned evidence, not one‑off screenshots. Today, teams rebuild evidence packages manually every quarter.

AgentMint automates that:

```text
Agent calls API normally
        ↓
API response returns
        ↓
AgentMint evaluates policy → builds receipt
        ↓
Ed25519 signature + RFC 3161 timestamp + SHA-256 commitments
        ↓
Anchored receipts written into a portable evidence package (ZIP)
```

Receipts stay with you; verification uses only OpenSSL and the TSA’s public cert.

---

## Tamper‑evidence: three independent anchors

**1. Ed25519 signature**  
Every receipt is signed with a private key that never leaves your environment. Any bit flip breaks the signature.

**2. RFC 3161 timestamp**  
The hash of the signed receipt is sent to a trusted timestamp authority (FreeTSA + optional DigiCert). The token proves the receipt existed at that time; you can’t backdate incidents.

**3. Commitment scheme**  
Receipts contain hashes of payloads and logs, not raw content, so you can share receipts with auditors, insurers, or governance platforms without leaking data.

---

## Verify receipts

```bash
./VERIFY.sh
```

Under the hood: pure OpenSSL against the included public key and TSA CA cert.

```text
Receipts verified: 80/80
Out-of-policy actions flagged: 12
Verification timestamp: 2026-03-05T14:32:01Z
```

Evidence bundle layout:

```text
agentmint_evidence_20260307/
├── receipt_index.json       # Aggregate summary — auditor reads first
├── receipts/
│   ├── receipt_001.json     # Individual signed receipt
│   ├── receipt_001.tsr      # RFC 3161 timestamp token
│   └── ...
├── keys/
│   └── public_key.pem       # Ed25519 public key
├── certs/
│   └── freetsa_cacert.pem   # TSA CA certificate
├── VERIFY.sh                # One-command verification — pure OpenSSL
├── TAMPER_TEST.sh           # Automated tamper demonstration
└── control_mapping.pdf      # AIUC‑1 / framework crosswalk
```

---

## Install

```bash
pip install agentmint
```

Or from source:

```bash
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
```

---

## Quick start — Gatekeeper (identity & least‑privilege)

```python
from agentmint import AgentMint

mint = AgentMint()

plan = mint.issue_plan(
    action="file-analysis",
    user="manager@company.com",
    scope=["read:public:*", "write:summary:*"],
    delegates_to=["claude-sonnet-4-20250514"],
    requires_checkpoint=["read:secret:*", "delete:*"],
)

result = mint.delegate(plan, "claude-sonnet-4-20250514", "read:public:report.txt")
if result.ok:
    pass  # proceed — result.receipt contains Ed25519-signed proof
```

---

## Quick start — Notary (receipts only)

```python
from agentmint.notary import Notary

notary = Notary(
    policy_id="elevenlabs-voice-policy-v2.3",
    policy_version="2.3",
    architecture_ref="arch-doc-2026Q1",
)

receipt = notary.notarize(
    action="tts:standard",
    api_provider="ElevenLabs",
    api_endpoint="/v1/text-to-speech/{voice_id}",
    agent_id="elevenlabs-demo-agent",
    in_policy=True,
    controls=["E015", "D003", "B001"],
    content="The synthesized text content",
    source_log="Provider response metadata",
)
```

---

## Run the demo

```bash
export ANTHROPIC_API_KEY=your-key
export ELEVENLABS_API_KEY=your-key
python examples/elevenlabs_demo.py
```

---

## Who this is for

- **Agent startups selling into enterprises.**  
Plug AgentMint in as a sidecar; ship AIUC‑1‑aligned receipts and a one‑command verifier with every proof‑of‑concept.
- **Enterprises deploying internal agents.**  
Use AIUC‑1 + IBM Risk Atlas to choose controls; use AgentMint to prove how your agents behaved between reviews.
- **Insurers and assessors.**  
Get tamper‑evident, replayable evidence instead of screenshots and spreadsheets.

---

## Status

MVP with end‑to‑end demos against ElevenLabs and Claude.  
Actively evolving the receipt schema and control mapping with AIUC‑1 / ISO 42001 / EU AI Act in mind.

If you’re deploying agents in regulated or high‑risk environments and quarterly evidence scrambles hurt, [open an issue](https://github.com/aniketh-maddipati/agentmint-python/issues) or reach out.

---

## License

MIT  

## Author

[Aniketh Maddipati](https://linkedin.com/in/anikethmaddipati)
```