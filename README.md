# AgentMint

**Open-source cryptographic notary for AI agent actions.**

No standard evidence format exists for AIUC-1 audits. Every certified company builds custom. AgentMint generates it automatically.

Cryptographic notary for AI agent actions. Tamper-evident, AIUC-1-tagged evidence receipts — generated passively, verified independently.

Passive notary — never in the call path. Ed25519 signed. RFC 3161 timestamped. Verifiable with OpenSSL alone. Receipts stay with the customer. AgentMint holds nothing.

**[GitHub](https://github.com/aniketh-maddipati/agentmint-python)** | **[One-Pager](https://agentmint-brief-builder.lovable.app/)**

---

## What it does

Agent calls the API normally. After it returns, AgentMint reads the response, evaluates policy, signs a receipt, and timestamps it via an independent authority. ~400ms. Zero changes to the call path.

Three anchors per receipt:
- **Ed25519 signature** — any modification breaks it instantly
- **RFC 3161 timestamp** — independent authority, backdating impossible
- **Commitment hashes** — receipts contain hashes, not content. Nothing sensitive leaves

---

## Architecture

AgentMint has two layers that coexist:

**Gatekeeper (`core.py`)** — Authorization *before* the action. Scoped delegation, checkpoints, replay protection. "Should this agent be allowed to do this?"

**Notary (`notary.py`)** — Evidence *after* the action. Passive receipt generation, policy evaluation, cryptographic signing, RFC 3161 timestamping. "Prove this agent did this, and prove the receipt hasn't been tampered with."
```
agentmint/
├── core.py            # Gatekeeper: scoped delegation, checkpoints, replay protection
├── notary.py          # Notary: passive receipt generation, policy evaluation
├── anchor.py          # RFC 3161 timestamping (FreeTSA + DigiCert fallback)
├── commitment.py      # SHA-256 commitment scheme (hash-only receipts)
├── batch.py           # Batch mode: scenario loading, execution, aggregation
├── export.py          # Evidence ZIP packaging
├── keystore.py        # Ed25519 key persistence (generate once, load thereafter)
├── receipt_store.py   # JSONL append-only receipt persistence
├── types.py           # Data types and enums
├── errors.py          # Exception hierarchy
├── console.py         # Terminal output formatting
└── decorator.py       # @require_receipt decorator
```

---

## Demo — real APIs, no mocks
```
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

![ElevenLabs Demo](elevenlabs.gif)

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

## AIUC-1 Control Mapping

| Receipt Field | Control | What It Proves |
|---|---|---|
| action + in_policy | E015 Action Logging | Every agent action logged with policy result |
| violation_type | D004 Tool Call Testing | Unauthorized actions detected and recorded |
| signature_ed25519 | B001 Adversarial Robustness | Evidence is tamper-evident and independently verifiable |
| content_hash | D003 Restrict Unsafe Tool Calls | Tool call content committed without exposing it |
| source_log_hash | B006 System Security | Cross-reference with provider logs detects manipulation |
| tsr_token_ref | E010 Acceptable Use Policy | Independent timestamp proves evidence existed before dispute |
| policy_id + version | E007 Change Management | Links each action to the specific policy version |
| architecture_ref | E005 Cloud vs On-Prem | Links runtime evidence to architecture documentation |
| agent_id | B005/B007 IAM/Access Control | Which agent acted, traceable to authorization chain |
| aiuc1_controls | All | Machine-readable mapping enables automated compliance reporting |

---

## Evidence package

AI agent certifications like AIUC-1 require quarterly re-testing. Every 90 days, someone rebuilds an evidence package from scratch — manually reconstructing what the agent did, which controls fired, which actions were in-policy. It's expensive, slow, and entirely dependent on trusting whoever wrote the report.

There's no continuous, cryptographically verifiable audit trail. Until now.

## What agentmint does

AgentMint sits passively alongside existing agent infrastructure. It never wraps API calls, never blocks actions, never creates an availability dependency. It observes what happened and signs evidence after the fact.

```
Agent calls ElevenLabs API normally
         ↓
API response returns
         ↓
AgentMint reads response → evaluates policy → builds receipt
         ↓
Ed25519 signature  +  RFC 3161 timestamp (FreeTSA)  +  SHA-256 commitment hashes
         ↓
Anchored receipt written to local evidence package
```

Every receipt is independently verifiable with a single OpenSSL command. No AgentMint infrastructure required. Receipts remain valid forever.

## Tamper-evidence: three independent anchors

**Anchor 1 — Ed25519 signature**
AgentMint signs every receipt at generation with a private key that never leaves the customer machine. Any modification to any field breaks the signature immediately.

**Anchor 2 — RFC 3161 timestamp**
The SHA-512 hash of the signed receipt goes to FreeTSA — an independent third party neither AgentMint nor the customer controls. The returned token cryptographically proves that exact receipt existed at that exact moment. Backdating is impossible.

**Anchor 3 — Commitment scheme**
Receipts contain SHA-256 hashes of evidence components, not raw content. No sensitive data leaves the customer environment. Anyone with the original evidence can verify the receipt is consistent with what happened.

## Verify receipts

```bash
./VERIFY.sh
```

One command. Pure OpenSSL against FreeTSA's public CA cert. No Python. No trust in AgentMint.

```
Receipts verified: 4
Out-of-policy actions flagged: 2
Verification timestamp: 2026-03-05T14:32:01Z
```
agentmint_evidence_20260307/
├── receipt_index.json       # Aggregate summary — auditor reads first
├── receipts/
│   ├── receipt_001.json     # Individual signed receipt
│   ├── receipt_001.tsr      # RFC 3161 timestamp token
│   └── ...
├── keys/
│   └── public_key.pem       # Ed25519 public key
├── certs/
│   └── freetsa_cacert.pem   # TSA CA certificate (bundled)
├── VERIFY.sh                # One-command verification — pure OpenSSL
├── TAMPER_TEST.sh           # Automated tamper demonstration
└── control_mapping.pdf      # AIUC-1 control mapping
```

---

## Verify it yourself
```bash
unzip agentmint_evidence_20260307.zip
bash VERIFY.sh
# Receipts verified: 80/80 · Flagged: 12 · No AgentMint code needed
```

Pure OpenSSL. No Python. No trust in the founder.

---

## Demo scenarios

| Scenario | What happens | Receipt outcome |
|---|---|---|
| Normal TTS call | Real ElevenLabs TTS call | `in_policy: true` |
| Voice clone attempt | ElevenLabs returns 403 | `in_policy: false` — violation recorded |
| Claude reads clean doc | Normal TTS tool call | `in_policy: true` |
| Claude reads injected doc | Prompt injection → clone attempt | `in_policy: false, violation_type: prompt_injection` |

## AIUC-1 control mapping

Every receipt tags three controls automatically from publicly available API output:

| Receipt field | AIUC-1 control | How it evidences the control |
|---|---|---|
| `action_type` | E015 | Records the category of agent action taken |
| `in_policy` | B001 | Boolean outcome of policy evaluation at action time |
| `source_log_hash` | D003 | Commits to ElevenLabs server-side log at notarisation moment |

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

## Quick start — Gatekeeper
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
    pass  # proceed — result.receipt contains Ed25519 signed proof
```

---

## Quick start — Notary
```python
from agentmint.notary import Notary

notary = Notary(
    policy_id="elevenlabs-voice-policy-v2.3",
    policy_version="2.3",
    architecture_ref="arch-doc-2026Q1",
)

# After your agent calls an API, notarize the action
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

## Architecture

AgentMint is a notary, not a gatekeeper.

| Model | How it works | Why it matters |
|---|---|---|
| Gatekeeper (rejected) | Sits between agent and API. Every call requires authorization. | AgentMint going down takes your product down. Unacceptable. |
| Notary (correct) | Reads the response after the fact. Issues signed receipt. Never in the call path. | No availability dependency. Receipts stay with you. No data leaves your environment. |

## Key design decisions

**Receipts stay with the customer.** AgentMint holds nothing. The only outbound call is a SHA-512 hash to FreeTSA.

**No sensitive content in receipts.** Commitment hashes only. Receipts can be shared freely with auditors and insurers without exposing implementation details.

**Verification requires no AgentMint infrastructure.** The Ed25519 public key is 32 bytes. The FreeTSA CA cert is public. If AgentMint ceases to exist tomorrow, every receipt ever generated remains independently verifiable forever.

**Platform agnostic.** The receipt schema has no ElevenLabs-specific fields. Adding a new platform is a new ingestion adapter — days, not months.

---

## Who this is for

**Agent startups shipping to enterprises** — Drop in a sidecar. Hand the auditor a zip.

**Insurers underwriting AI risk** — Tamper-evident receipts. The forensic trail exists before the incident.

**AIUC-1 ecosystem** — One evidence format. One verification command. Auditors know what to expect.

---

## Status

MVP. Four demo scenarios working end to end against ElevenLabs' public API.

Built for AIUC-1 certification evidence. If you're deploying agents in regulated industries and quarterly re-testing is painful, [open an issue](https://github.com/aniketh-maddipati/agentmint-python/issues) or reach out.

---

## License

MIT

## Author

[Aniketh Maddipati](https://linkedin.com/in/anikethmaddipati)
