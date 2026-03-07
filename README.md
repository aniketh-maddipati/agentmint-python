# AgentMint

**Open-source cryptographic notary for AI agent actions.**

No standard evidence format exists for AIUC-1 audits. Every certified company builds custom. AgentMint generates it automatically.

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
Receipts verified: 80/80 · Violations flagged: 12 · All signatures valid
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

## Who this is for

**Agent startups shipping to enterprises** — Drop in a sidecar. Hand the auditor a zip.

**Insurers underwriting AI risk** — Tamper-evident receipts. The forensic trail exists before the incident.

**AIUC-1 ecosystem** — One evidence format. One verification command. Auditors know what to expect.

---

## Status

Pre-revenue. Open source. Validating with AIUC-1 auditors and certified companies.

If you've been through AIUC-1 or are preparing — what did your evidence prep look like? [Open an issue](https://github.com/aniketh-maddipati/agentmint-python/issues) or DM me.

---

## License

MIT

## Author

[Aniketh Maddipati](https://linkedin.com/in/anikethmaddipati)
