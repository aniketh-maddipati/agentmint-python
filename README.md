# agentmint

Cryptographic notary for AI agent actions. Tamper-evident, AIUC-1-tagged evidence receipts — generated passively, verified independently.

## The problem

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

## Status

MVP. Four demo scenarios working end to end against ElevenLabs' public API.

Built for AIUC-1 certification evidence. If you're deploying agents in regulated industries and quarterly re-testing is painful, reach out.

## Contact

[linkedin.com/in/anikethmaddipati](https://linkedin.com/in/anikethmaddipati)