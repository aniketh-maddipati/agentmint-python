# AgentMint × Traversal AI — SRE Incident Response Demo

## What this demo shows

AgentMint sitting at the agent→tool boundary for a Traversal-style AI SRE agent handling a P1 incident at a Fortune 100 bank. It produces per-action cryptographic receipts — one in-policy rollback with checkpoint approval and one blocked PII violation — both tamper-evident and independently verifiable.

## How to run it

```bash
cd agentmint-python
pip install -e .
python examples/traversal_sre_demo.py
```

## What an enterprise audit team gets from this

- Which agent identity, under which policy version, took which action and when — bound cryptographically so it cannot be altered after the fact
- A tamper-evident record of every blocked violation during the incident — proof the agent was constrained, not just that it succeeded
- A self-contained evidence bundle verifiable with OpenSSL alone, no vendor portal or third-party trust required

## Why this matters for Traversal customers

When Traversal agents execute rollbacks inside Fortune 100 infrastructure, their enterprise customers' audit and compliance teams will eventually ask for per-action evidence that goes beyond platform logs. AgentMint produces that evidence as a sidecar — independently verifiable, not tied to Traversal's platform or any other vendor.