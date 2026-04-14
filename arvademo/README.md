# AgentMint x Arva AI -- AML Screening Agent Evidence Demo

An AML screening agent processes 1,000 alerts. 500 stay in scope. 500 attempt to access FinCEN 314(b), auto-close alerts, read SWIFT messages, and access other customers' profiles. Every tool call produces an Ed25519 signed, SHA-256 hash-chained receipt. A Merkle tree commits to all receipts -- any single receipt verifiable in O(log n). Independently verifiable with a shell script.

## The regulatory problem

- **OFAC:** Agent clears a sanctioned entity because injected web content influenced its decision -> $368,136+ per violation.
- **BSA/AML:** Agent closes a screening alert without human review -> FinCEN enforcement action.
- **FinCEN 314(b):** Agent reads shared suspicious activity data outside authorized scope -> criminal referral risk.

## Run

```bash
cd agentmint-python-main
pip install -e .
python3 arvademo/run_demo.py
```

No API keys. No network calls. ~60 seconds. ~12,000 signed receipts.

## Verify

```bash
python3 arvademo/scripts/verify_evidence.py
```

Requires only openssl. No AgentMint installed. No vendor account. The math is the proof.

## AgentMint

Open-source runtime enforcement for AI agents. Ed25519 signed, SHA-256 hash-chained, RFC 3161 timestamped receipts. 0.3ms, zero network calls. MIT licensed. OWASP listed.

[github.com/aniketh-maddipati/agentmint-python](https://github.com/aniketh-maddipati/agentmint-python)
