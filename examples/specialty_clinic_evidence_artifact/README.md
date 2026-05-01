# AgentMint :: signed receipts for AI agent actions

**Small teams should have big-company trust. Period.**

**Goal:** Get the first agent deal closed faster, with trust that compounds across every deal after.

A working primitive for cryptographic evidence of what your AI agent did. Customer holds the key. Vendor never sees it. Anyone can verify offline. 
Healthcare admin actions as an example but the primitive works for any agent action.

---

## The receipt

`sample_output/receipts/00001.json`:

```json
{
    "action": "prior_authorization_submission",
    "agent_id": "specialty-clinic-pa-agent-v1",
    "payload_sha256": "0bdc4757049c12b102789da4432e035ffdbd626b3df4d873b93a75c78e3ce20f",
    "previous_receipt_hash": "GENESIS",
    "public_key_id": "agentmint_demo_pub_v1",
    "receipt_id": "00001",
    "signature_alg": "ed25519",
    "subject_ref": "6a64cb593d3ba4c9f11d94d1c278ec5d2f7868fb939097f80c6be5d3f7607c46",
    "timestamp": "2026-05-01T19:07:43.317124+00:00",
    "version": "1.0"
}
```

Zero PHI — hashes only. Signed with Ed25519. Chain-linked via `previous_receipt_hash`.

---

## Try it

## Download and run

```bash
curl -LO https://github.com/aniketh-maddipati/agentmint-python/raw/main/examples/specialty_clinic_evidence_artifact/agentmint-evidence-demo.tar.gz
tar -xzf agentmint-evidence-demo.tar.gz
cd agentmint-evidence-demo
./agentmint verify
```

That's it. Three commands, no Python, no install. Verifies a real signed receipt against a real public key in about 2 seconds.

Then optionally:

```bash
./agentmint tamper    # flip a byte, watch verify fail, restore, watch it pass
./agentmint demo      # generate a fresh receipt (requires Python 3.8+)
./agentmint all       # all three in sequence
```

---

## Things you'd like to know

- **Install:** two pure-Python deps (`cryptography`, `rich`). No system packages, no Docker.
- **Crypto:** Ed25519, SHA-256, canonical JSON. Standard primitives via Python's `cryptography` library — same one Django and AWS CLI use.
- **Surface area:** 225 lines for the demo, 60 for the verifier. Audit-readable in an afternoon. Production library: 184 tests, MIT.
- **Scaling:** one receipt or a billion, same primitive. Append-only JSON, your existing S3 + lifecycle policy handles storage.
- **Verification cost:** O(1) per receipt for signature + hash. Chain validation is O(n), trivially parallel.
- **Vendor dependency at verify-time:** zero.

---

## Workflows Covered

1. Prior authorization submission *(shown)*
2. Claims submission and denial appeals
3. Eligibility verification and benefit checks
4. Patient intake and referral routing

Same primitive, different `action` strings and payload schemas.

---

## Why

no-BS evidence report your agent produces for the clinic - that the clinic hands to a payer, a hospital network, an auditor, or an insurnance carrier without you in the loop. Independently verfiable, no need to compensate with compliance infrastructure. Extend the spec up and down the stack and control map and let the agent to the work.

Not a SOC 2 platform, not a HITRUST cert, not a replacement for Vanta or Drata. Plugs in alongside them — the agent-action evidence layer those products don't produce on their own.

---

## What's in this folder

- `sample_output/` — pre-generated receipt + key, verifiable without running anything
- `run_demo.py` — generate a fresh receipt
- `verify.sh` — the offline verifier
- `controls.md` — HIPAA + HITRUST CSF v11 mappings
- `requirements.txt` — two dependencies

---

## Repo

[github.com/aniketh-maddipati/agentmint-python](https://github.com/aniketh-maddipati/agentmint-python)

Threat modeled with [Bil Harmer](https://www.linkedin.com/in/bilharmer/). Primitive listed in [OWASP Agentic AI Security Top 10](https://genai.owasp.org/) led by [Ken Huang](https://www.linkedin.com/in/kenhuang8/). [Prescient Assurance](https://prescientassurance.com) (AIUC-1 audit firm) is evaluating the primitive in their healthcare AI cohort.
