# AgentMint :: signed receipts for AI agent actions

When an agent submits a prior auth, routes a referral, or verifies
eligibility, someone may need to prove what it did — weeks or months
later, when a denial, audit, or dispute lands. Today that answer is
usually "let me check our logs and get back to you." Those logs come
from the vendor running the agent.

This demo shows the alternative: a 5-file primitive that produces
Ed25519-signed, offline-verifiable receipts for agent actions in
healthcare admin workflows. The clinic holds the key. The vendor
never sees it. An auditor verifies with `openssl` alone.

## The demo

```bash
pip install -r requirements.txt
python run_demo.py && bash verify.sh
```

Requires Python 3.8+, openssl 3.0+, jq.
Phase 1 :: Generate Ed25519 keypair
✓ Wrote keys/private.pem and keys/public.pem
Customer holds the key, vendor never sees it.
Phase 2 :: Construct payload :: hash with SHA-256
✓ Action: prior_authorization_submission
✓ Subject ref (hashed, no PHI): 6a64cb593d3ba4c9...
✓ Payload SHA-256: 56d96345fff0d650...
Phase 3 :: Build receipt :: sign with Ed25519
✓ Wrote receipts/00001.json (canonical bytes)
✓ Wrote receipts/00001.json.sig (raw 64-byte Ed25519 signature)
✓ Wrote receipts/00001.json.payload (canonical payload bytes)
Phase 4 :: Verify offline with openssl
$ openssl pkeyutl -verify -pubin -inkey keys/public.pem -rawin -in receipts/00001.json -sigfile receipts/00001.json.sig
✓ Signature Verified Successfully
✓ Receipt verifies offline. No AgentMint binary required.

Flip one byte of the payload, run `bash verify.sh`, watch verification fail.
Restore the byte, watch it pass. That's the "we'd notice" claim, made true.

## What the receipt contains

Zero PHI. Hashes only. Same structure for every workflow.

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

The receipt binds the action to a customer-held key. The primitive is
workflow-agnostic — change the action string and payload schema for
any healthcare admin workflow. It is not a SOC 2, HITRUST cert, or
audit-logging system. It's the evidence layer those products don't
produce on their own. Maps to HIPAA Security Rule and HITRUST CSF v11
— see [controls.md](controls.md).

## How the key works

- Customer generates the keypair, holds the private key on their infrastructure
- Agent signs by calling the customer's signing endpoint — never holds the key bytes
- Plugs into AWS KMS, GCP KMS, or HashiCorp Vault for HSM-backed production
- *GTM:* lets you say "customer holds the key" with a straight face in a security review
- *Security:* private key never crosses a vendor boundary; same trust model as Mastercard's agent receipt spec

## How verification works

- Auditor receives a tarball: receipts, public key, `verify.sh`
- Three checks run with openssl + jq alone: signature, payload hash, chain link
- Pass/fail is binary, deterministic, reproducible offline
- *GTM:* compresses the agent portion of an audit from days to minutes
- *Security:* no vendor binary, no network call, no shared secret; works air-gapped

## Where this applies

The demo uses prior authorization. Same primitive covers:

1. **Prior authorization submission** *(shown)*
2. **Claims submission and denial appeals**
3. **Eligibility verification and benefit checks**
4. **Patient intake and referral routing**

Voice scheduling, ambient documentation, and back-office coding extend
the same primitive at lower stakes.

## What changes for the people downstream

When something goes wrong — a denial, an audit, a patient question —
the clinic answers it themselves. They don't take your word; you don't
have to defend it. The receipt does both jobs.

- *GTM:* turns "let me check our logs and get back to you" into "here's the file, run one bash command"
- *Security:* the clinic owns the evidence, not the vendor — the audit chain stops at the customer

## Repo

[github.com/aniketh-maddipati/agentmint-python](https://github.com/aniketh-maddipati/agentmint-python)
