# AgentMint :: signed receipts for AI agent actions

**Small company, big-company trust.** A 5-file demo of cryptographic receipts
for AI agent actions in healthcare admin workflows — prior authorization,
eligibility verification, referral routing, voice-agent scheduling. Runs
offline in under 2 seconds. The customer holds the key, the vendor never
sees it. An auditor verifies offline with `openssl` alone.

---

## What the demo prints

```
Phase 1 :: Generate Ed25519 keypair
  ✓ Wrote keys/private.pem and keys/public.pem
  Customer holds the key, vendor never sees it.

Phase 2 :: Construct payload :: hash with SHA-256
  ✓ Action: prior_authorization_submission
  ✓ Subject ref (hashed, no PHI): 6a64cb593d3ba4c9...
  ✓ Payload SHA-256: 56d96345fff0d650...
  Receipt will reference this payload by SHA-256 only. No PHI on the wire.

Phase 3 :: Build receipt :: sign with Ed25519
  ✓ Wrote receipts/00001.json (canonical bytes)
  ✓ Wrote receipts/00001.json.sig (raw 64-byte Ed25519 signature)
  ✓ Wrote receipts/00001.json.payload (canonical payload bytes)

Phase 4 :: Verify offline with openssl
  $ openssl pkeyutl -verify -pubin -inkey keys/public.pem \
      -rawin -in receipts/00001.json -sigfile receipts/00001.json.sig
  ✓ Signature Verified Successfully
  ✓ Receipt verifies offline. No AgentMint binary required.
```

The receipt itself contains zero PHI — only hashes. Your hash and timestamp will differ when you run it; the structure is what matters:

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

---

## What this proves, on screen, in 3 seconds

Flip one byte of the payload, run `bash verify.sh`, watch verification fail.
Restore the byte, watch it pass. That is the "we'd notice" claim, made true.

---

## Run it (for your engineer)

```bash
pip install -r requirements.txt
python run_demo.py && bash verify.sh
```

Requires: Python 3.8+, openssl 3.0+, jq.

---

## What this is, said straight

- **The receipt** binds an agent action to a customer-held key at runtime.
  Tamper-evident, offline-verifiable, no vendor in the verification path.
- **The primitive** is workflow-agnostic. Same 5 files cover prior auth,
  eligibility checks, referral routing, voice-agent scheduling, EHR
  write-backs. Change the `action` string and the payload schema.
- **What it is not:** a complete audit-logging system, a SOC 2, a HITRUST
  cert. It's evidence that feeds those. Honest scope matters.

Maps to HIPAA Security Rule and HITRUST CSF v11 controls — see
[controls.md](controls.md).

## Repo

[github.com/aniketh-maddipati/agentmint-python](https://github.com/aniketh-maddipati/agentmint-python)
