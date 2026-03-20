# AgentMint — Improvements

All improvements specified in the architecture review, implemented and tested.

---

## 4.1 — Notary Uses KeyStore (Key Persistence)

**File:** `agentmint/notary.py`

The `Notary` constructor now accepts an optional `key` parameter:

```python
# Ephemeral (default — demos, quickstart)
notary = Notary()

# Persistent (production — loads or generates key on disk)
notary = Notary(key=".agentmint")
notary = Notary(key=Path("/etc/agentmint/keys"))
```

When a path is provided, the `KeyStore` class handles generation on first run
and loading on subsequent runs. Private key permissions are set to `0o600`.

**Backward compatible:** `Notary()` with no args still works (ephemeral key).

---

## 4.2 — Per-Plan Chain Isolation

**File:** `agentmint/notary.py`

Replaced the single `_last_receipt_hash` with `_chain_hashes: dict[str, Optional[str]]`
keyed by `plan_id`.

```python
# Before (bug): interleaving plans crossed chains
# After: each plan maintains its own independent chain
ra1 = notary.notarise(action="a:1", plan=plan_a, ...)  # chain A, first
rb1 = notary.notarise(action="b:1", plan=plan_b, ...)  # chain B, first
ra2 = notary.notarise(action="a:2", plan=plan_a, ...)  # chain A, links to ra1
rb2 = notary.notarise(action="b:2", plan=plan_b, ...)  # chain B, links to rb1
```

`create_plan()` initializes the chain for that plan ID instead of resetting
a global variable.

---

## 4.3 — Unified Pattern Matcher

**File:** `agentmint/patterns.py` (new)

Extracted a single `matches_pattern()` function used by both `core.py` and
`notary.py`. This fixes bug 3.2 (pattern matcher divergence).

```python
from agentmint.patterns import matches_pattern, in_scope

matches_pattern("read:reports:q4", "read:reports:*")  # True
matches_pattern("tts:standardabc", "tts:standard*")   # False (bare * not supported)
```

**Rule:** Only `:*` suffix is supported. Bare `*` suffix (`tts:standard*`) is
rejected. This enforces the colon hierarchy and prevents accidental over-matching.

---

## 4.4 — Plan Signature in Receipt

**File:** `agentmint/notary.py`

`NotarisedReceipt` now includes a `plan_signature` field containing the Ed25519
signature of the plan that authorized the action.

This creates a cryptographic chain: **Human → Plan (signed) → Receipt (signed,
includes plan signature)**. A verifier can check the full authorization chain
from the receipt alone.

The plan signature is included in the receipt's `signable_dict()` and is covered
by the receipt's own signature.

---

## 4.5 — Fallback TSA Configuration

**File:** `agentmint/notary.py`

`Notary` and `EvidencePackage` accept a `tsa_urls` parameter:

```python
notary = Notary(tsa_urls=[
    "https://freetsa.org/tsr",
    "http://timestamp.digicert.com",
])
```

If the first TSA fails, the next is tried. Default remains FreeTSA only.

**TSA options for production:**
- FreeTSA (free, no SLA) — `https://freetsa.org/tsr`
- DigiCert (commercial) — `http://timestamp.digicert.com`
- GlobalSign (commercial, eIDAS qualified)
- DFN (German research network) — `https://zeitstempel.dfn.de`

---

## 4.6 — verify_chain() API

**File:** `agentmint/notary.py`

New public function for verifying receipt chain integrity:

```python
from agentmint.notary import verify_chain

result = verify_chain([receipt_1, receipt_2, receipt_3])
print(result.valid)       # True
print(result.length)      # 3
print(result.root_hash)   # SHA-256 hex — summarizes the entire chain
```

Checks:
1. First receipt has `previous_receipt_hash == None`
2. Each subsequent receipt's hash matches SHA-256 of the previous receipt's signed payload
3. Returns `root_hash` — a single value summarizing the entire chain

If the chain is broken, `break_at_index` and `reason` explain where and why.

---

## 4.7 — Chain Root Hash + Signature + Timestamp at Export

**File:** `agentmint/notary.py` (in `EvidencePackage._write_index`)

At export time, the evidence package now includes chain verification in
`receipt_index.json`:

```json
{
  "chain": {
    "valid": true,
    "length": 4,
    "root_hash": "a1b2c3...",
    "root_signature": "d4e5f6...",
    "root_timestamp": {
      "tsa_url": "https://freetsa.org/tsr",
      "tsq_file": "chain_root.tsq",
      "tsr_file": "chain_root.tsr"
    }
  }
}
```

This creates a four-layer verification model:

| Layer | What | How |
|-------|------|-----|
| 1 | Individual receipt signatures | Ed25519 |
| 2 | Individual receipt timestamps | RFC 3161 |
| 3 | Chain integrity | SHA-256 linked hashes |
| 4 | Chain root commitment | Signed + timestamped root hash |

Any tampering is caught by at least one layer.

---

## 4.8 — Key ID for Revocation Support

**File:** `agentmint/notary.py`

Every receipt and plan now carries a `key_id`: the first 8 bytes of
SHA-256(public_key), hex-encoded (16 characters). Computed once at
`Notary.__init__`, stored in `__slots__`, passed to every receipt and plan.
```python
notary = Notary(key=".agentmint")
print(notary.key_id)  # e.g. "a3f1c9e802b7d4f6"
```

Present in `signable_dict()` (covered by the signature), in receipt JSON,
in plan JSON, and in `receipt_index.json`. Verifiers can match receipts to
keys and check against external revocation lists.

The hook exists. The revocation distribution mechanism (CRL, OCSP,
transparency log) is managed service scope.

---

## 4.9 — Chain State Persistence

**File:** `agentmint/notary.py`

When using persistent keys (`Notary(key=path)`), chain hashes are saved to
`chain_state.json` alongside the signing key. Atomic write (temp file +
`os.replace`), permissions `0o600`.

On restart, the Notary loads existing chain state and resumes where it left
off. Ephemeral mode (`Notary()`) never touches disk.
```python
# First run
notary = Notary(key=".agentmint")
plan = notary.create_plan(...)
notary.notarise(...)  # chain_state.json written

# Process crashes, restarts
notary = Notary(key=".agentmint")  # chain state loaded
notary.notarise(action=..., plan=plan, ...)  # chain continues
```

---

## 4.10 — Agent Co-Signature

**File:** `agentmint/notary.py`

`notarise()` accepts an optional `agent_key: SigningKey`. If provided, the
agent co-signs the evidence hash, and the receipt carries `agent_signature`
and `agent_key_id`.
```python
from nacl.signing import SigningKey
agent_sk = SigningKey.generate()

receipt = notary.notarise(
    action="tts:standard:abc", agent="voice-agent", plan=plan,
    evidence={"voice_id": "abc"}, agent_key=agent_sk,
)

print(receipt.agent_signature)  # 128-char hex — agent's Ed25519 sig
print(receipt.agent_key_id)     # 16-char hex — same derivation as key_id
```

Two signatures per receipt: Notary attests the evaluation happened, Agent
attests "I performed this action." The `agent_key_id` is stable across
receipts — auditors can track agent identity continuity across a chain.

Binding the key to a specific process requires runtime attestation
(SPIFFE/SPIRE, TEEs) — that's infrastructure, not SDK.

---

## 4.11 — Single Source of Truth Refactor

**File:** `agentmint/notary.py`

Both `create_plan()` and `notarise()` now use the dataclass's own
`signable_dict()` as the single source of truth for signing. The old
pattern built an inline dict, then built the dataclass separately —
two representations of the same data that could diverge when fields
were added.

New pattern:
1. Construct the dataclass with `signature=""`
2. Call `object.signable_dict()` — one definition, one place
3. Sign that
4. `dataclasses.replace(object, signature=sig)` — frozen, so reconstruct

Adding a new field now requires changing only the dataclass. No more
parallel dicts to keep in sync.

---

## Summary

| # | Improvement | Lines | Status |
|---|------------|-------|--------|
| 4.1 | Notary uses KeyStore | ~20 | Done |
| 4.2 | Per-plan chain isolation | ~15 | Done |
| 4.3 | Unified pattern matcher | ~40 | Done |
| 4.4 | Plan signature in receipt | ~10 | Done |
| 4.5 | Fallback TSA | ~30 | Done |
| 4.6 | verify_chain() API | ~40 | Done |
| 4.7 | Chain root at export | ~25 | Done |
| 4.8 | Key ID for revocation | ~20 | Done |
| 4.9 | Chain state persistence | ~35 | Done |
| 4.10 | Agent co-signature | ~15 | Done |
| 4.11 | Single source of truth refactor | ~20 | Done |

**111 tests passing.** Test count went from 76 → 111.
