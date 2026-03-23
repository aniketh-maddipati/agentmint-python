# AgentMint — Architectural Limits

What AgentMint does not do, by design. These are not bugs — they are boundaries
documented so you can evaluate them honestly.

---

## 1. Agent identity is asserted, not cryptographically proven

The `agent` string in a receipt is provided by integration code, not bound to a
cryptographic identity. Any code that can call `notary.notarise()` can claim to
be any agent.

**Mitigated:** `notarise(agent_key=signing_key)` accepts an optional agent
signing key. The agent co-signs the evidence hash, and the receipt carries
`agent_signature` and `agent_key_id`. Two signatures per receipt: Notary
attests the evaluation, Agent attests the action. Binding the key to a
specific process still requires runtime attestation (TEEs, SPIFFE/SPIRE).

**What you say to an auditor:** "Agent identity is declared. The plan's
`delegates_to` field restricts which declared identities are accepted, but the
declaration itself is not attested. This is documented."

---

## 2. AgentMint cannot prevent actions

AgentMint is a notary, not a firewall. It returns verdicts (`in_policy: true/false`).
It does not intercept or block API calls. The agent framework must act on the verdict.

**By design.** Enforcement belongs in the framework. AgentMint proves the evaluation
happened. If the framework ignores the verdict, the receipt still records it.

---

## 3. Scope patterns are string-based, not semantic

`read:reports:*` is a string pattern match. AgentMint has no understanding of what
"reports" means, what a "read" does, or whether the action is actually dangerous.

**Security depends on the quality of the action→string mapping.** If the mapping
is wrong, the policy is wrong.

---

## 4. No tamper prevention on evidence storage

Receipts detect tampering (signature fails, chain breaks). They do not prevent
deletion. If someone deletes all receipts, the absence is not self-evident unless
the chain root hash was published externally.

**Mitigation:** S3 object lock, append-only storage, or publishing the chain
root hash to an external transparency log. These are deployment decisions.

---

## 5. FreeTSA has no SLA

The default timestamp authority (freetsa.org) is free and has no uptime guarantee.
Production deployments should use a commercial TSA (DigiCert, GlobalSign).

**Mitigated:** The `tsa_urls` parameter on `Notary()` accepts a list of TSA URLs
with automatic fallback. If the first TSA fails, the next is tried. The limit
remains that FreeTSA is the *default*. Production deployments should configure
a paid TSA with an SLA (DigiCert, GlobalSign, Sectigo).

---

## 6. Limited behavioral analysis

AgentMint now includes per-agent rate limiting (circuit breaker) and per-session
action counting, but does not perform statistical anomaly detection or ML-based
pattern recognition.

**Mitigated:** `CircuitBreaker(max_calls=100, window_seconds=60)` enforces a
sliding-window rate limit per agent with three states (closed, half-open, open).
Session policy thresholds (`escalate_after`, `deny_after`) flag or block agents
that exceed per-pattern action counts within a session.

**Remaining limit:** Rate limits are count-based, not behavioral. True
anomaly detection (statistical baselines, drift scoring) is future work.
---

## 7. No key revocation

If the Ed25519 private key is compromised, all receipts signed with that key are
suspect. There is no revocation mechanism in the SDK itself.

**Mitigated:** Every receipt and plan now carries a `key_id` (first 8 bytes of
SHA-256 of the public key, hex). Verifiers can match receipts to keys and check
against external revocation lists. The hook exists; the distribution mechanism
(CRL, OCSP, transparency log) is managed service scope.

**Mitigation:** Short-lived keys, key rotation at plan boundaries, and the
RFC 3161 timestamps provide a temporal anchor — receipts timestamped before
compromise are still valid.

---

## 8. Single-process chain state

Chain state (`_chain_hashes`) lives in memory on a single `Notary` instance.
No distributed state.

**Mitigated:** When using persistent keys (`Notary(key=path)`), chain state is
saved to `chain_state.json` alongside the key (atomic write, 0o600 permissions).
On restart, the chain resumes. The limit remains for distributed/multi-process
deployments — that requires WAL and consensus.

**Managed service would add:** Persistent chain state with WAL, distributed
consensus for multi-node deployments.

---

## 9. Deterministic content scanning, not full DLP

The Shield module scans tool inputs and outputs for known PII, secrets, prompt
injection, encoding evasion, and structural attacks using 23 compiled regex
patterns, fuzzy typo matching, and Shannon entropy detection.

**Mitigated:** `scan(data)` returns threats with category, severity, and
field path. Scans both inbound (tool arguments) and outbound (tool results).

**Remaining limits:** Pattern-based only. No ML classifier, no LLM-in-the-loop.
Shield does not block actions itself — the caller must act on `result.blocked`.

**Shield is Layer 1.** Semantic analysis is future work.
---

## 10. Plan expiry at check time only

A plan's TTL is checked when `notarise()` is called. There is a gap between
the scope check and actual execution. This is inherent in every auth/exec
separation system (OAuth tokens have the same property).
