# agentmint

Runtime enforcement for AI agent tool calls. Scoped delegation, content scanning, rate limiting, and cryptographic audit trail — as a library.

Works with MCP, CrewAI, OpenAI Agents SDK, or any Python agent framework. Runs locally in Cursor, Claude Code, and dev environments. No SaaS. No gateway.

## The problem

MCP gives agents access to Gmail, Slack, databases. CrewAI chains agents autonomously. Permissions today are all-or-nothing.

Give an agent file access → it reads everything. Give it email access → it sends as you. One prompt injection → full access.

AgentMint enforces what actions are allowed, scans content for threats, rate-limits agents, and produces a cryptographic audit trail — all before the action executes.

## How it works

```
Human approves plan
        ↓
   ┌─────────────────────────────────────────────┐
   │              AgentMint Runtime               │
   │                                              │
   │  Circuit Breaker → Shield → Scope Check →    │
   │  Checkpoint Gate → Notary (sign + chain)  →  │
   │  File Sink (JSONL log)                       │
   └─────────────────────────────────────────────┘
        ↓                           ↓
   Action executes           Receipt (Ed25519)
   (or blocks)               + hash chain
                             + RFC 3161 timestamp
```

1. **Circuit breaker** checks per-agent rate limits. If the agent is over threshold, the call never reaches policy evaluation.
2. **Shield** scans tool inputs (and outputs) for PII, secrets, prompt injection, encoding evasion, and structural attacks. 23 compiled patterns + fuzzy matching + entropy detection.
3. **Scope check** verifies the action matches the human-approved plan. Glob-style patterns: `read:reports:*` allows `read:reports:quarterly`.
4. **Checkpoint gate** blocks actions matching sensitive patterns until explicitly approved.
5. **Notary** signs the receipt with Ed25519, links it to the hash chain, and optionally timestamps via RFC 3161.
6. **File sink** appends a JSONL line with SIEM-compatible fields for every notarised action.

## Quick start

```python
from agentmint import AgentMint
from agentmint.shield import scan
from agentmint.circuit_breaker import CircuitBreaker
from agentmint.sinks import FileSink

# 1. Scan tool input before execution
result = scan(tool_input)
if result.blocked:
    raise RuntimeError(f"Blocked: {result.summary()}")

# 2. Enforce delegation
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
    # result.receipt contains Ed25519 signed proof
    pass

# 3. Rate limiting
breaker = CircuitBreaker(max_calls=100, window_seconds=60)
check = breaker.check("claude-sonnet-4-20250514")
if not check.is_allowed:
    raise RuntimeError(check.reason)

# 4. Audit log
sink = FileSink("audit.jsonl")
# sink.emit(receipt) after each notarised action
```

## Architecture

```
agentmint/
├── core.py              # AgentMint class — delegation, checkpoints, replay protection
├── notary.py            # Notary — signing, timestamping, chain linking, evidence packaging
├── shield.py            # Content scanning — PII, secrets, injection, encoding, structural
├── circuit_breaker.py   # Per-agent sliding window rate limiter (closed/half-open/open)
├── sinks.py             # JSONL file sink with SIEM-compatible fields
├── timestamp.py         # RFC 3161 timestamping via FreeTSA
├── keystore.py          # Ed25519 key persistence and PEM export
├── patterns.py          # Glob pattern matching for scope enforcement
├── types.py             # DelegationStatus, DelegationResult
├── errors.py            # Exception hierarchy
├── console.py           # Terminal output formatting
└── decorator.py         # @require_receipt decorator
```

## Modules

### Shield — content scanning

Deterministic regex-based scanner for tool inputs and outputs. No LLM in the loop.

- **23 compiled patterns** across 5 categories: PII, secrets, injection, encoding, structural
- **Fuzzy matching** for typo variants of injection keywords (OWASP typoglycemia)
- **Shannon entropy detection** with base64 decode validation (eliminates false positives on UUIDs)
- Scans both **inbound** (tool inputs) and **outbound** (tool outputs)

```python
from agentmint.shield import scan

result = scan({"msg": "My SSN is 123-45-6789", "key": "AKIAIOSFODNN7EXAMPLE"})
result.blocked       # True (AWS key triggers block severity)
result.threat_count  # 2
result.categories    # ("pii", "secret")
```

### Circuit breaker — rate limiting

Per-agent sliding window with three states:

| State | Condition | Effect |
|---|---|---|
| closed | < 80% of max_calls | All calls proceed |
| half_open | >= 80% of max_calls | Calls proceed with warning |
| open | >= 100% of max_calls | All calls blocked |

```python
from agentmint.circuit_breaker import CircuitBreaker

breaker = CircuitBreaker(max_calls=100, window_seconds=60)
result = breaker.check("my-agent")
# result.is_allowed, result.state, result.reason
```

### Sinks — audit logging

Append-only JSONL with SIEM-compatible field names.

```python
from agentmint.sinks import FileSink

sink = FileSink("audit.jsonl")
sink.emit(receipt)  # One JSON line per receipt
```

Each line contains: `timestamp`, `severity`, `source`, `receipt_id`, `plan_id`, `agent`, `action`, `in_policy`, `policy_reason`, `evidence_hash`, `signature`, `key_id`.

### Notary — cryptographic receipts

Ed25519 signing, SHA-256 hash chain, RFC 3161 timestamping, evidence export.

```python
from agentmint.notary import Notary

notary = Notary()
plan = notary.create_plan(scope=["read:*"], checkpoints=["delete:*"], delegates_to=["agent-1"])
receipt = notary.notarise("read:file.txt", "agent-1", plan, evidence={"file": "report.pdf"})
notary.verify_receipt(receipt)  # raises on invalid signature
```

## Install

```
pip install agentmint
```

Or from source:

```
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
```

## Tests

```
uv run pytest tests/ -v
```

170+ tests across core delegation, notary signing/chaining, pattern matching, evidence verification, shield scanning, circuit breaker states, and sink output.

## Compliance

AgentMint receipt fields map to SOC 2 (CC6.1, CC7.2, CC8.1, PI1.1), NIST AI RMF (MAP 1.1, MEASURE 2.3, MANAGE 3.1, GOVERN 1.1), HIPAA (164.312 access control, audit, integrity, authentication), and EU AI Act Article 12 (record-keeping).

See [COMPLIANCE.md](COMPLIANCE.md) for the full field-by-framework mapping.

## Limits

See [LIMITS.md](LIMITS.md) for known limitations and design trade-offs.

## Status

Active development. Core protocol, shield, circuit breaker, and sink modules are implemented and tested. Looking for real use cases.

If you're building agents that need scoped permissions — file access, API calls, actions on behalf of users — open an issue or reach out.

## Contact

[linkedin.com/in/anikethmaddipati](https://linkedin.com/in/anikethmaddipati)

## License

MIT
