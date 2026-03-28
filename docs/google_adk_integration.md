# AgentMint × Google ADK

**Cryptographic receipts via `before_tool_callback` / `after_tool_callback`. No SDK modification.**

🔗 [AgentMint repo](https://github.com/aniketh-maddipati/agentmint-python) · [ADK Issue #4502](https://github.com/google/adk-python/issues/4502) (closed)

---

## Context

ADK issue #4502 asked for "deterministic tool-call receipt schema for invocation steps." PR #4503 attempted a telemetry-level solution — a flat dict with 5 fields (tool name, args hash, outcome, schema version, call ID). It was closed without merging.

**What #4503 built**: a span attribute. No signature. No chain. No tamper detection. If someone edits the span data after the fact, nothing breaks.

**What AgentMint adds**: Ed25519 signatures, SHA-256 hash chains, policy evaluation, agent identity, scoped delegation, independent verification. Editing a receipt breaks the signature and the chain.

## Integration pattern

ADK's `before_tool_callback` and `after_tool_callback` provide clean interception points:

```python
from google.adk.agents import Agent
from agentmint import AgentMint
from agentmint.notary import Notary

mint = AgentMint(quiet=True)
notary = Notary()

plan = mint.issue_plan(
    action="data-analysis",
    user="manager@company.com",
    scope=["tool:get_weather", "tool:lookup_account"],
    delegates_to=["analyst"],
)

notary_plan = notary.create_plan(
    user="manager@company.com",
    action="data-analysis",
    scope=["tool:get_weather", "tool:lookup_account"],
    delegates_to=["analyst"],
)

def before_tool(callback_context, tool_name, args):
    """Gate: check delegation, sign receipt, allow or block."""
    action = f"tool:{tool_name}"
    result = mint.delegate(parent=plan, agent="analyst", action=action)

    evidence = {
        "tool": tool_name,
        "args_hash": sha256(args),
        "allowed": result.ok,
    }
    notary.notarise(
        action=action, agent="analyst",
        plan=notary_plan, evidence=evidence,
    )

    if not result.ok:
        return {"error": f"Blocked: {result.status.value}"}
    return None  # proceed

agent = Agent(
    name="analyst",
    model="gemini-2.0-flash",
    tools=[get_weather, lookup_account],
    before_tool_callback=before_tool,
    after_tool_callback=after_tool,  # captures output hash
)
```

## Receipt comparison

| Field | #4503 (closed PR) | AgentMint |
|---|---|---|
| tool_name | ✓ | ✓ |
| args_hash | SHA-256 | SHA-256 |
| outcome | success/unknown | in_policy + policy_reason |
| signature | ✗ | Ed25519 |
| chain link | ✗ | SHA-256 hash of previous receipt |
| agent identity | ✗ | ✓ (signed) |
| agent co-signature | ✗ | ✓ (optional) |
| delegation check | ✗ | scoped delegation with attenuation |
| independent verification | ✗ | `pynacl` or `openssl` |
| RFC 3161 timestamp | ✗ | optional (FreeTSA) |

## Status

ADK integration is **functional but not yet pushed to the repo**. The OpenAI Agents SDK and CrewAI integrations are live:

- [OpenAI Agents SDK demo](https://github.com/aniketh-maddipati/agentmint-python/tree/main/examples/openai_agents_receipts_demo) — pushed, tested, commented on #2643
- [CrewAI demo](https://github.com/aniketh-maddipati/agentmint-python/tree/main/examples/crewai_receipts_demo) — pushed

ADK demo will be published once tested against the current SDK version.

## Compliance mapping

Receipt fields map directly to:

- **SOC 2** CC6.1 (access controls), CC7.2 (monitoring), CC8.1 (change management)
- **HIPAA** §164.312 (audit controls, integrity controls)
- **NIST AI RMF** MAP 1.5, MEASURE 2.6
- **EU AI Act** Article 12 (record-keeping, traceability)

Full mapping: [COMPLIANCE.md](https://github.com/aniketh-maddipati/agentmint-python/blob/main/COMPLIANCE.md)

---

**AgentMint** — `pip install agentmint` · MIT licensed · 184 tests · 2 dependencies · works offline

[github.com/aniketh-maddipati/agentmint-python](https://github.com/aniketh-maddipati/agentmint-python)