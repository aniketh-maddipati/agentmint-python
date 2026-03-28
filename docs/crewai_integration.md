# AgentMint × CrewAI

**Scoped delegation + cryptographic receipts for every tool call. No SDK modification.**

🔗 [Working demo](https://github.com/aniketh-maddipati/agentmint-python/tree/main/examples/crewai_receipts_demo) · [AgentMint repo](https://github.com/aniketh-maddipati/agentmint-python)

---

## The problem

CrewAI agents can call any tool they're given. There's no built-in mechanism to:

- **Scope** which tools an agent is allowed to use per-task
- **Block** unauthorized tool calls before they execute
- **Prove** what happened — signed, tamper-evident, independently verifiable
- **Record denials** — not just successes, but blocked attempts too

The `@before_tool_call` hook gives you the interception point. AgentMint gives you the enforcement and evidence layer.

## Before / After

**Before** — any tool, any time, no proof:

```python
analyst = Agent(role="analyst", tools=[WeatherTool(), SecretTool()])
# SecretTool reads credentials.txt. No approval. No record.
```

**After** — scoped delegation, gated execution, signed receipts:

> Abbreviated — full runnable demo coming soon.
```python
@before_tool_call
def gate(ctx: ToolCallHookContext) -> bool | None:
    result = mint.delegate(plan, ctx.agent.role, f"tool:{ctx.tool_name}")
    if result.ok:
        notary.notarise(...)  # signed receipt
        return None            # proceed
    notary.notarise(...)       # denial receipt (evidence too)
    return False               # block before execution
```

**20 lines of gate logic. Zero CrewAI modification.**

## What the demo shows

```
┌────────────────────────────────────────────────┐
│  Plan: manager@company.com → analyst           │
│  ✓ allow: tool:get_weather, tool:lookup_account│
│  ✗ block: tool:read_secret (checkpoint)        │
│  sig: 7a3f1b2c4d5e...                          │
└────────────────────────────────────────────────┘

Task 1: Weather + Account lookup
  ✓ ALLOWED  get_weather
    receipt: 24aa28  sig: 9c1e4a2b...
  ✓ ALLOWED  lookup_account
    receipt: f7b3c1  sig: 2d8f5c3a...

Task 2: Read secret file
  ✗ BLOCKED  read_secret
    reason: out_of_scope
    receipt: 8e4d2f  (denial signed too)
```

Three things to notice:

1. **`read_secret` never executes** — the `_run()` method is never called. The gate returns `False` before the tool body runs.
2. **Denials produce receipts too** — you can prove an agent *tried* to access something and was stopped.
3. **Every receipt is Ed25519 signed and hash-chained** — tamper with one, the chain breaks.

## Integration pattern

```python
from agentmint import AgentMint
from agentmint.notary import Notary
from crewai.hooks import before_tool_call, ToolCallHookContext

mint = AgentMint(quiet=True)
notary = Notary()

# Human issues a scoped plan
plan = mint.issue_plan(
    action="data-analysis",
    user="manager@company.com",
    scope=["tool:get_weather", "tool:lookup_account"],
    delegates_to=["analyst"],
    requires_checkpoint=["tool:read_secret"],
    max_depth=2,
    ttl=300,
)

notary_plan = notary.create_plan(
    user="manager@company.com",
    action="data-analysis",
    scope=["tool:get_weather", "tool:lookup_account"],
    delegates_to=["analyst"],
)

@before_tool_call
def gate(ctx: ToolCallHookContext) -> bool | None:
    action = f"tool:{ctx.tool_name}"
    agent_name = ctx.agent.role if ctx.agent else "unknown"
    result = mint.delegate(parent=plan, agent=agent_name, action=action)

    evidence = {
        "tool": ctx.tool_name,
        "agent": agent_name,
        "allowed": result.ok,
    }
    receipt = notary.notarise(
        action=action, agent=agent_name,
        plan=notary_plan, evidence=evidence,
    )

    if result.ok:
        return None   # proceed
    return False      # block
```

## Run the demo

```bash
pip install crewai agentmint
export OPENAI_API_KEY=your-key
cd examples/crewai_receipts_demo
python demo.py
python verify_receipts.py
```

**Output**: 3 receipts (2 allowed, 1 blocked), all Ed25519 verified, hash chain intact, `receipts.json` exported.

## How this relates to CrewAI's hooks model

Lorenze Jay Hernandez (Lead OSS Engineer @ CrewAI) described hooks as "middleware for your agentic systems" — intercept before execution, not just observe after. AgentMint is exactly that middleware layer:

| CrewAI hook | AgentMint function |
|---|---|
| `@before_tool_call` | Delegation check → allow/block |
| Return `None` | Signed receipt → proceed |
| Return `False` | Signed denial → tool never executes |

The hook pattern means AgentMint works with CrewAI today, without waiting for framework changes.

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