# AgentMint × OpenAI Agents SDK

**Cryptographic receipts for every tool call and agent handoff. No SDK modification.**

🔗 [Working demo](https://github.com/aniketh-maddipati/agentmint-python/tree/main/examples/openai_agents_receipts_demo) · [Issue #2643](https://github.com/openai/openai-agents-python/issues/2643) · [AgentMint repo](https://github.com/aniketh-maddipati/agentmint-python)

---

## The problem

The OpenAI Agents SDK has no built-in way to prove:

- Which agent executed which tool
- What inputs the tool received
- What output the tool produced
- Whether outputs were modified between agent handoffs

Logs can be edited after the fact. For SOC 2, HIPAA, and EU AI Act compliance, you need **cryptographic proof** — not just records.

## What AgentMint adds

Every tool call and agent handoff produces an **Ed25519-signed, SHA-256 hash-chained receipt**:

```
┌─────────────────────────────────────────────────┐
│  Receipt [1]  tool:get_weather                  │
│  sig: 7a3f1b...  agent_sig: 4e2d8c...          │
│  chain: (start)                                  │
├─────────────────────────────────────────────────┤
│  Receipt [2]  tool:lookup_account               │
│  sig: 9c1e4a...  agent_sig: 6b3f7d...          │
│  chain: a4f2e1b8c3d9...                         │
├─────────────────────────────────────────────────┤
│  Receipt [3]  agent:turn:notification_agent     │
│  sig: 2d8f5c...                                  │
│  chain: f7c3a2d1e5b8...                         │
├─────────────────────────────────────────────────┤
│  Receipt [4]  tool:send_notification            │
│  sig: 8b4e2f...  agent_sig: 1a5c9d...          │
│  chain: 3e9b7c4f2a1d...                         │
└─────────────────────────────────────────────────┘
```

- **Two signatures per tool receipt**: notary attests the policy evaluation, agent co-signs the evidence
- **Hashed evidence only**: args and outputs are SHA-256 hashed — no cleartext in the receipt chain
- **Tamper-evident**: editing any receipt breaks the hash chain and invalidates the signature
- **Independent verification**: requires only `pynacl` or `openssl` — no AgentMint software needed

## Integration pattern

```python
from agentmint.notary import Notary
from agents import Agent, Runner, RunHooks, function_tool

notary = Notary()
plan = notary.create_plan(
    user="ops@company.com",
    action="agent-ops",
    scope=["tool:get_weather", "tool:lookup_account", "tool:send_notification"],
    delegates_to=["main_agent", "notification_agent"],
)

# Inside each tool — signs receipt with actual args + output
@function_tool
def get_weather(city: str) -> str:
    result = fetch_weather(city)
    notary.notarise(
        action="tool:get_weather",
        agent="main_agent",
        plan=plan,
        evidence={"args_hash": sha256(city), "output_hash": sha256(result)},
        agent_key=agent_key,  # co-signature
    )
    return result

# RunHooks track handoffs for chain of custody
class ReceiptHooks(RunHooks):
    async def on_agent_end(self, context, agent, output):
        notary.notarise(action=f"agent:turn:{agent.name}", ...)

result = Runner.run_sync(agent, query, hooks=ReceiptHooks())
```

Tool-level signing is necessary because `RunHooks.on_tool_start` doesn't expose args ([SDK #939](https://github.com/openai/openai-agents-python/issues/939)).

## Run the demo

```bash
pip install openai-agents agentmint
export OPENAI_API_KEY=your-key
cd examples/openai_agents_receipts_demo
python demo.py
python verify_receipts.py
```

**Output**: 4 receipts, all verified, handoff from main agent to notification agent captured, 3/4 agent co-signatures, `receipts.json` exported.

## Known limitations

| Limitation | Cause | Workaround |
|---|---|---|
| Signing inside tool body, not via hooks | `on_tool_start` lacks args ([#939](https://github.com/openai/openai-agents-python/issues/939)) | Sign in tool function |
| Parallel tool calls share chain parent | SDK executes tools concurrently | Chain resumes sequential after batch |
| Ephemeral signing keys in demo | Demo simplification | Production uses persistent keys via SPIFFE/secrets manager |

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