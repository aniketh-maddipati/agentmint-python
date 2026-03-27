# AgentMint × OpenAI Agents SDK — Cryptographic Receipts for Tool Calls

Ed25519-signed, hash-chained receipts for every tool call and agent handoff. No SDK modification.

**Related:** [openai/openai-agents-python#2643](https://github.com/openai/openai-agents-python/issues/2643)

## What this shows

- Every tool call → signed receipt with hashed args + output (no cleartext in evidence)
- Every agent handoff → signed turn receipt for chain-of-custody
- Agent co-signatures → two signatures per tool receipt (notary + agent)
- Tamper-evident hash chain across the full run
- Verification with `pynacl` / `openssl` — no AgentMint needed

## Integration pattern

```python
from agentmint.notary import Notary

notary = Notary()
plan = notary.create_plan(user="ops@co.com", action="ops", scope=["tool:*"], ...)

# Inside each tool — signs receipt with actual args + output
@function_tool
def get_weather(city: str) -> str:
    result = fetch_weather(city)
    notary.notarise(action="tool:get_weather", agent="my_agent", plan=plan,
                     evidence={"args_hash": sha256(city), "output_hash": sha256(result)})
    return result

# RunHooks track handoffs (issue #2643 chain of custody)
result = Runner.run_sync(agent, query, hooks=ReceiptHooks())
```

Tool-level signing is necessary because `RunHooks.on_tool_start` doesn't expose args ([SDK #939](https://github.com/openai/openai-agents-python/issues/939)).

## Run

```bash
pip install openai-agents agentmint
export OPENAI_API_KEY=your-key
python demo.py
python verify_receipts.py
```

## Known limitations

- **Parallel tool execution**: When the SDK calls multiple tools in one turn, those receipts share the same chain parent. The chain resumes sequential linking after the batch.
- **Tool-level signing**: Signing inside each tool function, not transparently via hooks, due to [SDK #939](https://github.com/openai/openai-agents-python/issues/939).
- **Demo signing key**: Ephemeral. Production uses persistent keys. See [LIMITS.md](https://github.com/aniketh-maddipati/agentmint-python/blob/main/LIMITS.md).

---

[AgentMint](https://github.com/aniketh-maddipati/agentmint-python)