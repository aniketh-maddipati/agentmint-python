# AgentMint Demo — Clinical Ops Agent

30-minute call with Cleburn Walker. Demo portion: 3 minutes.

## The Demo

**Before you start:** `cd agentmint-demo` and make sure `agentmint` is installed (`pip install -e ../agentmint-python-main` or wherever your local checkout is). You need `rich` and `libcst` installed too.

### Beat 1 — The ungoverned agent (~30 seconds)

Open `agent.py` in your editor or `cat` it. Say:

> "This is a production agent built on the OpenAI Agents SDK. Four tools — patient record lookup, payment processing, notifications, and audit log queries. Right now there's zero governance. No audit trail, no policy enforcement, no evidence that any of this happened."

Point at `fetch_patient_record` and `charge_customer` specifically — they handle PHI and payments with no controls.

### Beat 2 — agentmint init scans the codebase (~60 seconds)

```bash
agentmint init .
```

Walk through the output:

1. **Scan results** — "It found all 4 tools, classified them as OpenAI SDK via the `@function_tool` decorator, high confidence."
2. **Heads up section** — "It flagged `charge_customer` and `send_notification` as write operations. Those start in audit mode — logging, not blocking."
3. **Generated config** — "This is `agentmint.yaml`. Scopes like `ehr:read:*` and `billing:charge:*` match the tool names. All facts from the scan, no guesses."
4. **Plan scaffold** — "This is the plan you'd paste into your entry point. Scopes, delegates, TTL."
5. **Shield snippet** — "This is a one-liner to test Shield on sample inputs."

If he asks: "The scan uses LibCST — full AST parsing, not regex. It detects CrewAI, OpenAI Agents SDK, LangChain, and MCP patterns."

### Beat 3 — The governed agent with evidence (~90 seconds)

```bash
python3 agent_governed.py
```

Walk through the output:

1. **Tool calls** — "Same 4 tools running, same fake data. But now each one is wrapped with `notary.notarise()`."
2. **Prompt injection** — "Notice tool 3 — the notification message contains a prompt injection attempt. Shield caught it."
3. **Receipts table** — "4 receipts, each signed with Ed25519, each chained to the previous one via SHA-256."
4. **Evidence export** — "That zip is the evidence package."

Then verify it:

```bash
cd agentmint-evidence
unzip agentmint_evidence_*.zip -d evidence
cd evidence
bash VERIFY.sh
```

Say:

> "This runs pure OpenSSL. No AgentMint software needed. An auditor gets this zip, runs one command, and can independently verify every timestamp. That's the whole point — the evidence is self-verifying."

## What This Shows

- **`agentmint init` is real** — it scans Python codebases with LibCST, detects framework-specific patterns, classifies operations, and generates actionable config. Not a mockup.
- **The wrapping pattern is minimal** — 3 lines per tool call gives you Ed25519-signed, chain-linked, independently verifiable evidence receipts.
- **Evidence is independently verifiable** — the zip contains everything an auditor needs. `VERIFY.sh` uses only OpenSSL. No AgentMint account, no cloud service, no vendor lock-in.

## What It Doesn't Show

This demo skips timestamps (the `enable_timestamp=False` flag) because they require a network call to FreeTSA and add ~2 seconds per receipt. In production you'd leave timestamps on — they anchor each receipt to wall-clock time via RFC 3161, which is what makes the evidence hold up under audit. The demo also doesn't show the circuit breaker (rate limiting per agent), the full Shield output (it scans for PII, secrets, and prompt injection but we only trigger the injection path here), session tracking (drift detection across a sequence of tool calls), or multi-agent delegation (scope intersection when one agent delegates to another). All of those are implemented and in the codebase — they just don't fit in 3 minutes. If Cleburn asks about any of them, they're real and you can show the code.