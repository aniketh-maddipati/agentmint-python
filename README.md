# agentmint

Cryptographic receipts for AI agent actions.

**The only SDK that produces a single receipt proving what an AI agent was authorized to do, what it actually did, and that the two match — independently verifiable, without touching your infrastructure.**

```
pip install agentmint
```

[![AgentMint Demo](combined-demo.gif)](combined-demo.gif)

---

## The problem

MCP gives agents access to Gmail, Slack, databases. CrewAI chains agents autonomously. Permissions today are all-or-nothing.

Give an agent file access → it reads everything.
Give it email access → it sends as you.
One prompt injection → full access.

Control planes monitor agents. Observability tools log what happened. Neither produces proof. When your buyer's security team asks "how do you know the agent only did what it was supposed to?" — logs aren't an answer. You need a receipt.

## What agentmint does

Two layers. One artifact.

**Gatekeeper** (`core.py`) — active authorization. Scoped delegation, checkpoints, replay protection. Blocks before execution. Sub-millisecond (<100μs).

**Notary** (`notary.py`) — passive receipt generation. Ed25519 signing, RFC 3161 timestamping, AIUC-1 control tagging. Signs after execution.

The receipt binds all four: human delegates → credential scoped → gatekeeper validates → agent executes → notary signs.

```
Human approves plan → Agent requests authorization → Action executes (or blocks)
                                ↓
                    Cryptographic receipt (Ed25519)
                    RFC 3161 timestamp (independent)
                    SHA-512 evidence hash
                    Receipt chain (hash of previous receipt)
```

## Verify without installing agentmint

```bash
bash VERIFY.sh
```

Uses only OpenSSL. No AgentMint software needed. No vendor dependency. No trust required.

---

## Quickstart

### Prerequisites

```bash
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
```

Create a `.env` file with the keys you need:

```bash
ANTHROPIC_API_KEY=your-key        # Claude demos
ELEVENLABS_API_KEY=your-key       # ElevenLabs demo
AWS_ACCESS_KEY_ID=your-key        # CrewAI + S3 demos
AWS_SECRET_ACCESS_KEY=your-key
```

### 1. Claude API — fastest path to a working demo

Claude tries to read files. AgentMint enforces scope. A prompt injection gets neutralized.

```bash
python examples/mcp_real_demo.py
```

A manager approves a plan scoping Claude to `read:public:*`. Claude is told to read all files. One file contains a `[SYSTEM]` injection telling Claude to read `secrets.txt`. AgentMint blocks it — the action matches a checkpoint, no human approved escalation. Every action gets an Ed25519 signed receipt.

**Requires:** `ANTHROPIC_API_KEY` only.

### 2. CrewAI + AWS S3 — prompt injection with real infrastructure

A CrewAI agent with GPT-4o-mini reads from a real S3 bucket. AgentMint sits in the `@before_tool_call` hook and enforces scoped delegation.

```bash
pip install crewai boto3
python examples/combined_demo.py
```

Two demos back-to-back. CrewAI reads `reports/q4-summary.txt` containing an injection pointing at `confidential/credentials.txt` — AgentMint blocks the follow-up read. Then the same pattern runs against Claude's tool-use API. Both produce signed receipts.

**Requires:** `ANTHROPIC_API_KEY`, AWS credentials, `pip install crewai boto3`.

### 3. CrewAI + AWS S3 — delegation chain depth

Shows multi-hop delegation: CISO → research-lead → data-analyst, with scope narrowing at each hop.

```bash
python examples/crewai_aws.py
```

Phase 1 runs without AgentMint — the agent reads credentials freely. Phase 2 adds AgentMint: the CISO's broad scope gets attenuated when delegated to the analyst. Three access attempts demonstrate allowed, out-of-scope, and checkpoint-blocked paths.

### 4. ElevenLabs — notary layer, evidence packages, tamper test

The deep architecture demo. Passive Notary running against production ElevenLabs and Claude APIs.

```bash
pip install rich anthropic elevenlabs
python examples/elevenlabs_demo.py
```

Claude processes two customer documents and calls ElevenLabs TTS. One is clean, one contains an injection trying to trigger voice cloning. AgentMint notarises both, produces an evidence package (.zip), and runs a live tamper test — flipping one bit in a 91-byte file and watching OpenSSL reject it.

**Produces:** `evidence_output/agentmint_evidence_*.zip` — self-contained with receipts, timestamps, CA certs, and `VERIFY.sh`.

### 5. MCP server — use from Claude Desktop or any MCP client

```bash
pip install fastmcp
python -m mcp_server.server
```

Or add to Claude Desktop (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "agentmint": {
      "command": "python",
      "args": ["-m", "mcp_server.server"],
      "cwd": "/path/to/agentmint-python"
    }
  }
}
```

Three tools: `agentmint_issue_plan`, `agentmint_authorize`, `agentmint_audit`.

---

## Usage

### Gatekeeper — identity and least-privilege

```python
from agentmint import AgentMint

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
    # proceed — result.receipt contains Ed25519 signed proof
    pass
else:
    # blocked — result.reason explains why
    pass
```

### Notary — receipts only (passive, post-execution)

```python
from agentmint.notary import Notary
from pathlib import Path

notary = Notary()

plan = notary.create_plan(
    user="marco@elevenlabs.io",
    action="elevenlabs:tts",
    scope=["tts:standard:*"],
    checkpoints=["tts:clone:*"],
    delegates_to=["claude-sonnet-4-5"],
)

receipt = notary.notarise(
    action="tts:standard:JBFqnCBs",
    agent="claude-sonnet-4-5",
    plan=plan,
    evidence={
        "voice_id": "JBFqnCBsd6RMkjVDRZzb",
        "tts_success": True,
        "audio_bytes": 302646,
    },
)

# Export evidence package
zip_path = notary.export_evidence(Path("./evidence"))
```

### CrewAI — the full `@before_tool_call` integration

```python
from crewai.hooks import before_tool_call, ToolCallHookContext
from agentmint import AgentMint

mint = AgentMint(quiet=True)
plan = mint.issue_plan(
    action="data:research",
    user="ciso@acme-corp.com",
    scope=["s3:read:reports:*"],
    delegates_to=["data-analyst"],
    requires_checkpoint=["s3:read:confidential:*"],
)

@before_tool_call
def gate(ctx: ToolCallHookContext) -> bool | None:
    if ctx.tool_name != "s3_reader":
        return None
    path = ctx.tool_input.get("path", "")
    action = f"s3:read:{path.replace('/', ':')}"
    result = mint.delegate(parent=plan, agent="data-analyst", action=action)
    if result.ok:
        return None      # allow
    return False          # block
```

That's the entire integration. ~20 lines.

---

## How it works

1. **Plan issuance** — Human approves a scoped authorization plan. Allowed actions (scope) and escalation triggers (checkpoints) are defined upfront.

2. **Delegation** — Before executing, the agent calls `mint.delegate()`. AgentMint checks scope. Checkpoint patterns block unless explicitly approved.

3. **Receipt** — Every delegation produces an Ed25519 signed receipt chained to the original plan. Each receipt includes the hash of the previous receipt. The full chain is independently verifiable.

```
plan (root)
├─ id:        4388f437-3679-4c96-9d9e-8736503bbceb
├─ sub:       manager@company.com
├─ signature: f1958df50730fc2b4fbec0a92178fc2a...
│
└─ delegation
   ├─ id:        15ac1666-04b3-4c7d-adb3-cfed52ac34bf
   ├─ parent_id: 4388f437-3679-4c96-9d9e-8736503bbceb
   ├─ sub:       claude-sonnet-4-20250514
   ├─ action:    read:public:report.txt
   └─ signature: e2aa114cc339fefd3d171474cceff961...
```

## Architecture

```
agentmint/
├── core.py            # Gatekeeper: scoped delegation, checkpoints, replay protection
├── notary.py          # Notary: passive receipt generation, policy evaluation
├── anchor.py          # RFC 3161 timestamping (FreeTSA)
├── commitment.py      # SHA-256 commitment scheme (hash-only receipts)
├── batch.py           # Batch mode: scenario loading, execution, aggregation
├── export.py          # Evidence ZIP packaging
├── keystore.py        # Ed25519 key persistence
├── receipt_store.py   # JSONL append-only receipt persistence
├── types.py           # Data types and enums
├── errors.py          # Exception hierarchy
├── console.py         # Terminal output formatting
└── decorator.py       # @require_receipt decorator
```

## Technical details

- **Ed25519 signatures** — private key never leaves your environment
- **RFC 3161 timestamps** — independent time authority (FreeTSA)
- **SHA-512 evidence hashes** — receipts contain hashes, not content. Nothing sensitive leaves.
- **Receipt chain** — each receipt includes hash of previous receipt
- **Receipt schema** — aligned to AIUC-1, ISO 42001, EU AI Act Article 12

## Why this must be independent

You cannot notarize your own actions. The proof layer must exist outside the agent vendor's infrastructure, identity plane, and key management.

AgentMint doesn't replace control planes or observability. It produces the one artifact neither can: proof that holds up when you're not in the room.

## Integrations

**CrewAI** — `@before_tool_call` hook, ~20 lines. [Examples →](examples/)

**MCP** — runs as MCP server. Available on Smithery and as hosted endpoint. [Server →](mcp_server/)

**LangChain** — ComplianceCallbackHandler RFC opened ([#35691](https://github.com/langchain-ai/langchain/issues/35691)). One line: `callbacks=[ComplianceCallbackHandler(...)]`.

**Raw APIs** — ElevenLabs, Claude, AWS S3. Any API call can produce a receipt. [Examples →](examples/)

## Status

Running against production APIs — ElevenLabs, Claude, AWS S3. 80 receipts generated and verified in a single batch run. In design partnership conversations with enterprise AI companies.

If you're building agents that touch customer data, make API calls on behalf of users, or need to pass security review — we want to work with you.

**[Book a conversation →](https://calendar.app.google/pT1Sz8EUtqowWABi8)**

## Tests

```bash
pip install pytest
pytest tests/ -v
```

## License

MIT

## Contact

[linkedin.com/in/anikethmaddipati](https://linkedin.com/in/anikethmaddipati) · [agent-mint.dev](https://agent-mint.dev)