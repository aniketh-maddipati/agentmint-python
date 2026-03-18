# agentmint

Cryptographic receipts for AI agent actions.

**Every agent action gets a signed, timestamped, chained receipt — verifiable with OpenSSL alone. No vendor software required.**

```
pip install agentmint
```

---

## Verify without installing agentmint

Real receipts with real Ed25519 signatures and RFC 3161 timestamps are committed in the repo:

```bash
cd examples/sample_evidence && bash VERIFY.sh
```

Requires only OpenSSL. [See what's inside →](examples/sample_evidence/)

---

## The problem

Control planes monitor agents. Observability tools log what happened. Neither produces proof. When your buyer's security team asks "show me evidence the agent stayed in scope during the Q4 incident" — unsigned app logs from the infrastructure under investigation aren't an answer.

## What agentmint does

Two layers. Neither touches the API call.

**Scope** (`core.py`) — evaluates the action against the plan's policy before execution. Returns allowed/denied/checkpoint. Sub-millisecond, in-memory. The agent framework acts on the verdict.

**Notary** (`notary.py`) — signs a receipt after execution proving what happened and whether it was in policy. Ed25519 + RFC 3161 timestamp + receipt chain linking.

```
Human approves plan → Agent requests action → Scope evaluates
                                                    ↓
                                        Allowed: tool call executes
                                        Denied: framework skips call
                                                    ↓
                                        Notary signs receipt
                                        Chain links to previous receipt
                                        FreeTSA timestamps independently
```

---

## Quickstart

```bash
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
```

### 1. Claude API — prompt injection defense

```bash
python examples/mcp_real_demo.py
```

A manager scopes Claude to `read:public:*`. Claude reads a file containing a `[SYSTEM]` injection telling it to read `secrets.txt`. AgentMint blocks it — the action matches a checkpoint. Every action gets a signed receipt. Requires `ANTHROPIC_API_KEY`.

### 2. CrewAI + AWS S3 — real infrastructure

```bash
pip install crewai boto3
python examples/combined_demo.py
```

A CrewAI agent with GPT-4o-mini reads from a real S3 bucket. AgentMint sits in the `@before_tool_call` hook. The agent reads a report containing an injection pointing at credentials — AgentMint blocks the follow-up read.

### 3. ElevenLabs — notary layer, evidence packages

```bash
pip install rich anthropic elevenlabs
python examples/elevenlabs_demo.py
```

Claude processes two documents and calls ElevenLabs TTS. One is clean, one contains an injection trying to trigger voice cloning. AgentMint notarises both, produces an evidence package, and runs a live tamper test.

### 4. SRE incident response — Traversal demo

```bash
python examples/traversal_sre_demo.py
```

Four scenarios at the remediation boundary: happy-path rollback with human approval, scope violation blocked, autonomous L5 execution with policy engine, and checkpoint escalation for high-risk actions. Each produces a real signed receipt.

### 5. MCP server

```bash
pip install fastmcp
python -m mcp_server.server
```

Three tools: `agentmint_issue_plan`, `agentmint_authorize`, `agentmint_audit`.

---

## Usage

### Scope evaluation — identity and least-privilege

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
    # proceed — result.receipt is Ed25519 signed
    pass
else:
    # blocked — result.reason explains why
    pass
```

### Notary — receipts with chain linking

```python
from agentmint.notary import Notary
from pathlib import Path

notary = Notary()

plan = notary.create_plan(
    user="admin@company.com",
    action="sre:remediation",
    scope=["remediate:rollback:*"],
    checkpoints=["remediate:delete:*"],
    delegates_to=["sre-agent"],
)

# Each receipt chains to the previous one
r1 = notary.notarise(
    action="remediate:rollback:payments-api",
    agent="sre-agent",
    plan=plan,
    evidence={"target": "payments-api", "from": "v2.3.1", "to": "v2.3.0"},
)
# r1.previous_receipt_hash is None (first in chain)

r2 = notary.notarise(
    action="remediate:rollback:auth-service",
    agent="sre-agent",
    plan=plan,
    evidence={"target": "auth-service", "from": "v1.8.2", "to": "v1.8.1"},
)
# r2.previous_receipt_hash == SHA-256 of r1's signed payload

# Export evidence package (includes public key + verify scripts)
zip_path = notary.export_evidence(Path("./evidence"))
```

### CrewAI integration — 20 lines

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

---

## End-to-end scenario: banking agent

A customer schedules a $500 weekly withdrawal. An attacker injects instructions into account notes trying to change it to $5,000.

```python
notary = Notary()

plan = notary.create_plan(
    user="platform-team@bank.com",
    action="customer-transfers",
    scope=["transfer:checking:savings:*"],
    checkpoints=["transfer:*:external:*"],
    delegates_to=["banking-agent-v2"],
)

# Legitimate $500 transfer
r1 = notary.notarise(
    action="transfer:checking:savings:500",
    agent="banking-agent-v2", plan=plan,
    evidence={"customer_id": "cust-8291", "amount": 500, "status": 200},
)
# r1.in_policy == True, r1.previous_receipt_hash == None

# Injection attempt: $5000
r2 = notary.notarise(
    action="transfer:checking:savings:5000",
    agent="banking-agent-v2", plan=plan,
    evidence={"customer_id": "cust-8291", "amount": 5000, "status": 403,
              "injection_detected": "SYSTEM OVERRIDE in account notes"},
)
# r2.previous_receipt_hash == SHA-256(r1) — chain intact

zip_path = notary.export_evidence(Path("./evidence"))
```

**What the auditor gets:**

```
agentmint_evidence_*.zip
├── receipt_index.json     ← start here
├── plan.json              ← what was authorized
├── public_key.pem         ← verify signatures independently
├── receipts/
│   ├── {r1}.json          ← $500 transfer, in policy
│   ├── {r1}.tsr           ← FreeTSA timestamp
│   ├── {r2}.json          ← $5000 attempt, flagged
│   └── {r2}.tsr           ← FreeTSA timestamp
├── freetsa_cacert.pem
├── freetsa_tsa.crt
├── VERIFY.sh              ← bash VERIFY.sh (timestamps, pure OpenSSL)
└── verify_sigs.py         ← python3 verify_sigs.py (Ed25519 signatures)
```

---

## How it works

1. **Plan issuance** — Human (or policy engine) approves a scoped plan. Allowed actions and escalation triggers defined upfront.

2. **Scope evaluation** — Before executing, the agent calls `mint.delegate()`. AgentMint checks scope. Checkpoint patterns require re-approval.

3. **Receipt + chain** — Every action produces an Ed25519 signed receipt. Each receipt includes the SHA-256 hash of the previous receipt. Deleting or reordering any receipt breaks the chain.

4. **Evidence package** — Receipts export as a self-contained zip with the public key, CA certs, and verification scripts. Anyone can verify with OpenSSL and Python alone.

## Architecture

```
agentmint/
├── core.py            # Scope: delegation, checkpoints, replay protection
├── notary.py          # Notary: signing, timestamping, chain linking, packaging
├── timestamp.py       # RFC 3161 timestamping via FreeTSA
├── keystore.py        # Ed25519 key persistence and PEM export
├── types.py           # DelegationStatus, DelegationResult
├── errors.py          # Exception hierarchy
├── console.py         # Terminal output formatting
└── decorator.py       # @require_receipt decorator
```

## Technical details

- **Ed25519 signatures** — private key never leaves your environment
- **RFC 3161 timestamps** — independent time authority (FreeTSA)
- **SHA-512 evidence hashes** — receipts contain hashes, not content
- **Receipt chain** — each receipt includes SHA-256 hash of the previous receipt
- **Public key in package** — evidence zip includes PEM for independent verification
- **Two verification scripts** — `VERIFY.sh` for timestamps (OpenSSL), `verify_sigs.py` for signatures (pynacl)

## Why this must be independent

You cannot notarize your own actions. The proof layer must exist outside the agent vendor's infrastructure.

AgentMint doesn't replace control planes or observability. It produces the one artifact neither can: proof that holds up when you're not in the room.

## Integrations

- **CrewAI** — `@before_tool_call` hook, ~20 lines. [Examples →](examples/)
- **MCP** — runs as MCP server. [Server →](mcp_server/)
- **LangChain** — ComplianceCallbackHandler RFC opened ([#35691](https://github.com/langchain-ai/langchain/issues/35691))
- **Raw APIs** — ElevenLabs, Claude, AWS S3. Any API call can produce a receipt.

## Status

Running against production APIs — ElevenLabs, Claude, AWS S3. In design partnership conversations with enterprise AI companies.

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
