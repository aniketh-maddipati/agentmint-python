# AgentMint

Unlock agent autonomy. Runtime Enforcement for AI agent actions.

Your agent takes an action. AgentMint produces a signed, timestamped, chained crypto receipt proving what was authorized, what happened, and whether the two match — verifiable with OpenSSL alone. No vendor software. No trust required.

```
pip install agentmint
```

---

## See receipts in 30 seconds

```bash
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
python examples/quickstart.py
```

No API keys needed. The receipts are real — Ed25519 signed, RFC 3161 timestamped, independently verifiable. The quickstart walks you through the full lifecycle: plan creation, scope evaluation, receipt signing, evidence export, and verification.

**Optional:** Set `ANTHROPIC_API_KEY` and/or `ELEVENLABS_API_KEY` to notarise real API calls instead of simulated actions.

- Get an Anthropic key: [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
- Get an ElevenLabs key: [elevenlabs.io/app/settings/api-keys](https://elevenlabs.io/app/settings/api-keys)

### What you'll see

The quickstart produces two receipts — one in-policy action and one violation — then exports a self-contained evidence package and runs verification live in your terminal.

Here's what a receipt looks like:

```json
{
  "id": "f45894e5-a562-4c59-977d-994c6b04acb2",
  "type": "notarised_evidence",
  "plan_id": "3805bfc6-...",              // ← links to the human-approved plan
  "agent": "demo-agent",                  // ← who acted
  "action": "read:reports:quarterly",      // ← what they did
  "in_policy": true,                       // ← was it authorized?
  "policy_reason": "matched scope read:reports:*",
  "evidence_hash_sha512": "beaeb2c0ac...", // ← SHA-512 of the evidence dict
  "observed_at": "2026-03-18T18:20:16Z",
  "previous_receipt_hash": null,           // ← chain link (first receipt)
  "signature": "938d4090...",              // ← Ed25519, covers all fields above
  "timestamp": {
    "tsa_url": "https://freetsa.org/tsr", // ← independent third-party time authority
    "digest_hex": "4b106920..."
  }
}
```

The evidence package verifies with two commands:

```bash
cd evidence_output && unzip -o agentmint_evidence_*.zip
bash VERIFY.sh           # timestamps — pure OpenSSL, no dependencies
python3 verify_sigs.py   # signatures — needs pynacl
```

No AgentMint software needed to verify. Just OpenSSL and Python.

---

## What this proves

Your stack already logs what happened. AgentMint adds proof.

**What your stack produces today:**

```json
{
  "timestamp": "2026-03-18T14:35:42Z",
  "agent": "sre-agent",
  "action": "kubectl rollout undo",
  "target": "payments-api",
  "result": "success"
}
```

No signature — anyone with DB access can edit this. No authorization context — was this action even allowed? Server timestamp — backdatable.

**What AgentMint adds:**

- **Ed25519 signature** — one bit changes, verification fails. Private key never leaves your environment.
- **Authorization bound to execution** — the receipt proves the action was evaluated against a scoped plan at the time it happened.
- **RFC 3161 timestamp** — independent time authority (FreeTSA). Backdating is mathematically impossible.
- **Receipt chain** — each receipt includes the SHA-256 hash of the previous receipt. Delete or reorder any receipt, the chain breaks.

Your buyer's security team doesn't want to trust your dashboard. They want to run `bash VERIFY.sh` and see proof.

---

## How it works

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

**1. Plan** — A human or policy engine defines what the agent can do. Which actions, which targets, how long. Signed at creation.

**2. Scope** — Before execution, the action is evaluated against the plan's scope patterns. Sub-millisecond, in-memory. The agent framework acts on the verdict — AgentMint returns the answer, the framework enforces it.

**3. Execution** — The agent does its job. AgentMint is not in this path.

**4. Receipt** — After execution, the Notary binds authorization to execution. Ed25519 signature + RFC 3161 timestamp + evidence hash + chain link. One artifact.

---

## Integrate with your agent

The Notary wraps any action with receipts:

```python
from agentmint.notary import Notary
from pathlib import Path

notary = Notary()

# 1. Human or policy engine approves a scoped plan
plan = notary.create_plan(
    user="admin@company.com",
    action="sre:remediation",
    scope=["remediate:rollback:*"],
    checkpoints=["remediate:delete:*"],
    delegates_to=["sre-agent"],
)

# 2. After your agent acts, notarise the action
receipt = notary.notarise(
    action="remediate:rollback:payments-api",
    agent="sre-agent",
    plan=plan,
    evidence={"target": "payments-api", "from": "v2.3.1", "to": "v2.3.0"},
)

print(receipt.in_policy)              # True — matched scope
print(receipt.signature[:16])         # Ed25519 signature
print(receipt.previous_receipt_hash)  # Chain link to previous receipt

# 3. Export verifiable evidence package
zip_path = notary.export_evidence(Path("./evidence"))
```

### Framework integrations

**CrewAI** — `@before_tool_call` hook, ~20 lines:

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
    return None if result.ok else False
```

**MCP** — runs as an MCP server with three tools. [Server →](mcp_server/)

**Claude, ElevenLabs, AWS S3** — any API call can produce a receipt. [Demos →](examples/)

---

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

**Dependencies:** `pynacl` (Ed25519 signing) + `requests` (FreeTSA timestamping). That's it.

**Three independent anchors** — no single party, including AgentMint, can tamper with the evidence:

- **Ed25519 signature** — private key never leaves your environment. Verifiable with OpenSSL.
- **RFC 3161 timestamp** — independent time authority. Only a hash leaves your environment.
- **Commitment hashes** — receipts contain SHA-512 hashes, not content. Nothing sensitive is exposed.

---

## Verify without installing AgentMint

Real receipts with real signatures and timestamps are committed in the repo:

```bash
cd examples/sample_evidence && bash VERIFY.sh
```

Requires only OpenSSL. [See what's inside →](examples/sample_evidence/)

---

## Tests

```bash
pip install pytest
pytest tests/ -v    # 76 tests
```

---

## Status

Running against production APIs — ElevenLabs, Claude, AWS S3. In design partnership conversations with enterprise AI companies.

Receipt schema aligned to AIUC-1, ISO 42001, EU AI Act Article 12.

---

## Want receipts for your agent?

You bring the agent. I instrument it, map your actions to receipts, and hand you an evidence package your buyer's security team can verify independently.

**[Book 15 minutes →](https://calendar.app.google/pT1Sz8EUtqowWABi8)** · [anikethcov@gmail.com](mailto:anikethcov@gmail.com) · [linkedin.com/in/anikethmaddipati](https://linkedin.com/in/anikethmaddipati)

## License

MIT
