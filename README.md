# agentmint

IAM for AI agents. Cryptographic delegation with audit trail.

![AgentMint Demo](demo.gif)

## The problem

MCP gives agents access to Gmail, Slack, databases. CrewAI chains agents autonomously. Permissions today are all-or-nothing.

Give an agent file access → it reads everything.
Give it email access → it sends as you.
One prompt injection → full access.

Two bad options:
1. Trust the agent completely
2. Approve every single action

There's no way to say "read reports, not secrets" and have that enforced *before* actions execute.

## What agentmint does
```
Human approves plan → Agent requests authorization → Action executes (or blocks)
                                ↓
                    Cryptographic receipt (Ed25519)
```

- **Scoped delegation**: define what actions are allowed
- **Checkpoints**: sensitive actions require human approval
- **Receipts**: every action is signed and auditable
- **Framework agnostic**: works with MCP, CrewAI, raw API calls

## Usage
```python
from agentmint import AgentMint

mint = AgentMint()

# Human approves a scoped plan
plan = mint.issue_plan(
    action="file-analysis",
    user="manager@company.com",
    scope=["read:public:*", "write:summary:*"],
    delegates_to=["claude-sonnet-4-20250514"],
    requires_checkpoint=["read:secret:*", "delete:*"],
)

# Agent requests authorization before acting
result = mint.delegate(plan, "claude-sonnet-4-20250514", "read:public:report.txt")

if result.ok:
    # proceed with action
    # result.receipt contains Ed25519 signed proof
    pass
else:
    # blocked: result.reason explains why
    pass

# Audit trail
for receipt in mint.audit(plan):
    print(receipt.action, receipt.signature)
```

## How it works

1. **Plan issuance**: Human approves a scoped authorization plan. The plan specifies allowed actions (scope) and actions requiring escalation (checkpoints).

2. **Delegation**: Before executing an action, the agent calls `mint.delegate()`. AgentMint checks if the action matches the scope. If it matches a checkpoint pattern, it's blocked unless explicitly approved.

3. **Receipts**: Every successful delegation produces an Ed25519 signed receipt. Receipts chain back to the original plan. The chain is independently verifiable.
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

## Install
```bash
pip install agentmint
```

Or from source:
```bash
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
```

## Run the demo
```bash
export ANTHROPIC_API_KEY=your-key
python examples/mcp_real_demo.py
```

The demo shows Claude attempting to read files with AgentMint gating access. Secrets are blocked. Public files are read. Every action has a receipt.

## Status

Early stage. Core protocol works. Looking for real use cases.

If you're building agents that need scoped permissions — file access, API calls, actions on behalf of users — I want to hear from you.

## Contact

[linkedin.com/in/anikethmaddipati](https://linkedin.com/in/anikethmaddipati)

