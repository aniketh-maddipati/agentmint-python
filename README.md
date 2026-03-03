# AgentMint

Cryptographic proof that a human approved an AI agent action.

## Install
```bash
pip install agentmint
```

## Quick Start
```python
from agentmint import AgentMint

mint = AgentMint()

# Human approves an action
receipt = mint.issue("deploy", "alice@co.com")

# Agent presents receipt before acting
if mint.verify(receipt):
    do_deploy()  # Authorized
```

## Delegation
```python
# Human approves a plan with scope limits
plan = mint.issue_plan(
    action="pipeline",
    user="alice@co.com",
    scope=["build:*", "test:*"],
    delegates_to=["build-agent", "test-agent"],
    requires_checkpoint=["deploy:*"],
)

# Agent requests authorization
result = mint.delegate(plan, "build-agent", "build:docker")
if result.ok:
    do_build(result.receipt)
elif result.needs_approval:
    wait_for_human()
```

## Features

- **Ed25519 signatures** – tamper-proof receipts
- **Single-use enforcement** – replay attacks blocked
- **Scoped delegation** – `build:*` matches `build:docker`
- **Checkpoints** – pause for human approval
- **Audit trails** – full authorization chain

## Run Demo
```bash
git clone https://github.com/aniketh-maddipati/agentmint-python
cd agentmint-python
pip install -e .
python examples/crewai_demo.py
```

## License

MIT
