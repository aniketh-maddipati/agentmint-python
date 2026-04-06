# AgentMint Demo — Clinical Ops Agent

## Setup (before the call)

```bash
cd ~/agentmint-python
pip install -e ".[cli]"
agentmint init demo/
python3 demo/agent_governed.py
rm -rf agentmint-evidence agentmint.yaml   # clean for live run
```

## The Demo (3 minutes)

### Beat 1 — The ungoverned agent (~30s)

```bash
cat demo/agent.py
```

> "Production agent on the OpenAI Agents SDK. Four tools — patient
> records, payments, notifications, audit log. Zero governance."

Point at `fetch_patient_record` (PHI) and `charge_customer` (payments).

### Beat 2 — agentmint init scans it (~60s)

```bash
agentmint init demo/
```

1. "Found 8 tool calls across 1 file" — 4 definitions + 4 registrations, all high confidence openai-sdk
2. "Heads up" — flagged charge_customer and send_notification as write ops
3. Generated config — scopes from the scan, all facts
4. Plan scaffold — copy-paste starter code

If asked: "LibCST — full AST, not regex. Detects CrewAI, OpenAI Agents SDK, LangChain, MCP."

### Beat 3 — Governed agent + evidence (~90s)

```bash
python3 demo/agent_governed.py
```

1. Tools 1-2: clean, 0 threats
2. Tool 3: **Shield catches prompt injection** — BLOCKED=True, shows ignore_instructions + data_exfil
3. Receipts: Ed25519 signed, SHA-256 chained, RFC 3161 timestamped
4. VERIFY.sh: **pure OpenSSL** verifies timestamps
5. verify_sigs.py: Ed25519 sigs verified

> "Auditor gets this zip, runs two commands, independently verifies
> every action. No AgentMint account, no cloud, no vendor lock-in."

## What This Shows

- `agentmint init` scans real code with LibCST, detects framework patterns, generates config
- 3 lines per tool call → signed, chained, timestamped evidence receipts
- Evidence is independently verifiable with OpenSSL + pynacl only

## What It Doesn't Show

Circuit breaker (rate limiting per agent), session tracking (drift detection + auto-escalation), multi-agent delegation (scope intersection), full Shield surface (SSNs, credit cards, AWS keys, JWTs, encoding anomalies). All implemented, all tested. Offer to show the code if asked.
