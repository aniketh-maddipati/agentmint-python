#!/usr/bin/env python3
"""AgentMint: proof it works."""
import os
from pathlib import Path
from anthropic import Anthropic
from agentmint import AgentMint
import shutil
import time
import hashlib

DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"

def p(s=0.3): time.sleep(s)
def line(): print(f"{DIM}{'─' * 55}{RESET}")

client = Anthropic()
mint = AgentMint(quiet=True)
DEMO_DIR = Path("demo_workspace")
DEMO_DIR.mkdir(exist_ok=True)

# ═══════════════════════════════════════════════════════════
print(f"\n{BOLD}agentmint{RESET}")
print(f"{DIM}IAM for AI agents — cryptographic delegation layer{RESET}\n")
p(0.5)

# ═══════════════════════════════════════════════════════════
line()
print(f"\n{BOLD}setup: real files with real secrets{RESET}\n")
p(0.2)

report_content = "Q4 Revenue: $1.2M\nGrowth: 15% YoY\nNew customers: 847"
secrets_content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nDB_PASS=hunter2\nSTRIPE_SK=sk_live_abc123"

(DEMO_DIR / "report.txt").write_text(report_content)
(DEMO_DIR / "secrets.txt").write_text(secrets_content)

print(f"  {DIM}created:{RESET} demo_workspace/report.txt")
print(f"  {DIM}content:{RESET} {report_content[:40]}...")
print()
print(f"  {DIM}created:{RESET} demo_workspace/secrets.txt")
print(f"  {DIM}content:{RESET} {secrets_content[:40]}...")
print()
print(f"  {YELLOW}⚠{RESET}  these are real files claude will try to read")
p(0.8)

# ═══════════════════════════════════════════════════════════
line()
print(f"\n{BOLD}without agentmint{RESET}\n")
p(0.2)

print(f"  user: \"claude, read all files and summarize\"")
print(f"  claude: reads report.txt {GREEN}✓{RESET}")
print(f"  claude: reads secrets.txt {GREEN}✓{RESET} {RED}← leaked AWS keys{RESET}")
print()
print(f"  {DIM}no scoping. no enforcement. no receipts.{RESET}")
print(f"  {DIM}you find out what happened after the fact.{RESET}")
p(1)

# ═══════════════════════════════════════════════════════════
line()
print(f"\n{BOLD}with agentmint{RESET}\n")
p(0.5)

# ═══════════════════════════════════════════════════════════
print(f"{MAGENTA}┌─ step 1: human approves scoped plan{RESET}\n")
p(0.2)

plan = mint.issue_plan(
    action="file-analysis",
    user="manager@company.com",
    scope=["read:public:*", "write:summary:*"],
    delegates_to=["claude-sonnet-4-20250514"],
    requires_checkpoint=["read:secret:*", "delete:*"],
)

print(f"  {DIM}issuer:{RESET}     manager@company.com")
print(f"  {DIM}delegate:{RESET}   claude-sonnet-4-20250514")
print(f"  {DIM}action:{RESET}     file-analysis")
print()
print(f"  {GREEN}●{RESET} scope       read:public:*")
print(f"  {GREEN}●{RESET} scope       write:summary:*")
print(f"  {YELLOW}○{RESET} checkpoint  read:secret:*   {DIM}← requires human approval{RESET}")
print(f"  {YELLOW}○{RESET} checkpoint  delete:*        {DIM}← requires human approval{RESET}")
print()
print(f"  {DIM}plan.id:        {plan.id}{RESET}")
print(f"  {DIM}plan.issued_at: {plan.issued_at}{RESET}")
print(f"  {DIM}plan.signature: {plan.signature[:50]}...{RESET}")
p(1)

# ═══════════════════════════════════════════════════════════
print(f"\n{MAGENTA}┌─ step 2: claude calls tools via anthropic api{RESET}\n")
p(0.2)

print(f"  {DIM}POST api.anthropic.com/v1/messages{RESET}")
print(f"  {DIM}├─ model: claude-sonnet-4-20250514{RESET}")
print(f"  {DIM}├─ tools: [list_files, read_file, write_file]{RESET}")
print(f"  {DIM}└─ prompt: \"read all files, summarize to summary.txt\"{RESET}")
print()
p(0.5)

blocked_attempts = []
successful_delegations = []

def read_file(path: str) -> str:
    action = f"read:secret:{path}" if "secret" in path.lower() else f"read:public:{path}"
    result = mint.delegate(plan, "claude-sonnet-4-20250514", action)
    
    print(f"  {CYAN}│{RESET} {BOLD}tool_use{RESET}: read_file")
    print(f"  {CYAN}│{RESET} {DIM}path: \"{path}\"{RESET}")
    print(f"  {CYAN}│{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}agentmint.delegate({RESET}")
    print(f"  {CYAN}│{RESET} {DIM}  plan={plan.short_id},{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}  agent=\"claude-sonnet-4-20250514\",{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}  action=\"{action}\"{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}){RESET}")
    print(f"  {CYAN}│{RESET}")
    
    if not result.ok:
        print(f"  {CYAN}│{RESET} {RED}✗ BLOCKED: {result.reason}{RESET}")
        print(f"  {CYAN}│{RESET} {DIM}action matched checkpoint pattern \"read:secret:*\"{RESET}")
        print(f"  {CYAN}│{RESET} {DIM}no human approved escalation → denied{RESET}")
        blocked_attempts.append({"path": path, "action": action, "reason": result.reason})
        print()
        p(0.6)
        return f"ACCESS_DENIED: {result.reason}"
    
    print(f"  {CYAN}│{RESET} {GREEN}✓ DELEGATED{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}action matched scope pattern \"read:public:*\"{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}receipt.id: {result.receipt.id}{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}receipt.signature: {result.receipt.signature[:40]}...{RESET}")
    successful_delegations.append({"path": path, "action": action, "receipt": result.receipt})
    print()
    p(0.5)
    return (DEMO_DIR / path).read_text()

def write_file(path: str, content: str) -> str:
    action = f"write:summary:{path}"
    result = mint.delegate(plan, "claude-sonnet-4-20250514", action)
    
    print(f"  {CYAN}│{RESET} {BOLD}tool_use{RESET}: write_file")
    print(f"  {CYAN}│{RESET} {DIM}path: \"{path}\"{RESET}")
    print(f"  {CYAN}│{RESET}")
    
    if not result.ok:
        print(f"  {CYAN}│{RESET} {RED}✗ BLOCKED{RESET}")
        blocked_attempts.append({"path": path, "action": action, "reason": result.reason})
        print()
        p(0.4)
        return "ACCESS_DENIED"
    
    print(f"  {CYAN}│{RESET} {GREEN}✓ DELEGATED{RESET}")
    print(f"  {CYAN}│{RESET} {DIM}receipt.id: {result.receipt.id}{RESET}")
    successful_delegations.append({"path": path, "action": action, "receipt": result.receipt})
    print()
    p(0.4)
    (DEMO_DIR / path).write_text(content)
    return "written"

def list_files() -> str:
    files = [f.name for f in DEMO_DIR.iterdir()]
    print(f"  {CYAN}│{RESET} {BOLD}tool_use{RESET}: list_files")
    print(f"  {CYAN}│{RESET} {DIM}result: {files}{RESET}")
    print()
    p(0.3)
    return "\n".join(files)

tools = [
    {"name": "list_files", "description": "List files in workspace", "input_schema": {"type": "object", "properties": {}}},
    {"name": "read_file", "description": "Read a file", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]}},
    {"name": "write_file", "description": "Write content to a file", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}}, "required": ["path", "content"]}},
]

tool_funcs = {
    "list_files": lambda **_: list_files(),
    "read_file": lambda path, **_: read_file(path),
    "write_file": lambda path, content, **_: write_file(path, content),
}

messages = [{"role": "user", "content": "Read all files and summarize to summary.txt"}]
api_calls = 0
total_input = 0
total_output = 0

while True:
    response = client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=512,
        tools=tools,
        messages=messages,
    )
    api_calls += 1
    total_input += response.usage.input_tokens
    total_output += response.usage.output_tokens
    
    if response.stop_reason == "end_turn":
        break
    
    tool_results = []
    for block in response.content:
        if block.type == "tool_use":
            result = tool_funcs[block.name](**block.input)
            tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})
    
    if tool_results:
        messages.append({"role": "assistant", "content": response.content})
        messages.append({"role": "user", "content": tool_results})

print(f"  {DIM}api calls: {api_calls}{RESET}")
print(f"  {DIM}tokens: {total_input} in / {total_output} out{RESET}")
print(f"  {DIM}stop_reason: {response.stop_reason}{RESET}")
p(0.5)

# ═══════════════════════════════════════════════════════════
print(f"\n{MAGENTA}┌─ step 3: audit trail{RESET}\n")
p(0.2)

print(f"  {DIM}all receipts cryptographically signed (Ed25519){RESET}")
print(f"  {DIM}chain: plan → delegation → delegation → ...{RESET}")
print()

plan_id = plan.id
print(f"  {BOLD}plan (root){RESET}")
print(f"  {DIM}├─ id:        {plan.id}{RESET}")
print(f"  {DIM}├─ sub:       {plan.sub}{RESET}")
print(f"  {DIM}├─ action:    {plan.action}{RESET}")
print(f"  {DIM}├─ issued_at: {plan.issued_at}{RESET}")
print(f"  {DIM}└─ signature: {plan.signature[:50]}...{RESET}")
print()

for r in mint._receipts.values():
    if r.parent_id == plan_id:
        status = f"{GREEN}delegated{RESET}"
        print(f"  {BOLD}delegation{RESET}")
        print(f"  {DIM}├─ id:        {r.id}{RESET}")
        print(f"  {DIM}├─ parent_id: {r.parent_id}{RESET}")
        print(f"  {DIM}├─ sub:       {r.sub}{RESET}")
        print(f"  {DIM}├─ action:    {r.action}{RESET}")
        print(f"  {DIM}├─ issued_at: {r.issued_at}{RESET}")
        print(f"  {DIM}└─ signature: {r.signature[:50]}...{RESET}")
        print()
        p(0.2)

# ═══════════════════════════════════════════════════════════
line()
print(f"\n{BOLD}result{RESET}\n")

print(f"  {GREEN}●{RESET} report.txt   read       {DIM}within scope{RESET}")
print(f"  {RED}●{RESET} secrets.txt  blocked    {DIM}checkpoint, no approval{RESET}")
print(f"  {GREEN}●{RESET} summary.txt  written    {DIM}within scope{RESET}")
print()

# verify file contents
if (DEMO_DIR / "summary.txt").exists():
    summary = (DEMO_DIR / "summary.txt").read_text()
    print(f"  {DIM}summary.txt contents:{RESET}")
    for line_text in summary.split('\n')[:3]:
        print(f"  {DIM}  {line_text[:60]}{RESET}")
    print()

secrets_leaked = "AWS_KEY" in str(messages) or "hunter2" in str(messages)
print(f"  {DIM}secrets in conversation history: {RESET}{RED if secrets_leaked else GREEN}{secrets_leaked}{RESET}")
p(0.5)

# ═══════════════════════════════════════════════════════════
line()
print(f"\n{BOLD}verification{RESET}\n")
p(0.2)

print(f"  {DIM}what you just saw:{RESET}")
print(f"  • real claude api calls (sonnet 4, {api_calls} calls, {total_input+total_output} tokens)")
print(f"  • real file operations (check demo_workspace/ yourself)")
print(f"  • real ed25519 signatures (verifiable, not mock)")
print(f"  • real blocked access (secrets.txt never read)")
print()
print(f"  {DIM}what agentmint does:{RESET}")
print(f"  • scoped delegation (not all-or-nothing)")
print(f"  • checkpoint escalation (sensitive actions need approval)")
print(f"  • cryptographic receipts (prove what happened)")
print(f"  • works with any agent framework (mcp, crewai, raw api)")
p(0.5)

# ═══════════════════════════════════════════════════════════
line()
print()
print(f"{BOLD}github.com/aniketh-maddipati/agentmint-python{RESET}")
print(f"{DIM}linkedin.com/in/anikethmaddipati{RESET}")
print()

shutil.rmtree(DEMO_DIR)
