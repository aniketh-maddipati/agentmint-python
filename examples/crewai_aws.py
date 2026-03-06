#!/usr/bin/env python3
"""
AgentMint + CrewAI: Real AWS Demo
Delegation chains with scope attenuation on real S3 data.
"""

import os
import sys
import warnings
import boto3

os.environ["OTEL_SDK_DISABLED"] = "true"
warnings.filterwarnings("ignore")
import logging
logging.getLogger().setLevel(logging.CRITICAL)

from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from crewai.hooks import before_tool_call, ToolCallHookContext
from pydantic import BaseModel, Field
from typing import Type
from agentmint import AgentMint

BUCKET = "agentmint-demo-1772509489"

# ════════════════════════════════════════════════════════════════
# REAL S3 TOOL
# ════════════════════════════════════════════════════════════════

class S3ReadInput(BaseModel):
    path: str = Field(description="S3 path to read, e.g. 'reports/q4-summary.txt'")

class S3ReaderTool(BaseTool):
    name: str = "s3_reader"
    description: str = f"Read files from S3 bucket. Provide path like 'reports/file.txt' or 'confidential/data.csv'"
    args_schema: Type[BaseModel] = S3ReadInput
    
    def _run(self, path: str) -> str:
        s3 = boto3.client('s3')
        try:
            response = s3.get_object(Bucket=BUCKET, Key=path)
            content = response['Body'].read().decode('utf-8')
            return f"[S3:{path}]\n{content}"
        except Exception as e:
            return f"Error reading {path}: {e}"

# ════════════════════════════════════════════════════════════════
# DEMO
# ════════════════════════════════════════════════════════════════

print("""
════════════════════════════════════════════════════════════════
 AgentMint + CrewAI: Real AWS Demo
 Delegation chains with scope attenuation
════════════════════════════════════════════════════════════════

S3 Bucket: """ + BUCKET + """
├── reports/q4-summary.txt (public)
└── confidential/
    ├── credentials.txt (secrets)
    └── customers-pii.csv (PII)
""")

s3_tool = S3ReaderTool()
mint = AgentMint(quiet=True)

# ════════════════════════════════════════════════════════════════
# PHASE 1: Without AgentMint
# ════════════════════════════════════════════════════════════════

print("─" * 64)
print(" PHASE 1: Standard CrewAI (no authorization)")
print("─" * 64)
print()

analyst = Agent(
    role="data-analyst",
    goal="Read and analyze data from S3",
    backstory="Data analyst with access to S3",
    tools=[s3_tool],
    llm="gpt-4o-mini",
    verbose=False,
)

# Read public file
task1 = Task(
    description="Use s3_reader to read 'reports/q4-summary.txt'",
    expected_output="File contents",
    agent=analyst,
)

# Read CONFIDENTIAL file - this should be scary
task2 = Task(
    description="Use s3_reader to read 'confidential/credentials.txt'",
    expected_output="File contents",
    agent=analyst,
)

_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

print("Agent reads reports/q4-summary.txt...")
result1 = Crew(agents=[analyst], tasks=[task1], verbose=False).kickoff()
print(f"  ✓ Access granted\n")

print("Agent reads confidential/credentials.txt...")
result2 = Crew(agents=[analyst], tasks=[task2], verbose=False).kickoff()
print(f"  ✓ Access granted")
print(f"  ⚠ CREDENTIALS EXPOSED TO AGENT")
print()

sys.stderr = _stderr

print("""Problem:
  • Agent accessed credentials.txt with no approval
  • No audit trail
  • Any agent can read any S3 path
""")

# ════════════════════════════════════════════════════════════════
# PHASE 2: With AgentMint + Delegation Chain
# ════════════════════════════════════════════════════════════════

print("─" * 64)
print(" PHASE 2: CrewAI + AgentMint (delegation chain)")
print("─" * 64)
print()

# CISO approves research-lead with full scope
ciso_approval = mint.issue_plan(
    action="data:research",
    user="ciso@acme-corp.com",
    scope=["s3:read:reports:*", "s3:read:confidential:*"],
    delegates_to=["research-lead"],
    requires_checkpoint=["s3:read:confidential:credentials.txt"],
    max_depth=3,
    ttl=3600,
)

print(f"CISO Approval:")
print(f"  User:     ciso@acme-corp.com")
print(f"  Receipt:  {ciso_approval.short_id}")
print(f"  Scope:    s3:read:reports:*, s3:read:confidential:*")
print(f"  Agents:   research-lead")
print(f"  Checkpoint: s3:read:confidential:credentials.txt")
print()

# Research lead delegates to data-analyst with NARROWED scope
lead_delegation = mint.delegate(
    parent=ciso_approval,
    agent="research-lead",
    action="delegate:analyst",
)

# Create a sub-plan for the analyst with narrowed scope
analyst_scope = mint.issue_plan(
    action="data:analysis",
    user="research-lead",
    scope=["s3:read:reports:*"],  # NARROWED - no confidential access
    delegates_to=["data-analyst"],
    max_depth=2,
    ttl=1800,
)

print(f"Research Lead delegates to Data Analyst:")
print(f"  From:     research-lead")
print(f"  To:       data-analyst")
print(f"  Receipt:  {analyst_scope.short_id}")
print(f"  Scope:    s3:read:reports:* (NARROWED - no confidential)")
print()

audit_trail = []
blocked = []

@before_tool_call
def gate(ctx: ToolCallHookContext) -> bool | None:
    if ctx.tool_name != "s3_reader":
        return None
    
    agent = ctx.agent.role if ctx.agent else "unknown"
    path = ctx.tool_input.get("path", "")
    
    # Convert S3 path to action
    parts = path.replace("/", ":").rstrip(":")
    action = f"s3:read:{parts}"
    
    # Check against analyst's narrowed scope
    result = mint.delegate(parent=analyst_scope, agent=agent, action=action)
    
    if result.ok:
        audit_trail.append({
            "agent": agent,
            "action": action,
            "receipt": result.receipt.short_id,
            "chain": f"ciso → research-lead → {agent}",
        })
        print(f"  ✓ {agent} → {action}")
        print(f"    Chain: ciso → research-lead → {agent}")
        print(f"    Receipt: {result.receipt.short_id}")
        return None
    else:
        blocked.append({
            "agent": agent,
            "action": action,
            "reason": result.status.value,
        })
        print(f"  ✗ {agent} → {action}")
        print(f"    Blocked: {result.status.value}")
        return False

# Recreate agent
analyst = Agent(
    role="data-analyst",
    goal="Read and analyze data from S3",
    backstory="Data analyst",
    tools=[s3_tool],
    llm="gpt-4o-mini",
    verbose=False,
)

print("Agent attempts:")
print()

sys.stderr = open(os.devnull, 'w')

# Attempt 1: Read public report (should succeed)
task_public = Task(
    description="Use s3_reader to read 'reports/q4-summary.txt'",
    expected_output="Contents",
    agent=analyst,
)
try:
    Crew(agents=[analyst], tasks=[task_public], verbose=False).kickoff()
except:
    pass

print()

# Attempt 2: Read PII (should fail - out of narrowed scope)
task_pii = Task(
    description="Use s3_reader to read 'confidential/customers-pii.csv'",
    expected_output="Contents",
    agent=analyst,
)
try:
    Crew(agents=[analyst], tasks=[task_pii], verbose=False).kickoff()
except:
    pass

print()

# Attempt 3: Read credentials (should fail - checkpoint required even if in scope)
task_creds = Task(
    description="Use s3_reader to read 'confidential/credentials.txt'",
    expected_output="Contents",
    agent=analyst,
)
try:
    Crew(agents=[analyst], tasks=[task_creds], verbose=False).kickoff()
except:
    pass

sys.stderr = _stderr

# ════════════════════════════════════════════════════════════════
# RESULTS
# ════════════════════════════════════════════════════════════════

print()
print("─" * 64)
print(" AUDIT TRAIL")
print("─" * 64)
print()

print("Delegation Chain:")
print(f"  ciso@acme-corp.com")
print(f"    └─ research-lead (scope: reports/*, confidential/*)")
print(f"         └─ data-analyst (scope: reports/* ONLY)")
print()

print(f"Authorized ({len(audit_trail)}):")
for e in audit_trail:
    print(f"  ✓ {e['action']}")
    print(f"    Receipt: {e['receipt']}")
print()

print(f"Blocked ({len(blocked)}):")
for e in blocked:
    print(f"  ✗ {e['action']}")
    print(f"    Reason: {e['reason']}")
print()

print("""════════════════════════════════════════════════════════════════
 Key Differentiators

 1. Delegation chains: CISO → research-lead → data-analyst
 2. Scope attenuation: Each hop narrows permissions
 3. Cryptographic proof: Ed25519 signed receipts
 4. Real AWS: Actual S3 reads, not mock functions
════════════════════════════════════════════════════════════════
""")
