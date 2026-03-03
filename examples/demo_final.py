#!/usr/bin/env python3
"""AgentMint Demo"""

import os, sys, warnings
os.environ["OTEL_SDK_DISABLED"] = "true"
warnings.filterwarnings("ignore")
import logging
logging.getLogger().setLevel(logging.CRITICAL)

import boto3
from crewai import Agent, Task, Crew
from crewai.tools import BaseTool
from crewai.hooks import before_tool_call, ToolCallHookContext
from pydantic import BaseModel, Field
from typing import Type
from agentmint import AgentMint

BUCKET = "agentmint-demo-1772509489"

class S3Input(BaseModel):
    path: str = Field(description="S3 path")

class S3Reader(BaseTool):
    name: str = "s3_reader"
    description: str = "Read file from S3"
    args_schema: Type[BaseModel] = S3Input
    def _run(self, path: str) -> str:
        obj = boto3.client('s3').get_object(Bucket=BUCKET, Key=path)
        return obj['Body'].read().decode('utf-8')

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CrewAI agent reads credentials from S3
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

s3 = S3Reader()
analyst = Agent(role="analyst", goal="Read data", backstory="Analyst", tools=[s3], llm="gpt-4o-mini", verbose=True)
task = Task(description="Read 'confidential/credentials.txt' using s3_reader", expected_output="data", agent=analyst)
Crew(agents=[analyst], tasks=[task], verbose=True).kickoff()

print("""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
What CrewAI logged vs what's missing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Logged:                          Missing:
  Tool: s3_reader                  Who approved this?
  Args: credentials.txt            What was the authorized scope?
  Output: <keys>                   Cryptographic receipt?
                                   Verifiable later?

Auditor: "Who approved reading credentials.txt?"
You: "I don't know."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Same agent with AgentMint
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")

mint = AgentMint(quiet=True)

plan = mint.issue_plan(
    action="quarterly:analysis",
    user="manager@acme.com",
    scope=["s3:read:reports:*"],
    delegates_to=["analyst"],
    max_depth=2,
    ttl=300,
)

print(f"""Human authorization:
  user:   manager@acme.com
  scope:  s3:read:reports:*
  plan:   {plan.short_id}
  sig:    {plan.signature[:40]}...
""")

seen = set()

@before_tool_call
def gate(ctx: ToolCallHookContext) -> bool | None:
    if ctx.tool_name != "s3_reader":
        return None
    path = ctx.tool_input.get("path", "")
    if path in seen:
        return False
    seen.add(path)
    
    action = f"s3:read:{path.replace('/', ':')}"
    result = mint.delegate(parent=plan, agent="analyst", action=action)
    
    if result.ok:
        print(f"s3_reader({path})")
        print(f"  scope:   s3:read:reports:*")
        print(f"  action:  {action}")
        print(f"  result:  allowed")
        print(f"  receipt: {result.receipt.short_id}  sig: {result.receipt.signature[:24]}...\n")
        return None
    else:
        print(f"s3_reader({path})")
        print(f"  scope:   s3:read:reports:*")
        print(f"  action:  {action}")
        print(f"  result:  blocked\n")
        return False

analyst2 = Agent(role="analyst", goal="Read data", backstory="Analyst", tools=[s3], llm="gpt-4o-mini", verbose=False)
sys.stderr = open(os.devnull, 'w')

Crew(agents=[analyst2], tasks=[Task(description="Read 'reports/q4-summary.txt' using s3_reader", expected_output="data", agent=analyst2)], verbose=False).kickoff()

try:
    Crew(agents=[analyst2], tasks=[Task(description="Read 'confidential/credentials.txt' using s3_reader", expected_output="data", agent=analyst2)], verbose=False).kickoff()
except:
    pass

sys.stderr = sys.__stderr__

print(f"""━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Auditor: "Who approved reading q4-summary.txt?"
You: "manager@acme.com, receipt {plan.short_id}, Ed25519 signature."

Auditor: "Did the agent access credentials.txt?"
You: "It tried. Blocked. No receipt exists."

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Limits
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

AgentMint is authorization, not data classification.
If a secret is in an allowed file, it's still exposed.
If the agent leaks data in its response, AgentMint can't stop that.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
""")
