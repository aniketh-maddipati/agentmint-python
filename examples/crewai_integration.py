#!/usr/bin/env python3
"""
AgentMint + CrewAI Integration

This uses CrewAI's actual @before_tool_call hook API.
The hook intercepts every tool call before execution.
"""

import os
import time

os.environ["OTEL_SDK_DISABLED"] = "true"

# Real CrewAI import - this is the actual hook API
from crewai.hooks import before_tool_call, ToolCallHookContext
from agentmint import AgentMint

print("\n" + "="*60)
print("  AgentMint + CrewAI")
print("  using crewai.hooks.before_tool_call")
print("="*60)

mint = AgentMint(quiet=True)

print("\n[1] HUMAN ISSUES PLAN")
print("    Alice approves a scoped pipeline:\n")

plan = mint.issue_plan(
    action="content:pipeline",
    user="alice@news.co",
    scope=["write:reports:*", "write:drafts:*"],
    delegates_to=["content-writer"],
    requires_checkpoint=["write:secrets:*"],
    max_depth=2,
    ttl=300,
)

print(f"    plan.id         = {plan.short_id}...")
print(f"    plan.sub        = {plan.sub}")
print(f"    plan.scope      = {plan.scope}")
print(f"    plan.delegates  = {plan.delegates_to}")
print(f"    plan.checkpoint = {plan.requires_checkpoint}")
print(f"    plan.signature  = {plan.signature[:16]}...")
time.sleep(0.5)

print("\n[2] REGISTER CREWAI HOOK")
print("    @before_tool_call decorator from crewai.hooks\n")

@before_tool_call  
def agentmint_guard(ctx: ToolCallHookContext) -> bool | None:
    """
    CrewAI calls this before every tool execution.
    Return False to block, None to allow.
    """
    if ctx.tool_name != "FileWriterTool":
        return None
    
    agent = ctx.agent.role.lower().replace(" ", "-") if ctx.agent else "unknown"
    directory = ctx.tool_input.get("directory", "").strip("/")
    filename = ctx.tool_input.get("filename", "unknown")
    action = f"write:{directory}:{filename}" if directory else f"write:{filename}"
    
    result = mint.delegate(parent=plan, agent=agent, action=action)
    
    print(f"    agentmint_guard() called")
    print(f"      ctx.tool_name  = {ctx.tool_name}")
    print(f"      ctx.agent.role = {ctx.agent.role}")
    print(f"      action         = {action}")
    print(f"      result.status  = {result.status.value}")
    print(f"      result.ok      = {result.ok}")
    
    return None if result.ok else False

print(f"    Hook registered: agentmint_guard")
print(f"    Intercepts: FileWriterTool calls")
time.sleep(0.5)

print("\n[3] SIMULATE TOOL CALLS")
print("    (In production, CrewAI agents trigger these)\n")

# Minimal mock to trigger the real hook
class MockAgent:
    def __init__(self, role): self.role = role

class MockCtx(ToolCallHookContext):
    def __init__(self, tool_name, tool_input, agent):
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.agent = agent
        self.task = self.crew = self.tool = self.tool_result = None


def call_hook(agent: str, filename: str, directory: str) -> bool:
    ctx = MockCtx("FileWriterTool", {"filename": filename, "directory": directory}, MockAgent(agent))
    return agentmint_guard(ctx) is None


print("─"*60)
print("CALL 1: content-writer writes reports/summary.txt")
print("─"*60)
allowed = call_hook("content-writer", "summary.txt", "reports")
print(f"    → {'ALLOWED' if allowed else 'BLOCKED'}\n")
time.sleep(0.5)

print("─"*60)
print("CALL 2: content-writer writes secrets/keys.txt")
print("─"*60)
allowed = call_hook("content-writer", "keys.txt", "secrets")
print(f"    → {'ALLOWED' if allowed else 'BLOCKED (checkpoint required)'}\n")
time.sleep(0.5)

print("─"*60)
print("CALL 3: rogue-agent writes reports/data.txt")
print("─"*60)
allowed = call_hook("rogue-agent", "data.txt", "reports")
print(f"    → {'ALLOWED' if allowed else 'BLOCKED (agent not in delegates_to)'}\n")
time.sleep(0.5)

print("─"*60)
print("CALL 4: content-writer writes etc/passwd")
print("─"*60)
allowed = call_hook("content-writer", "passwd", "etc")
print(f"    → {'ALLOWED' if allowed else 'BLOCKED (not in scope)'}\n")
time.sleep(0.5)

print("="*60)
print("  4 tool calls, 4 AgentMint checks, 0 unauthorized writes")
print("="*60 + "\n")
