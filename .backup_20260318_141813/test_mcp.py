"""Quick test of AgentMint MCP server."""
import asyncio
from fastmcp import Client
from mcp_server.server import mcp

async def test():
    async with Client(mcp) as client:
        # Issue a plan
        result = await client.call_tool("agentmint_issue_plan", {
            "user": "alice@company.com",
            "action": "file:ops",
            "scope": ["read:docs:*"],
            "delegates_to": ["file-agent"]
        })
        print("Issue plan:", result.data)
        
        plan_id = result.data["plan_id"]
        
        # Request authorization (should pass)
        result = await client.call_tool("agentmint_authorize", {
            "plan_id": plan_id,
            "agent": "file-agent",
            "action": "read:docs:report.pdf"
        })
        print("Auth (in scope):", result.data)
        
        # Request authorization (should fail - out of scope)
        result = await client.call_tool("agentmint_authorize", {
            "plan_id": plan_id,
            "agent": "file-agent",
            "action": "delete:docs:report.pdf"
        })
        print("Auth (out of scope):", result.data)
        
        # Request authorization (should fail - wrong agent)
        result = await client.call_tool("agentmint_authorize", {
            "plan_id": plan_id,
            "agent": "rogue-agent",
            "action": "read:docs:report.pdf"
        })
        print("Auth (wrong agent):", result.data)

asyncio.run(test())
