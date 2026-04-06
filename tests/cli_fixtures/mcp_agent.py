"""MCP server with tool registrations — matches mcp_server/server.py patterns."""
from mcp.server import Server
from mcp.types import Tool

server = Server("agentmint-mcp")


@server.tool()
async def read_receipt(receipt_id: str) -> str:
    """Read a notarised receipt by ID."""
    return f"Receipt {receipt_id}"


@server.tool()
async def list_receipts(plan_id: str) -> list:
    """List all receipts for a plan."""
    return []


@server.tool()
async def verify_chain(evidence_path: str) -> dict:
    """Verify the hash chain of an evidence package."""
    return {"valid": True}


def helper(x):
    """Not a tool."""
    return x
