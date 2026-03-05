"""
AgentMint MCP Server
Cryptographic authorization for AI agents.
https://agent-mint.dev
"""

import os
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from agentmint import AgentMint

# ─────────────────────────────────────────────────────────────
# Server setup
# ─────────────────────────────────────────────────────────────

mcp = FastMCP("AgentMint")
mint = AgentMint(quiet=True)
plans = {}

# ─────────────────────────────────────────────────────────────
# Tools
# ─────────────────────────────────────────────────────────────

@mcp.tool()
def agentmint_issue_plan(
    user: str,
    action: str,
    scope: list[str],
    delegates_to: list[str],
    requires_checkpoint: list[str] = None,
    ttl: int = 300,
    max_depth: int = 2,
) -> dict:
    """Human approves a scoped authorization plan."""
    plan = mint.issue_plan(
        action=action,
        user=user,
        scope=scope,
        delegates_to=delegates_to,
        requires_checkpoint=requires_checkpoint or [],
        max_depth=max_depth,
        ttl=min(max(ttl, 1), 300),
    )
    plans[plan.id] = plan
    return {"plan_id": plan.id, "scope": scope, "delegates_to": delegates_to}


@mcp.tool()
def agentmint_authorize(plan_id: str, agent: str, action: str) -> dict:
    """Agent requests authorization before acting."""
    plan = plans.get(plan_id)
    
    if not plan:
        return {"authorized": False, "reason": "plan_not_found"}
    if plan.is_expired:
        return {"authorized": False, "reason": "plan_expired"}
    
    result = mint.delegate(plan, agent, action)
    
    if result.ok:
        return {"authorized": True, "receipt_id": result.receipt.short_id}
    return {"authorized": False, "reason": result.status.value}


@mcp.tool()
def agentmint_audit(plan_id: str = None) -> dict:
    """View authorization audit trail."""
    if not plan_id:
        return {"plans": list(plans.keys())}
    
    plan = plans.get(plan_id)
    if not plan:
        raise ToolError(f"Plan not found: {plan_id}")
    
    receipts = [
        {"id": r.short_id, "agent": r.sub, "action": r.action}
        for r in mint.audit(plan)
    ]
    return {"plan_id": plan_id, "receipts": receipts}


# ─────────────────────────────────────────────────────────────
# Run with HTTP transport (Streamable HTTP - newer standard)
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    mcp.run(transport="http", host="0.0.0.0", port=port)
