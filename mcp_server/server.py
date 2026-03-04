"""AgentMint MCP Server - Cryptographic authorization for AI agents."""
import os
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from agentmint import AgentMint

mcp = FastMCP("AgentMint")
_mint = AgentMint(quiet=True)
_plans = {}

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
    """Human approves a scoped authorization plan for agents."""
    plan = _mint.issue_plan(
        action=action,
        user=user,
        scope=scope,
        delegates_to=delegates_to,
        requires_checkpoint=requires_checkpoint or [],
        max_depth=max_depth,
        ttl=min(max(ttl, 1), 300),
    )
    _plans[plan.id] = plan
    return {"plan_id": plan.id, "scope": scope, "delegates_to": delegates_to}

@mcp.tool()
def agentmint_request_authorization(plan_id: str, agent: str, action: str) -> dict:
    """Agent requests authorization before taking an action."""
    plan = _plans.get(plan_id)
    if not plan:
        return {"authorized": False, "reason": "plan_not_found"}
    if plan.is_expired:
        return {"authorized": False, "reason": "plan_expired"}
    result = _mint.delegate(plan, agent, action)
    if result.ok:
        return {"authorized": True, "receipt_id": result.receipt.short_id}
    return {"authorized": False, "reason": result.status.value}

@mcp.tool()
def agentmint_audit(plan_id: str = None) -> dict:
    """View authorization audit trail."""
    if plan_id:
        plan = _plans.get(plan_id)
        if not plan:
            raise ToolError(f"Plan not found: {plan_id}")
        return {"receipts": [{"id": r.short_id, "sub": r.sub, "action": r.action} for r in _mint.audit(plan)]}
    return {"plans": list(_plans.keys())}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    mcp.run(transport="sse", host="0.0.0.0", port=port)
