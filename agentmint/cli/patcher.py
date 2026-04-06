"""
patcher.py — YAML generation + codemod patches.

Generates:
  - agentmint.yaml with audit-mode defaults
  - Import injection (from agentmint.notary import Notary)
  - Per-tool patch instructions matching real SDK patterns
"""
from __future__ import annotations

from typing import List

import yaml
import libcst as cst

from .candidates import ToolCandidate


# ═══════════════════════════════════════════════════════════════
# YAML generation
# ═══════════════════════════════════════════════════════════════

_RATE_LIMITS = {
    "write": "10/min", "delete": "10/min", "exec": "10/min",
    "network": "30/min",
}
_DEFAULT_RATE = "100/min"


def generate_yaml(candidates: List[ToolCandidate]) -> str:
    """Generate agentmint.yaml — all tools start in audit mode."""
    tools = {}
    for c in candidates:
        if c.symbol.startswith("<"):
            continue
        tools[c.symbol] = {
            "scope": c.scope_suggestion,
            "mode": "audit",
            "rate_limit": _RATE_LIMITS.get(c.operation_guess, _DEFAULT_RATE),
            "framework": c.framework,
            "file": c.file,
            "line": c.line,
        }

    config = {
        "version": 1,
        "mode": "audit",
        "notary": {"enabled": True, "export_path": "./evidence"},
        "signing": {
            "enabled": False,
            "algorithm": "ed25519",
            "key_path": "~/.agentmint/keys/default.pem",
        },
        "shield": {
            "enabled": True, "mode": "audit",
            "patterns": ["secrets", "pii", "injection"],
        },
        "circuit_breaker": {
            "enabled": True, "mode": "audit",
            "default_max_calls": 100, "default_window_seconds": 60,
        },
        "tools": tools,
    }
    return yaml.dump(config, default_flow_style=False, sort_keys=False, width=120)


# ═══════════════════════════════════════════════════════════════
# Import injection
# ═══════════════════════════════════════════════════════════════

def generate_import_patch(source: str) -> str:
    """Add `from agentmint.notary import Notary` if not already present.

    No visitors, no .walk(), no MetadataWrapper. Just parse → find
    last import index → insert → serialize.
    """
    if "import agentmint" in source or "from agentmint" in source:
        return source

    tree = cst.parse_module(source)

    # Find last import by iterating body directly
    last_import_idx = -1
    for i, stmt in enumerate(tree.body):
        if isinstance(stmt, cst.SimpleStatementLine):
            for s in stmt.body:
                if isinstance(s, (cst.Import, cst.ImportFrom)):
                    last_import_idx = i

    new_stmt = cst.parse_statement("from agentmint.notary import Notary\n")
    body = list(tree.body)
    body.insert(last_import_idx + 1 if last_import_idx >= 0 else 0, new_stmt)
    return tree.with_changes(body=body).code


# ═══════════════════════════════════════════════════════════════
# Patch instructions
# ═══════════════════════════════════════════════════════════════

def _notarise_snippet(scope: str, symbol: str) -> str:
    return (
        f'    # AgentMint: notarise this tool call\n'
        f'    notary.notarise(\n'
        f'        action="{scope}",\n'
        f'        agent="<agent_name>",\n'
        f'        plan=plan,\n'
        f'        evidence={{"tool": "{symbol}"}},\n'
        f'    )\n'
    )


def generate_patch_instructions(candidates: List[ToolCandidate]) -> List[dict]:
    """Generate per-tool patch instructions.

    Returns list of dicts: {file, line, symbol, action, code?, note?}
    """
    instructions = []
    for c in candidates:
        base = {"file": c.file, "line": c.line, "symbol": c.symbol}

        if c.confidence == "low":
            instructions.append({**base, "action": "manual_review",
                                 "note": "Low confidence — review manually"})
        elif c.boundary == "definition":
            action = ("add_notarise_to_run" if c.framework == "crewai" and c.base_classes
                      else "add_notarise_to_body")
            instructions.append({**base, "action": action,
                                 "code": _notarise_snippet(c.scope_suggestion, c.symbol)})
        else:
            instructions.append({**base, "action": "add_to_plan_scope",
                                 "code": f'    "{c.scope_suggestion}",  # {c.symbol}'})

    return instructions
