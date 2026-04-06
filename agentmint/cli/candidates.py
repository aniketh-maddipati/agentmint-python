"""
ToolCandidate — the normalized record every framework detector emits.

Scope syntax matches the SDK's patterns.py: colon-separated segments,
trailing :* for hierarchy wildcards.

    "tool:get_weather"      — exact action
    "tool:*"                — all tools
    "s3:read:reports:*"     — all report reads
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import List, Optional


# ── Verb → operation mapping ─────────────────────────────────────

_PATTERNS = [
    ("delete",  re.compile(r"^(delete|remove|drop|purge|destroy|revoke)_", re.I)),
    ("exec",    re.compile(r"^(execute|run|invoke|call|trigger|dispatch|send|emit)_", re.I)),
    ("network", re.compile(r"^(http|request|api|webhook|ping|curl)_", re.I)),
    ("write",   re.compile(r"^(write|save|store|create|insert|update|upsert|put|set|upload|post)_", re.I)),
    ("read",    re.compile(r"^(get|fetch|load|read|search|query|list|find|lookup|retrieve|check|inspect|describe)_", re.I)),
]

_VERB_PREFIX = re.compile(
    r"^(get|fetch|load|read|search|query|list|find|lookup|retrieve|check|"
    r"inspect|describe|write|save|store|create|insert|update|upsert|put|"
    r"set|upload|post|delete|remove|drop|purge|destroy|revoke|execute|"
    r"run|invoke|call|trigger|dispatch|send|emit|http|request|api|"
    r"webhook|ping|curl)_", re.I,
)


def guess_operation(name: str) -> str:
    """First match wins — order matters (delete before write)."""
    for op, pat in _PATTERNS:
        if pat.search(name):
            return op
    return "unknown"


def guess_resource(name: str) -> str:
    """Strip verb prefix → resource noun. CamelCase → colon-separated."""
    remainder = _VERB_PREFIX.sub("", name)
    if remainder and remainder != name:
        return remainder.replace("_", ":").lower()
    if name[0:1].isupper():
        cleaned = re.sub(r"Tool$", "", name)
        cleaned = re.sub(r"([A-Z])", r"_\1", cleaned).strip("_").lower()
        if cleaned:
            return cleaned.replace("_", ":")
    return "*"


def suggest_scope(name: str, operation: str, resource: str) -> str:
    """Build scope using the SDK's syntax: tool:<name> for known tools,
    operation:resource:* for inferred scopes."""
    # For named tools, use tool:<name> — matches how the real SDK does it
    # (see examples/openai_agents_receipts_demo and crewai_demo)
    return f"tool:{name}"


@dataclass
class ToolCandidate:
    """A single detected tool-call site in the codebase."""

    file: str
    line: int
    framework: str          # langgraph | openai-sdk | crewai | mcp | adk | raw
    symbol: str             # function or class name
    boundary: str           # "definition" or "registration"
    operation_guess: str = ""
    resource_guess: str = ""
    confidence: str = "high"
    scope_suggestion: str = ""
    detection_rule: str = ""
    base_classes: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.operation_guess:
            self.operation_guess = guess_operation(self.symbol)
        if not self.resource_guess:
            self.resource_guess = guess_resource(self.symbol)
        if not self.scope_suggestion:
            self.scope_suggestion = suggest_scope(
                self.symbol, self.operation_guess, self.resource_guess
            )

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def short_rule(self) -> str:
        return self.detection_rule or self.boundary
