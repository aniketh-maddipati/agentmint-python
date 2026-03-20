"""Unified scope pattern matching for AgentMint.

One behaviour, one implementation, one set of tests.

Patterns:
    *              matches everything
    read:reports:* matches read:reports, read:reports:quarterly, etc.
    read:reports   exact match only

The colon is the scope separator. Wildcards are only valid as
the final segment after a colon (`:*`). Bare `*` suffix
(e.g., `tts:standard*`) is NOT supported — use `tts:standard:*`
for hierarchy matching.
"""

from __future__ import annotations
from typing import Sequence

__all__ = ["matches_pattern", "in_scope"]


def matches_pattern(action: str, pattern: str) -> bool:
    """Match action against a scope pattern.

    Returns True if the action is covered by the pattern.
    """
    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        return action == prefix or action.startswith(prefix + ":")
    return action == pattern


def in_scope(action: str, patterns: Sequence[str]) -> bool:
    """Return True if action matches any pattern in the list."""
    return any(matches_pattern(action, p) for p in patterns)
