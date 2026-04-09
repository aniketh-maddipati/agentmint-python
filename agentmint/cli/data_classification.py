"""
Data classification for AI agent tool call parameters and responses.

Every piece of data flowing through a tool call gets classified:

    PUBLIC       Safe to log, cache, return to user
    INTERNAL     Company data — ok in agent context, mask in logs
    CONFIDENTIAL Salary, API keys, passwords — mask in output
    RESTRICTED   PII, credentials, health data — triggers auto-escalation

When RESTRICTED data is detected in a tool call, the tool's risk
level auto-escalates to CRITICAL regardless of its default level.
This is OWASP AI Agent Security Cheat Sheet §8 (Data Protection).

The classification result is embedded in every signed receipt as
a `data_classification` field. Auditors can prove that sensitive
data was detected and flagged at the tool boundary.

How it works:

    1. Walk every string field in the tool call dict (params or response)
    2. Match each string against regex patterns (SSN, credit card, etc.)
    3. Highest match wins — one RESTRICTED field taints the whole call
    4. Early exit on RESTRICTED (can't go higher, skip remaining fields)

Patterns are compiled once at import time. Classification of a
typical tool call dict takes <0.1ms.

Example:
    >>> classify_dict({"query": "patient SSN is 123-45-6789"})
    Classification(level=RESTRICTED, flags=[("query", "ssn", RESTRICTED)])
"""
from __future__ import annotations

import re
from enum import IntEnum
from typing import Any, Iterator

__all__ = ["DataLevel", "Classification", "classify_data", "classify_dict"]


# ── Sensitivity levels ───────────────────────────────────────

class DataLevel(IntEnum):
    """Ordered data sensitivity. Higher = more sensitive.

    IntEnum so max() works across fields:
        overall = max(field_a_level, field_b_level)
    """

    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3

    @property
    def label(self) -> str:
        """Human-readable name for receipts."""
        return self.name


# ── Classification result ────────────────────────────────────

class Classification:
    """Result of classifying a dict of tool call data.

    Attributes:
        level:   Highest sensitivity found across all fields.
        flags:   List of (field_path, pattern_name, level) matches.
        fields:  Number of string fields scanned (not total fields).
    """

    __slots__ = ("level", "flags", "fields")

    def __init__(self) -> None:
        self.level: DataLevel = DataLevel.PUBLIC
        self.flags: list[tuple[str, str, DataLevel]] = []
        self.fields: int = 0

    def record(self, field_path: str, pattern_name: str, level: DataLevel) -> None:
        """Record a match. Highest level always wins."""
        self.flags.append((field_path, pattern_name, level))
        if level > self.level:
            self.level = level

    def to_dict(self) -> dict[str, Any]:
        """Compact dict for embedding in signed receipts.

        This exact structure appears in the receipt JSON:
            "data_classification": {"level": "RESTRICTED", "flags": [...]}
        """
        result: dict[str, Any] = {
            "level": self.level.label,
            "fields_scanned": self.fields,
        }
        if self.flags:
            result["flags"] = [
                {"field": f, "pattern": p, "level": lv.label}
                for f, p, lv in self.flags
            ]
        return result

    @property
    def has_restricted(self) -> bool:
        """True if any field contains RESTRICTED data (PII, keys, health)."""
        return self.level >= DataLevel.RESTRICTED

    @property
    def has_confidential(self) -> bool:
        """True if any field is CONFIDENTIAL or higher."""
        return self.level >= DataLevel.CONFIDENTIAL


# ── Detection patterns ───────────────────────────────────────
#
# Aligned with OWASP AI Agent Security §8 code example and
# the same patterns used in shield.py for threat detection.
#
# Compiled once at import time. Order doesn't matter — all
# patterns are checked and the highest matching level wins.

_PATTERNS: tuple[tuple[str, DataLevel, re.Pattern[str]], ...] = (

    # ── RESTRICTED: PII and credentials ──────────────────────
    # Detection of these triggers risk auto-escalation to CRITICAL.

    ("ssn", DataLevel.RESTRICTED,
     re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),

    ("credit_card", DataLevel.RESTRICTED,
     re.compile(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")),

    ("passport", DataLevel.RESTRICTED,
     re.compile(r"\b[A-Z]{1,2}\d{6,9}\b")),

    ("health_data", DataLevel.RESTRICTED,
     re.compile(
         r"(?i)\b(?:diagnosis|prescription|patient\s*id"
         r"|medical\s*record|hipaa)\b"
     )),

    ("private_key", DataLevel.RESTRICTED,
     re.compile(
         r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?"
         r"PRIVATE\s+KEY-----"
     )),

    ("aws_access_key", DataLevel.RESTRICTED,
     re.compile(r"\bAKIA[0-9A-Z]{16}\b")),

    # ── CONFIDENTIAL: sensitive business data ────────────────

    ("salary_data", DataLevel.CONFIDENTIAL,
     re.compile(r"(?i)\b(?:salary|compensation|bonus|stock\s*options?)\b")),

    ("api_key_value", DataLevel.CONFIDENTIAL,
     re.compile(
         r"(?i)(?:api[_\-]?key|secret[_\-]?key|auth[_\-]?token)"
         r"[\s:=\"']+\S{8,}"
     )),

    ("password_field", DataLevel.CONFIDENTIAL,
     re.compile(r"(?i)password\s*[:=]\s*\S+")),

    ("confidential_marker", DataLevel.CONFIDENTIAL,
     re.compile(
         r"(?i)\b(?:confidential|internal\s+only"
         r"|do\s+not\s+distribute)\b"
     )),

    # ── INTERNAL: company data ───────────────────────────────

    ("internal_email", DataLevel.INTERNAL,
     re.compile(r"\b[A-Za-z0-9._%+-]+@(?:company|corp|internal)\.\w+\b")),

    ("draft_marker", DataLevel.INTERNAL,
     re.compile(r"(?i)\b(?:draft|not\s+for\s+(?:distribution|external))\b")),
)


# ── Field walker ─────────────────────────────────────────────

def _walk_strings(data: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (field_path, string_value) from nested dicts/lists.

    Handles arbitrary nesting. Non-string leaf values (int, float,
    bool, None) are silently skipped — we only classify strings.
    """
    if isinstance(data, str):
        yield (prefix or "_root", data)
    elif isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_strings(value, path)
    elif isinstance(data, (list, tuple)):
        for i, item in enumerate(data):
            yield from _walk_strings(item, f"{prefix}[{i}]")


# ── Public API ───────────────────────────────────────────────

def classify_data(text: str) -> DataLevel:
    """Classify a single string. Returns the highest matching level.

    Fast: returns immediately when RESTRICTED is found (can't go higher).
    """
    level = DataLevel.PUBLIC
    for _, data_level, regex in _PATTERNS:
        if regex.search(text):
            level = max(level, data_level)
            if level == DataLevel.RESTRICTED:
                return level
    return level


def classify_dict(data: dict[str, Any] | str) -> Classification:
    """Classify all string fields in a tool call dict.

    Use on tool parameters (before execution) and tool responses
    (after execution). The result embeds in the signed receipt
    as the `data_classification` field.

    Performance: early-exits on RESTRICTED since that's the maximum.
    Typical tool call dicts classify in <0.1ms.

    Args:
        data: Dict of tool call params/response, or a raw string.

    Returns:
        Classification with .level, .flags, .fields, and .to_dict().
    """
    if isinstance(data, str):
        data = {"_input": data}

    result = Classification()

    for field_path, text in _walk_strings(data):
        result.fields += 1
        for name, data_level, regex in _PATTERNS:
            if regex.search(text):
                result.record(field_path, name, data_level)
                if result.level == DataLevel.RESTRICTED:
                    return result  # Can't go higher — skip remaining fields

    return result
