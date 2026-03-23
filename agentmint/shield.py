"""
AgentMint Shield — deterministic content scanning for agent tool calls.

Layer 1 in a defense-in-depth stack. Catches known PII, secrets,
injection patterns, and encoding anomalies. Does NOT catch novel
or semantically disguised attacks.

    from agentmint.shield import scan
    result = scan({"msg": "My SSN is 123-45-6789"})
    assert result.blocked

Defense stack (Shield is one layer):
    1. Shield — pattern matching (this module)
    2. Scope enforcement — policy limits
    3. Circuit breaker — rate limits
    4. Session tracking — drift detection
    5. Receipts — forensic proof
    6. LLM intent evaluation — future
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Iterator

__all__ = ["scan", "ShieldResult", "Threat", "DEFAULT_PATTERNS"]


# ── Data types ────────────────────────────────────────────

@dataclass(frozen=True)
class Threat:
    """A single detected threat."""
    pattern_name: str
    category: str       # pii, secret, injection, encoding, structural
    severity: str       # info, warn, block
    field_path: str     # dot-separated path in scanned dict
    match_preview: str  # redacted — see _preview()


@dataclass(frozen=True)
class ShieldResult:
    """Result of scanning a dict for threats."""
    threats: tuple[Threat, ...] = ()
    scanned_fields: int = 0

    @property
    def blocked(self) -> bool:
        return any(t.severity == "block" for t in self.threats)

    @property
    def warn_count(self) -> int:
        return sum(1 for t in self.threats if t.severity == "warn")

    @property
    def threat_count(self) -> int:
        return len(self.threats)

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(sorted(set(t.category for t in self.threats)))

    def summary(self) -> dict[str, Any]:
        """Compact dict for embedding in receipts."""
        return {
            "blocked": self.blocked,
            "threat_count": self.threat_count,
            "categories": list(self.categories),
            "scanned_fields": self.scanned_fields,
        }


# ── Patterns ──────────────────────────────────────────────
#
# (name, category, severity, regex_string)
# Compiled once at import time. Reused across all scan() calls.

_RAW: list[tuple[str, str, str, str]] = [
    # PII — detection, not blocking by default
    ("ssn",         "pii", "warn",  r"\b\d{3}-\d{2}-\d{4}\b"),
    ("email",       "pii", "info",  r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ("phone_us",    "pii", "info",  r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
    ("credit_card", "pii", "warn",  r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"),

    # Secrets — should never appear in tool args or outputs
    ("aws_access_key",  "secret", "block", r"\bAKIA[0-9A-Z]{16}\b"),
    ("aws_secret_key",  "secret", "block",
     r"(?i)(?:aws|secret)[_\s:=]{1,4}[A-Za-z0-9/+=]{40}"),
    ("jwt", "secret", "block",
     r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-]+\b"),
    ("private_key", "secret", "block",
     r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----"),
    ("generic_api_key", "secret", "warn",
     r'(?i)(?:api[_\-]?key|token|secret)[\s:="\x27]+[A-Za-z0-9_\-]{20,}'),

    # Prompt injection — known attack patterns (OWASP LLM Top 10)
    ("ignore_instructions", "injection", "block",
     r"(?i)ignore\s+(?:all\s+)?(?:previous|above|prior)\s+"
     r"(?:instructions?|prompts?|rules?|guidelines?)"),
    ("system_override", "injection", "block",
     r"(?i)(?:system\s+override|override\s+system|admin\s+mode|developer\s+mode)"),
    ("role_switch", "injection", "warn",
     r"(?i)(?:you\s+are\s+now|act\s+as\s+(?:a|an|if)|"
     r"pretend\s+(?:you(?:'re|\s+are)\s+)|"
     r"from\s+now\s+on\s+you\s+are)"),
    ("reveal_prompt", "injection", "block",
     r"(?i)(?:reveal|show|display|output|print|repeat)"
     r"\s+(?:your\s+)?(?:system\s+)?(?:prompt|instructions|rules)"),
    ("data_exfil", "injection", "block",
     r"(?i)(?:send|post|upload|transmit|forward|exfiltrate)"
     r"\s+.{0,40}(?:to|at)\s+https?://"),
    ("forget_instructions", "injection", "block",
     r"(?i)forget\s+(?:"
     r"everything|"
     r"all(?:\s+(?:your|the|previous))?\s+(?:instructions?|rules?|context|guidelines?)|"
     r"your\s+(?:previous\s+)?(?:instructions?|rules?|context|guidelines?)"
     r")"),
    ("dump_sensitive", "injection", "block",
     r"(?i)(?:output|dump|print|list|show|reveal)\s+(?:all\s+)?"
     r"(?:api[_\s]?keys?|credentials?|secrets?|passwords?|tokens?)"),
    # Encoding anomalies — evasion detection
    ("unicode_control", "encoding", "warn",
     r"[\u200b\u200c\u200d\u200e\u200f\u202a-\u202e\u2060\ufeff]"),
    ("url_encoded_chain", "encoding", "warn",
     r"(?:%[0-9A-Fa-f]{2}){4,}"),

    # Structural injection — instruction-like content in data
    ("system_role_tag", "structural", "warn",
     r"(?i)<\|?(?:im_start|system|assistant|user)\|?>"),
    ("html_injection", "structural", "warn",
     r"(?i)<(?:script|iframe|object|embed|form|img\s+[^>]*onerror)[^>]*>"),
    ("markdown_link_injection", "structural", "warn",
     r"!\[.*?\]\((?:javascript|data|vbscript):"),
]

DEFAULT_PATTERNS: list[tuple[str, str, str, re.Pattern]] = [
    (name, cat, sev, re.compile(rx, re.IGNORECASE))
    for name, cat, sev, rx in _RAW
]


# ── Fuzzy typo detection (OWASP typoglycemia defense) ─────

_FUZZY_TARGETS: tuple[str, ...] = (
    "ignore", "bypass", "override", "reveal",
    "delete", "system", "inject", "prompt",
)
_FUZZY_SORTED: dict[str, str] = {t: "".join(sorted(t)) for t in _FUZZY_TARGETS}


def _is_typo_variant(word: str, target: str) -> bool:
    """Same first/last letter, same length, same characters — likely typo."""
    if len(word) != len(target) or len(word) < 4:
        return False
    if word[0] != target[0] or word[-1] != target[-1]:
        return False
    return "".join(sorted(word)) == _FUZZY_SORTED[target] and word != target


# ── Entropy detection ─────────────────────────────────────

def _shannon_entropy(s: str) -> float:
    """Shannon entropy in bits per character."""
    if len(s) < 2:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _is_plausible_base64(s: str) -> bool:
    """Check if a high-entropy string is actually base64-encoded text."""
    try:
        decoded = __import__("base64").b64decode(s + "==")
        printable_ratio = sum(1 for b in decoded if 32 <= b < 127) / max(len(decoded), 1)
        return printable_ratio > 0.7
    except Exception:
        return False


# ── Preview helper ────────────────────────────────────────

def _preview(text: str, category: str) -> str:
    """Redacted preview. PII/secrets get heavy redaction. Others show context."""
    text = text.strip()[:60]
    if category in ("pii", "secret"):
        if len(text) <= 6:
            return "***"
        return text[:3] + "***" + text[-3:]
    if len(text) <= 24:
        return text
    return text[:10] + "..." + text[-10:]


# ── Field extraction (generator — constant memory) ────────

def _walk_strings(data: Any, prefix: str = "") -> Iterator[tuple[str, str]]:
    """Yield (field_path, string_value) from nested dicts/lists."""
    if isinstance(data, str):
        yield (prefix or "_root", data)
    elif isinstance(data, dict):
        for key, value in data.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield from _walk_strings(value, path)
    elif isinstance(data, (list, tuple)):
        for i, item in enumerate(data):
            yield from _walk_strings(item, f"{prefix}[{i}]")


# ── Core scan ─────────────────────────────────────────────

def scan(
    data: dict[str, Any] | str,
    patterns: list[tuple[str, str, str, re.Pattern]] | None = None,
    enable_fuzzy: bool = True,
    enable_entropy: bool = True,
) -> ShieldResult:
    """Scan a dict or string for PII, secrets, injection, and anomalies.

    Args:
        data: Dict of tool args/output, or a raw string.
        patterns: Custom pattern list. None = DEFAULT_PATTERNS.
        enable_fuzzy: Detect typo variants of injection keywords.
        enable_entropy: Flag high-entropy strings (potential obfuscated payloads).

    Returns:
        ShieldResult with all detected threats.
    """
    if patterns is None:
        patterns = DEFAULT_PATTERNS

    if isinstance(data, str):
        data = {"_input": data}

    threats: list[Threat] = []
    field_count = 0

    for field_path, text in _walk_strings(data):
        field_count += 1

        # Regex patterns
        for name, category, severity, regex in patterns:
            for match in regex.finditer(text):
                threats.append(Threat(
                    pattern_name=name,
                    category=category,
                    severity=severity,
                    field_path=field_path,
                    match_preview=_preview(match.group(), category),
                ))

        # Fuzzy typo detection
        if enable_fuzzy:
            for word in re.findall(r"\b[a-zA-Z]{4,}\b", text.lower()):
                for target in _FUZZY_TARGETS:
                    if _is_typo_variant(word, target):
                        threats.append(Threat(
                            pattern_name=f"typo_{target}",
                            category="injection",
                            severity="warn",
                            field_path=field_path,
                            match_preview=word,
                        ))

        # High-entropy string detection
        if enable_entropy:
            for tok in re.finditer(r"[A-Za-z0-9+/=_\-]{24,}", text):
                token = tok.group()
                if _shannon_entropy(token) >= 4.5 and _is_plausible_base64(token):
                    threats.append(Threat(
                        pattern_name="high_entropy_base64",
                        category="encoding",
                        severity="warn",
                        field_path=field_path,
                        match_preview=_preview(token, "encoding"),
                    ))

    return ShieldResult(threats=tuple(threats), scanned_fields=field_count)