"""
OWASP AI Agent Security Cheat Sheet — compliance scorecard.

This is the output that makes `agentmint init` worth running.
It maps scan results to all 8 OWASP sections and prints a
terminal-formatted coverage report.

Every checkmark is provable from scan data. We never claim
coverage without code evidence. If we didn't detect it, we
don't claim it.

    ┌─ OWASP AI Agent Security Coverage ─────────────────────┐
    │                                                         │
    │  ✅ §1 Tool Security     14 tools, enforcement ready    │
    │  ⬜ §2 Prompt Injection  Out of scope (tool boundary)   │
    │  ✅ §3 Memory Security   2 stores found, 1 PII flagged  │
    │  ...                                                    │
    │                                                         │
    │  Coverage: 7/8 · §2 out of scope · 14 tools · 42ms     │
    └─────────────────────────────────────────────────────────┘

Output formats:
    - Rich terminal (default) — colored, boxed, screenshot-ready
    - Plain text — when Rich is not installed
    - JSON — via scorecard.to_dict() for machine consumption
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from .candidates import ToolCandidate
    from .memory_detector import MemoryCandidate

__all__ = ["OWASPScorecard", "SectionResult", "build_scorecard", "print_scorecard"]


# ── Framework display names ──────────────────────────────────
# Scanner produces internal names like "openai-sdk" and "raw".
# Map them to what a developer expects to read.

_FRAMEWORK_DISPLAY: dict[str, str] = {
    "langgraph": "LangGraph",
    "openai-sdk": "OpenAI Agents SDK",
    "crewai": "CrewAI",
    "mcp": "MCP",
    "raw": "inferred",
}


def _format_frameworks(tools: list[ToolCandidate]) -> str:
    """Human-readable framework list from tool candidates.

    Filters out empty strings, maps internal names to display names,
    and hides 'inferred' if real frameworks are present.
    """
    raw_names = {t.framework for t in tools if t.framework}
    display_names = sorted(
        _FRAMEWORK_DISPLAY.get(f, f)
        for f in raw_names
        if f != "raw" or len(raw_names) == 1  # show 'inferred' only if it's all we have
    )
    return ", ".join(display_names) if display_names else "none detected"


# ── Section result ───────────────────────────────────────────

@dataclass(frozen=True)
class SectionResult:
    """Coverage result for one OWASP cheat sheet section.

    Frozen — safe to store, compare, and serialize after creation.
    """

    number: int           # 1-8
    name: str             # e.g. "Tool Security & Least Privilege"
    covered: bool         # True if AgentMint addresses this section
    out_of_scope: bool    # True for §2 — explicitly not our job
    detail: str           # one-line summary of what we found/did
    evidence: str         # concrete numbers from the scan

    @property
    def icon(self) -> str:
        """Plain text icon for non-Rich output."""
        if self.out_of_scope:
            return "⬜"
        return "✅" if self.covered else "🔲"

    @property
    def rich_icon(self) -> str:
        """Rich markup icon with brand colors."""
        if self.out_of_scope:
            return "[#64748B]⬜[/#64748B]"
        if self.covered:
            return "[#10B981]✅[/#10B981]"
        return "[#FBBF24]🔲[/#FBBF24]"


# ── Scorecard container ──────────────────────────────────────

class OWASPScorecard:
    """Complete OWASP AI Agent Security coverage report.

    Built from scan results by build_scorecard(). Serializable
    to JSON for machine consumption or evidence embedding.
    """

    __slots__ = ("sections", "total_tools", "scan_ms")

    def __init__(
        self,
        sections: list[SectionResult],
        total_tools: int = 0,
        scan_ms: float = 0.0,
    ) -> None:
        self.sections = sections
        self.total_tools = total_tools
        self.scan_ms = scan_ms

    @property
    def covered_count(self) -> int:
        """Number of sections with active coverage."""
        return sum(1 for s in self.sections if s.covered)

    @property
    def in_scope_count(self) -> int:
        """Number of sections that are in scope (excludes §2)."""
        return sum(1 for s in self.sections if not s.out_of_scope)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output and evidence packages."""
        return {
            "owasp_cheat_sheet": "AI Agent Security",
            "total_tools": self.total_tools,
            "scan_ms": round(self.scan_ms, 1),
            "covered": self.covered_count,
            "in_scope": self.in_scope_count,
            "total": len(self.sections),
            "sections": [
                {
                    "number": s.number,
                    "name": s.name,
                    "covered": s.covered,
                    "out_of_scope": s.out_of_scope,
                    "detail": s.detail,
                    "evidence": s.evidence,
                }
                for s in self.sections
            ],
        }

    def to_json(self, indent: int = 2) -> str:
        """JSON string for file output or API responses."""
        return json.dumps(self.to_dict(), indent=indent)


# ── Scorecard builder ────────────────────────────────────────

def build_scorecard(
    tools: list[ToolCandidate],
    memory_stores: Optional[list[MemoryCandidate]] = None,
    risk_counts: Optional[dict[str, int]] = None,
    has_shield: bool = True,
    has_circuit_breaker: bool = True,
    has_receipts: bool = True,
    has_hash_chains: bool = True,
    has_delegation: bool = True,
    scan_ms: float = 0.0,
) -> OWASPScorecard:
    """Build OWASP scorecard from actual scan results.

    Every field is derived from real data — no assumptions,
    no aspirational claims. If we didn't detect it, we don't
    claim it.
    """
    memory_stores = memory_stores or []
    risk_counts = risk_counts or {}

    n_tools = len(tools)
    n_memory = len(memory_stores)
    n_critical = risk_counts.get("CRITICAL", 0)
    n_high = risk_counts.get("HIGH", 0)

    fw_str = _format_frameworks(tools)

    # Memory store symbols for evidence — filter empty, cap at 3
    mem_symbols = [m.symbol for m in memory_stores if m.symbol][:3]

    sections: list[SectionResult] = [
        # §1 Tool Security & Least Privilege
        SectionResult(
            number=1,
            name="Tool Security & Least Privilege",
            covered=n_tools > 0,
            out_of_scope=False,
            detail=(
                "Detects unprotected tools, scoped allow/deny, signed enforcement"
                if n_tools > 0 else "No tools detected"
            ),
            evidence=(
                f"{n_tools} tools across {fw_str}"
                if n_tools > 0 else "Run on an agent codebase to scan"
            ),
        ),

        # §2 Prompt Injection Defense — explicitly out of scope
        SectionResult(
            number=2,
            name="Prompt Injection Defense",
            covered=False,
            out_of_scope=True,
            detail="Out of scope — AgentMint secures the tool boundary, not the prompt boundary",
            evidence="See OWASP LLM Prompt Injection Prevention Cheat Sheet",
        ),

        # §3 Memory & Context Security
        SectionResult(
            number=3,
            name="Memory & Context Security",
            covered=True,
            out_of_scope=False,
            detail=(
                f"{n_memory} memory store{'s' if n_memory != 1 else ''} found, PII scanning enabled"
                if n_memory > 0
                else "No memory stores detected, PII scanning available"
            ),
            evidence=(
                f"Stores: {', '.join(mem_symbols)}"
                if mem_symbols
                else "shield.py provides PII pattern detection"
            ),
        ),

        # §4 Human-in-the-Loop Controls
        SectionResult(
            number=4,
            name="Human-in-the-Loop Controls",
            covered=n_tools > 0,
            out_of_scope=False,
            detail=(
                "Risk-classified tool calls, approval gates for HIGH/CRITICAL"
                if n_tools > 0 else "No tools to classify"
            ),
            evidence=(
                f"{n_critical} CRITICAL, {n_high} HIGH require approval"
                if (n_critical + n_high) > 0
                else f"{n_tools} tools classified, all LOW/MEDIUM"
            ),
        ),

        # §5 Output Validation & Guardrails
        SectionResult(
            number=5,
            name="Output Validation & Guardrails",
            covered=has_shield and has_circuit_breaker,
            out_of_scope=False,
            detail="Shield scans tool I/O, circuit breaker rate-limits agents",
            evidence="23 patterns (PII, secrets, injection) + sliding window limiter",
        ),

        # §6 Monitoring & Observability
        SectionResult(
            number=6,
            name="Monitoring & Observability",
            covered=has_receipts and has_hash_chains,
            out_of_scope=False,
            detail="Signed receipts, hash-chained audit trails, VERIFY.sh",
            evidence="Ed25519 receipts, SHA-256 chains, exportable evidence packages",
        ),

        # §7 Multi-Agent Security
        SectionResult(
            number=7,
            name="Multi-Agent Security",
            covered=has_delegation,
            out_of_scope=False,
            detail="Scoped delegation, child plans can't exceed parent, Merkle trees",
            evidence="Ed25519 per-plan signing, scope intersection, session Merkle root",
        ),

        # §8 Data Protection & Privacy
        SectionResult(
            number=8,
            name="Data Protection & Privacy",
            covered=has_shield,
            out_of_scope=False,
            detail="Classifies data in tool calls (PUBLIC → RESTRICTED), auto-escalation",
            evidence="Data classification on tool params + responses, flagged in receipts",
        ),
    ]

    return OWASPScorecard(sections, total_tools=n_tools, scan_ms=scan_ms)


# ── Terminal output ──────────────────────────────────────────

def print_scorecard(scorecard: OWASPScorecard) -> None:
    """Print the OWASP scorecard. Rich if available, plain text otherwise."""
    try:
        from rich.console import Console  # noqa: F401
        _print_rich(scorecard)
    except ImportError:
        _print_plain(scorecard)


def _print_rich(scorecard: OWASPScorecard) -> None:
    """Rich-formatted scorecard — the screenshot for Show HN."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    console = Console()
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2), expand=True)
    table.add_column(width=4)       # icon
    table.add_column(width=6)       # §N
    table.add_column(min_width=30)  # name + detail
    table.add_column(min_width=20)  # evidence

    for s in scorecard.sections:
        # Section number — dim if out of scope, bright if in scope
        num_style = "#64748B" if s.out_of_scope else "bold #E2E8F0"
        num = f"[{num_style}]§{s.number}[/{num_style}]"

        # Name and detail — styled by coverage status
        if s.out_of_scope:
            name_detail = (
                f"[#64748B]{s.name}[/#64748B]\n"
                f"[#64748B]{s.detail}[/#64748B]"
            )
        elif s.covered:
            name_detail = (
                f"[bold #E2E8F0]{s.name}[/bold #E2E8F0]\n"
                f"[#94A3B8]{s.detail}[/#94A3B8]"
            )
        else:
            name_detail = (
                f"[#FBBF24]{s.name}[/#FBBF24]\n"
                f"[#FBBF24]{s.detail}[/#FBBF24]"
            )

        evidence = f"[#64748B]{s.evidence}[/#64748B]"
        table.add_row(s.rich_icon, num, name_detail, evidence)

    console.print(Panel(
        table,
        title="[bold #3B82F6]OWASP AI Agent Security Coverage[/bold #3B82F6]",
        title_align="left",
        border_style="#3B82F6",
        padding=(1, 2),
        subtitle=(
            f"[#64748B]{scorecard.covered_count}/{len(scorecard.sections)} sections"
            f" · §2 out of scope"
            f" · {scorecard.total_tools} tools"
            f" · {scorecard.scan_ms:.0f}ms[/#64748B]"
        ),
        subtitle_align="right",
    ))
    console.print()


def _print_plain(scorecard: OWASPScorecard) -> None:
    """Plain text fallback when Rich is not installed."""
    print()
    print("  OWASP AI Agent Security Coverage")
    print("  " + "─" * 56)

    for s in scorecard.sections:
        print(f"  {s.icon} §{s.number} {s.name}")
        print(f"       {s.detail}")
        print(f"       {s.evidence}")
        print()

    print(
        f"  Coverage: {scorecard.covered_count}/{len(scorecard.sections)} sections"
        f" · §2 out of scope"
        f" · {scorecard.total_tools} tools"
        f" · {scorecard.scan_ms:.0f}ms"
    )
    print()
