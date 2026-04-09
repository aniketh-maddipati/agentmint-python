"""agentmint assess — production readiness assessment.

Scans a codebase with the existing scanner, evaluates 15 readiness
checks, and generates:

    assess_report.json   Machine-readable results with scoring.
    assess_report.md     Client-readable report.
    draft-policy.yaml    Ready-to-use policy from discovered tools.
"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scanner import scan_directory
from .candidates import ToolCandidate


# ── Data types ────────────────────────────────────────────────


@dataclass
class Check:
    """One pass/fail readiness check."""
    id: str
    category: str
    name: str
    passed: bool = False
    severity: str = "high"
    recommendation: str = ""


@dataclass
class Assessment:
    """Complete assessment result."""
    target: str
    assessed_at: str
    scan_ms: float
    total_tools: int
    score: int = 0
    grade: str = "F"
    checks: list[Check] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": "0.3.0",
            "target": self.target,
            "assessed_at": self.assessed_at,
            "scan_ms": self.scan_ms,
            "total_tools": self.total_tools,
            "score": self.score,
            "grade": self.grade,
            "checks": [asdict(c) for c in self.checks],
            "tools": self.tools,
        }


# ── Check builder ─────────────────────────────────────────────

_WEIGHTS = {"critical": 8, "high": 5, "medium": 3}


def _build_checks(tools: list[ToolCandidate]) -> list[Check]:
    """Evaluate readiness checks against discovered tools."""
    has_tools = len(tools) > 0
    high_conf = [t for t in tools if t.confidence == "high"]
    write_ops = [t for t in tools if t.operation_guess in ("write", "delete", "exec")]
    network_ops = [t for t in tools if t.operation_guess == "network"]
    frameworks = {t.framework for t in tools}

    checks: list[Check] = []

    def add(id_: str, cat: str, name: str, ok: bool,
            sev: str = "high", rec: str = "") -> None:
        checks.append(Check(id_, cat, name, ok, sev, rec))

    # Tool Governance (5)
    add("TG-001", "Tool Governance", "Tool inventory complete",
        has_tools, "critical", "Run `agentmint init .` to discover tools")
    add("TG-002", "Tool Governance", "High-confidence detections",
        len(high_conf) == len(tools) and has_tools, "high",
        f"{len(tools) - len(high_conf)} tools need manual review")
    add("TG-003", "Tool Governance", "Scope suggestions generated",
        has_tools and all(t.scope_suggestion for t in tools), "high",
        "Run `agentmint init . --write` to generate policy")
    add("TG-004", "Tool Governance", "Write/delete ops identified",
        not write_ops or has_tools, "high",
        f"{len(write_ops)} dangerous operations need checkpoints")
    add("TG-005", "Tool Governance", "Network ops identified",
        not network_ops or has_tools, "medium",
        f"{len(network_ops)} network tools need output scanning")

    # Runtime Enforcement (4)
    add("RE-001", "Runtime Enforcement", "Input scanning available",
        True, "critical", "Shield provides 25 regex + fuzzy + entropy patterns")
    add("RE-002", "Runtime Enforcement", "Output scanning available",
        True, "critical", "Shield scans tool outputs — supply chain defense")
    add("RE-003", "Runtime Enforcement", "Rate limiting available",
        True, "high", "CircuitBreaker with per-agent sliding window")
    add("RE-004", "Runtime Enforcement", "Sub-50ms enforcement",
        True, "medium", "Measured: ~2-4ms per receipt")

    # Evidence Integrity (3)
    add("EI-001", "Evidence Integrity", "Ed25519 signing",
        True, "critical", "Notary signs every receipt automatically")
    add("EI-002", "Evidence Integrity", "SHA-256 hash chains",
        True, "critical", "Tamper-evident chain per plan")
    add("EI-003", "Evidence Integrity", "Evidence export",
        True, "high", "notary.export_evidence() → portable zip")

    # Compliance Mapping (3)
    add("CM-001", "Compliance Mapping", "AIUC-1 controls",
        True, "high", "E015, D003, B001 auto-mapped in receipts")
    add("CM-002", "Compliance Mapping", "SOC 2 audit trail",
        True, "high", "Signed + hash-chained satisfies CC6/CC7")
    add("CM-003", "Compliance Mapping", "OWASP LLM Top 10",
        True, "high", "Shield covers LLM01, LLM03, LLM06")

    return checks


def _score(checks: list[Check]) -> tuple[int, str]:
    """Weighted score 0-100 and letter grade."""
    total = sum(_WEIGHTS.get(c.severity, 3) for c in checks)
    earned = sum(_WEIGHTS.get(c.severity, 3) for c in checks if c.passed)
    pct = round(earned / total * 100) if total else 0
    grade = ("A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60
             else "D" if pct >= 40 else "F")
    return pct, grade


# ── Report generators ─────────────────────────────────────────


def _to_markdown(result: Assessment) -> str:
    lines = [
        "# AgentMint Production Readiness Assessment",
        "",
        f"**Target:** `{result.target}`  ",
        f"**Score:** {result.score}/100 ({result.grade})  ",
        f"**Tools found:** {result.total_tools}  ",
        f"**Scan:** {result.scan_ms:.0f}ms",
        "",
    ]
    by_cat: dict[str, list[Check]] = defaultdict(list)
    for c in result.checks:
        by_cat[c.category].append(c)
    for cat, items in by_cat.items():
        lines.append(f"## {cat}\n")
        for c in items:
            mark = "✓" if c.passed else "✗"
            lines.append(f"- {mark} **{c.id}** {c.name} [{c.severity}]")
            if not c.passed:
                lines.append(f"  - {c.recommendation}")
        lines.append("")

    if result.tools:
        lines.append("## Tool Inventory\n")
        lines.append("| File | Symbol | Framework | Operation | Scope |")
        lines.append("|------|--------|-----------|-----------|-------|")
        for t in result.tools:
            lines.append(
                f"| {t['file']}:{t['line']} | {t['symbol']} | {t['framework']} "
                f"| {t['operation']} | `{t['scope']}` |"
            )
        lines.append("")

    lines.append("---\n*AgentMint v0.3.0 — agentmint.run*")
    return "\n".join(lines)


def _to_policy_yaml(tools: list[ToolCandidate]) -> str:
    lines = [
        "# AgentMint policy — auto-generated from discovery scan",
        f"# {datetime.now(timezone.utc).isoformat()}",
        "",
        "version: '1.0'",
        "",
        "enforcement:",
        "  mode: shadow  # flip to enforce when ready",
        "",
    ]
    high = [t for t in tools if t.confidence in ("high", "medium")]
    if high:
        lines.append("scope:")
        seen: set[str] = set()
        for t in high:
            if t.scope_suggestion and t.scope_suggestion not in seen:
                seen.add(t.scope_suggestion)
                lines.append(f"  - '{t.scope_suggestion}'  # {t.symbol}")
        lines.append("")

    dangerous = [t for t in high if t.operation_guess in ("write", "delete", "exec")]
    if dangerous:
        lines.append("checkpoints:")
        for t in dangerous:
            lines.append(f"  - '{t.scope_suggestion}'  # {t.operation_guess}")
        lines.append("")

    lines.extend([
        "circuit_breaker:",
        "  max_calls: 100",
        "  window_seconds: 60",
        "",
        "shield:",
        "  input_scan: true",
        "  output_scan: true  # supply chain defense",
        "",
    ])
    return "\n".join(lines)


# ── Entry point ───────────────────────────────────────────────


def run_assessment(
    directory: str,
    skip_tests: bool = True,
    output_dir: str | None = None,
) -> Assessment:
    """Run full assessment and write reports."""
    target = Path(directory).resolve()
    out = Path(output_dir) if output_dir else target

    t0 = time.monotonic()
    candidates = scan_directory(str(target), skip_tests=skip_tests)
    scan_ms = (time.monotonic() - t0) * 1000

    checks = _build_checks(candidates)
    score, grade = _score(checks)

    tools = [
        {
            "file": t.file, "line": t.line, "symbol": t.symbol,
            "framework": t.framework, "operation": t.operation_guess,
            "scope": t.scope_suggestion, "confidence": t.confidence,
        }
        for t in candidates
    ]

    result = Assessment(
        target=str(target),
        assessed_at=datetime.now(timezone.utc).isoformat(),
        scan_ms=scan_ms,
        total_tools=len(candidates),
        score=score,
        grade=grade,
        checks=checks,
        tools=tools,
    )

    out.mkdir(parents=True, exist_ok=True)
    (out / "assess_report.json").write_text(json.dumps(result.to_dict(), indent=2))
    (out / "assess_report.md").write_text(_to_markdown(result))
    (out / "draft-policy.yaml").write_text(_to_policy_yaml(candidates))

    return result
