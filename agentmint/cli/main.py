"""
main.py — CLI entry point for agentmint.

Commands:
    agentmint init .                Scan + OWASP scorecard + setup
    agentmint init . --write        Apply patches + generate yaml
    agentmint init . --output json  Machine-readable
    agentmint audit .               OWASP compliance assessment
    agentmint verify .              Check enforcement coverage
"""
from __future__ import annotations

import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

import click

from .scanner import scan_directory
from .candidates import ToolCandidate
from .display import _out, print_status


@click.group()
@click.version_option(version="0.2.0", prog_name="agentmint")
def cli():
    """AgentMint — OWASP AI Agent Security compliance for AI agent tool calls."""
    pass


@cli.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option("--write", is_flag=True, default=False,
              help="Apply patches to files (default: dry-run).")
@click.option("--output", type=click.Choice(["rich", "json"]), default="rich",
              help="Output format.")
@click.option("--skip-tests/--include-tests", default=True,
              help="Skip test directories.")
@click.option("--confidence", type=click.Choice(["all", "high", "medium"]),
              default="all", help="Minimum confidence to show.")
@click.option("--confirm/--no-confirm", default=False,
              help="Interactively confirm medium-confidence matches.")
def init(directory, write, output, skip_tests, confidence, confirm):
    """Scan a Python codebase for AI agent tool calls and generate OWASP coverage."""
    target = Path(directory).resolve()

    if output == "rich":
        from .display import print_banner
        print_banner()
        _out(f"[dim]  Scanning[/dim] [bold]{target}[/bold] [dim]...[/dim]\n",
             f"  Scanning {target} ...\n")

    # ── Scan ─────────────────────────────────────────────
    t0 = time.monotonic()
    candidates = scan_directory(str(target), skip_tests=skip_tests)
    scan_ms = (time.monotonic() - t0) * 1000

    # Filter by confidence
    if confidence == "high":
        candidates = [c for c in candidates if c.confidence == "high"]
    elif confidence == "medium":
        candidates = [c for c in candidates if c.confidence in ("high", "medium")]

    if confirm and output == "rich":
        candidates = _confirm_medium(candidates)

    # ── Memory scan ──────────────────────────────────────
    from .memory_detector import scan_directory_for_memory
    memory_stores = scan_directory_for_memory(str(target), skip_tests=skip_tests)

    # ── Risk counts ──────────────────────────────────────
    risk_counts = Counter()
    for c in candidates:
        risk_counts[c.risk_level] += 1

    # ── JSON output ──────────────────────────────────────
    if output == "json":
        from .owasp_scorecard import build_scorecard
        scorecard = build_scorecard(
            tools=candidates, memory_stores=memory_stores,
            risk_counts=dict(risk_counts), scan_ms=scan_ms,
        )
        result = {
            "tools": [c.to_dict() for c in candidates],
            "memory_stores": [m.to_dict() for m in memory_stores],
            "risk_summary": dict(risk_counts),
            "owasp": scorecard.to_dict(),
        }
        click.echo(json.dumps(result, indent=2))
        return

    # ── Rich output ──────────────────────────────────────
    from .display import (print_scan_report, print_patch_instructions,
                          print_yaml_preview, print_plan_scaffold,
                          print_risk_summary, print_shield_check,
                          print_quickstart_notice)
    from .patcher import (generate_yaml, generate_quickstart,
                          generate_shield_check)
    from .owasp_scorecard import build_scorecard, print_scorecard

    # ── What we found ─────────────────────────────────
    print_scan_report(candidates)
    _print_risk_classification(candidates, risk_counts)
    _print_memory_findings(memory_stores)

    # ── OWASP Scorecard (the payoff) ─────────────────
    scorecard = build_scorecard(
        tools=candidates, memory_stores=memory_stores,
        risk_counts=dict(risk_counts), scan_ms=scan_ms,
    )
    print_scorecard(scorecard)

    # ── Apply (verbose details only with --write) ────
    yaml_content = generate_yaml(candidates)
    if write:
        print_risk_summary(candidates)
        print_patch_instructions(candidates)
        print_yaml_preview(yaml_content)
        print_plan_scaffold(candidates)
        shield_snippet = generate_shield_check(candidates)
        print_shield_check(shield_snippet)
        _apply_patches(candidates, target, yaml_content)
    elif candidates:
        n_high = risk_counts.get("HIGH", 0) + risk_counts.get("CRITICAL", 0)
        n_total = len(candidates)
        try:
            from rich.console import Console
            console = Console()
            console.print()
            if n_high > 0:
                console.print(
                    f"  [bold #EF4444]{n_high} of your {n_total} tools "
                    f"can act outside your app with no audit trail.[/bold #EF4444]"
                )
            else:
                console.print(
                    f"  [#10B981]{n_total} tools detected, all LOW/MEDIUM risk.[/#10B981]"
                )
            console.print()
            console.print("  [bold #E2E8F0]Get compliant in 60 seconds:[/bold #E2E8F0]")
            console.print()
            console.print(
                "  [#3B82F6]1.[/#3B82F6] [#E2E8F0]agentmint init . --write[/#E2E8F0]"
                "         [#64748B]generate config + quickstart[/#64748B]"
            )
            console.print(
                "  [#3B82F6]2.[/#3B82F6] [#E2E8F0]python quickstart_agentmint.py[/#E2E8F0]"
                "  [#64748B]see your first signed receipt[/#64748B]"
            )
            console.print(
                "  [#3B82F6]3.[/#3B82F6] [#E2E8F0]agentmint audit .[/#E2E8F0]"
                "              [#64748B]get your compliance score[/#64748B]"
            )
            console.print()
            console.print(
                "  [#94A3B8]Show the scorecard to your founder. Hand the evidence "
                "package to your auditor.[/#94A3B8]"
            )
            console.print(
                "  [#94A3B8]Drop it into your agent. Run it in CI. Ship it.[/#94A3B8]"
            )
            console.print()
            console.print(
                "  [#64748B]Feedback → linkedin.com/in/anikethmaddipati[/#64748B]"
            )
            console.print(
                "  [#64748B]Docs    → github.com/aniketh-maddipati/agentmint-python[/#64748B]"
            )
            console.print()
        except ImportError:
            if n_high > 0:
                print(f"\n  {n_high} of your {n_total} tools can act outside your app with no audit trail.")
            else:
                print(f"\n  {n_total} tools detected, all LOW/MEDIUM risk.")
            print("\n  Get compliant in 60 seconds:")
            print("    1. agentmint init . --write         generate config + quickstart")
            print("    2. python quickstart_agentmint.py  see your first signed receipt")
            print("    3. agentmint audit .                get your compliance score")
            print("\n  Show the scorecard to your founder. Hand the evidence package to your auditor.")
            print("  Drop it into your agent. Run it in CI. Ship it.")
            print("\n  Feedback → linkedin.com/in/anikethmaddipati")
            print("  Docs    → github.com/aniketh-maddipati/agentmint-python\n")


@cli.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
@click.option("--output", type=click.Choice(["rich", "json", "markdown"]),
              default="rich", help="Output format.")
@click.option("--output-dir", type=click.Path(), default=None,
              help="Write reports to this directory.")
def audit(directory, output, output_dir):
    """Run OWASP compliance assessment and generate audit reports."""
    from .assess import run_assessment
    target = Path(directory).resolve()
    _out(f"\n[dim]Running OWASP compliance audit on[/dim] [bold]{target}[/bold] [dim]...[/dim]\n",
         f"\nRunning OWASP compliance audit on {target} ...\n")
    result = run_assessment(directory=str(target), skip_tests=True, output_dir=output_dir)
    if output == "json":
        click.echo(json.dumps(result.to_dict(), indent=2))
    else:
        _print_audit_results(result)


@cli.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
def verify(directory):
    """Check that all detected tools have AgentMint enforcement wired up."""
    target = Path(directory).resolve()
    yaml_path = target / "agentmint.yaml"
    if not yaml_path.exists():
        click.echo("No agentmint.yaml found. Run `agentmint init . --write` first.")
        sys.exit(1)
    candidates = scan_directory(str(target), skip_tests=True)
    missing = []
    for c in candidates:
        if c.confidence != "high":
            continue
        full = target / c.file
        try:
            source = full.read_text(encoding="utf-8")
            if "agentmint" not in source:
                missing.append(c)
        except OSError:
            continue
    if missing:
        _out(f"\n[#FBBF24]⚠ {len(missing)} tools missing AgentMint enforcement:[/#FBBF24]\n",
             f"\n⚠ {len(missing)} tools missing AgentMint enforcement:\n")
        for c in missing:
            _out(f"  {c.file}:{c.line}  {c.symbol}  ({c.framework}  {c.risk_level})",
                 f"  {c.file}:{c.line}  {c.symbol}  ({c.framework}  {c.risk_level})")
        _out("", "")
    else:
        _out(f"\n[#10B981]✓ All {len(candidates)} detected tools have AgentMint imports.[/#10B981]\n",
             f"\n✓ All {len(candidates)} detected tools have AgentMint imports.\n")

# ── Helpers ──────────────────────────────────────────────

def _confirm_medium(candidates):
    """Prompt user to confirm or reject medium-confidence candidates."""
    confirmed = []
    for c in candidates:
        if c.confidence != "medium":
            confirmed.append(c)
            continue
        answer = click.prompt(
            f"  {c.file}:{c.line} {c.symbol} ({c.framework}, {c.detection_rule}) "
            f"— is this an agent tool?",
            type=click.Choice(["y", "n", "skip"]), default="n",
        )
        if answer == "y":
            c.confidence = "high"
            confirmed.append(c)
        elif answer == "skip":
            confirmed.extend(x for x in candidates if x.confidence != "medium"
                             and x not in confirmed)
            break
    return confirmed


def _apply_patches(candidates, root, yaml_content):
    """Write agentmint.yaml and inject imports."""
    from .patcher import generate_import_patch
    by_file = defaultdict(list)
    for c in candidates:
        if c.confidence == "high":
            by_file[c.file].append(c)
    for filepath in by_file:
        full = root / filepath
        try:
            source = full.read_text(encoding="utf-8")
            modified = generate_import_patch(source)
            if modified != source:
                full.write_text(modified, encoding="utf-8")
                print_status(True, f"Added import to {filepath}")
        except Exception as e:
            print_status(False, f"Failed to patch {filepath}: {e}")
    yaml_path = root / "agentmint.yaml"
    yaml_path.write_text(yaml_content, encoding="utf-8")
    print_status(True, "Generated agentmint.yaml")
    from .patcher import generate_quickstart
    from .display import print_quickstart_notice
    quickstart = generate_quickstart(candidates)
    if quickstart:
        qs_path = root / "quickstart_agentmint.py"
        qs_path.write_text(quickstart, encoding="utf-8")
        print_quickstart_notice(str(qs_path.relative_to(root)))
    n = sum(len(v) for v in by_file.values())
    _out(f"\n  [bold]{n} tools[/bold] ready for enforcement.\n",
         f"\n  {n} tools ready for enforcement.\n")


def _print_risk_classification(candidates, risk_counts):
    """Print risk level summary with brand colors."""
    if not candidates:
        return
    critical = risk_counts.get("CRITICAL", 0)
    high = risk_counts.get("HIGH", 0)
    medium = risk_counts.get("MEDIUM", 0)
    low = risk_counts.get("LOW", 0)
    try:
        from rich.console import Console
        from rich.rule import Rule
        console = Console()
        console.print(Rule("[bold]Risk classification (OWASP §4)[/bold]", style="#3B82F6"))
        console.print()
        parts = []
        if critical:
            parts.append(f"[bold #EF4444]{critical} CRITICAL[/bold #EF4444]")
        if high:
            parts.append(f"[#EF4444]{high} HIGH[/#EF4444]")
        if medium:
            parts.append(f"[#FBBF24]{medium} MEDIUM[/#FBBF24]")
        if low:
            parts.append(f"[#10B981]{low} LOW[/#10B981]")
        console.print(f"  {' · '.join(parts)}")
        if critical or high:
            console.print()
            console.print("  [#64748B]HIGH and CRITICAL tools require approval gates in production.[/#64748B]")
            console.print("  [#64748B]See OWASP AI Agent Security Cheat Sheet §4.[/#64748B]")
        console.print()
    except ImportError:
        parts = []
        if critical:
            parts.append(f"{critical} CRITICAL")
        if high:
            parts.append(f"{high} HIGH")
        if medium:
            parts.append(f"{medium} MEDIUM")
        if low:
            parts.append(f"{low} LOW")
        print(f"\n  Risk: {' · '.join(parts)}\n")


def _print_memory_findings(memory_stores):
    """Print memory store detections."""
    if not memory_stores:
        return
    try:
        from rich.console import Console
        from rich.rule import Rule
        console = Console()
        console.print(Rule("[bold]Memory stores (OWASP §3)[/bold]", style="#3B82F6"))
        console.print()
        for m in memory_stores:
            console.print(f"  [#FBBF24]⚠[/#FBBF24] [bold #E2E8F0]{m.symbol}[/bold #E2E8F0]  [#64748B]{m.file}:{m.line}[/#64748B]")
            console.print(f"    [#94A3B8]{m.risk_note}[/#94A3B8]")
            console.print(f"    [#64748B]→ {m.recommendation}[/#64748B]")
            console.print()
    except ImportError:
        print("\n  Memory stores:")
        for m in memory_stores:
            print(f"  ⚠ {m.symbol}  {m.file}:{m.line}")
            print(f"    {m.risk_note}")
            print()


def _print_audit_results(result):
    """Pretty-print audit results."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        grade_colors = {"A": "#10B981", "B": "#10B981", "C": "#FBBF24", "D": "#EF4444", "F": "bold #EF4444"}
        gc = grade_colors.get(result.grade, "#E2E8F0")
        console.print(Panel(
            f"  Score: [bold]{result.score}/100[/bold]  Grade: [{gc}]{result.grade}[/{gc}]  "
            f"Tools: [bold]{result.total_tools}[/bold]  Scan: {result.scan_ms:.0f}ms",
            title="[bold #3B82F6]AgentMint Compliance Audit[/bold #3B82F6]",
            border_style="#3B82F6",
        ))
        console.print()
        by_cat = defaultdict(list)
        for c in result.checks:
            by_cat[c.category].append(c)
        for cat, checks in by_cat.items():
            console.print(f"  [bold]{cat}[/bold]")
            for c in checks:
                icon = "[#10B981]✓[/#10B981]" if c.passed else "[#EF4444]✗[/#EF4444]"
                console.print(f"    {icon} {c.id} {c.name}")
                if not c.passed:
                    console.print(f"      [#64748B]→ {c.recommendation}[/#64748B]")
            console.print()
    except ImportError:
        print(f"\n  Score: {result.score}/100 ({result.grade})")
        for c in result.checks:
            icon = "✓" if c.passed else "✗"
            print(f"  {icon} {c.id} {c.name}")
        print()


def main():
    cli()


if __name__ == "__main__":
    main()
