"""
main.py — CLI entry point for agentmint init.

Usage:
  agentmint init .                      # dry-run scan
  agentmint init ./src --write          # apply patches + generate yaml
  agentmint init . --output json        # machine-readable
  agentmint init . --confidence high    # only high-confidence
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

import click

from .scanner import scan_directory
from .candidates import ToolCandidate
from .display import _out, print_status


@click.group()
@click.version_option(version="0.1.0", prog_name="agentmint")
def cli():
    """AgentMint CLI — runtime enforcement for AI agent tool calls."""
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
def init(directory: str, write: bool, output: str,
         skip_tests: bool, confidence: str, confirm: bool):
    """Scan a Python codebase, detect AI agent tool calls, generate AgentMint enforcement."""

    target = Path(directory).resolve()

    if output == "rich":
        _out(f"\n[dim]Scanning[/dim] [bold]{target}[/bold] [dim]...[/dim]\n",
             f"\nScanning {target} ...\n")

    # ── Phase 1: SCAN ────────────────────────────────────────
    candidates = scan_directory(str(target), skip_tests=skip_tests)

    # Filter by confidence
    if confidence == "high":
        candidates = [c for c in candidates if c.confidence == "high"]
    elif confidence == "medium":
        candidates = [c for c in candidates if c.confidence in ("high", "medium")]

    # Interactive confirmation for medium confidence
    if confirm and output == "rich":
        candidates = _confirm_medium(candidates)

    # ── Phase 2: REPORT ──────────────────────────────────────
    if output == "json":
        click.echo(json.dumps([c.to_dict() for c in candidates], indent=2))
        return

    from .display import print_full_report
    from .patcher import generate_yaml

    print_full_report(candidates)

    # ── Phase 3: APPLY ───────────────────────────────────────
    if write:
        yaml_content = generate_yaml(candidates)
        _apply_patches(candidates, target, yaml_content)


def _confirm_medium(candidates: list[ToolCandidate]) -> list[ToolCandidate]:
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
            # Keep remaining non-medium candidates
            confirmed.extend(x for x in candidates if x.confidence != "medium"
                             and x not in confirmed)
            break
    return confirmed


def _apply_patches(candidates: list[ToolCandidate], root: Path, yaml_content: str):
    """Write agentmint.yaml and inject imports into files with high-confidence tools."""
    from .patcher import generate_import_patch

    by_file: dict[str, list[ToolCandidate]] = defaultdict(list)
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

    # Generate quickstart.py
    from .patcher import generate_quickstart
    from .display import print_quickstart_notice
    quickstart = generate_quickstart(candidates)
    if quickstart:
        qs_path = root / "quickstart_agentmint.py"
        qs_path.write_text(quickstart, encoding="utf-8")
        print_quickstart_notice(str(qs_path.relative_to(root)))

    n = sum(len(v) for v in by_file.values())
    _out(f"\n  [bold]{n} tools[/bold] ready for enforcement. "
         f"See patch instructions above to add notary.notarise() calls.\n",
         f"\n  {n} tools ready for enforcement.\n")


@cli.command()
@click.argument("directory", default=".", type=click.Path(exists=True))
def verify(directory: str):
    """Check that all detected tools have AgentMint enforcement wired up."""
    target = Path(directory).resolve()
    yaml_path = target / "agentmint.yaml"

    if not yaml_path.exists():
        click.echo("No agentmint.yaml found. Run `agentmint init .` first.")
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
        _out(f"\n[yellow]⚠ {len(missing)} tools missing AgentMint enforcement:[/yellow]\n",
             f"\n⚠ {len(missing)} tools missing AgentMint enforcement:\n")
        for c in missing:
            _out(f"  {c.file}:{c.line}  {c.symbol}  ({c.framework})",
                 f"  {c.file}:{c.line}  {c.symbol}  ({c.framework})")
        _out("", "")
    else:
        _out(f"\n[green]✓ All {len(candidates)} detected tools have AgentMint imports.[/green]\n",
             f"\n✓ All {len(candidates)} detected tools have AgentMint imports.\n")


def main():
    cli()


if __name__ == "__main__":
    main()
