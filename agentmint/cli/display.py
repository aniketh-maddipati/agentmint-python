"""
display.py — Console output for agentmint init.

Uses Rich when available, falls back to plain print().
"""
from __future__ import annotations

from collections import defaultdict
from typing import List

from .candidates import ToolCandidate

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.syntax import Syntax
    _CONSOLE: Console | None = Console()
except ImportError:
    _CONSOLE = None


CONFIDENCE_COLORS = {"high": "green", "medium": "yellow", "low": "red"}
FRAMEWORK_COLORS = {
    "langgraph": "cyan", "openai-sdk": "magenta",
    "crewai": "blue", "adk": "green", "raw": "dim",
}


def _out(rich_msg: str, plain_msg: str) -> None:
    """Print with Rich formatting if available, plain text otherwise."""
    if _CONSOLE:
        _CONSOLE.print(rich_msg)
    else:
        print(plain_msg)


def _group_by_file(candidates: List[ToolCandidate]) -> dict:
    by_file: dict[str, list[ToolCandidate]] = defaultdict(list)
    for c in candidates:
        by_file[c.file].append(c)
    return by_file


def print_scan_report(candidates: List[ToolCandidate]) -> None:
    if not candidates:
        _out("\n[dim]AgentMint found 0 tool calls.[/dim]\n",
             "\nAgentMint found 0 tool calls.\n")
        return

    by_file = _group_by_file(candidates)
    n_tools, n_files = len(candidates), len(by_file)
    header = (f"AgentMint found {n_tools} tool call{'s' if n_tools != 1 else ''} "
              f"across {n_files} file{'s' if n_files != 1 else ''}")

    if _CONSOLE:
        _CONSOLE.print()
        _CONSOLE.print(Panel(f"[bold]{header}[/bold]",
                             border_style="bright_blue", padding=(0, 2)))
        _CONSOLE.print()
    else:
        print(f"\n{header}\n")

    for filepath, tools in by_file.items():
        _out(f"  [bold white]{filepath}[/bold white]", f"  {filepath}")
        for t in sorted(tools, key=lambda x: x.line):
            ln = f"line {t.line:<4}" if t.line > 0 else "line ?   "
            fc = FRAMEWORK_COLORS.get(t.framework, "white")
            cc = CONFIDENCE_COLORS.get(t.confidence, "white")
            _out(
                f"    [dim]{ln}[/dim]  [bold]{t.symbol:<24}[/bold]  "
                f"[{fc}]{t.framework:<12}[/{fc}]  "
                f"[dim]{t.short_rule:<22}[/dim]  "
                f"confidence: [{cc}]{t.confidence}[/{cc}]",
                f"    {ln}  {t.symbol:<24}  {t.framework:<12}  "
                f"{t.short_rule:<22}  confidence: {t.confidence}",
            )
        _out("", "")


def print_patch_instructions(candidates: List[ToolCandidate]) -> None:
    if not candidates:
        return

    by_file = _group_by_file(candidates)

    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Patch Instructions[/bold]", style="bright_blue"))
        _CONSOLE.print()
    else:
        print("── Patch Instructions ──\n")

    for filepath, tools in by_file.items():
        _out(f"  [bold]{filepath}[/bold]", f"  {filepath}")
        _out("  [dim]Add at top:[/dim] [green]from agentmint.notary import Notary[/green]",
             "  Add at top: from agentmint.notary import Notary")
        _out("", "")

        for t in sorted(tools, key=lambda x: x.line):
            if t.confidence == "low":
                _out(f"    [dim]line {t.line}  {t.symbol}  → manual review required[/dim]",
                     f"    line {t.line}  {t.symbol}  → manual review required")
                continue
            scope = t.scope_suggestion
            if t.boundary == "definition":
                _out(f"    line {t.line}  [bold]{t.symbol}[/bold]  →  "
                     f'[green]notary.notarise(action="{scope}", ...)[/green]',
                     f'    line {t.line}  {t.symbol}  →  notary.notarise(action="{scope}", ...)')
            else:
                _out(f"    line {t.line}  [bold]{t.symbol}[/bold]  →  "
                     f'[green]add "{scope}" to plan scope list[/green]',
                     f'    line {t.line}  {t.symbol}  →  add "{scope}" to plan scope')
        _out("", "")


def print_yaml_preview(yaml_content: str) -> None:
    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Generated agentmint.yaml[/bold]", style="bright_blue"))
        _CONSOLE.print()
        _CONSOLE.print(Syntax(yaml_content, "yaml", theme="monokai", line_numbers=False))
        _CONSOLE.print()
    else:
        print("── Generated agentmint.yaml ──\n")
        print(yaml_content)


def print_plan_scaffold(candidates: List[ToolCandidate]) -> None:
    """Print a ready-to-paste Notary plan covering all detected tools."""
    scopes = sorted({c.scope_suggestion for c in candidates if c.symbol != "<dynamic>"})
    agents = sorted({c.framework for c in candidates})

    code = (
        'from agentmint.notary import Notary\n\n'
        'notary = Notary()\n'
        'plan = notary.create_plan(\n'
        '    user="ops@company.com",\n'
        '    action="agent-ops",\n'
        f'    scope={scopes},\n'
        f'    delegates_to={agents},\n'
        '    ttl_seconds=600,\n'
        ')\n'
    )

    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Starter Plan (paste into your entry point)[/bold]",
                            style="bright_blue"))
        _CONSOLE.print()
        _CONSOLE.print(Syntax(code, "python", theme="monokai", line_numbers=False))
        _CONSOLE.print()
    else:
        print("── Starter Plan ──\n")
        print(code)


def print_status(ok: bool, message: str) -> None:
    """Print a ✓/✗ status line. Used by main.py for patch results."""
    if ok:
        _out(f"  [green]✓[/green] {message}", f"  ✓ {message}")
    else:
        _out(f"  [red]✗[/red] {message}", f"  ✗ {message}")
