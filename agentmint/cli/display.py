"""
display.py — Friendly, clear console output for agentmint init.

Tone: a helpful teammate who scanned your code and is showing you
what they found. Not alarming, not corporate — just clear and useful.
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


def _out(rich_msg: str, plain_msg: str) -> None:
    if _CONSOLE:
        _CONSOLE.print(rich_msg)
    else:
        print(plain_msg)


def print_banner() -> None:
    """Brand banner shown at the start of agentmint init."""
    if _CONSOLE:
        _CONSOLE.print()
        _CONSOLE.print(
            "  [#3B82F6]╭─────────────────────────────────────────────────────╮[/#3B82F6]"
        )
        _CONSOLE.print(
            "  [#3B82F6]│[/#3B82F6]"
            "  [bold #3B82F6]Agent[/bold #3B82F6][bold #E2E8F0]Mint[/bold #E2E8F0]"
            "                                          "
            "[#3B82F6]│[/#3B82F6]"
        )
        _CONSOLE.print(
            "  [#3B82F6]│[/#3B82F6]"
            "  [#94A3B8]OWASP AI Agent Security compliance in one command[/#94A3B8]"
            "  "
            "[#3B82F6]│[/#3B82F6]"
        )
        _CONSOLE.print(
            "  [#3B82F6]│[/#3B82F6]"
            "                                                       "
            "[#3B82F6]│[/#3B82F6]"
        )
        _CONSOLE.print(
            "  [#3B82F6]│[/#3B82F6]"
            "  [#64748B]Ed25519 receipts · SHA-256 chains · Merkle trees[/#64748B]"
            "   "
            "[#3B82F6]│[/#3B82F6]"
        )
        _CONSOLE.print(
            "  [#3B82F6]│[/#3B82F6]"
            "  [#64748B]1 runtime dep · works offline · MIT license[/#64748B]"
            "        "
            "[#3B82F6]│[/#3B82F6]"
        )
        _CONSOLE.print(
            "  [#3B82F6]╰─────────────────────────────────────────────────────╯[/#3B82F6]"
        )
        _CONSOLE.print()
    else:
        print()
        print("  ┌─────────────────────────────────────────────────────┐")
        print("  │  AgentMint                                          │")
        print("  │  OWASP AI Agent Security compliance in one command  │")
        print("  │                                                     │")
        print("  │  Ed25519 receipts · SHA-256 chains · Merkle trees   │")
        print("  │  1 runtime dep · works offline · MIT license        │")
        print("  └─────────────────────────────────────────────────────┘")
        print()


def _group_by_file(candidates: List[ToolCandidate]) -> dict:
    by_file: dict[str, list[ToolCandidate]] = defaultdict(list)
    for c in candidates:
        by_file[c.file].append(c)
    return by_file


def print_scan_report(candidates: List[ToolCandidate]) -> None:
    if not candidates:
        _out("\n  [dim]Didn't find any tool calls — is this the right directory?[/dim]\n",
             "\n  Didn't find any tool calls — is this the right directory?\n")
        return

    by_file = _group_by_file(candidates)
    n_tools = len(candidates)
    n_files = len(by_file)

    high = sum(1 for c in candidates if c.confidence == "high")
    med = sum(1 for c in candidates if c.confidence == "medium")
    low = sum(1 for c in candidates if c.confidence == "low")

    # Friendly summary
    if _CONSOLE:
        _CONSOLE.print()
        summary = f"  Found [bold]{n_tools}[/bold] tool calls across [bold]{n_files}[/bold] files"
        if high == n_tools:
            summary += " — all high confidence, nice."
        elif low > 0:
            summary += f" — {low} need a closer look."
        _CONSOLE.print(Panel(
            summary,
            border_style="bright_blue",
            title="[bold bright_blue]agentmint[/bold bright_blue]",
            title_align="left",
            padding=(0, 2),
        ))
        _CONSOLE.print()

        for filepath, tools in by_file.items():
            _CONSOLE.print(f"  [bold]{filepath}[/bold]")
            for t in sorted(tools, key=lambda x: x.line):
                ln = f":{t.line}" if t.line > 0 else ""
                risk_fmt = {
                    "LOW": "[#10B981]LOW [/#10B981]",
                    "MEDIUM": "[#FBBF24]MED [/#FBBF24]",
                    "HIGH": "[#EF4444]HIGH[/#EF4444]",
                    "CRITICAL": "[bold #EF4444]CRIT[/bold #EF4444]",
                }
                risk_tag = risk_fmt.get(getattr(t, "risk_level", ""), "[#64748B]—   [/#64748B]")
                fw = {"langgraph": "[#3B82F6]langgraph[/#3B82F6]", "openai-sdk": "[#3B82F6]openai[/#3B82F6]",
                      "crewai": "[#3B82F6]crewai[/#3B82F6]", "mcp": "[#3B82F6]mcp[/#3B82F6]",
                      "raw": "[#64748B]inferred[/#64748B]"}
                _CONSOLE.print(
                    f"    {risk_tag}  "
                    f"[bold #E2E8F0]{t.symbol}[/bold #E2E8F0]"
                    f"[#64748B]{ln}[/#64748B]  "
                    f"{fw.get(t.framework, t.framework)}  "
                    f"[#64748B]{t.short_rule}[/#64748B]"
                )
            _CONSOLE.print()
    else:
        qualifier = " — all high confidence." if high == n_tools else ""
        print(f"\n  Found {n_tools} tool calls across {n_files} files{qualifier}\n")
        for filepath, tools in by_file.items():
            print(f"  {filepath}")
            for t in sorted(tools, key=lambda x: x.line):
                ln = f":{t.line}" if t.line > 0 else ""
                dot = {"high": "●", "medium": "●", "low": "○"}
                print(f"    {dot.get(t.confidence, '○')}  {t.symbol}{ln}  {t.framework}  {t.short_rule}")
            print()


def print_risk_summary(candidates: List[ToolCandidate]) -> None:
    if not candidates:
        return

    write_ops = [c for c in candidates if c.operation_guess in ("write", "delete", "exec")]
    read_ops = [c for c in candidates if c.operation_guess == "read"]
    low_conf = [c for c in candidates if c.confidence == "low"]

    if not write_ops and not low_conf:
        _out("  [green]All tools look safe — read-only operations, audit mode covers you.[/green]\n",
             "  All tools look safe — read-only operations, audit mode covers you.\n")
        return

    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Heads up[/bold]", style="yellow"))
        _CONSOLE.print()
    else:
        print("── Heads up ──\n")

    if write_ops:
        _out(f"  [yellow]These {len(write_ops)} tools can change things outside your app:[/yellow]",
             f"  These {len(write_ops)} tools can change things outside your app:")
        for c in write_ops:
            _out(f"    → [bold]{c.symbol}[/bold]  [dim]{c.file}:{c.line}[/dim]",
                 f"    → {c.symbol}  {c.file}:{c.line}")
        _out("  [dim]They'll start in audit mode (log only). Tighten later when you're ready.[/dim]\n",
             "  They'll start in audit mode (log only). Tighten later when you're ready.\n")

    if read_ops:
        _out(f"  [green]✓ {len(read_ops)} read-only tools — safe defaults applied.[/green]",
             f"  ✓ {len(read_ops)} read-only tools — safe defaults applied.")
        _out("", "")

    if low_conf:
        _out(f"  [dim]{len(low_conf)} matches look iffy — skipped from config, flag if we got it wrong.[/dim]\n",
             f"  {len(low_conf)} matches look iffy — skipped from config, flag if we got it wrong.\n")


def print_patch_instructions(candidates: List[ToolCandidate]) -> None:
    if not candidates:
        return

    by_file = _group_by_file(candidates)

    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]What to add[/bold]", style="bright_blue"))
        _CONSOLE.print()
    else:
        print("── What to add ──\n")

    for filepath, tools in by_file.items():
        _out(f"  [bold]{filepath}[/bold]", f"  {filepath}")
        _out("  [dim]Add at top →[/dim] [green]from agentmint.notary import Notary[/green]",
             "  Add at top → from agentmint.notary import Notary")
        _out("", "")

        for t in sorted(tools, key=lambda x: x.line):
            if t.confidence == "low":
                _out(f"    [dim]{t.symbol} — not sure about this one, take a look[/dim]",
                     f"    {t.symbol} — not sure about this one, take a look")
                continue
            scope = t.scope_suggestion
            if t.boundary == "definition":
                _out(f"    [bold]{t.symbol}[/bold] [dim]→[/dim] [green]notary.notarise(action=\"{scope}\", ...)[/green]",
                     f'    {t.symbol} → notary.notarise(action="{scope}", ...)')
            else:
                _out(f"    [bold]{t.symbol}[/bold] [dim]→[/dim] [green]add \"{scope}\" to plan scope[/green]",
                     f'    {t.symbol} → add "{scope}" to plan scope')
        _out("", "")


def print_yaml_preview(yaml_content: str) -> None:
    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Generated config[/bold]", style="bright_blue"))
        _CONSOLE.print()
        _CONSOLE.print(Syntax(yaml_content, "yaml", theme="monokai", line_numbers=False,
                              padding=(0, 2)))
        _CONSOLE.print()
    else:
        print("── Generated config ──\n")
        print(yaml_content)


def print_plan_scaffold(candidates: List[ToolCandidate]) -> None:
    scopes = sorted({c.scope_suggestion for c in candidates if c.symbol != "<dynamic>"})
    agents = sorted({c.framework for c in candidates})

    code = (
        'from agentmint.notary import Notary\n\n'
        'notary = Notary()\n'
        'plan = notary.create_plan(\n'
        '    user="you@yourcompany.com",\n'
        '    action="agent-ops",\n'
        f'    scope={scopes},\n'
        f'    delegates_to={agents},\n'
        '    ttl_seconds=600,\n'
        ')\n'
    )

    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Starter plan — paste into your entry point[/bold]",
                            style="bright_blue"))
        _CONSOLE.print()
        _CONSOLE.print(Syntax(code, "python", theme="monokai", line_numbers=False,
                              padding=(0, 2)))
        _CONSOLE.print()
    else:
        print("── Starter plan ──\n")
        print(code)


def print_shield_check(shield_snippet: str) -> None:
    if not shield_snippet:
        return
    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Try Shield — paste into a Python shell[/bold]",
                            style="bright_blue"))
        _CONSOLE.print()
        _CONSOLE.print(Syntax(shield_snippet, "python", theme="monokai", line_numbers=False,
                              padding=(0, 2)))
        _CONSOLE.print()
    else:
        print("── Try Shield ──\n")
        print(shield_snippet)


def print_status(ok: bool, message: str) -> None:
    if ok:
        _out(f"  [green]✓[/green] {message}", f"  ✓ {message}")
    else:
        _out(f"  [red]✗[/red] {message}", f"  ✗ {message}")


def _python_cmd() -> str:
    """Return the Python command name for this system."""
    import sys as _sys, os as _os
    name = _os.path.basename(_sys.executable) or "python"
    # Prefer 'python3' over 'python3.8' or 'python3.12' for readability
    if name.startswith("python3."):
        return "python3"
    return name


def print_quickstart_notice(path: str) -> None:
    _out(f"\n  [green]✓[/green] Generated [bold]{path}[/bold]",
         f"\n  ✓ Generated {path}")
    _out(f"    Run it → [bold]{_python_cmd()} {path}[/bold] — see your first signed receipt\n",
         f"    Run it → {_python_cmd()} {path} — see your first signed receipt\n")


def print_next_steps(has_quickstart: bool = False) -> None:
    """The friendly nudge at the end."""
    if _CONSOLE:
        _CONSOLE.print(Rule("[bold]Next up[/bold]", style="bright_blue"))
        _CONSOLE.print()
        if has_quickstart:
            _CONSOLE.print("  [bold]1.[/bold] Run the quickstart to see your first receipt")
        _CONSOLE.print("  [bold]2.[/bold] Add notary.notarise() to your tools (see above)")
        _CONSOLE.print("  [bold]3.[/bold] Run [bold]agentmint verify .[/bold] in CI to stay covered")
        _CONSOLE.print("  [bold]4.[/bold] Hand the evidence package to your auditor")
        _CONSOLE.print()
        _CONSOLE.print("  [dim]Questions? github.com/aniketh-maddipati/agentmint-python[/dim]")
        _CONSOLE.print()
    else:
        print("── Next up ──\n")
        if has_quickstart:
            print("  1. Run the quickstart to see your first receipt")
        print("  2. Add notary.notarise() to your tools (see above)")
        print("  3. Run `agentmint verify .` in CI to stay covered")
        print("  4. Hand the evidence package to your auditor")
        print()
