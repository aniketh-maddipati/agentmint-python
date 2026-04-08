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


def _group_by_file(candidates: List[ToolCandidate]) -> dict:
    by_file: dict[str, list[ToolCandidate]] = defaultdict(list)
    for c in candidates:
        by_file[c.file].append(c)
    return by_file


# ── Exposure classification helpers ───────────────────────

INPUT_CONSEQUENCES: dict[str, str] = {
    "exec": "LLM-generated arguments execute directly",
    "write": "injection could alter what gets written",
    "delete": "injection could target wrong resources",
    "network": "URL or endpoint determined by LLM",
    "read": "prompt content influences data access",
    "unknown": "arguments are not validated",
}

OUTPUT_CONSEQUENCES: dict[str, str] = {
    "exec": "execution result feeds back to LLM unfiltered",
    "write": "confirmation/response flows to LLM unfiltered",
    "delete": "deletion result unfiltered",
    "network": "external content is prime indirect injection vector",
    "read": "query results flow directly to LLM",
    "unknown": "return value feeds to LLM unfiltered",
}


def _classify_risk(c: ToolCandidate) -> str:
    """Classify a tool candidate as dangerous, moderate, or safe."""
    op = c.operation_guess
    name = c.symbol.lower()

    # Dangerous: write/exec/delete/network operations, or unknown with external-sounding names
    if op in ("write", "exec", "delete", "network"):
        return "dangerous"
    if op == "unknown":
        external_hints = ("send", "email", "post", "upload", "submit", "push",
                          "charge", "pay", "transfer", "deploy", "execute",
                          "delete", "remove", "drop")
        if any(hint in name for hint in external_hints):
            return "dangerous"

    # Moderate: read + external/database resource
    if op == "read":
        resource = c.resource_guess.lower()
        external_hints = ("api", "web", "http", "url", "database", "db",
                          "sql", "query", "fetch", "external")
        if any(hint in name or hint in resource for hint in external_hints):
            return "moderate"

    # Safe: read + local/pure computation
    return "safe"


def _scope_description(c: ToolCandidate) -> str:
    """Generate a scope line based on tool name and operation."""
    name = c.symbol.lower()
    op = c.operation_guess

    if "email" in name or "mail" in name:
        return "no limits on recipients, content, or frequency"
    if "pay" in name or "charge" in name or "billing" in name or "invoice" in name:
        return "no amount ceiling, no customer allowlist"
    if "database" in name or "query" in name or "sql" in name or "db" in name:
        return "can query any table"
    if op == "delete" or "delete" in name or "remove" in name:
        return "can delete any resource"
    if op == "network" or "fetch" in name or "http" in name or "url" in name or "web" in name:
        return "can fetch any URL"
    if "file" in name or "write" in name or "upload" in name:
        return "can write to any path"

    # Fallback by operation
    fallback = {
        "exec": "no limits on what gets executed",
        "write": "no restrictions on write targets",
        "delete": "can delete any resource",
        "network": "can reach any endpoint",
        "read": "can read any data source",
        "unknown": "no constraints on behavior",
    }
    return fallback.get(op, "no constraints on behavior")


def _rate_suggestion(c: ToolCandidate) -> str:
    """Suggest a rate limit based on tool operation."""
    op = c.operation_guess
    name = c.symbol.lower()
    if "pay" in name or "charge" in name:
        return "10/hr"
    if "email" in name or "send" in name:
        return "50/hr"
    if op == "network" or "fetch" in name:
        return "30/hr"
    if op == "read" or "query" in name:
        return "100/hr"
    if op == "delete":
        return "5/hr"
    return "50/hr"


def _scope_pattern(c: ToolCandidate) -> str:
    """Generate scope pattern for enforcement preview."""
    name = c.symbol.lower()
    parts = name.split("_", 1)
    if len(parts) > 1 and len(parts[0]) > 2:
        return f"tool:{parts[0]}_*"
    return f"tool:{name}"


# ── Full report: Discovery + Exposure + Enforcement Preview + Summary ──

def print_full_report(candidates: List[ToolCandidate]) -> None:
    """Print the complete agentmint init report with four phases."""
    if not candidates:
        print("\n  No tool calls found — is this the right directory?\n")
        return

    by_file = _group_by_file(candidates)
    n_tools = len(candidates)
    n_files = len(by_file)

    # Classify all tools
    dangerous = [c for c in candidates if _classify_risk(c) == "dangerous"]
    moderate = [c for c in candidates if _classify_risk(c) == "moderate"]
    safe = [c for c in candidates if _classify_risk(c) == "safe"]
    not_ready = len(dangerous) + len(moderate)

    # Collect framework counts
    fw_counts: dict[str, int] = defaultdict(int)
    for c in candidates:
        fw_counts[c.framework] += 1

    # ── HEADLINE BOX ──────────────────────────────────
    print()
    print(f"  \u250c\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2510")
    print(f"  \u2502                                                       \u2502")
    print(f"  \u2502  {not_ready} of {n_tools} tools are not production-ready.{' ' * max(0, 18 - len(str(not_ready)) - len(str(n_tools)))}\u2502")
    print(f"  \u2502                                                       \u2502")
    print(f"  \u2502  No scope limits. No input/output scanning.           \u2502")
    print(f"  \u2502  No rate controls. No audit trail.                    \u2502")
    print(f"  \u2502                                                       \u2502")
    print(f"  \u2502  Same gaps behind:                                    \u2502")
    print(f"  \u2502    Kiro       \u2192 deleted production    (Dec 2025)    \u2502")
    print(f"  \u2502    LiteLLM    \u2192 500K machines owned   (Mar 2026)    \u2502")
    print(f"  \u2502    Claude Code \u2192 27M tokens / $400+    (2025)       \u2502")
    print(f"  \u2502                                                       \u2502")
    print(f"  \u2514\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2518")

    # ── Phase 1: SCAN ─────────────────────────────────
    print()
    print(f"  SCAN")
    print()

    fw_summary = ", ".join(f"{fw} ({count})" for fw, count in sorted(fw_counts.items(), key=lambda x: -x[1]))
    print(f"  Found {n_tools} tool calls across {n_files} files")
    print(f"  Frameworks: {fw_summary}")
    print()

    # Compact file listing
    for filepath, tools in sorted(by_file.items()):
        n = len(tools)
        file_fws: dict[str, int] = defaultdict(int)
        for t in tools:
            file_fws[t.framework] += 1
        dominant_fw = max(file_fws, key=file_fws.get)  # type: ignore[arg-type]
        label = "tool" if n == 1 else "tools"
        print(f"  {filepath:<22s} {n} {label:<6s} {dominant_fw}")
    print()

    # ── Phase 2: EXPOSURE ─────────────────────────────
    print(f"  EXPOSURE")
    print()

    # Incident reference strings for each dimension
    SCOPE_INCIDENT = "Kiro had unrestricted scope. It deleted production."
    INPUT_INCIDENT = "OWASP #1 agentic risk. Injection goes straight to execution."
    OUTPUT_INCIDENT = "LiteLLM attack vector. Tool output = LLM instructions."
    RATE_INCIDENT = "Claude Code burned 27M tokens with no kill switch."
    AUDIT_INCIDENT = "88% of orgs had agent incidents. 0% could prove what happened."

    for c, risk in [(c, "dangerous") for c in dangerous] + [(c, "moderate") for c in moderate]:
        op = c.operation_guess
        ln = f":{c.line}" if c.line > 0 else ""
        marker = "\u26a0" if risk == "dangerous" else "~"

        dec_map = {
            "openai-sdk": "@function_tool",
            "crewai": "@tool",
            "langgraph": "@tool",
            "mcp": "@server.tool",
            "raw": "inferred",
        }
        decorator = dec_map.get(c.framework, c.framework)

        op_label_map = {
            "exec": "exec \u2192 sends data externally",
            "write": "write \u2192 modifies external state",
            "delete": "delete \u2192 removes data",
            "network": "network \u2192 fetches external content",
            "read": "read \u2192 queries data",
            "unknown": "unknown \u2192 behavior not determinable",
        }
        op_label = op_label_map.get(op, f"{op}")

        print(f"  {marker} {c.symbol} ({c.file}{ln}) \u2014 {c.framework} {decorator}")
        print(f"    scope:    UNRESTRICTED \u2014 {_scope_description(c)}")
        print(f"              \u2514 {SCOPE_INCIDENT}")
        print(f"    inputs:   UNSCANNED \u2014 {INPUT_CONSEQUENCES.get(op, INPUT_CONSEQUENCES['unknown'])}")
        print(f"              \u2514 {INPUT_INCIDENT}")
        print(f"    outputs:  UNSCANNED \u2014 {OUTPUT_CONSEQUENCES.get(op, OUTPUT_CONSEQUENCES['unknown'])}")
        print(f"              \u2514 {OUTPUT_INCIDENT}")
        print(f"    rate:     UNLIMITED \u2014 no circuit breaker")
        print(f"              \u2514 {RATE_INCIDENT}")
        print(f"    audit:    NONE \u2014 no receipt, no proof of what happened")
        print(f"              \u2514 {AUDIT_INCIDENT}")
        print()

    # Safe tools — compact listing
    for c in safe:
        name_lower = c.symbol.lower()
        if "parse" in name_lower or "compute" in name_lower or "format" in name_lower:
            label = "read, local computation"
        else:
            label = "read, low risk"
        print(f"  \u2713 {c.symbol} ({c.file}:{c.line}) \u2014 {label}")

    if safe:
        print()

    # ── Phase 3: ENFORCEMENT PREVIEW ──────────────────
    print(f"  WITH AGENTMINT")
    print()
    print(f"  import agentmint")
    print(f"  wrapped = agentmint.wrap_agent(agent)")
    print()

    # Table header
    hdr = f"  {'Tool':<24s} {'Inputs':<11s} {'Outputs':<11s} {'Scope':<18s} {'Rate':<9s} Identity"
    sep = "  " + "\u2500" * 78
    print(hdr)
    print(sep)

    for c in candidates:
        risk = _classify_risk(c)
        name = c.symbol
        if len(name) > 22:
            name = name[:20] + ".."

        if risk == "safe":
            print(f"  {name:<24s} {'passthrough':<11s} {'':11s} {'':18s} {'':9s} receipts \u2713")
        else:
            scope_pat = _scope_pattern(c)
            if len(scope_pat) > 16:
                scope_pat = scope_pat[:14] + ".."
            rate = _rate_suggestion(c)
            print(f"  {name:<24s} {'scanned':<11s} {'scanned':<11s} {scope_pat:<18s} {rate:<9s} receipts \u2713")

    print()
    print(f"  Every allow and deny is Ed25519 signed and SHA-256 hash-chained.")
    print(f"  Verify with openssl. No vendor software. No account.")
    print()
    print(f"  See it working:  python enforce_demo.py")
    print()

    # ── Phase 4: SUMMARY ──────────────────────────────
    print('  ' + '─' * 52)
    print()
    print(f"  {n_tools} tools found across {n_files} files")
    print()
    print(f"  Now:                          With AgentMint:")
    print(f"  0 inputs scanned              {n_tools} inputs scanned")
    print(f"  0 outputs scanned             {n_tools} outputs scanned")
    print(f"  0 scope restrictions          {n_tools} scoped to plan")
    print(f"  0 rate limits                 {n_tools} rate-limited")
    print(f"  0 identity governance         {n_tools} with signed receipts")
    print()
    print(f"  Next steps:")
    print(f"    python enforce_demo.py        # see enforcement in action")
    print(f"    agentmint wrap .              # add enforcement to your code")
    print(f"    agentmint verify .            # check coverage in CI")
    print()


# ── Original functions (preserved for backward compatibility) ─────

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
                dot = {"high": "[green]●[/green]", "medium": "[yellow]●[/yellow]", "low": "[dim]○[/dim]"}
                fw = {"langgraph": "[cyan]langgraph[/cyan]", "openai-sdk": "[magenta]openai[/magenta]",
                      "crewai": "[blue]crewai[/blue]", "mcp": "[bright_cyan]mcp[/bright_cyan]",
                      "raw": "[dim]inferred[/dim]"}
                _CONSOLE.print(
                    f"    {dot.get(t.confidence, '○')}  "
                    f"[bold]{t.symbol}[/bold]"
                    f"[dim]{ln}[/dim]  "
                    f"{fw.get(t.framework, t.framework)}  "
                    f"[dim]{t.short_rule}[/dim]"
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


def print_quickstart_notice(path: str) -> None:
    _out(f"\n  [green]✓[/green] Generated [bold]{path}[/bold]",
         f"\n  ✓ Generated {path}")
    _out(f"    Run it → [bold]python3 {path}[/bold] — see your first signed receipt\n",
         f"    Run it → python3 {path} — see your first signed receipt\n")


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
