#!/usr/bin/env python3
"""
AgentMint × SRE Agent — Traversal Demo (with evidence export)
=============================================================

Four scenarios + evidence package export with live verification.

Run:
    uv run python3 examples/traversal_sre_demo.py

No real infrastructure. No LLM calls. No external deps beyond agentmint + rich.
The receipt is the product. Everything else is scaffolding.
"""

# ────────────────────────────────────────────────────────────
# This file is the ORIGINAL traversal_sre_demo.py with one addition:
# After scenario 4, it exports an evidence package and verifies it.
#
# To apply: copy this file over examples/traversal_sre_demo.py
# Only the main() function changes — everything else is identical.
#
# CHANGE: Added export_and_verify() call at the end of main().
# ────────────────────────────────────────────────────────────

from __future__ import annotations

import hashlib
import json
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, TypeVar

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentmint import AgentMint, DelegationStatus
from agentmint.notary import Notary, NotarisedReceipt


console = Console(highlight=False)
T = TypeVar("T")


# ── Display helpers ────────────────────────────────────────

def pause(seconds: float = 0.3) -> None:
    time.sleep(seconds)

def heading(text: str) -> None:
    console.print(f"\n[bold white]{text}[/]\n")
    pause(0.15)

def ok(msg: str) -> None:
    console.print(f"  [bold green]✓[/] {msg}")

def fail(msg: str) -> None:
    console.print(f"  [bold red]✗[/] {msg}")

def warn(msg: str) -> None:
    console.print(f"  [bold yellow]![/] {msg}")

def info(msg: str) -> None:
    console.print(f"  [dim]{msg}[/]")

def numbered(n: int, msg: str) -> None:
    console.print(f"  [bold cyan]{n}.[/] [white]{msg}[/]")
    pause(0.35)

def source(name: str, detail: str) -> None:
    console.print(f"     [cyan]→[/] [bold]{name}[/]  [dim]{detail}[/]")
    pause(0.2)

def section_break() -> None:
    console.print()
    console.rule(style="dim white")
    console.print()

def banner(num: int, title: str, description: str, color: str) -> None:
    console.print(Panel(
        Text.from_markup(f"[bold white]Scenario {num} — {title}[/]\n\n[dim]{description}[/]"),
        border_style=color, padding=(1, 2),
    ))
    pause(0.6)

def takeaway(title: str, body: str, color: str) -> None:
    console.print(Panel(
        Text.from_markup(body),
        title=f"[bold white]{title}[/]",
        border_style=f"dim {color}", padding=(1, 2),
    ))
    pause(0.4)


# ── Latency ───────────────────────────────────────────────

@dataclass
class Latency:
    gatekeeper_us: float = 0.0
    sign_ms: float = 0.0
    timestamp_ms: float = 0.0

    @property
    def total_ms(self) -> float:
        return self.sign_ms + self.timestamp_ms


def timed_us(fn: Callable[[], T]) -> tuple[T, float]:
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1_000_000


def timed_ms(fn: Callable[[], T]) -> tuple[T, float]:
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1_000


# ── Mock Data ──────────────────────────────────────────────

GRAFANA = {
    "service": "payments-api",
    "error_rate_5xx": 0.12,
    "error_rate_5xx_baseline": 0.01,
    "p99_latency_ms": 2340,
    "p99_latency_baseline_ms": 180,
}

ELASTIC = {
    "query": "service:payments-api AND level:error AND @timestamp>now-15m",
    "total_hits": 1847,
    "entries": [
        {"time": "14:32:07", "msg": "NullPointerException in PaymentProcessor.validate()"},
        {"time": "14:32:09", "msg": "Connection timeout to downstream auth-service"},
    ],
    "error_pattern": "all_errors_correlate_to_deployment_v2.3.1",
}

GITHUB = {
    "repo": "acme-corp/payments-api",
    "deploy": {
        "version": "v2.3.1", "deployed_at": "2026-03-18T14:15:00Z",
        "author": "dev@acme-corp.com", "sha": "a1b2c3d4",
        "message": "feat: add retry logic to payment validation",
    },
}

INCIDENT = {
    "channel": "#inc-payments-api-20260318",
    "alert_source": "alertmanager",
    "severity": "P1",
    "on_call": "sre-lead@acme-corp.com",
}


# ── Shared logic ──────────────────────────────────────────

def _hash(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()[:12]


def show_investigation() -> float:
    t0 = time.time()

    heading("① Alert Detection")
    numbered(1, "Alertmanager fires HighErrorRate_payments-api")
    source("Slack", f"{INCIDENT['channel']}  severity: {INCIDENT['severity']}")

    heading("② Multi-Source Investigation")
    numbered(2, "Query Grafana for golden signals")
    source("Grafana", f"error_rate: {GRAFANA['error_rate_5xx']:.0%} (baseline: {GRAFANA['error_rate_5xx_baseline']:.0%})")
    source("Grafana", f"p99 latency: {GRAFANA['p99_latency_ms']}ms (baseline: {GRAFANA['p99_latency_baseline_ms']}ms)")

    numbered(3, "Query Elastic for error logs")
    source("Elastic", f"{ELASTIC['total_hits']} errors in last 15m")
    source("Elastic", f"pattern: {ELASTIC['error_pattern']}")

    d = GITHUB["deploy"]
    numbered(4, "Query GitHub for recent deployments")
    source("GitHub", f"{d['version']} deployed by {d['author']}")

    heading("③ Root Cause")
    console.print(Panel(
        Text.from_markup(
            "[bold white]Root Cause:[/] deployment v2.3.1 introduced regression\n"
            "[bold white]Confidence:[/] [green]0.94[/]\n"
            "[bold white]Chain:[/] retry logic → pool exhaustion → auth timeouts → payment failures"
        ),
        title="[bold cyan]Diagnosis[/]", border_style="cyan", padding=(0, 2),
    ))
    return t0


def make_plans(mint, notary, user, scope, checks, agent="sre-agent"):
    gk = mint.issue_plan(
        action="remediation", user=user, scope=scope,
        delegates_to=[agent], requires_checkpoint=checks, ttl=300,
    )
    ny = notary.create_plan(
        user=user, action="remediation", scope=scope,
        checkpoints=checks, delegates_to=[agent],
    )
    return gk, ny


def gate_check(mint, plan, agent, action):
    return timed_us(lambda: mint.delegate(plan, agent, action))


def sign_and_stamp(notary, action, agent, plan, evidence):
    lat = Latency()
    _, lat.sign_ms = timed_ms(lambda: notary.notarise(
        action=action, agent=agent, plan=plan,
        evidence=evidence, enable_timestamp=False,
    ))
    fresh = notary.create_plan(
        user=plan.user, action=plan.action,
        scope=list(plan.scope), checkpoints=list(plan.checkpoints),
        delegates_to=list(plan.delegates_to),
    )
    receipt, total = timed_ms(lambda: notary.notarise(
        action=action, agent=agent, plan=fresh,
        evidence=evidence, enable_timestamp=True,
    ))
    lat.timestamp_ms = total - lat.sign_ms
    return receipt, lat


def render_receipt(receipt: NotarisedReceipt) -> None:
    is_ok = receipt.in_policy
    color = "green" if is_ok else "red"
    label = "IN POLICY" if is_ok else "OUT OF POLICY"

    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 1))
    tbl.add_column("Field", style="cyan", no_wrap=True, min_width=18)
    tbl.add_column("Value", style="white")

    rows = [
        ("receipt_id", receipt.id[:20] + "..."),
        ("agent", receipt.agent),
        ("action", receipt.action),
        ("in_policy", f"[{color}]{receipt.in_policy}[/]"),
        ("policy_reason", f"[{color}]{receipt.policy_reason}[/]"),
        ("chain_hash", (receipt.previous_receipt_hash or "None (first)")[:24] + "..."),
        ("signature", receipt.signature[:28] + "..."),
    ]
    if receipt.timestamp_result:
        rows.append(("tsa_url", receipt.timestamp_result.tsa_url))
    for f, v in rows:
        tbl.add_row(f, v)

    console.print(Panel(tbl, title=f"[bold {color}]{label}[/]", border_style=color, padding=(0, 1)))


def verify(notary, receipt, note=""):
    suffix = f" — {note}" if note else ""
    if notary.verify_receipt(receipt):
        ok(f"[bold green]Ed25519 signature verified[/]{suffix}")
    if receipt.timestamp_result:
        ok("[bold green]RFC 3161 timestamp present[/]")


# ── Scenario 1: Happy Path ────────────────────────────────

def scenario_1(mint, notary):
    banner(1, "Happy Path (L4: Human-Approved)",
        "Agent investigates → human approves → agent rolls back → receipt proves it.", "green")

    t0 = show_investigation()

    heading("④ Authorization + Execution")
    scope = ["remediate:rollback:payments-api", "remediate:restart:payments-api"]
    checks = ["remediate:scale_down:*", "remediate:delete:*"]
    gk, ny = make_plans(mint, notary, INCIDENT["on_call"], scope, checks)

    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:rollback:payments-api")
    ok(f"AUTHORIZED — {gk_us:.0f}μs")

    heading("⑤ Receipt")
    evidence = {
        "severity": INCIDENT["severity"],
        "root_cause": "deployment_v2.3.1_regression",
        "confidence": 0.94,
        "rollback_from": "v2.3.1", "rollback_to": "v2.3.0",
        "execution_result": True, "pods_restarted": 6,
        "approved_by": INCIDENT["on_call"],
    }
    receipt, lat = sign_and_stamp(notary, "remediate:rollback:payments-api", "sre-agent", ny, evidence)
    render_receipt(receipt)
    verify(notary, receipt)
    return receipt


# ── Scenario 2: Scope Violation ───────────────────────────

def scenario_2(mint, notary):
    banner(2, "Scope Violation",
        "Agent targets wrong service. Not in scope. Blocked.", "red")

    scope = ["remediate:rollback:payments-api"]
    checks = ["remediate:delete:*"]
    gk, ny = make_plans(mint, notary, INCIDENT["on_call"], scope, checks)

    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:restart:auth-service")
    fail(f"BLOCKED — {result.status.value} — {gk_us:.0f}μs")

    receipt, _ = sign_and_stamp(notary, "remediate:restart:auth-service", "sre-agent", ny, {
        "attempted": "remediate:restart:auth-service",
        "result": result.status.value,
    })
    render_receipt(receipt)
    verify(notary, receipt, "denials are signed too")
    return receipt


# ── Scenario 3: L5 Autonomous ─────────────────────────────

def scenario_3(mint, notary):
    banner(3, "Autonomous (L5: No Human)",
        "Policy engine approves. No Slack button. Receipt is the accountability.", "yellow")

    scope = ["remediate:rollback:payments-api"]
    checks = ["remediate:delete:*"]
    gk, ny = make_plans(mint, notary, "policy-engine@acme-corp.com", scope, checks)

    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:rollback:payments-api")
    ok(f"AUTHORIZED by policy engine — {gk_us:.0f}μs")

    receipt, _ = sign_and_stamp(notary, "remediate:rollback:payments-api", "sre-agent", ny, {
        "rollback_from": "v2.3.1", "rollback_to": "v2.3.0",
        "approved_by": "policy-engine@acme-corp.com",
        "human_in_loop": False, "autonomy_level": "L5",
    })
    render_receipt(receipt)
    verify(notary, receipt)
    return receipt


# ── Scenario 4: Checkpoint ────────────────────────────────

def scenario_4(mint, notary):
    banner(4, "Checkpoint Escalation",
        "Agent wants to scale down — high risk. Escalated, not denied.", "magenta")

    scope = ["remediate:rollback:*", "remediate:scale_down:*"]
    checks = ["remediate:scale_down:*"]
    gk, ny = make_plans(mint, notary, INCIDENT["on_call"], scope, checks)

    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:scale_down:payments-api")
    warn(f"CHECKPOINT — needs re-approval — {gk_us:.0f}μs")

    receipt, _ = sign_and_stamp(notary, "remediate:scale_down:payments-api", "sre-agent", ny, {
        "attempted": "remediate:scale_down:payments-api",
        "result": "checkpoint_required",
        "blast_radius": "high",
    })
    render_receipt(receipt)
    verify(notary, receipt, "escalations are signed too")
    return receipt


# ── Evidence Export + Verification ─────────────────────────

def export_and_verify(notary):
    """Export evidence package and verify both timestamps and signatures."""
    heading("⑨ Evidence Package — Export + Verify")

    output_dir = Path("./evidence_output")
    zip_path = notary.export_evidence(output_dir)
    ok(f"Exported: {zip_path.name}")

    # Show contents
    with zipfile.ZipFile(zip_path) as zf:
        names = sorted(zf.namelist())
        tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
        tbl.add_column("File", style="cyan")
        tbl.add_column("Size", style="dim", justify="right")
        for name in names:
            size = zf.getinfo(name).file_size
            tbl.add_row(name, f"{size:,} B")
        console.print(tbl)

    # Verify signatures inline (same logic as verify_sigs.py)
    heading("Signature Verification")
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
    import base64

    def canonical(d):
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

    with zipfile.ZipFile(zip_path) as zf:
        # Load public key
        pem = zf.read("public_key.pem").decode()
        pem_lines = pem.strip().split("\n")
        der = base64.b64decode("".join(pem_lines[1:-1]))
        vk = VerifyKey(der[12:])  # Skip SPKI prefix

        sig_ok = sig_fail = 0
        for name in sorted(zf.namelist()):
            if not name.startswith("receipts/") or not name.endswith(".json"):
                continue
            receipt = json.loads(zf.read(name))
            sig = bytes.fromhex(receipt["signature"])
            signable = {k: v for k, v in receipt.items() if k not in ("signature", "timestamp")}
            try:
                vk.verify(canonical(signable), sig)
                tag = "[green]in policy[/]" if receipt.get("in_policy") else "[red]violation[/]"
                ok(f"{receipt['id'][:8]}  {receipt['action']}  ({tag})")
                sig_ok += 1
            except BadSignatureError:
                fail(f"{receipt['id'][:8]}  {receipt['action']}  SIGNATURE FAILED")
                sig_fail += 1

    console.print(f"\n  [bold]Signatures: {sig_ok} verified, {sig_fail} failed[/]")
    if sig_fail == 0:
        ok("[bold green]All signatures verified[/]")

    console.print(Panel(
        Text.from_markup(
            "[bold white]What's in the zip:[/]\n\n"
            "  [cyan]VERIFY.sh[/]        — bash VERIFY.sh — timestamps, pure OpenSSL\n"
            "  [cyan]verify_sigs.py[/]   — python3 verify_sigs.py — Ed25519 signatures\n"
            "  [cyan]public_key.pem[/]   — verify without trusting AgentMint\n\n"
            "[dim]Give this zip to an auditor. They verify on their own machine.\n"
            "No AgentMint software. No account. No network connection.[/]"
        ),
        border_style="dim green", padding=(1, 2),
    ))


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    console.print(Panel(
        Text.from_markup(
            "[bold white]AgentMint × SRE Agent[/]\n"
            "[dim]Cryptographic receipts at the remediation boundary[/]"
        ),
        border_style="white", padding=(0, 2),
    ))

    mint = AgentMint(quiet=True)
    notary = Notary()

    scenario_1(mint, notary)
    section_break()
    scenario_2(mint, notary)
    section_break()
    scenario_3(mint, notary)
    section_break()
    scenario_4(mint, notary)
    section_break()

    # NEW: export evidence and verify live
    export_and_verify(notary)

    console.print()
    info("All receipts signed with Ed25519 + RFC 3161 timestamps from FreeTSA.")
    info("Verification requires only openssl + pynacl — no AgentMint software.")
    console.print()
    console.print("  [bold]github.com/aniketh-maddipati/agentmint-python[/]")
    console.print()


if __name__ == "__main__":
    main()
