#!/usr/bin/env python3
"""
AgentMint × SRE Agent — Traversal Demo
=======================================

Four scenarios showing AgentMint at the remediation boundary of an SRE agent.
Each scenario produces a real Ed25519-signed, RFC 3161-timestamped receipt.

    Scenario 1 — L4 Happy Path:       Human approves rollback → receipt proves match
    Scenario 2 — Scope Violation:      Agent targets wrong service → blocked + signed denial
    Scenario 3 — L5 Autonomous:        Policy engine approves (no human) → receipt proves scope
    Scenario 4 — Checkpoint Escalation: High-risk action → escalated, receipt captures it

Run:
    uv run python3 examples/sre_demo.py

No real infrastructure. No LLM calls. No external deps beyond agentmint + rich.
Mock data mirrors DigitalOcean/Eventbrite/PepsiCo/Cloudways integration stacks.
The receipt is the product. Everything else is scaffolding.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, TypeVar

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from agentmint import AgentMint, DelegationStatus
from agentmint.notary import Notary, NotarisedReceipt


# ── Console ────────────────────────────────────────────────

console = Console(highlight=False)

T = TypeVar("T")


# ── Display helpers (DRY — every scenario uses these) ──────

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
        border_style=color,
        padding=(1, 2),
    ))
    pause(0.6)


def takeaway(title: str, body: str, color: str) -> None:
    console.print(Panel(
        Text.from_markup(body),
        title=f"[bold white]{title}[/]",
        border_style=f"dim {color}",
        padding=(1, 2),
    ))
    pause(0.4)


# ── Latency measurement ───────────────────────────────────

@dataclass
class Latency:
    gatekeeper_us: float = 0.0
    sign_ms: float = 0.0
    timestamp_ms: float = 0.0

    @property
    def total_ms(self) -> float:
        return self.sign_ms + self.timestamp_ms


def timed_us(fn: Callable[[], T]) -> tuple[T, float]:
    """Run fn, return (result, elapsed_microseconds)."""
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1_000_000


def timed_ms(fn: Callable[[], T]) -> tuple[T, float]:
    """Run fn, return (result, elapsed_milliseconds)."""
    t0 = time.perf_counter()
    result = fn()
    return result, (time.perf_counter() - t0) * 1_000


# ── Mock Data ──────────────────────────────────────────────
# Mirrors the integration stacks Traversal deploys into:
#   DigitalOcean: Grafana, Elastic, VictoriaMetrics, GitHub, Alertmanager, Slack
#   Eventbrite:   Datadog, GitHub, Slack, FireHydrant
#   PepsiCo:      Elastic, AppDynamics, ServiceNow, Grafana
#   Cloudways:    Sensu, Ansible, custom proxy

GRAFANA = {
    "service": "payments-api",
    "error_rate_5xx": 0.12,
    "error_rate_5xx_baseline": 0.01,
    "p99_latency_ms": 2340,
    "p99_latency_baseline_ms": 180,
    "request_rate_rpm": 14200,
    "golden_signals_violated": ["error_rate", "latency"],
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
        "files": 3, "added": 47, "removed": 12,
    },
    "previous_version": "v2.3.0",
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
    """Print investigation steps. Returns start timestamp for duration calc."""
    t0 = time.time()

    heading("① Alert Detection")
    numbered(1, "Alertmanager fires HighErrorRate_payments-api")
    source("Slack", f"{INCIDENT['channel']}  severity: {INCIDENT['severity']}")
    info(f"on-call: {INCIDENT['on_call']}")
    pause(0.2)

    heading("② Multi-Source Investigation")
    info("(Same data sources Traversal's agents already query)\n")

    numbered(2, "Query Grafana for golden signals")
    source("Grafana", f"error_rate: {GRAFANA['error_rate_5xx']:.0%} (baseline: {GRAFANA['error_rate_5xx_baseline']:.0%})")
    source("Grafana", f"p99 latency: {GRAFANA['p99_latency_ms']}ms (baseline: {GRAFANA['p99_latency_baseline_ms']}ms)")
    source("Grafana", f"signals violated: {', '.join(GRAFANA['golden_signals_violated'])}")

    numbered(3, "Query Elastic for error logs")
    source("Elastic", f"{ELASTIC['total_hits']} errors in last 15m")
    for e in ELASTIC["entries"]:
        info(f"    {e['time']}  {e['msg']}")
    source("Elastic", f"pattern: {ELASTIC['error_pattern']}")

    d = GITHUB["deploy"]
    numbered(4, "Query GitHub for recent deployments")
    source("GitHub", f"{d['version']} deployed {d['deployed_at'][11:16]} by {d['author']}")
    source("GitHub", f"sha: {d['sha']}  \"{d['message']}\"")
    source("GitHub", f"{d['files']} files, +{d['added']}/-{d['removed']}")

    heading("③ Root Cause Analysis")
    console.print(Panel(
        Text.from_markup(
            "[bold white]Root Cause:[/] deployment v2.3.1 introduced regression\n"
            "[bold white]Confidence:[/] [green]bulls_eye_rca (0.94)[/]\n"
            "[bold white]Causal Chain:[/]\n"
            "  v2.3.1 retry logic → connection pool exhaustion\n"
            "  → auth-service timeouts → payment validation failures\n\n"
            "[dim]Rejected hypotheses: downstream auth degradation, traffic spike, capacity[/]"
        ),
        title="[bold cyan]Diagnosis[/]",
        border_style="cyan",
        padding=(0, 2),
    ))
    pause(0.4)
    return t0


def build_rollback_evidence(approver: str, channel: str, investigation_start: float) -> dict:
    """Full evidence dict for a rollback receipt."""
    return {
        "incident_channel": INCIDENT["channel"],
        "alert_source": INCIDENT["alert_source"],
        "severity": INCIDENT["severity"],
        "investigation_duration_ms": int((time.time() - investigation_start) * 1000),
        "data_sources": {
            "grafana_metrics": {
                "query_hash": f"sha256:{_hash(json.dumps(GRAFANA, sort_keys=True))}",
                "error_rate_observed": GRAFANA["error_rate_5xx"],
                "golden_signals_violated": GRAFANA["golden_signals_violated"],
            },
            "elastic_logs": {
                "query_hash": f"sha256:{_hash(ELASTIC['query'])}",
                "total_error_hits": ELASTIC["total_hits"],
                "error_pattern": ELASTIC["error_pattern"],
            },
            "github_commits": {
                "query_hash": f"sha256:{_hash(GITHUB['repo'])}",
                "correlated_deployment": "v2.3.1",
                "deployed_at": GITHUB["deploy"]["deployed_at"],
            },
        },
        "root_cause": "deployment_v2.3.1_introduced_regression",
        "confidence_tier": "bulls_eye_rca",
        "confidence_score": 0.94,
        "causal_chain": (
            "v2.3.1 retry logic → connection pool exhaustion "
            "→ auth-service timeouts → payment validation failures"
        ),
        "alternate_hypotheses_rejected": [
            "downstream_auth_service_degradation",
            "traffic_spike",
            "infrastructure_capacity",
        ],
        "remediation_type": "rollback",
        "target_service": "payments-api",
        "rollback_from": "v2.3.1",
        "rollback_to": "v2.3.0",
        "execution_result": True,
        "execution_duration_ms": 720,
        "pods_restarted": 6,
        "health_check_passed": True,
        "approved_by": approver,
        "approval_channel": channel,
        "approval_timestamp": datetime.now(timezone.utc).isoformat(),
    }


def make_plans(
    mint: AgentMint,
    notary: Notary,
    user: str,
    scope: list[str],
    checkpoints: list[str],
    agent: str = "sre-agent",
) -> tuple:
    """Create paired Gatekeeper + Notary plans."""
    gk = mint.issue_plan(
        action="remediation", user=user, scope=scope,
        delegates_to=[agent], requires_checkpoint=checkpoints, ttl=300,
    )
    ny = notary.create_plan(
        user=user, action="remediation", scope=scope,
        checkpoints=checkpoints, delegates_to=[agent],
    )
    return gk, ny


def gate_check(mint: AgentMint, plan, agent: str, action: str) -> tuple:
    """Gatekeeper authorization with measured latency. Returns (result, μs)."""
    return timed_us(lambda: mint.delegate(plan, agent, action))


def sign_and_stamp(
    notary: Notary, action: str, agent: str, plan, evidence: dict,
) -> tuple[NotarisedReceipt, Latency]:
    """Notarize with separate signing/timestamp measurement."""
    lat = Latency()

    # Phase 1: sign only (no network)
    _, lat.sign_ms = timed_ms(lambda: notary.notarise(
        action=action, agent=agent, plan=plan,
        evidence=evidence, enable_timestamp=False,
    ))

    # Phase 2: sign + timestamp (fresh plan for clean evidence package)
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


def show_latency(lat: Latency) -> None:
    """Latency breakdown panel."""
    console.print(Panel(
        Text.from_markup(
            "[bold white]Latency Breakdown — What This Costs You[/]\n\n"
            f"  [green]Gatekeeper check:[/]     {lat.gatekeeper_us:>8.0f}μs   [dim]in-memory scope eval + Ed25519 sign[/]\n"
            f"  [green]Notary signing:[/]        {lat.sign_ms:>7.1f}ms   [dim]Ed25519 + SHA-512 + policy eval[/]\n"
            f"  [yellow]FreeTSA timestamp:[/]    {lat.timestamp_ms:>7.0f}ms   [dim]only network call (async, post-exec)[/]\n"
            f"  [bold white]Total overhead:[/]       {lat.total_ms:>7.0f}ms   [dim]none of this blocks your remediation[/]\n\n"
            "[dim]Gatekeeper runs before execution (sub-millisecond, in-memory).\n"
            "Notary runs after execution (never in the critical path).\n"
            "If FreeTSA is slow or down, you still get a signed receipt.\n"
            "Your agent's remediation speed is completely unaffected.[/]"
        ),
        border_style="dim cyan",
        padding=(1, 2),
    ))
    pause(0.3)


# ── Receipt renderer ──────────────────────────────────────

def render_receipt(receipt: NotarisedReceipt) -> None:
    """Render any receipt — authorized, denied, or escalated."""
    is_ok = receipt.in_policy
    color = "green" if is_ok else "red"
    label = "AUTHORIZED — IN POLICY" if is_ok else "OUT OF POLICY"
    console.print(f"\n  [bold {color}]{label}[/]\n")

    # Core fields
    tbl = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 1))
    tbl.add_column("Field", style="cyan", no_wrap=True, min_width=22)
    tbl.add_column("Value", style="white", min_width=34)
    tbl.add_column("Why it matters", style="dim")

    rows = [
        ("receipt_id",    receipt.id[:20] + "...",            "Unique. Used in VERIFY.sh"),
        ("plan_id",       receipt.plan_id[:20] + "...",       "Links to human/policy-signed plan"),
        ("agent",         receipt.agent,                      "Who acted"),
        ("action",        receipt.action,                     "What was requested"),
        ("in_policy",     f"[{color}]{receipt.in_policy}[/]", "Policy evaluation result"),
        ("policy_reason", f"[{'green' if is_ok else 'yellow'}]{receipt.policy_reason}[/]", "Exact reason — audit trail"),
        ("evidence_hash", receipt.evidence_hash[:28] + "...", "SHA-512 of evidence. Tamper detection"),
        ("observed_at",   receipt.observed_at[:25],           "UTC timestamp"),
        ("signature",     receipt.signature[:28] + "...",     "Ed25519. Covers all fields"),
    ]
    if receipt.timestamp_result:
        rows.append(("tsa_url",    receipt.timestamp_result.tsa_url,                "FreeTSA — independent RFC 3161"))
        rows.append(("tsa_digest", receipt.timestamp_result.digest_hex[:28] + "...", "Hash anchored to wall-clock time"))
    for f, v, w in rows:
        tbl.add_row(f, v, w)
    console.print(tbl)
    console.print()

    # Evidence table (only for in-policy with investigation data)
    ev = receipt.evidence
    if is_ok and "data_sources" in ev:
        et = Table(box=box.SIMPLE, show_header=True, header_style="bold white", padding=(0, 1),
                   title="[bold white]Evidence Committed to Receipt[/]")
        et.add_column("Category", style="cyan", min_width=18)
        et.add_column("Key Finding", style="white")
        et.add_row("Incident",    f"{ev.get('severity', '')} — {ev.get('incident_channel', '')}")
        et.add_row("Root Cause",  ev.get("root_cause", ""))
        et.add_row("Confidence",  f"{ev.get('confidence_tier', '')} ({ev.get('confidence_score', '')})")
        et.add_row("Causal Chain", (ev.get("causal_chain", "") or "")[:70] + "...")
        for name, vals in ev.get("data_sources", {}).items():
            detail = ", ".join(f"{k}={v}" for k, v in vals.items() if k != "query_hash")
            et.add_row(f"  {name}", detail[:65])
        et.add_row("Remediation", f"{ev.get('remediation_type', '')} {ev.get('rollback_from', '')} → {ev.get('rollback_to', '')}")
        et.add_row("Execution",   f"{'success' if ev.get('execution_result') else 'failed'} ({ev.get('execution_duration_ms', 0)}ms, {ev.get('pods_restarted', 0)} pods)")
        et.add_row("Approved By", f"{ev.get('approved_by', '')} via {ev.get('approval_channel', '')}")
        console.print(et)
        console.print()

    # Three anchors
    lines = [f"  [bold green]Anchor 1[/] — Ed25519 signature: {receipt.signature[:16]}..."]
    if receipt.timestamp_result:
        lines.append(f"  [bold yellow]Anchor 2[/] — RFC 3161 timestamp: FreeTSA ({receipt.timestamp_result.digest_hex[:16]}...)")
    lines.append(f"  [bold cyan]Anchor 3[/] — Evidence hash: {receipt.evidence_hash[:16]}...")
    console.print(Panel(Text.from_markup("\n".join(lines)),
                        title="[bold white]Three Independent Anchors[/]",
                        border_style="dim white", padding=(0, 2)))
    pause(0.2)


def verify(notary: Notary, receipt: NotarisedReceipt, note: str = "") -> None:
    """Verify and print."""
    suffix = f" — {note}" if note else ""
    if notary.verify_receipt(receipt):
        ok(f"[bold green]Ed25519 signature verified[/]{suffix}")
    else:
        fail("Signature verification failed")
    if receipt.timestamp_result:
        ok("[bold green]RFC 3161 timestamp present[/] — independently verifiable with OpenSSL")


# ── Scenario 1: L4 Happy Path ────────────────────────────

def scenario_1(mint: AgentMint, notary: Notary) -> None:
    banner(1, "Happy Path (L4: Human-Approved Remediation)",
        "Agent detects degradation → investigates 4 data sources → identifies root cause →\n"
        "human approves → agent executes rollback → receipt proves execution matched approval.",
        "green")

    t0 = show_investigation()

    # Authorization
    heading("④ AgentMint Authorization")
    scope = ["remediate:rollback:payments-api", "remediate:restart:payments-api"]
    checks = ["remediate:scale_down:*", "remediate:delete:*"]

    numbered(5, "Issue scoped plan for remediation")
    gk, ny = make_plans(mint, notary, INCIDENT["on_call"], scope, checks)
    info(f"plan: {gk.short_id}  scope: {', '.join(scope)}")
    info(f"checkpoints: {', '.join(checks)}")
    info(f"signature: {gk.signature[:40]}...")
    pause(0.2)

    numbered(6, "Agent requests: remediate:rollback:payments-api")
    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:rollback:payments-api")
    if not result.ok:
        fail(f"Unexpected denial: {result.reason}")
        return

    ok(f"AUTHORIZED — receipt {result.receipt.short_id}")
    ok(f"[bold]Gatekeeper latency: {gk_us:.0f}μs[/] [dim](in-memory, no network)[/]")
    info(f"chain: {INCIDENT['on_call']} → sre-agent")

    # Approval + execution
    heading("⑤ Human Approval (Slack)")
    info(f"{INCIDENT['on_call']} approved rollback in {INCIDENT['channel']}")

    heading("⑥ Execute Remediation")
    numbered(7, "Rolling back payments-api v2.3.1 → v2.3.0")
    pause(0.5)
    ok("Rollback complete — 720ms, 6 pods restarted")
    ok("Health check passed")

    # Notarize
    heading("⑦ AgentMint Notarization — Measured Latency")
    numbered(8, "Building evidence and signing receipt...")
    evidence = build_rollback_evidence(INCIDENT["on_call"], "slack", t0)

    receipt, lat = sign_and_stamp(notary, "remediate:rollback:payments-api", "sre-agent", ny, evidence)
    lat.gatekeeper_us = gk_us

    ok(f"[bold]Ed25519 signing: {lat.sign_ms:.1f}ms[/] [dim](local crypto, zero network)[/]")
    ok(f"[bold]Full notarization: {lat.total_ms:.0f}ms[/] [dim](includes FreeTSA round-trip)[/]")
    ok(f"Receipt [bold]{receipt.short_id}[/] — signed and timestamped")
    pause(0.3)

    show_latency(lat)

    heading("⑧ Cryptographic Receipt")
    render_receipt(receipt)
    verify(notary, receipt)

    takeaway("For Traversal", (
        "[bold white]What This Receipt Proves[/]\n\n"
        "  [green]✓[/]  Which agent acted — sre-agent, delegated by sre-lead@acme-corp.com\n"
        "  [green]✓[/]  What it was authorized to do — rollback payments-api [bold]only[/]\n"
        "  [green]✓[/]  What it actually did — rollback v2.3.1 → v2.3.0\n"
        "  [green]✓[/]  That execution matched approval — action in scope, evidence committed\n"
        "  [green]✓[/]  When it happened — RFC 3161 timestamp, backdating impossible\n"
        "  [green]✓[/]  That nobody tampered — Ed25519 + FreeTSA + evidence hash\n\n"
        "[bold white]How this maps to Traversal:[/]\n"
        "  Your investigation UI shows blast radius, timeline, hypotheses.\n"
        "  This receipt makes that evidence [bold]cryptographically verifiable[/].\n\n"
        "[bold white]IAM Gateway → Receipt flow:[/]\n"
        "  [dim]1.[/] Scoped plan issued (human or policy engine)\n"
        "  [dim]2.[/] Gatekeeper checks scope before execution [dim](sub-ms, in-memory)[/]\n"
        "  [dim]3.[/] Agent executes remediation normally [dim](AgentMint not in this path)[/]\n"
        "  [dim]4.[/] Notary signs receipt after execution [dim](links back via plan_id)[/]\n"
        "  [dim]5.[/] Receipt proves the chain: plan → auth → action → evidence"
    ), "green")


# ── Scenario 2: Scope Violation ───────────────────────────

def scenario_2(mint: AgentMint, notary: Notary) -> None:
    banner(2, "Scope Violation",
        "Agent tries to restart auth-service instead of payments-api.\n"
        "auth-service is not in scope. AgentMint blocks. Receipt proves constraint.",
        "red")

    scope = ["remediate:rollback:payments-api", "remediate:restart:payments-api"]
    checks = ["remediate:scale_down:*", "remediate:delete:*"]

    heading("① Plan Scope")
    gk, ny = make_plans(mint, notary, INCIDENT["on_call"], scope, checks)
    info(f"scope: {', '.join(scope)}")
    info("note:  auth-service is NOT in scope")

    heading("② Agent Requests: remediate:restart:auth-service")
    numbered(1, "Agent concludes auth-service needs restart (wrong diagnosis)")
    numbered(2, "Agent requests authorization...")

    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:restart:auth-service")
    fail(f"BLOCKED — {result.status.value}")
    fail(f"[bold]Blocked in {gk_us:.0f}μs[/] [dim](no network, instant)[/]")
    info(f"reason: {result.reason}")

    heading("③ Notarize the Denial")
    numbered(3, "AgentMint records the denied action...")
    receipt, _ = sign_and_stamp(notary, "remediate:restart:auth-service", "sre-agent", ny, {
        "attempted_action": "remediate:restart:auth-service",
        "gatekeeper_result": result.status.value,
        "agent_reasoning": "Agent incorrectly concluded auth-service was root cause",
        "incident_channel": INCIDENT["channel"],
        "severity": INCIDENT["severity"],
    })
    fail(f"Receipt [bold]{receipt.short_id}[/] — [bold red]OUT OF POLICY[/]")

    heading("④ Denial Receipt")
    render_receipt(receipt)
    verify(notary, receipt, "even denials are signed")

    takeaway("For Traversal", (
        "[bold white]What This Proves[/]\n\n"
        "  [red]✗[/]  Agent tried to restart auth-service\n"
        "  [green]✓[/]  AgentMint blocked it — action not in authorized scope\n"
        "  [green]✓[/]  The denial is signed and timestamped\n"
        "  [green]✓[/]  auth-service was never touched\n\n"
        "[dim]Your Slack log would show a failed action. This receipt PROVES the agent\n"
        "was constrained — cryptographically, not by trust in your application logs.[/]"
    ), "red")


# ── Scenario 3: L5 Autonomous ─────────────────────────────

def scenario_3(mint: AgentMint, notary: Notary) -> None:
    banner(3, "Autonomous Execution (L5: No Human in the Loop)",
        "Same rollback, but the plan is issued by an automated policy engine — not a human.\n"
        "No Slack approval. No human checkpoint. The receipt proves the agent acted within\n"
        "automated policy scope. This is what replaces the Slack button when the human is removed.",
        "yellow")

    heading("① Policy Engine Issues Plan")
    info("No human involved — automated runbook policy authorizes rollback")
    info("This mirrors Cloudways SmartFix: one-click → zero-click remediation\n")

    scope = ["remediate:rollback:payments-api"]  # NARROWER than L4
    checks = ["remediate:scale_down:*", "remediate:delete:*"]

    gk, ny = make_plans(mint, notary, "policy-engine@acme-corp.com", scope, checks)
    info(f"plan: {gk.short_id}  issuer: policy-engine@acme-corp.com")
    info(f"scope: {', '.join(scope)}")
    info("note:  scope is NARROWER than L4 — only rollback, no restart")

    heading("② Agent Requests Authorization")
    numbered(1, "Agent requests: remediate:rollback:payments-api")
    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:rollback:payments-api")

    if not result.ok:
        fail(f"Unexpected: {result.reason}")
        return

    ok(f"AUTHORIZED — receipt {result.receipt.short_id}")
    ok(f"[bold]Gatekeeper latency: {gk_us:.0f}μs[/]")
    info("No human approval needed — policy engine is the authority")

    heading("③ Execute + Notarize")
    numbered(2, "Rolling back payments-api v2.3.1 → v2.3.0")
    pause(0.5)
    ok("Rollback complete — 720ms")

    numbered(3, "Notarizing with automated policy as approver...")
    evidence = {
        "incident_channel": INCIDENT["channel"],
        "severity": INCIDENT["severity"],
        "remediation_type": "rollback",
        "target_service": "payments-api",
        "rollback_from": "v2.3.1",
        "rollback_to": "v2.3.0",
        "execution_result": True,
        "approved_by": "policy-engine@acme-corp.com",
        "approval_channel": "automated_runbook",
        "approval_timestamp": datetime.now(timezone.utc).isoformat(),
        "autonomy_level": "L5",
        "human_in_loop": False,
    }

    receipt, _ = sign_and_stamp(notary, "remediate:rollback:payments-api", "sre-agent", ny, evidence)
    ok(f"Receipt [bold]{receipt.short_id}[/] — signed and timestamped")

    heading("④ L5 Receipt")
    render_receipt(receipt)
    verify(notary, receipt)

    takeaway("For Traversal", (
        "[bold white]What This Proves (L5 — No Human)[/]\n\n"
        "  [green]✓[/]  Plan issued by [bold]policy-engine@acme-corp.com[/] — not a person\n"
        "  [green]✓[/]  Agent acted within automated policy scope\n"
        "  [green]✓[/]  Receipt captures [bold]human_in_loop: false[/] and [bold]autonomy_level: L5[/]\n"
        "  [green]✓[/]  Scope was NARROWER — only rollback, restart not authorized\n"
        "  [green]✓[/]  Same receipt format, same verification, same OpenSSL command\n\n"
        "[dim]When the human is removed from the loop, the receipt becomes the\n"
        "accountability mechanism. The plan_id links to the policy that authorized\n"
        "the action. The receipt proves the agent stayed within that policy.[/]\n\n"
        "[bold]Traversal runs L5 internally. Their customers run L4.[/]\n"
        "[dim]This receipt is what makes the transition auditable.[/]"
    ), "yellow")


# ── Scenario 4: Checkpoint Escalation ─────────────────────

def scenario_4(mint: AgentMint, notary: Notary) -> None:
    banner(4, "Checkpoint Escalation (Blast Radius Exceeded)",
        "Agent wants to scale down payments-api — a high-risk action in requires_checkpoint.\n"
        "AgentMint doesn't deny it — it ESCALATES. Different from denial. The action needs\n"
        "re-approval from a higher authority before it can proceed.",
        "magenta")

    heading("① Plan with Checkpoint Rules")
    scope = ["remediate:rollback:*", "remediate:restart:*", "remediate:scale_down:*"]
    checks = ["remediate:scale_down:*", "remediate:delete:*"]

    gk, ny = make_plans(mint, notary, INCIDENT["on_call"], scope, checks)
    info(f"scope: {', '.join(scope)}")
    info(f"checkpoints: {', '.join(checks)}")
    info("note:  scale_down IS in scope but ALSO in checkpoints — checkpoints win")

    heading("② Agent Requests: remediate:scale_down:payments-api")
    numbered(1, "Agent determines scaling down would reduce blast radius")
    numbered(2, "Agent requests authorization...")

    result, gk_us = gate_check(mint, gk, "sre-agent", "remediate:scale_down:payments-api")

    if result.status == DelegationStatus.CHECKPOINT:
        warn("CHECKPOINT — requires human re-approval")
        warn(f"[bold]Caught in {gk_us:.0f}μs[/] [dim](not a denial — an escalation)[/]")
        info(f"reason: {result.reason}")
        info("The agent cannot proceed without additional authorization")
    elif result.ok:
        warn("Unexpected: checkpoint was not triggered")
    else:
        fail(f"Unexpected denial: {result.reason}")

    heading("③ Notarize the Escalation")
    numbered(3, "AgentMint records the checkpoint event...")

    receipt, _ = sign_and_stamp(notary, "remediate:scale_down:payments-api", "sre-agent", ny, {
        "attempted_action": "remediate:scale_down:payments-api",
        "gatekeeper_result": "checkpoint_required",
        "checkpoint_reason": "matched checkpoint pattern remediate:scale_down:*",
        "agent_reasoning": "Agent determined scale-down would reduce blast radius",
        "requires_approval_from": "senior-sre@acme-corp.com or incident-commander",
        "incident_channel": INCIDENT["channel"],
        "severity": INCIDENT["severity"],
        "blast_radius": "high — affects all payment processing capacity",
    })
    warn(f"Receipt [bold]{receipt.short_id}[/] — [bold yellow]CHECKPOINT ESCALATION[/]")

    heading("④ Escalation Receipt")
    render_receipt(receipt)
    verify(notary, receipt, "escalation events are signed too")

    takeaway("For Traversal", (
        "[bold white]What This Proves (Checkpoint ≠ Denial)[/]\n\n"
        "  [yellow]![/]  Agent wanted to scale down payments-api\n"
        "  [yellow]![/]  Action is in scope BUT requires checkpoint re-approval\n"
        "  [green]✓[/]  AgentMint escalated — not denied. Different semantics.\n"
        "  [green]✓[/]  The escalation event itself is signed and timestamped\n"
        "  [green]✓[/]  Receipt captures blast radius and who needs to approve\n\n"
        "[dim]This is the boundary between L4 and L5. Investigation is autonomous.\n"
        "Rollbacks are autonomous. But destructive actions — scale_down, delete —\n"
        "require human re-approval. The receipt captures that boundary.[/]\n\n"
        "[bold]When blast radius exceeds autonomous authority,\n"
        "the receipt captures the escalation.[/]"
    ), "magenta")


# ── Main ──────────────────────────────────────────────────

def main() -> None:
    console.print()
    console.print(Panel(
        Text.from_markup(
            "[bold white]AgentMint × SRE Agent[/]\n"
            "[dim]Cryptographic receipts at the remediation boundary[/]"
        ),
        border_style="white", padding=(0, 2),
    ))
    pause(0.4)

    # Architecture
    console.print(Panel(
        Text.from_markup(
            "[bold white]Where AgentMint Sits — Sidecar, Not in the Critical Path[/]\n\n"
            "  [bold cyan]Your Agent[/]  →  Investigate (Grafana, Elastic, GitHub, Slack)\n"
            "      │                [dim]← AgentMint is not here. Investigation is untouched.[/]\n"
            "      ▼\n"
            "  [bold yellow]REMEDIATION BOUNDARY[/]  ←  [bold green]Gatekeeper checks scope[/]  [dim](in-memory, <100μs)[/]\n"
            "      │\n"
            "      ▼\n"
            "  [bold cyan]Agent executes[/]  →  kubectl rollback, API call, Ansible playbook\n"
            "      │                [dim]← AgentMint is not here either. Execution is untouched.[/]\n"
            "      ▼\n"
            "  [bold green]Notary signs receipt[/]  [dim](post-execution, async, ~2ms sign + ~350ms FreeTSA)[/]\n"
            "      │\n"
            "      ▼\n"
            "  [bold yellow]Signed Receipt[/]  ←  Ed25519 + RFC 3161 + evidence hash\n\n"
            "[bold white]What touches your infrastructure:[/]\n"
            "  [green]✓[/]  Gatekeeper: in-process library call. No network. No new service.\n"
            "  [green]✓[/]  Notary: signs locally, sends one SHA-512 hash to FreeTSA.\n"
            "  [red]✗[/]  Never proxies API calls. Never modifies requests. Never adds latency.\n"
            "  [red]✗[/]  No new infra to deploy. No database. No queue. pip install agentmint.\n\n"
            "[bold white]Two integration modes:[/]\n"
            "  [cyan]Mode A — IAM Gateway:[/]   Scoped credential before, receipt after. ~20 lines.\n"
            "  [cyan]Mode B — Passive Notary:[/] No gating, just observe and sign. ~10 lines.\n"
            "  Both produce the same receipt format. Same verification. Same OpenSSL command."
        ),
        title="[bold white]Architecture — Sidecar Model[/]",
        border_style="dim white", padding=(1, 2),
    ))
    pause(0.8)

    # Initialize once, share across all scenarios
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

    # Summary
    console.print(Panel(
        Text.from_markup(
            "[bold white]Summary — Four Scenarios, One Principle[/]\n\n"
            "  [green]Scenario 1[/]  L4 happy path — human approved, agent executed, receipt proves match.\n"
            "  [red]Scenario 2[/]  Scope violation — agent blocked, denial signed and timestamped.\n"
            "  [yellow]Scenario 3[/]  L5 autonomous — no human, policy engine, receipt is accountability.\n"
            "  [magenta]Scenario 4[/]  Checkpoint — high-risk escalated, receipt captures the boundary.\n\n"
            "[bold white]Addressing the hard questions:[/]\n\n"
            "  [bold]\"Does this affect production?\"[/]\n"
            "  No. Gatekeeper: in-process call (<100μs). Notary: post-execution.\n"
            "  Only network call is SHA-512 hash to FreeTSA. Remove AgentMint → agent unchanged.\n\n"
            "  [bold]\"Are the receipts meaningful?\"[/]\n"
            "  Every receipt commits full context — data sources, query hashes, root cause,\n"
            "  confidence, hypotheses, approval chain, execution result.\n"
            "  Verified with OpenSSL alone. No AgentMint software needed.\n\n"
            "  [bold]\"Does this work with our stack?\"[/]\n"
            "  AgentMint sits at the remediation boundary. Doesn't integrate with Grafana\n"
            "  or Elastic — your agent already does. Zero changes to your existing tools.\n\n"
            "  [bold]\"What's the integration?\"[/]\n"
            "  IAM Gateway (~20 lines) or Passive Notary (~10 lines). pip install agentmint.\n\n"
            "  [bold]\"Do we need a UI?\"[/]\n"
            "  No. Receipts are JSON + .tsr files. VERIFY.sh is pure OpenSSL.\n"
            "  Any GRC tool, SIEM, or audit platform can ingest them."
        ),
        title="[bold white]AgentMint × Traversal[/]",
        border_style="white", padding=(1, 2),
    ))

    console.print()
    info("All receipts signed with Ed25519 + RFC 3161 timestamps from FreeTSA.")
    info("Verification requires only openssl — no AgentMint software or account.")
    console.print()
    console.print("  [bold]github.com/aniketh-maddipati/agentmint-python[/]")
    console.print()


if __name__ == "__main__":
    main()