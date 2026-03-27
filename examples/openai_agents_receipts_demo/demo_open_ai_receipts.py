#!/usr/bin/env python3
"""
AgentMint × OpenAI Agents SDK — Cryptographic Receipts for Tool Calls

Every tool call and agent handoff produces an Ed25519-signed,
hash-chained receipt. No SDK modification — uses tool-level signing
and RunHooks for handoff tracking.

    pip install openai-agents agentmint
    export OPENAI_API_KEY=your-key
    python demo.py

References:
    openai/openai-agents-python#2643  — verifiable action receipts
    openai/openai-agents-python#939   — on_tool_start lacks args
    github.com/aniketh-maddipati/agentmint-python
"""

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from nacl.signing import SigningKey
from agents import Agent, Runner, RunHooks, function_tool
from agentmint.notary import Notary


# ── Config ─────────────────────────────────────────────────

MAIN_AGENT = "receipts_demo_agent"
NOTIF_AGENT = "notification_agent"

notary = Notary()
agent_key = SigningKey.generate()  # agent co-signing key (demo; production uses SPIFFE/secrets mgr)
receipts = []


# ── Helpers ────────────────────────────────────────────────

def sha256_json(obj: dict) -> str:
    """Deterministic SHA-256 of a JSON-serializable dict."""
    return hashlib.sha256(json.dumps(obj, sort_keys=True, default=str).encode()).hexdigest()


def sha256_str(s: str) -> str:
    """SHA-256 of a plain string."""
    return hashlib.sha256(s.encode()).hexdigest()


def notarise(action: str, agent_name: str, evidence: dict, cosign: bool = False) -> None:
    """Sign a receipt and append to the chain. Shared by tools and hooks."""
    receipt = notary.notarise(
        action=action,
        agent=agent_name,
        plan=plan,
        evidence=evidence,
        agent_key=agent_key if cosign else None,
        enable_timestamp=False,  # True for production (adds FreeTSA RFC 3161)
    )
    receipts.append(receipt)
    return receipt


def print_receipt(receipt, action: str) -> None:
    """One-line receipt summary for terminal output."""
    status = "✓" if receipt.in_policy else "✗"
    chain = receipt.previous_receipt_hash[:24] + "…" if receipt.previous_receipt_hash else "start"
    sig_info = f"sig:{receipt.signature[:16]}…"
    if receipt.agent_signature:
        sig_info += f"  agent_sig:{receipt.agent_signature[:16]}…"
    print(f"  🪙 {status} {receipt.short_id} | {action} | {sig_info} | chain:{chain}")


# ── Plan ───────────────────────────────────────────────────

plan = notary.create_plan(
    user="ops-lead@company.com",
    action="openai-agent-ops",
    scope=[
        "tool:get_weather", "tool:lookup_account", "tool:send_notification",
        f"agent:turn:{MAIN_AGENT}", f"agent:turn:{NOTIF_AGENT}",
    ],
    delegates_to=[MAIN_AGENT, NOTIF_AGENT],
    ttl_seconds=600,
)


# ── Tools ──────────────────────────────────────────────────
# Receipts signed inside each tool to capture actual args + output.
# RunHooks.on_tool_start doesn't expose args (SDK issue #939).


@function_tool
def get_weather(city: str) -> str:
    """Get current weather for a city."""
    weather = {"new york": "72°F, partly cloudy", "london": "58°F, overcast", "tokyo": "68°F, clear skies"}
    result = weather.get(city.lower(), f"Weather unavailable for {city}")
    r = notarise(
        action="tool:get_weather", agent_name=MAIN_AGENT, cosign=True,
        evidence={"tool": "get_weather", "args_hash": sha256_json({"city": city}), "output_hash": sha256_str(result)},
    )
    print_receipt(r, "tool:get_weather")
    return result


@function_tool
def lookup_account(account_id: str) -> str:
    """Look up account details by ID."""
    accounts = {"ACC-001": "Active | Balance: $12,450 | Owner: Alice Chen", "ACC-002": "Active | Balance: $8,200 | Owner: Bob Smith"}
    result = accounts.get(account_id, f"Account {account_id} not found")
    r = notarise(
        action="tool:lookup_account", agent_name=MAIN_AGENT, cosign=True,
        evidence={"tool": "lookup_account", "args_hash": sha256_json({"account_id": account_id}), "output_hash": sha256_str(result)},
    )
    print_receipt(r, "tool:lookup_account")
    return result


@function_tool
def send_notification(recipient: str, message: str) -> str:
    """Send a notification to a user."""
    result = f"Notification sent to {recipient}: '{message[:50]}'"
    r = notarise(
        action="tool:send_notification", agent_name=NOTIF_AGENT, cosign=True,
        evidence={"tool": "send_notification", "args_hash": sha256_json({"recipient": recipient, "message": message}), "output_hash": sha256_str(result)},
    )
    print_receipt(r, "tool:send_notification")
    return result


# ── Hooks ──────────────────────────────────────────────────
# Track agent handoffs for chain-of-custody (issue #2643).


class ReceiptHooks(RunHooks):
    async def on_agent_start(self, context, agent) -> None:
        print(f"  📋 {agent.name} started")

    async def on_agent_end(self, context, agent, output) -> None:
        action = f"agent:turn:{agent.name}"
        r = notarise(
            action=action, agent_name=agent.name,
            evidence={"event": "agent_turn_complete", "has_output": output is not None},
        )
        print_receipt(r, action)


# ── Agents ─────────────────────────────────────────────────

notification_agent = Agent(
    name=NOTIF_AGENT,
    instructions="You send notifications. Use send_notification when asked.",
    tools=[send_notification],
)

main_agent = Agent(
    name=MAIN_AGENT,
    instructions=(
        "Use get_weather for weather, lookup_account for account info. "
        "Hand off to notification_agent to notify someone. Use tools — don't guess."
    ),
    tools=[get_weather, lookup_account],
    handoffs=[notification_agent],
)


# ── Run ────────────────────────────────────────────────────

def main():
    print(f"\n{'=' * 64}")
    print(f"  AgentMint × OpenAI Agents SDK")
    print(f"{'=' * 64}")
    print(f"  Plan: {plan.short_id} | by: {plan.user} | delegates: {list(plan.delegates_to)}")
    print(f"  Scope: {list(plan.scope)}")
    print(f"  Plan sig: {plan.signature[:40]}…")
    print(f"{'─' * 64}")

    result = Runner.run_sync(
        main_agent,
        "Check the weather in New York, look up account ACC-001, "
        "and notify Alice about the weather.",
        hooks=ReceiptHooks(),
    )

    # Verify
    print(f"\n{'─' * 64}")
    print(f"  VERIFICATION")
    print(f"{'─' * 64}")
    valid_count = sum(1 for r in receipts if notary.verify_receipt(r))
    cosigned = sum(1 for r in receipts if r.agent_signature)
    for r in receipts:
        mark = "✓" if notary.verify_receipt(r) else "✗"
        print(f"  {mark} {r.short_id}  {r.action}")

    print(f"\n  {valid_count}/{len(receipts)} signatures verified (Ed25519)")
    print(f"  {cosigned}/{len(receipts)} agent co-signatures")

    # Export
    Path("receipts.json").write_text(json.dumps([r.to_dict() for r in receipts], indent=2))
    print(f"\n  Exported: receipts.json")
    print(f"  Agent: {(result.final_output or '(none)')[:100]}…")
    print(f"{'=' * 64}\n")


if __name__ == "__main__":
    main()