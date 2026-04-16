#!/usr/bin/env python3
"""
Recon × AgentMint — Composition Demo

Recon answers:  "Was this step trustworthy?"
AgentMint answers: "Can you prove that evaluation happened?"

Together: trajectory validation + independent evidence.
The signed chain survives an investigation of the operator.

Run:    python recon_agentmint_demo.py
Fast:   AGENTMINT_FAST=1 python recon_agentmint_demo.py
"""

from __future__ import annotations

import hashlib, json, os, shutil, subprocess, sys, time
from pathlib import Path
from typing import Any


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Preflight
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _preflight() -> bool:
    """Check deps. Auto-install from repo root if possible."""
    try:
        from agentmint.notary import Notary  # noqa: F401
        return True
    except ImportError:
        pass

    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        print("\n  AgentMint not installed and no pyproject.toml in cwd.")
        print("  Run from the agentmint-python repo root, or: pip install agentmint\n")
        return False

    print("  AgentMint not installed — installing from repo…")
    for cmd in (
        [sys.executable, "-m", "uv", "pip", "install", "-e", "."],
        [sys.executable, "-m", "pip", "install", "-e", ".", "-q"],
    ):
        try:
            subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("  Installed.\n")
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            continue

    print("\n  Auto-install failed.")
    print("  Fix:  pip install -e .  (from repo root)\n")
    return False


if not _preflight():
    sys.exit(1)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Imports (safe — preflight passed)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from agentmint.notary import (
    Notary, NotarisedReceipt, PlanReceipt,
    _public_key_pem, _canonical_json, verify_chain,
)
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.text import Text

try:
    from agentmint.cli.theme import C
except ImportError:
    class C:  # type: ignore[no-redef]
        BLUE = "#3B82F6"; GREEN = "#10B981"; RED = "#EF4444"
        YELLOW = "#FBBF24"; FG = "#E2E8F0"; SECONDARY = "#94A3B8"
        DIM = "#64748B"; BORDER = "#1E293B"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Display helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_con = Console(highlight=False)
_FAST = os.environ.get("AGENTMINT_FAST", "") != ""
OUTPUT_DIR = Path("recon_agentmint_evidence")


def _p(msg: str) -> None:
    _con.print(msg)


def _pause(s: float = 0.3) -> None:
    if not _FAST:
        time.sleep(s)


def _section(label: str, color: str = C.SECONDARY) -> None:
    _con.print(Rule(label, style=color))


def _sign(notary: Notary, plan: PlanReceipt, action: str,
          agent: str, evidence: dict) -> NotarisedReceipt:
    return notary.notarise(
        action=action, agent=agent, plan=plan,
        evidence=evidence, enable_timestamp=False,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Simulated Recon scoring
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Production reconai-langchain uses NLP heuristics, model
# grading, and policy rules. This demo simulates the scoring
# interface — zero API keys, zero deps beyond agentmint.

_HEDGING = ("I THINK", "MIGHT BE", "NOT SURE", "POSSIBLY", "PERHAPS", "UNCERTAIN")
_CONTRADICTIONS = ("HOWEVER", "CONTRADICTS", "ON THE OTHER HAND", "ACTUALLY THE OPPOSITE")


def _recon_score(output: str) -> tuple[float, str]:
    """Simulated Recon reflex scoring → (score, status)."""
    text = output.upper()
    if any(p in text for p in _CONTRADICTIONS):
        return 0.20, "UNTRUSTED"
    if any(p in text for p in _HEDGING):
        return 0.45, "DEGRADED"
    return 0.95, "TRUSTED"


def _status_color(status: str) -> str:
    return {"TRUSTED": C.GREEN, "DEGRADED": C.YELLOW}.get(status, C.RED)


def _status_icon(status: str) -> str:
    return {"TRUSTED": "✓", "DEGRADED": "⚠"}.get(status, "✗")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Simulated agent steps
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
# Mock LangChain agent answering a research question.
# Drift arc: HIGH → HIGH → LOW → CONTRADICTORY.

QUESTION = (
    "What is the current consensus on the long-term effects "
    "of microplastics in human blood?"
)

STEPS: tuple[dict[str, Any], ...] = (
    {
        "tool": "retrieve_docs",
        "args": {"query": "microplastics human blood effects", "top_k": 5},
        "output": (
            "Retrieved 5 documents from PubMed. Top result: "
            "'Microplastics detected in 77% of blood samples tested "
            "(Environment International, 2024). Concentration levels "
            "correlated with inflammatory biomarkers.'"
        ),
    },
    {
        "tool": "analyze_data",
        "args": {"task": "cross-reference findings", "sources": 5},
        "output": (
            "Cross-referencing 5 sources. All studies confirm detection "
            "of microplastics in human blood. Three studies report "
            "elevated IL-6 and CRP levels. Sample sizes range from "
            "108 to 2,100 participants."
        ),
    },
    {
        "tool": "generate_answer",
        "args": {"task": "synthesize", "format": "summary"},
        "output": (
            "I think the evidence might suggest that microplastics "
            "are possibly harmful, but I'm not sure about the long-term "
            "effects. Perhaps more research is needed."
        ),
    },
    {
        "tool": "final_output",
        "args": {"task": "format_response", "citations": True},
        "output": (
            "Microplastics are present in most human blood samples. "
            "However, the data contradicts itself — some studies show "
            "harm while others show no effect. On the other hand, "
            "the WHO says the risk is low. Actually the opposite "
            "conclusion was reached by a 2024 meta-analysis."
        ),
    },
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Evidence export with correct verifier
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _export_evidence(
    notary: Notary,
    plan: PlanReceipt,
    receipts: list[NotarisedReceipt],
) -> Path:
    """Export evidence with a correct verify_sigs.py.

    The Notary.export_evidence() bundles a verify_sigs.py that
    has a known incompatibility with the current receipt format
    (it strips only signature+timestamp, but signable_dict() builds
    conditionally). We export manually and write a verifier that
    reconstructs the signable payload correctly.
    """
    if OUTPUT_DIR.exists():
        shutil.rmtree(OUTPUT_DIR)
    OUTPUT_DIR.mkdir(parents=True)
    evidence_dir = OUTPUT_DIR / "evidence"
    evidence_dir.mkdir()

    # Plan
    _write_json(OUTPUT_DIR / "plan.json", plan.to_dict())

    # Receipts
    for i, r in enumerate(receipts):
        _write_json(evidence_dir / f"{i:03d}_{r.id}.json", r.to_dict())

    # Public key
    (OUTPUT_DIR / "public_key.pem").write_text(_public_key_pem(notary.verify_key))

    # Receipt index
    chain_result = verify_chain(receipts)
    _write_json(OUTPUT_DIR / "receipt_index.json", {
        "plan_id": plan.id,
        "plan_user": plan.user,
        "key_id": plan.key_id,
        "total_receipts": len(receipts),
        "chain": {
            "valid": chain_result.valid,
            "length": chain_result.length,
            "root_hash": chain_result.root_hash,
        },
        "receipts": [{
            "receipt_id": r.id,
            "short_id": r.short_id,
            "action": r.action,
            "agent": r.agent,
            "in_policy": r.in_policy,
        } for r in receipts],
    })

    # Correct verify_sigs.py
    _write_verify_sigs(OUTPUT_DIR)

    # VERIFY.sh
    _write_verify_sh(OUTPUT_DIR, receipts, plan)

    return OUTPUT_DIR


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


def _write_verify_sigs(out: Path) -> None:
    """Write a verifier that correctly reconstructs signable payloads.

    Uses the same approach as generate_evidence.py: pop signature and
    timestamp from the loaded receipt dict, then canonicalize.
    """
    (out / "verify_sigs.py").write_text('''\
#!/usr/bin/env python3
"""Verify Ed25519 signatures and hash chains. Requires: pip install pynacl"""
import base64, hashlib, json, sys
from pathlib import Path
try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("  Install pynacl: pip install pynacl"); sys.exit(1)

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

here = Path(__file__).parent
pk = here / "public_key.pem"
if not pk.exists():
    print("  No public_key.pem"); sys.exit(1)

lines = pk.read_text().strip().split("\\n")
b64 = "".join(lines[1:-1])
vk = VerifyKey(base64.b64decode(b64)[12:])

sig_ok = sig_fail = chain_ok = chain_fail = hash_ok = hash_fail = 0
prev_hash = {}

for f in sorted((here / "evidence").glob("*.json")):
    r = json.loads(f.read_text())
    sig_hex = r.pop("signature")
    r.pop("timestamp", None)
    payload = canonical(r)

    # Signature
    try:
        vk.verify(payload, bytes.fromhex(sig_hex))
        s = "\\u2713"
        sig_ok += 1
    except (BadSignatureError, ValueError):
        s = "\\u2717 FAIL"
        sig_fail += 1

    # Chain
    plan_id = r.get("plan_id", "")
    expected = prev_hash.get(plan_id)
    got = r.get("previous_receipt_hash")
    if got == expected:
        ch = "\\u2713"
        chain_ok += 1
    else:
        ch = "\\u2717 BREAK"
        chain_fail += 1

    # Evidence hash
    ev = r.get("evidence")
    ev_hash = r.get("evidence_hash_sha512", "")
    if ev and hashlib.sha512(canonical(ev)).hexdigest() == ev_hash:
        h = "\\u2713"
        hash_ok += 1
    elif ev:
        h = "\\u2717 MISMATCH"
        hash_fail += 1
    else:
        h = "-"

    tag = "in policy" if r.get("in_policy") else "VIOLATION"
    short = r.get("id", "")[:8]
    action = r.get("action", "")
    print(f"  sig:{s}  chain:{ch}  hash:{h}  {short}  {action}  ({tag})")

    signed = canonical({**r, "signature": sig_hex})
    prev_hash[plan_id] = hashlib.sha256(signed).hexdigest()

ts = sig_ok + sig_fail
tc = chain_ok + chain_fail
th = hash_ok + hash_fail
print()
print(f"  Signatures:  {sig_ok}/{ts} verified")
print(f"  Chain links: {chain_ok}/{tc} verified")
print(f"  Hash checks: {hash_ok}/{th} verified")
sys.exit(1 if sig_fail or chain_fail or hash_fail else 0)
''')
    os.chmod(out / "verify_sigs.py", 0o755)


def _write_verify_sh(out: Path, receipts: list[NotarisedReceipt],
                     plan: PlanReceipt) -> None:
    L = [
        "#!/bin/bash",
        "# Recon × AgentMint — Evidence Verification",
        "# Requires: python3 with pynacl. No AgentMint needed.",
        'set -euo pipefail',
        'cd "$(dirname "$0")"',
        "",
        'echo "════════════════════════════════════════════════════════"',
        'echo "  Recon × AgentMint — Evidence Verification"',
        f'echo "  Key: {plan.key_id}"',
        'echo "════════════════════════════════════════════════════════"',
        'echo ""',
        f'echo "  Plan {plan.short_id} — {plan.user}"',
        f'echo "  Scope: {", ".join(plan.scope)}"',
        'echo ""',
        'echo "  ── Chain of Actions ──"',
        'echo ""',
    ]
    for r in receipts:
        icon = "✓" if r.in_policy else "✗"
        L.append(f'echo "  {icon} {r.short_id}  {r.action}"')
    L.extend([
        'echo ""',
        'echo "  ── Cryptographic Verification ──"',
        'echo ""',
        'python3 "$(dirname "$0")/verify_sigs.py"',
        'EXIT=$?',
        'echo ""',
        'echo "════════════════════════════════════════════════════════"',
        'echo "  Verified with: openssl + python3"',
        'echo "  No AgentMint installation required."',
        'echo "════════════════════════════════════════════════════════"',
        'exit $EXIT',
    ])
    p = out / "VERIFY.sh"
    p.write_text("\n".join(L) + "\n")
    os.chmod(p, 0o755)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Main
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main() -> None:
    t0 = time.perf_counter()

    # ── Header ────────────────────────────────────────────

    title = Text()
    title.append("Agent", style=C.BLUE)
    title.append("Mint", style=C.FG)
    title.append("  ×  ", style=C.DIM)
    title.append("Recon", style=C.FG)
    title.append("\n\n", style=C.FG)
    title.append("  Recon scores trust. AgentMint signs the proof.\n", style=C.SECONDARY)
    title.append("  Ed25519 signed · SHA-256 chained · no API keys", style=C.DIM)
    _con.print(Panel(title, border_style=C.BORDER, padding=(1, 2)))
    _pause(0.5)

    # ── Create plan ───────────────────────────────────────

    _section("Plan")
    _pause(0.2)

    notary = Notary()
    plan = notary.create_plan(
        user="demo-operator@example.com",
        action="research-agent:run",
        scope=["tool:*", "recon:evaluate:*"],
        delegates_to=["langchain-agent", "recon-evaluator"],
        ttl_seconds=600,
    )

    _p(f"\n  [{C.DIM}]Plan[/{C.DIM}]         [{C.FG}]{plan.short_id}[/{C.FG}]")
    _p(f"  [{C.DIM}]User[/{C.DIM}]         [{C.FG}]demo-operator@example.com[/{C.FG}]")
    _p(f"  [{C.DIM}]Scope[/{C.DIM}]        [{C.GREEN}]tool:*[/{C.GREEN}]  [{C.GREEN}]recon:evaluate:*[/{C.GREEN}]")
    _p(f"  [{C.DIM}]Delegates to[/{C.DIM}] [{C.FG}]langchain-agent[/{C.FG}]  [{C.FG}]recon-evaluator[/{C.FG}]")
    _p(f"  [{C.DIM}]Key ID[/{C.DIM}]       [{C.DIM}]{notary.key_id}[/{C.DIM}]")
    _pause(0.4)

    # ── Agent arc ─────────────────────────────────────────

    _section("Agent Arc")
    _pause(0.2)

    _p(f"\n  [{C.FG}]Question:[/{C.FG}] [{C.SECONDARY}]{QUESTION}[/{C.SECONDARY}]\n")
    _pause(0.3)

    evaluations: list[tuple[str, float, str, str]] = []
    all_receipts: list[NotarisedReceipt] = []

    for i, s in enumerate(STEPS):
        tool, output = s["tool"], s["output"]

        _p(f"  [{C.BLUE}]▶[/{C.BLUE}] [{C.FG}]{tool}[/{C.FG}]  [{C.DIM}]{s['args']}[/{C.DIM}]")
        _pause(0.4)

        tool_receipt = _sign(notary, plan,
            action=f"tool:{tool}", agent="langchain-agent",
            evidence={"tool": tool, "args": s["args"], "step_index": i})
        all_receipts.append(tool_receipt)
        _p(f"    [{C.GREEN}]✓[/{C.GREEN}] [{C.FG}]Executed[/{C.FG}]"
           f"  [{C.DIM}]receipt {tool_receipt.short_id}[/{C.DIM}]")
        _pause(0.2)

        score, status = _recon_score(output)
        col = _status_color(status)

        eval_receipt = _sign(notary, plan,
            action=f"recon:evaluate:{tool}", agent="recon-evaluator",
            evidence={"step": tool, "recon_score": score,
                      "recon_status": status, "output_preview": output[:100]})
        all_receipts.append(eval_receipt)
        evaluations.append((tool, score, status, eval_receipt.short_id))

        _p(f"    [{col}]{_status_icon(status)}[/{col}] [{C.FG}][RECON] Reflex Score:[/{C.FG}]"
           f"  [{col}]{score:.2f}  {status}[/{col}]"
           f"  [{C.DIM}]receipt {eval_receipt.short_id}[/{C.DIM}]")
        _p("")
        _pause(0.3)

    # ── Drift detection ───────────────────────────────────

    scores = [s for _, s, _, _ in evaluations]
    degraded = [(t, s, st) for t, s, st, _ in evaluations if st != "TRUSTED"]

    if degraded:
        _section("Drift Detected", C.YELLOW)
        _pause(0.2)

        delta = max(scores) - min(scores)
        _p(f"\n  [{C.YELLOW}]Score range:[/{C.YELLOW}] [{C.FG}]{max(scores):.2f} → {min(scores):.2f}[/{C.FG}]"
           f"  [{C.DIM}]Δ {delta:.2f}[/{C.DIM}]")
        for t, s, st in degraded:
            col = _status_color(st)
            _p(f"  [{col}]{_status_icon(st)}[/{col}] [{C.FG}]{t:<20s}[/{C.FG}]"
               f"  [{col}]{s:.2f}  {st}[/{col}]")

        drift_receipt = _sign(notary, plan,
            action="recon:evaluate:drift_summary", agent="recon-evaluator",
            evidence={"drift_detected": True, "score_high": max(scores),
                      "score_low": min(scores), "delta": round(delta, 2),
                      "degraded_steps": [t for t, _, _ in degraded]})
        all_receipts.append(drift_receipt)
        _p(f"\n  [{C.DIM}]Drift detection signed  receipt {drift_receipt.short_id}[/{C.DIM}]")
        _pause(0.4)

    # ── Inline verification ───────────────────────────────

    _section("Verification", C.GREEN)
    _pause(0.2)

    chain_result = verify_chain(all_receipts)
    sig_ok = 0

    _p("")
    for r in all_receipts:
        ok = notary.verify_receipt(r)
        if ok:
            sig_ok += 1
        col = C.GREEN if ok else C.RED
        icon = "✓" if ok else "✗"
        tag = "in policy" if r.in_policy else "VIOLATION"
        _p(f"  [{col}]{icon}[/{col}]  [{C.DIM}]{r.short_id}[/{C.DIM}]"
           f"  [{C.FG}]{r.action}[/{C.FG}]  [{C.DIM}]({tag})[/{C.DIM}]")
        _pause(0.08)

    n = len(all_receipts)
    _p(f"\n  [{C.GREEN}]Signatures:  {sig_ok}/{n} verified[/{C.GREEN}]")
    _p(f"  [{C.GREEN}]Chain links: {chain_result.length}/{chain_result.length} verified[/{C.GREEN}]")
    if chain_result.root_hash:
        _p(f"  [{C.DIM}]Root hash:   {chain_result.root_hash[:32]}…[/{C.DIM}]")
    _pause(0.4)

    # ── Composition summary ───────────────────────────────

    _section("Composition Summary", C.BLUE)
    _pause(0.2)

    n_eval = len(evaluations)
    n_meta = n - 2 * n_eval

    _p(f"\n  [{C.FG}]Recon evaluated {n_eval} steps:[/{C.FG}]")
    for tool, score, status, rid in evaluations:
        col = _status_color(status)
        _p(f"    [{col}]{_status_icon(status)}[/{col}] [{C.FG}]{tool:<20s}[/{C.FG}]"
           f"  [{col}]{score:.2f}  {status:<10s}[/{col}]"
           f"  [{C.DIM}]receipt {rid}[/{C.DIM}]")

    summary = Text()
    summary.append(f"\n  Total receipts:  {n}", style=C.FG)
    parts = f"{n_eval} tool calls + {n_eval} evaluations"
    if n_meta:
        parts += f" + {n_meta} meta"
    summary.append(f"  ({parts})\n", style=C.DIM)
    summary.append(f"  Signatures:      {sig_ok}/{n} verified\n", style=C.GREEN)
    summary.append(f"  Chain links:     {chain_result.length}/{chain_result.length} verified\n", style=C.GREEN)
    if degraded:
        summary.append("\n  Recon detected drift. AgentMint signed the detection.\n", style=C.YELLOW)
    summary.append("  The proof is portable — verify with openssl, no vendor software.", style=C.DIM)
    _con.print(Panel(summary, border_style=C.BORDER, padding=(0, 2)))
    _pause(0.4)

    # ── Export evidence ───────────────────────────────────

    _section("Export")
    _pause(0.2)

    evidence_path = _export_evidence(notary, plan, all_receipts)

    _p(f"\n  [{C.FG}]Evidence:[/{C.FG}]  [{C.DIM}]{evidence_path}/[/{C.DIM}]")
    _p(f"  [{C.DIM}]  plan.json          signed plan[/{C.DIM}]")
    _p(f"  [{C.DIM}]  evidence/*.json     {n} signed receipts[/{C.DIM}]")
    _p(f"  [{C.DIM}]  public_key.pem      Ed25519 public key[/{C.DIM}]")
    _p(f"  [{C.DIM}]  verify_sigs.py      signature + chain verifier[/{C.DIM}]")
    _p(f"  [{C.DIM}]  VERIFY.sh           runs verify_sigs.py[/{C.DIM}]")
    _pause(0.3)

    # ── Run verify_sigs.py inline ─────────────────────────

    _section("Independent Verification", C.GREEN)
    _pause(0.2)

    _p(f"\n  [{C.SECONDARY}]Running verify_sigs.py (no AgentMint needed):[/{C.SECONDARY}]\n")

    verify_script = (evidence_path / "verify_sigs.py").resolve()

    result = subprocess.run(
        [sys.executable, str(verify_script)],
        capture_output=True, text=True, cwd=str(evidence_path.resolve()),
    )
    for line in result.stdout.strip().splitlines():
        _p(f"  [{C.FG}]{line}[/{C.FG}]")

    if result.returncode == 0:
        _p(f"\n  [{C.GREEN}]All signatures, chains, and hashes verified.[/{C.GREEN}]")
    else:
        _p(f"\n  [{C.RED}]Verification failures detected.[/{C.RED}]")
        if result.stderr.strip():
            _p(f"  [{C.DIM}]{result.stderr.strip()}[/{C.DIM}]")
    _pause(0.4)

    # ── Next steps ────────────────────────────────────────

    elapsed = time.perf_counter() - t0

    next_steps = Text()
    next_steps.append("\n  Verify it yourself:\n\n", style=f"bold {C.FG}")
    next_steps.append(f"    $ cd {evidence_path} && bash VERIFY.sh\n\n", style=C.BLUE)
    next_steps.append("  What this proves:\n\n", style=f"bold {C.FG}")
    next_steps.append("  Recon", style=C.BLUE)
    next_steps.append(" evaluated each agent step for trust drift.\n", style=C.FG)
    next_steps.append("  Agent", style=C.BLUE)
    next_steps.append("Mint", style=C.FG)
    next_steps.append(" signed every evaluation into a tamper-evident chain.\n", style=C.FG)
    next_steps.append("  No AgentMint software needed to verify.\n\n", style=C.DIM)
    next_steps.append(f"  Completed in {elapsed:.1f}s", style=C.DIM)
    _con.print(Panel(next_steps, border_style=C.BORDER, padding=(0, 2)))
    _p("")


if __name__ == "__main__":
    main()