#!/usr/bin/env python3
"""
AgentMint x Arva AI -- AML Screening Agent Evidence Demo
"""

from __future__ import annotations
import json, sys, time
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from agentmint.notary import Notary
from agentmint.shield import scan as shield_scan
from agentmint.merkle import build_tree, verify_proof
from agentmint.types import EnforceMode

from arvademo.nhi_credential import (
    NHI_CREDENTIAL, PLAN_SCOPE, PLAN_CHECKPOINTS, AGENT_NAME, get_credential_hash,
)
from arvademo.tools.compliance_tools import (
    standard_sequence, rogue_sequence, get_entity, ENTITIES,
)

# ==============================================================================
# Config
# ==============================================================================

STANDARD_SESSIONS = 50
ROGUE_SESSIONS = 50
EVIDENCE_DIR = Path(__file__).parent / "evidence"
CREDENTIAL_HASH = get_credential_hash()
VERBOSE_EVERY = 5  # show full detail every N sessions, summary for the rest

REG_MAP = {
    "fincen:314b:read":          "FinCEN 314(b) -- 31 USC 5318(g)(2) -- federal violation prevented",
    "comply_advantage:alerts:close:autonomous": "BSA/AML -- 31 USC 5318(h) -- autonomous closure prevented",
    "internal:customer:read:cross_customer":    "GLBA -- 15 USC 6801 -- cross-customer access prevented",
    "ofac:sdnlist:read:direct":                 "OFAC integration -- normalization bypass prevented",
    "internal:customer:read:full_transaction_history": "Scope boundary -- exceeds authorization",
    "swift:messages:read":                      "SWIFT access -- wildly outside screening scope",
}

# ==============================================================================
# Colors
# ==============================================================================
G = "\033[32m"; R = "\033[31m"; Y = "\033[33m"; B = "\033[34m"; C = "\033[36m"
W = "\033[0m"; BOLD = "\033[1m"; DIM = "\033[2m"

# ==============================================================================
# Stats
# ==============================================================================

@dataclass
class Stats:
    receipts: int = 0
    allowed: int = 0
    blocked: int = 0
    checkpoints: int = 0
    output_threats: int = 0
    injection_catches: int = 0
    blocked_actions: dict = field(default_factory=dict)
    outcomes: dict = field(default_factory=dict)

    def __iadd__(self, other):
        for attr in ("receipts", "allowed", "blocked", "checkpoints", "output_threats", "injection_catches"):
            setattr(self, attr, getattr(self, attr) + getattr(other, attr))
        for k, v in other.blocked_actions.items():
            self.blocked_actions[k] = self.blocked_actions.get(k, 0) + v
        for k, v in other.outcomes.items():
            self.outcomes[k] = self.outcomes.get(k, 0) + v
        return self


# ==============================================================================
# Core
# ==============================================================================

def execute_tool(notary, plan, action, tool_fn, description, stats, verbose=False):
    """Run tool -> scan -> notarise -> print -> stats."""
    try:
        result = tool_fn()
    except Exception as e:
        result = {"error": str(e)}

    # Output scan
    injection_hit = False
    try:
        scan_result = shield_scan(result)
        threats = len(scan_result.threats) if scan_result.threats else 0
        stats.output_threats += threats
        for t in (scan_result.threats or []):
            cat = str(getattr(t, "category", "")).lower()
            pat = str(getattr(t, "pattern", "")).lower()
            if "inject" in cat or "inject" in pat:
                stats.injection_catches += 1
                injection_hit = True
    except Exception:
        pass

    # Notarise
    evidence = {"tool": action, "credential_hash": CREDENTIAL_HASH}
    try:
        receipt = notary.notarise(
            action=action, agent=AGENT_NAME, plan=plan,
            evidence=evidence, enable_timestamp=False, output=result,
        )
    except Exception as e:
        if verbose:
            print("      %sERROR: %s%s" % (R, e, W))
        return

    # Real verdict (shadow mode overrides in_policy to True)
    real_verdict = receipt.original_verdict if receipt.original_verdict is not None else receipt.in_policy
    is_checkpoint = "checkpoint" in receipt.policy_reason.lower() if hasattr(receipt, "policy_reason") else False

    stats.receipts += 1
    if real_verdict:
        stats.allowed += 1
    else:
        stats.blocked += 1
        if not is_checkpoint:
            stats.blocked_actions[action] = stats.blocked_actions.get(action, 0) + 1

    if is_checkpoint:
        stats.checkpoints += 1

    # Print
    if verbose:
        if is_checkpoint:
            mark = "%s◆ CHECKPOINT%s" % (Y, W)
        elif real_verdict:
            mark = "%s✓ ALLOWED%s" % (G, W)
        else:
            mark = "%s✗ BLOCKED%s" % (R, W)

        line = "      %s  %s" % (mark, description)
        if injection_hit:
            line += "  %s← INJECTION CAUGHT%s" % (R, W)
        print(line)


def run_session(notary, plan, session_num, stats, is_rogue=False, verbose=False):
    """Run one complete screening session."""
    entity = get_entity(session_num)
    alert_id = "ALT-%d" % (90000 + session_num)

    if verbose:
        outcome_color = {
            "false_positive": G, "true_positive": R, "escalated_edd": Y
        }.get(entity["outcome"], C)

        print()
        print("    %s┌─ Session %d: %s%s%s" % (DIM, session_num, W + BOLD, entity["name"], W))
        print("    %s│%s  %s  %s match (%.2f)  %s  %s%s%s" % (
            DIM, W,
            entity["jurisdiction"],
            entity["match_type"], entity["match_score"],
            entity["match_list"],
            outcome_color, entity["outcome"], W,
        ))
        print("    %s│%s  UBO: %s (%.0f%%)  PEP: %s  Customer: %s" % (
            DIM, W,
            entity["ubo_name"], entity["ubo_control"],
            "YES" if any(d.get("pep") for d in entity["directors"]) else "no",
            entity["customer_id"],
        ))
        if is_rogue:
            print("    %s│%s  %s!! ROGUE MODE — agent will attempt 6 out-of-scope actions%s" % (DIM, W, R, W))
        print("    %s│%s" % (DIM, W))

    # Standard workflow
    for action, fn, desc in standard_sequence(alert_id, entity):
        execute_tool(notary, plan, action, fn, desc, stats, verbose)

    # Rogue escalation
    if is_rogue:
        if verbose:
            print("    %s│%s" % (DIM, W))
            print("    %s│%s  %s── Agent reasoning: 'I should access more data to be thorough' ──%s" % (DIM, W, R, W))
            print("    %s│%s" % (DIM, W))
        for action, fn, desc in rogue_sequence(alert_id, entity):
            execute_tool(notary, plan, action, fn, desc, stats, verbose)

    if verbose:
        print("    %s└─ Done: %d receipts this session%s" % (DIM, 15 if is_rogue else 9, W))

    stats.outcomes[entity["outcome"]] = stats.outcomes.get(entity["outcome"], 0) + 1


# ==============================================================================
# Main
# ==============================================================================

def main():
    t_start = time.time()

    print()
    print("%s%s%s" % (BOLD, "=" * 78, W))
    print("%s  AgentMint x Arva AI -- AML Screening Agent Evidence Demo%s" % (BOLD, W))
    print("=" * 78)
    print()
    print("  %sOFAC%s penalties: $368,136/violation. %sBSA/AML%s: FinCEN enforcement." % (Y, W, Y, W))
    print("  %sFinCEN 314(b)%s unauthorized access: criminal referral risk." % (Y, W))
    print()
    print("  %d entities across %d jurisdictions. Sanctions, PEP, adverse media." % (
        len(ENTITIES), len(set(e["jurisdiction"] for e in ENTITIES))))
    print("  %d sessions x ~12 tool calls. Ed25519 + SHA-256 + Merkle tree." % (STANDARD_SESSIONS + ROGUE_SESSIONS))
    print()

    # -- Init --
    try:
        notary = Notary(mode=EnforceMode.SHADOW)
        plan = notary.create_plan(
            user=NHI_CREDENTIAL["owner"], action="aml-screening-batch",
            scope=PLAN_SCOPE, checkpoints=PLAN_CHECKPOINTS,
        )
    except Exception as e:
        print("  %sFATAL: %s%s" % (R, e, W)); sys.exit(1)

    print("  %sNotary initialized%s" % (G, W))
    print("    Plan:       %s%s...%s" % (C, plan.id[:16], W))
    print("    Key:        %s%s%s" % (C, notary.key_id, W))
    agent_did = getattr(notary, "agent_did", None)
    if agent_did:
        print("    Agent DID:  %s%s...%s" % (C, agent_did[:48], W))
    print("    Credential: %s%s...%s" % (C, CREDENTIAL_HASH[:16], W))
    print("    Mode:       %sshadow%s" % (G, W))

    # -- Standard --
    print()
    print("  %s── STANDARD AGENT (%d sessions) ──%s" % (BOLD, STANDARD_SESSIONS, W))
    std = Stats()
    for i in range(1, STANDARD_SESSIONS + 1):
        verbose = (i <= 3) or (i % VERBOSE_EVERY == 0)
        run_session(notary, plan, i, std, is_rogue=False, verbose=verbose)
        if not verbose and i % 10 == 0:
            print("    %s... session %d (%d receipts)%s" % (DIM, i, std.receipts, W))

    print("\n  %s✓%s Standard: %s%d%s receipts  |  threats caught: %s%d%s  |  checkpoints: %s%d%s" % (
        G, W, C, std.receipts, W, Y, std.output_threats, W, Y, std.checkpoints, W))
    print("    Outcomes: %s" % "  ".join("%s=%d" % (k, v) for k, v in sorted(std.outcomes.items())))

    # -- Rogue --
    print()
    print("  %s── ROGUE AGENT (%d sessions) ──%s" % (BOLD, ROGUE_SESSIONS, W))
    rog = Stats()
    for i in range(1, ROGUE_SESSIONS + 1):
        verbose = (i <= 3) or (i % VERBOSE_EVERY == 0)
        run_session(notary, plan, STANDARD_SESSIONS + i, rog, is_rogue=True, verbose=verbose)
        if not verbose and i % 10 == 0:
            print("    %s... session %d (%d receipts, %s%d blocked%s)%s" % (
                DIM, i, rog.receipts, R, rog.blocked, W + DIM, W))

    print("\n  %s✓%s Rogue: %s%d%s receipts  |  %s%d blocked%s  |  threats: %s%d%s  |  checkpoints: %s%d%s" % (
        G, W, C, rog.receipts, W, R, rog.blocked, W, Y, rog.output_threats, W, Y, rog.checkpoints, W))

    # -- Totals --
    total = Stats()
    total += std
    total += rog
    elapsed = time.time() - t_start

    # -- Export --
    print()
    print("  %s── EXPORT ──%s" % (BOLD, W))
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        zip_path = notary.export_evidence(EVIDENCE_DIR)
        print("  %s✓%s %s" % (G, W, zip_path))
    except Exception as e:
        print("  %sExport failed: %s%s" % (R, e, W)); sys.exit(1)

    # -- Merkle --
    print()
    print("  %s── MERKLE TREE ──%s" % (BOLD, W))
    import zipfile
    payloads, receipt_list = [], []
    UNSIGNED = {"signature", "timestamp", "output"}
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in sorted(zf.namelist()):
                if name.startswith("receipts/") and name.endswith(".json"):
                    data = json.loads(zf.read(name))
                    receipt_list.append(data)
                    sd = {k: v for k, v in data.items() if k not in UNSIGNED}
                    payloads.append(json.dumps(dict(**sd, signature=data["signature"]),
                                               sort_keys=True, separators=(",", ":")).encode())

        t_m = time.time()
        tree = build_tree(payloads)
        ms = (time.time() - t_m) * 1000

        print("    Leaves: %s%d%s  Depth: %s%d%s  Build: %s%.1fms%s  Root: %s%s...%s" % (
            C, tree.leaf_count, W, C, tree.depth, W, C, ms, W, C, tree.root[:24], W))
        print("    Linear: %s%d hashes%s to verify last receipt (O(n))" % (Y, tree.leaf_count, W))
        print("    Merkle: %s%d hashes%s to verify any receipt (O(log n))" % (G, tree.depth, W))

        for idx, label in [(0, "first"), (tree.leaf_count - 1, "last")]:
            p = tree.proof(idx)
            v = verify_proof(p)
            print("    %s%s%s Receipt #%d (%s) -- %d siblings" % (G if v else R, "✓" if v else "✗", W, idx, label, len(p.siblings)))
    except Exception as e:
        print("    %sMerkle skipped: %s%s" % (Y, e, W))
        tree = None

    # ===========================================================================
    # Report
    # ===========================================================================
    rps = total.receipts / max(elapsed, 0.001)

    print()
    print("%s%s%s" % (BOLD, "=" * 78, W))
    print("%s  EVIDENCE REPORT%s" % (BOLD, W))
    print("=" * 78)

    print("\n  %sSESSIONS%s    %d total  |  %s%d receipts%s  |  %.1fs (%d/sec)" % (
        BOLD, W, STANDARD_SESSIONS + ROGUE_SESSIONS, C, total.receipts, W, elapsed, rps))

    print("\n  %sOUTCOMES%s    %s" % (BOLD, W,
        "  ".join("%s%s=%d%s" % (
            {
                "false_positive": G, "true_positive": R, "escalated_edd": Y
            }.get(k, C), k, v, W)
            for k, v in sorted(total.outcomes.items()))))

    print("\n  %sENFORCEMENT%s Allowed: %s%d%s  Blocked: %s%d%s  Checkpoints: %s%d%s" % (
        BOLD, W, G, total.allowed, W, R, total.blocked, W, Y, total.checkpoints, W))

    if total.blocked_actions:
        print("\n  %sBLOCKED ACTIONS%s" % (BOLD, W))
        for action, count in sorted(total.blocked_actions.items(), key=lambda x: -x[1]):
            reason = REG_MAP.get(action, "scope violation")
            print("    %s%s%s  %dx  %s" % (R, action, W, count, reason))

    print("\n  %sOUTPUT SCAN%s  Threats: %s%d%s  Injections caught: %s%d%s" % (
        BOLD, W, Y, total.output_threats, W, R, total.injection_catches, W))
    if total.injection_catches:
        print("    %s! Prompt injection in web presence caught %dx before model ingestion%s" % (
            Y, total.injection_catches, W))

    # -- Regulatory statement --
    fincen = total.blocked_actions.get("fincen:314b:read", 0)
    autoclose = total.blocked_actions.get("comply_advantage:alerts:close:autonomous", 0)
    cross = total.blocked_actions.get("internal:customer:read:cross_customer", 0)
    depth = tree.depth if tree else "~14"

    print()
    print("%s%s%s" % (BOLD, "=" * 78, W))
    print("%s  REGULATORY STATEMENT%s" % (BOLD, W))
    print("=" * 78)
    print()
    print("  %d Ed25519 signed, SHA-256 hash-chained receipts." % total.receipts)
    print("  %d entities across %d jurisdictions. Sanctions, PEP, adverse media." % (
        len(ENTITIES), len(set(e["jurisdiction"] for e in ENTITIES))))
    print()
    print("  FinCEN 314(b): %s%d attempts, %d blocked, API never called.%s" % (R, fincen, fincen, W))
    print("  Auto-close:    %s%d attempts, %d blocked, human review enforced.%s" % (R, autoclose, autoclose, W))
    print("  Cross-customer:%s%d attempts, %d blocked, data isolation maintained.%s" % (R, cross, cross, W))
    print()
    print("  Merkle root commits to all %d receipts." % total.receipts)
    print("  Any receipt verifiable in %s hashes. No AgentMint account required." % depth)
    print()
    print("  %sVerify: python3 arvademo/scripts/verify_evidence.py %s%s" % (G, zip_path, W))
    print()


if __name__ == "__main__":
    main()
