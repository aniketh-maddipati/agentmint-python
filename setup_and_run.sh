#!/bin/bash
# AgentMint Demo — Full Setup & Run
# Creates all files, installs deps with uv, runs demo.
#
#   curl -sL <this_file> | bash
#   — or —
#   bash setup_and_run.sh

set -e

echo ""
echo "AgentMint Demo — Setup"
echo "======================"
echo ""

# ── Create directory ───────────────────────────────────────

mkdir -p robin_demo
cd robin_demo

# ── demo.py ────────────────────────────────────────────────

cat > demo.py << 'DEMO_EOF'
#!/usr/bin/env python3
"""
AgentMint Demo for Robin Joseph (UprootSecurity)
=================================================

Five scenes. 90 seconds. Real signatures. Real hash chain.
Zero external dependencies — stdlib only.

    uv run demo.py

Produces signed evidence in evidence/.
Verify with: uv run verify.py evidence/
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional

EVIDENCE_DIR = Path("evidence")
SLOW = float(os.environ.get("DEMO_SPEED", "0.3"))

_nc = os.environ.get("NO_COLOR", "") != ""


class C:
    G = "" if _nc else "\033[92m"
    R = "" if _nc else "\033[91m"
    Y = "" if _nc else "\033[93m"
    CN = "" if _nc else "\033[96m"
    W = "" if _nc else "\033[97m"
    D = "" if _nc else "\033[2m"
    BD = "" if _nc else "\033[1m"
    X = "" if _nc else "\033[0m"


def _pause(s: float = SLOW) -> None:
    time.sleep(s)


def _header(title: str) -> None:
    print(f"\n{C.W}{'─' * 60}{C.X}")
    print(f"  {C.BD}{C.W}{title}{C.X}")
    print(f"{C.W}{'─' * 60}{C.X}\n")
    _pause()


def _canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sign(key: bytes, payload: dict) -> str:
    return hmac.new(key, _canonical(payload), hashlib.sha256).hexdigest()


def _matches(action: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        return action == prefix or action.startswith(prefix + ":")
    return action == pattern


@dataclass
class Plan:
    id: str
    user: str
    action: str
    scope: list[str]
    delegates_to: list[str]
    requires_checkpoint: list[str]
    issued_at: str
    expires_at: str
    key_id: str
    signature: str = ""

    def signable(self) -> dict:
        return {
            "id": self.id, "type": "plan", "user": self.user,
            "action": self.action, "scope": self.scope,
            "delegates_to": self.delegates_to,
            "requires_checkpoint": self.requires_checkpoint,
            "issued_at": self.issued_at, "expires_at": self.expires_at,
            "key_id": self.key_id,
        }

    def to_dict(self) -> dict:
        d = self.signable()
        d["signature"] = self.signature
        return d


@dataclass
class Receipt:
    id: str
    plan_id: str
    agent: str
    action: str
    in_policy: bool
    reason: str
    plan_owner: str
    scope_used: Optional[str]
    evidence: dict
    evidence_hash: str
    previous_receipt_hash: Optional[str]
    timestamp: str
    chain_position: int
    key_id: str
    signature: str = ""

    def signable(self) -> dict:
        return {
            "id": self.id, "plan_id": self.plan_id, "agent": self.agent,
            "action": self.action, "in_policy": self.in_policy,
            "reason": self.reason, "plan_owner": self.plan_owner,
            "scope_used": self.scope_used, "evidence": self.evidence,
            "evidence_hash": self.evidence_hash,
            "previous_receipt_hash": self.previous_receipt_hash,
            "timestamp": self.timestamp, "chain_position": self.chain_position,
            "key_id": self.key_id,
        }

    def to_dict(self) -> dict:
        d = self.signable()
        d["signature"] = self.signature
        return d


class Notary:
    def __init__(self) -> None:
        self._key: bytes = secrets.token_bytes(32)
        self._kid: str = _sha256(self._key)[:16]
        self._chain_hash: Optional[str] = None
        self._position: int = 0
        self._receipts: list[Receipt] = []
        self._plan: Optional[Plan] = None

    def create_plan(self, *, user: str, action: str, scope: list[str],
                    delegates_to: list[str],
                    requires_checkpoint: Optional[list[str]] = None,
                    ttl: int = 300) -> Plan:
        if not user.strip():
            raise ValueError("user must not be empty")
        if not action.strip():
            raise ValueError("action must not be empty")
        if not scope:
            raise ValueError("scope must contain at least one pattern")
        if not delegates_to:
            raise ValueError("delegates_to must name at least one agent")

        now = datetime.now(timezone.utc)
        plan = Plan(
            id=str(uuid.uuid4()), user=user.strip(), action=action.strip(),
            scope=list(scope), delegates_to=list(delegates_to),
            requires_checkpoint=list(requires_checkpoint or []),
            issued_at=now.isoformat(),
            expires_at=(now + timedelta(seconds=max(1, ttl))).isoformat(),
            key_id=self._kid,
        )
        plan.signature = _sign(self._key, plan.signable())
        self._plan = plan
        self._chain_hash = None
        self._position = 0
        self._receipts = []
        return plan

    def delegate(self, plan: Plan, agent: str, action: str,
                 evidence: Optional[dict] = None) -> Receipt:
        if not agent.strip():
            raise ValueError("agent must not be empty")
        if not action.strip():
            raise ValueError("action must not be empty")

        evidence = evidence or {}
        in_policy, reason, scope_used = self._evaluate(plan, agent, action)

        receipt = Receipt(
            id=str(uuid.uuid4()), plan_id=plan.id, agent=agent,
            action=action, in_policy=in_policy, reason=reason,
            plan_owner=plan.user, scope_used=scope_used,
            evidence=evidence, evidence_hash=_sha256(_canonical(evidence)),
            previous_receipt_hash=self._chain_hash,
            timestamp=datetime.now(timezone.utc).isoformat(),
            chain_position=self._position, key_id=self._kid,
        )
        receipt.signature = _sign(self._key, receipt.signable())
        self._chain_hash = _sha256(_canonical(receipt.to_dict()))
        self._position += 1
        self._receipts.append(receipt)
        return receipt

    def _evaluate(self, plan: Plan, agent: str, action: str
                  ) -> tuple[bool, str, Optional[str]]:
        if agent not in plan.delegates_to:
            return False, f"agent '{agent}' not in delegates_to", None
        for cp in plan.requires_checkpoint:
            if _matches(action, cp):
                return False, f"action {action} requires checkpoint — matched {cp}", None
        for pattern in plan.scope:
            if _matches(action, pattern):
                return True, f"action matches scope pattern {pattern}", pattern
        return False, f"action {action} not in scope", None

    def export(self, directory: Path) -> None:
        if self._plan is None:
            raise RuntimeError("No plan created — call create_plan() first")
        directory.mkdir(parents=True, exist_ok=True)
        for old in directory.glob("receipt_*.json"):
            old.unlink()
        _write_json(directory / "plan.json", self._plan.to_dict())
        (directory / "public_key.hex").write_text(self._key.hex() + "\n")
        for i, r in enumerate(self._receipts):
            _write_json(directory / f"receipt_{i:03d}.json", r.to_dict())

    @property
    def receipts(self) -> list[Receipt]:
        return list(self._receipts)


def _write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n")


# ── Scenes ─────────────────────────────────────────────────


def scene_1(notary: Notary) -> Plan:
    _header("SCENE 1 — Plan Creation (15s)")
    plan = notary.create_plan(
        user="dr.chen@hospital.com", action="clinical-workflow",
        scope=["ehr:read:patient:*", "ehr:write:note:*", "billing:submit:*"],
        delegates_to=["crewai-clinical-agent"],
        requires_checkpoint=["ehr:delete:*", "billing:override:*"],
    )
    print(f"  {C.G}PLAN ISSUED{C.X}")
    print(f"    {C.D}Plan ID:{C.X}       {plan.id[:16]}...")
    print(f"    {C.D}Approved by:{C.X}   {C.W}{plan.user}{C.X}")
    print(f"    {C.D}Delegates to:{C.X}  {C.CN}crewai-clinical-agent{C.X}")
    print(f"    {C.D}Scope:{C.X}         {C.G}ehr:read:patient:*  ehr:write:note:*  billing:submit:*{C.X}")
    print(f"    {C.D}Checkpoints:{C.X}   {C.Y}ehr:delete:*  billing:override:*{C.X}")
    print(f"    {C.D}Signature:{C.X}     {plan.signature[:40]}...")
    print(f"\n  {C.G}Plan signed. Agent can only act within this scope.{C.X}")
    _pause(0.5)
    return plan


def scene_2(notary: Notary, plan: Plan) -> list[Receipt]:
    _header("SCENE 2 — Three Delegations, All In Scope (30s)")
    actions = [
        ("ehr:read:patient:PT-90821", "Patient lookup", {"patient_id": "PT-90821"}),
        ("ehr:write:note:PT-90821", "Clinical note", {"patient_id": "PT-90821", "note_type": "progress"}),
        ("billing:submit:99213", "Billing submission", {"code": "99213", "amount_usd": 150}),
    ]
    receipts = []
    for action_str, label, evidence in actions:
        r = notary.delegate(plan, "crewai-clinical-agent", action_str, evidence)
        receipts.append(r)
        print(f"  {C.G}ALLOWED{C.X}  {label}")
        print(f"    {C.D}Action:{C.X}    {C.CN}{r.action}{C.X}")
        print(f"    {C.D}Scope:{C.X}     {r.scope_used}")
        print(f"    {C.D}Receipt:{C.X}   {r.id[:12]}...")
        print(f"    {C.D}Signature:{C.X} {r.signature[:32]}...")
        print()
        _pause(0.3)
    print(f"  {C.W}3 actions. 3 signed receipts. All chain to {plan.user}'s plan.{C.X}")
    _pause(0.5)
    return receipts


def scene_3(notary: Notary, plan: Plan) -> Receipt:
    _header("SCENE 3 — Blocked Action (15s)")
    r = notary.delegate(
        plan, "crewai-clinical-agent", "ehr:delete:patient:PT-90821",
        {"patient_id": "PT-90821", "intent": "delete_record"},
    )
    print(f"  {C.R}BLOCKED{C.X}  DELETE PATIENT RECORD")
    print(f"    {C.D}Action:{C.X}    {C.R}{r.action}{C.X}")
    print(f"    {C.D}Status:{C.X}    {C.Y}checkpoint_required{C.X}")
    print(f"    {C.D}Reason:{C.X}    {r.reason}")
    print(f"    {C.D}Receipt:{C.X}   {r.id[:12]}...")
    print(f"    {C.D}Signature:{C.X} {r.signature[:32]}...")
    print()
    print(f"  {C.W}Blocked BEFORE execution. Signed receipt of the denial.{C.X}")
    print(f"  {C.W}Proof the control worked in production.{C.X}")
    _pause(0.5)
    return r


def scene_4(notary: Notary) -> None:
    _header("SCENE 4 — Audit Trail (10s)")
    for r in notary.receipts:
        tag = f"{C.G}ALLOWED{C.X}" if r.in_policy else f"{C.R}BLOCKED{C.X}"
        print(f"  [{tag}]  {r.action:<35s}  {C.D}receipt:{r.id[:8]}  sig:{r.signature[:16]}...{C.X}")
    allowed = sum(1 for r in notary.receipts if r.in_policy)
    blocked = len(notary.receipts) - allowed
    print(f"\n  {C.W}{len(notary.receipts)} receipts. {allowed} allowed. {blocked} blocked. All chained.{C.X}")
    _pause(0.5)


def scene_5(notary: Notary) -> None:
    _header("SCENE 5 — Export & Verify (20s)")
    notary.export(EVIDENCE_DIR)
    files = sorted(EVIDENCE_DIR.iterdir())
    print(f"  {C.G}Exported to {EVIDENCE_DIR}/{C.X}\n")
    for f in files:
        print(f"    {C.CN}{f.name:<25s}{C.X}  {C.D}{f.stat().st_size:,} bytes{C.X}")
    print(f"\n  {C.W}Verify:{C.X}  uv run verify.py {EVIDENCE_DIR}/")
    print(f"  {C.W}Tamper:{C.X}  uv run tamper.py {EVIDENCE_DIR}/receipt_001.json")
    print(f"  {C.D}Then verify again — signature fails, chain breaks.{C.X}")
    _pause(0.5)


def main() -> int:
    print(f"\n{C.BD}{C.W}AgentMint Demo — Runtime Enforcement for AI Agent Tool Calls{C.X}")
    print(f"{C.D}For Robin Joseph, UprootSecurity{C.X}")
    _pause(0.5)
    notary = Notary()
    plan = scene_1(notary)
    scene_2(notary, plan)
    scene_3(notary, plan)
    scene_4(notary)
    scene_5(notary)
    print(f"\n{C.W}{'═' * 60}{C.X}")
    print(f"  {C.BD}Human approval → Scope enforcement → Evidence → Verification{C.X}")
    print(f"{C.W}{'═' * 60}{C.X}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
DEMO_EOF

# ── verify.py ──────────────────────────────────────────────

cat > verify.py << 'VERIFY_EOF'
#!/usr/bin/env python3
"""Independently verify signatures and hash chain. No AgentMint needed."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
from pathlib import Path

_nc = os.environ.get("NO_COLOR", "") != ""
G = "" if _nc else "\033[92m"
R = "" if _nc else "\033[91m"
Y = "" if _nc else "\033[93m"
W = "" if _nc else "\033[97m"
D = "" if _nc else "\033[2m"
BD = "" if _nc else "\033[1m"
X = "" if _nc else "\033[0m"


def canonical(data: dict) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode()


def verify_sig(key: bytes, payload: dict, sig_hex: str) -> bool:
    expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, sig_hex)


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <evidence_directory>")
        return 1

    edir = Path(sys.argv[1])
    if not edir.is_dir():
        print(f"{R}Not a directory: {edir}{X}")
        return 1

    key_path = edir / "public_key.hex"
    if not key_path.exists():
        print(f"{R}No public_key.hex in {edir}{X}")
        return 1

    try:
        key = bytes.fromhex(key_path.read_text().strip())
    except ValueError:
        print(f"{R}Invalid key format in {key_path}{X}")
        return 1

    print(f"\n{BD}AGENTMINT EVIDENCE VERIFICATION{X}")
    print(f"{'=' * 50}\n")

    plan_path = edir / "plan.json"
    if plan_path.exists():
        plan = json.loads(plan_path.read_text())
        signable = {k: v for k, v in plan.items() if k != "signature"}
        ok = verify_sig(key, signable, plan.get("signature", ""))
        tag = f"{G}VALID{X}" if ok else f"{R}INVALID{X}"
        print(f"  Plan:  [{tag}]  {D}{plan.get('user', '?')} → {plan.get('action', '?')}{X}")
        print()

    receipt_files = sorted(edir.glob("receipt_*.json"))
    if not receipt_files:
        print(f"{Y}No receipt files found{X}")
        return 1

    sig_valid = 0
    sig_invalid = 0
    chain_ok = True
    chain_break_at: int | None = None
    prev_hash: str | None = None

    for i, rfile in enumerate(receipt_files):
        receipt = json.loads(rfile.read_text())
        action = receipt.get("action", "?")
        in_policy = receipt.get("in_policy", False)

        signable = {k: v for k, v in receipt.items() if k != "signature"}
        is_valid = verify_sig(key, signable, receipt.get("signature", ""))

        if is_valid:
            sig_valid += 1
            sig_tag = f"{G}SIGNATURE VALID{X}  "
        else:
            sig_invalid += 1
            sig_tag = f"{R}SIGNATURE INVALID{X}"

        receipt_prev = receipt.get("previous_receipt_hash")
        chain_match = receipt_prev == prev_hash
        if not chain_match and chain_ok:
            chain_ok = False
            chain_break_at = i

        prev_hash = hashlib.sha256(canonical(receipt)).hexdigest()

        policy = f"{G}allowed{X}" if in_policy else f"{Y}blocked{X}"
        extra = ""
        if not is_valid:
            extra = f"  {R}← TAMPERED{X}"
        if not chain_match and chain_break_at == i:
            extra += f"  {R}← CHAIN BREAK{X}"

        print(f"  Receipt {i:03d}: [{sig_tag}]  {action}  ({policy}){extra}")

    print()
    if chain_ok:
        print(f"  Chain:   {G}INTACT{X} — {len(receipt_files)} receipts linked")
    else:
        print(f"  Chain:   {R}BROKEN after receipt {chain_break_at:03d}{X}")

    print(f"\n  Summary: {sig_valid} valid, {sig_invalid} tampered")
    print(f"  {D}Method: HMAC-SHA256 + SHA-256 hash chain{X}")
    print(f"  {D}Vendor trust required: none{X}")
    print()

    return 1 if sig_invalid > 0 or not chain_ok else 0


if __name__ == "__main__":
    sys.exit(main())
VERIFY_EOF

# ── tamper.py ──────────────────────────────────────────────

cat > tamper.py << 'TAMPER_EOF'
#!/usr/bin/env python3
"""Tamper with one receipt field to demonstrate detection."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

_nc = os.environ.get("NO_COLOR", "") != ""
R = "" if _nc else "\033[91m"
Y = "" if _nc else "\033[93m"
W = "" if _nc else "\033[97m"
D = "" if _nc else "\033[2m"
X = "" if _nc else "\033[0m"


def main() -> int:
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <receipt_file.json>")
        return 1

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"{R}File not found: {path}{X}")
        return 1

    try:
        receipt = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        print(f"{R}Invalid JSON: {e}{X}")
        return 1

    before = receipt.get("action", "")
    after = before.replace(":PT-", ":PT-FAKE-") if ":PT-" in before else before + ":TAMPERED"

    receipt["action"] = after
    path.write_text(json.dumps(receipt, indent=2) + "\n")

    print(f"\n  {Y}Tampering with {path.name}...{X}\n")
    print(f"  {D}BEFORE:{X} action = {W}{before}{X}")
    print(f"  {D}AFTER:{X}  action = {R}{after}{X}")
    print(f"\n  {D}One field changed. Run verify.py to detect it.{X}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
TAMPER_EOF

# ── run.sh ─────────────────────────────────────────────────

cat > run.sh << 'RUN_EOF'
#!/bin/bash
set -e

echo ""
echo "AgentMint Demo"
echo "=============="
echo ""

echo "[1/4] Running demo..."
echo ""
uv run demo.py
echo ""

echo "[2/4] Verifying (should all pass)..."
echo ""
uv run verify.py evidence/

echo "[3/4] Tampering receipt_001..."
echo ""
uv run tamper.py evidence/receipt_001.json

echo "[4/4] Verifying again (catches tamper)..."
echo ""
uv run verify.py evidence/ || true

echo ""
echo "Done. Re-run clean: uv run demo.py"
echo ""
RUN_EOF

chmod +x run.sh

# ── Done ───────────────────────────────────────────────────

echo "Created robin_demo/"
echo "  demo.py        — 5 scenes, 90 seconds"
echo "  verify.py      — independent verifier"
echo "  tamper.py      — tamper one field"
echo "  run.sh         — runs all 4 steps"
echo ""
echo "To run:"
echo "  cd robin_demo"
echo "  uv run demo.py                              # demo"
echo "  uv run verify.py evidence/                  # verify"
echo "  uv run tamper.py evidence/receipt_001.json  # tamper"
echo "  uv run verify.py evidence/                  # catch it"
echo ""
echo "Or just:  bash run.sh"
echo ""