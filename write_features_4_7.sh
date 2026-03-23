#!/usr/bin/env bash
# =============================================================
# AgentMint — Features 4-7: Notary upgrades + tests
# Run from repo root: bash write_features_4_7.sh
# =============================================================
set -euo pipefail

REPO_ROOT="$(pwd)"
echo "Writing files to: $REPO_ROOT"

# ------------------------------------------------------------------
# We use Python to do the notary.py surgery — heredoc-in-heredoc
# quoting is too fragile for bash. Write a Python patcher script.
# ------------------------------------------------------------------
cat > "$REPO_ROOT/_patch_notary.py" << 'PATCHER_EOF'
"""Patch notary.py with Features 4-7."""
import re
from pathlib import Path

notary_path = Path("agentmint/notary.py")
src = notary_path.read_text()

# ══════════════════════════════════════════════════════════════
# Feature 4a: Fix TSA fallback bug (line ~555 area)
# The loop calls ts_timestamp(data) ignoring the url variable.
# Fix: pass url to ts_timestamp().
# ══════════════════════════════════════════════════════════════

old_fallback = '''def _timestamp_with_fallback(
    data: bytes,
    tsa_urls: Optional[list[str]] = None,
) -> TimestampResult:
    """Try each TSA URL in order, return first success."""
    urls = tsa_urls or DEFAULT_TSA_URLS
    if len(urls) == 1:
        # Fast path — no fallback needed
        return ts_timestamp(data)
    last_error: Optional[Exception] = None
    for url in urls:
        try:
            return ts_timestamp(data)
        except TimestampError as e:
            last_error = e
            continue
    raise TimestampError(f"all TSA endpoints failed, last error: {last_error}")'''

new_fallback = '''def _timestamp_with_fallback(
    data: bytes,
    tsa_urls: Optional[list[str]] = None,
) -> TimestampResult:
    """Try each TSA URL in order, return first success."""
    urls = tsa_urls or DEFAULT_TSA_URLS
    if len(urls) == 1:
        # Fast path — no fallback needed
        return ts_timestamp(data, url=urls[0])
    last_error: Optional[Exception] = None
    for url in urls:
        try:
            return ts_timestamp(data, url=url)
        except TimestampError as e:
            last_error = e
            continue
    raise TimestampError(f"all TSA endpoints failed, last error: {last_error}")'''

if old_fallback in src:
    src = src.replace(old_fallback, new_fallback)
    print("  ✓ Fixed TSA fallback bug (now passes url to ts_timestamp)")
else:
    print("  ⚠ TSA fallback patch target not found — may already be fixed")

# ══════════════════════════════════════════════════════════════
# Feature 4b: Add policy_hash, output_hash to NotarisedReceipt
# Feature 5: Add session_id, session_trajectory, session_escalation
# Feature 6: Add reasoning_hash
# ══════════════════════════════════════════════════════════════

# --- Add new fields to NotarisedReceipt dataclass ---

old_receipt_fields = '''    agent_signature: str = ""
    agent_key_id: str = ""'''

new_receipt_fields = '''    agent_signature: str = ""
    agent_key_id: str = ""
    # Feature 4: receipt upgrades
    policy_hash: str = ""
    output_hash: str = ""
    # Feature 5: session context
    session_id: str = ""
    session_trajectory: tuple[dict[str, Any], ...] = ()
    session_escalation: Optional[str] = None
    # Feature 6: reasoning capture
    reasoning_hash: Optional[str] = None'''

if old_receipt_fields in src:
    src = src.replace(old_receipt_fields, new_receipt_fields)
    print("  ✓ Added policy_hash, output_hash, session_id, session_trajectory, session_escalation, reasoning_hash to NotarisedReceipt")
else:
    print("  ⚠ NotarisedReceipt field patch target not found")

# --- Add new fields to signable_dict ---

old_signable_agent = '''            "agent_key_id": self.agent_key_id,
        }'''

new_signable_agent = '''            "agent_key_id": self.agent_key_id,
        }
        # Feature 4: policy + output hashes
        if self.policy_hash:
            d["policy_hash"] = self.policy_hash
        if self.output_hash:
            d["output_hash"] = self.output_hash
        # Feature 5: session context
        if self.session_id:
            d["session_id"] = self.session_id
        if self.session_trajectory:
            d["session_trajectory"] = list(self.session_trajectory)
        if self.session_escalation:
            d["session_escalation"] = self.session_escalation
        # Feature 6: reasoning hash
        if self.reasoning_hash:
            d["reasoning_hash"] = self.reasoning_hash'''

if old_signable_agent in src:
    src = src.replace(old_signable_agent, new_signable_agent)
    print("  ✓ Added new fields to signable_dict")
else:
    print("  ⚠ signable_dict patch target not found")

# ══════════════════════════════════════════════════════════════
# Feature 4c: Add _compute_policy_hash helper
# Feature 5: Add session state to Notary.__slots__ and __init__
# Feature 6: Add reasoning support to notarise()
# Feature 7: Add intersect_scopes and delegate_to_agent
# ══════════════════════════════════════════════════════════════

# --- Add helper functions before the Notary class ---

notary_class_marker = '''_CHAIN_STATE_FILE = "chain_state.json"'''

new_helpers = '''_CHAIN_STATE_FILE = "chain_state.json"


# ── Feature 4: policy hash ────────────────────────────────

def _compute_policy_hash(plan: PlanReceipt) -> str:
    """SHA-256 of canonical(scope + checkpoints + delegates_to)."""
    policy_data = {
        "scope": list(plan.scope),
        "checkpoints": list(plan.checkpoints),
        "delegates_to": list(plan.delegates_to),
    }
    return hashlib.sha256(_canonical_json(policy_data)).hexdigest()


# ── Feature 7: scope intersection for multi-agent delegation ──

def intersect_scopes(
    parent_scope: Sequence[str],
    requested: Sequence[str],
) -> tuple[str, ...]:
    """Compute the intersection of parent and requested scopes.

    Rules:
    - Exact match: keep
    - Child more specific than parent wildcard: keep child
    - Parent more specific than child wildcard: keep parent
    - No overlap: skip

    Returns empty tuple if no intersection (= deny).
    """
    result: list[str] = []
    for child in requested:
        for parent in parent_scope:
            if child == parent:
                if child not in result:
                    result.append(child)
            elif matches_pattern(child, parent):
                # child is more specific, parent is wildcard — keep child
                if child not in result:
                    result.append(child)
            elif matches_pattern(parent, child):
                # parent is more specific, child is wildcard — keep parent
                if parent not in result:
                    result.append(parent)
    return tuple(result)'''

if notary_class_marker in src and 'def _compute_policy_hash' not in src:
    src = src.replace(notary_class_marker, new_helpers)
    print("  ✓ Added _compute_policy_hash and intersect_scopes helpers")
else:
    print("  ⚠ Helper insertion target not found or already present")

# --- Expand Notary __slots__ ---

old_slots = '''    __slots__ = ("_key", "_vk", "_key_id", "_key_dir", "_package", "_chain_hashes", "_tsa_urls")'''

new_slots = '''    __slots__ = (
        "_key", "_vk", "_key_id", "_key_dir", "_package", "_chain_hashes", "_tsa_urls",
        "_circuit_breaker", "_sink",
        "_session_id", "_session_policy", "_session_counters", "_session_trajectory",
        "_child_plans",
    )'''

if old_slots in src:
    src = src.replace(old_slots, new_slots)
    print("  ✓ Expanded Notary __slots__")
else:
    print("  ⚠ Notary __slots__ patch target not found")

# --- Expand Notary.__init__ ---

old_init_end = '''        # Improvement 4.5: fallback TSA
        self._tsa_urls = tsa_urls or DEFAULT_TSA_URLS'''

new_init_end = '''        # Improvement 4.5: fallback TSA
        self._tsa_urls = tsa_urls or DEFAULT_TSA_URLS
        # Feature 2: circuit breaker (set via property)
        self._circuit_breaker = None
        # Feature 3: sink (set via property)
        self._sink = None
        # Feature 5: session context
        self._session_id: str = str(uuid.uuid4())
        self._session_policy: Optional[dict[str, Any]] = None
        self._session_counters: dict[str, int] = {}
        self._session_trajectory: deque = deque(maxlen=20)
        # Feature 7: child plan tracking
        self._child_plans: dict[str, list[str]] = {}'''

if old_init_end in src:
    src = src.replace(old_init_end, new_init_end)
    print("  ✓ Expanded Notary.__init__")
else:
    print("  ⚠ Notary.__init__ patch target not found")

# --- Add 'from collections import deque' import at top ---

old_import = 'from collections import deque'
# Only the dataclass import is there, not deque. Check:
if 'from collections import deque' not in src:
    src = src.replace(
        'from dataclasses import dataclass, field, replace',
        'from collections import deque\nfrom dataclasses import dataclass, field, replace',
    )
    print("  ✓ Added 'from collections import deque' import")
else:
    print("  ⚠ deque import already present")

# --- Expand Notary.__init__ signature ---

old_init_sig = '''    def __init__(
        self,
        key: str | Path | None = None,
        tsa_urls: list[str] | None = None,
    ) -> None:'''

new_init_sig = '''    def __init__(
        self,
        key: str | Path | None = None,
        tsa_urls: list[str] | None = None,
        circuit_breaker: Any = None,
        sink: Any = None,
        session_policy: Optional[dict[str, Any]] = None,
    ) -> None:'''

if old_init_sig in src:
    src = src.replace(old_init_sig, new_init_sig)
    print("  ✓ Expanded Notary.__init__ signature")
else:
    print("  ⚠ Notary.__init__ signature patch target not found")

# --- Wire circuit_breaker, sink, session_policy in __init__ body ---
# Replace the lines we just added with proper wiring

old_cb_init = '''        # Feature 2: circuit breaker (set via property)
        self._circuit_breaker = None
        # Feature 3: sink (set via property)
        self._sink = None
        # Feature 5: session context
        self._session_id: str = str(uuid.uuid4())
        self._session_policy: Optional[dict[str, Any]] = None'''

new_cb_init = '''        # Feature 2: circuit breaker integration
        self._circuit_breaker = circuit_breaker
        # Feature 3: sink integration
        self._sink = sink
        # Feature 5: session context
        self._session_id: str = str(uuid.uuid4())
        self._session_policy: Optional[dict[str, Any]] = session_policy'''

if old_cb_init in src:
    src = src.replace(old_cb_init, new_cb_init)
    print("  ✓ Wired circuit_breaker, sink, session_policy in __init__")

# --- Expand notarise() signature and body ---

old_notarise_sig = '''    def notarise(
        self,
        action: str,
        agent: str,
        plan: PlanReceipt,
        evidence: dict[str, Any],
        enable_timestamp: bool = True,
        agent_key: Optional[SigningKey] = None,
    ) -> NotarisedReceipt:
        """Observe an action and produce signed evidence.

        Each receipt includes the SHA-256 hash of the previous receipt's
        signed payload, forming a tamper-evident chain per plan.
        """
        action = _require_non_empty_string(action, "action", MAX_ACTION_LEN)
        agent = _require_non_empty_string(agent, "agent", MAX_IDENTITY_LEN)
        evidence = _require_evidence(evidence)

        evaluation = evaluate_policy('''

new_notarise_sig = '''    def notarise(
        self,
        action: str,
        agent: str,
        plan: PlanReceipt,
        evidence: dict[str, Any],
        enable_timestamp: bool = True,
        agent_key: Optional[SigningKey] = None,
        output: Optional[dict[str, Any]] = None,
        reasoning: Optional[str] = None,
    ) -> NotarisedReceipt:
        """Observe an action and produce signed evidence.

        Each receipt includes the SHA-256 hash of the previous receipt's
        signed payload, forming a tamper-evident chain per plan.
        """
        action = _require_non_empty_string(action, "action", MAX_ACTION_LEN)
        agent = _require_non_empty_string(agent, "agent", MAX_IDENTITY_LEN)
        evidence = _require_evidence(evidence)

        # Feature 2: circuit breaker — check FIRST, before policy
        if self._circuit_breaker is not None:
            br = self._circuit_breaker.check(agent)
            if not br.is_allowed:
                # Short-circuit: build a denied receipt without policy eval
                return self._make_denied_receipt(
                    action, agent, plan, evidence,
                    f"circuit_breaker:{br.reason}",
                    enable_timestamp,
                )

        evaluation = evaluate_policy('''

if old_notarise_sig in src:
    src = src.replace(old_notarise_sig, new_notarise_sig)
    print("  ✓ Expanded notarise() signature with output, reasoning, circuit breaker check")
else:
    print("  ⚠ notarise() signature patch target not found")

# --- Add policy_hash, output_hash, session, reasoning to receipt construction ---

old_unsigned_build = '''        # Build receipt with placeholder signature — signable_dict() is
        # the single source of truth for what gets signed.
        unsigned = NotarisedReceipt(
            id=receipt_id,
            plan_id=plan.id,
            agent=agent,
            action=action,
            in_policy=evaluation.in_policy,
            policy_reason=evaluation.reason,
            evidence_hash=evidence_hash,
            evidence=evidence,
            observed_at=observed_at,
            signature="",
            previous_receipt_hash=prev_hash,
            plan_signature=plan.signature,
            key_id=self._key_id,
            agent_signature=agent_sig,
            agent_key_id=agent_kid,
        )'''

new_unsigned_build = '''        # Feature 4: compute policy_hash and output_hash
        policy_hash = _compute_policy_hash(plan)
        output_hash = ""
        if output is not None:
            output_bytes = _canonical_json(output)
            output_hash = hashlib.sha256(output_bytes).hexdigest()

        # Feature 6: reasoning hash
        reasoning_hash: Optional[str] = None
        if reasoning is not None:
            reasoning_hash = hashlib.sha256(reasoning.encode("utf-8")).hexdigest()

        # Feature 5: session escalation check
        session_escalation: Optional[str] = None
        if self._session_policy:
            for pattern, limits in self._session_policy.items():
                if matches_pattern(action, pattern):
                    count = self._session_counters.get(pattern, 0)
                    deny_after = limits.get("deny_after")
                    escalate_after = limits.get("escalate_after")
                    if deny_after is not None and count >= deny_after:
                        session_escalation = f"denied:{pattern}:{count}/{deny_after}"
                    elif escalate_after is not None and count >= escalate_after:
                        session_escalation = f"escalate:{pattern}:{count}/{escalate_after}"

        # Feature 5: build trajectory entry
        trajectory_entry = {
            "action": action,
            "agent": agent,
            "in_policy": evaluation.in_policy,
            "observed_at": observed_at,
        }
        self._session_trajectory.append(trajectory_entry)
        recent_trajectory = tuple(self._session_trajectory)[-5:]

        # Build receipt with placeholder signature — signable_dict() is
        # the single source of truth for what gets signed.
        unsigned = NotarisedReceipt(
            id=receipt_id,
            plan_id=plan.id,
            agent=agent,
            action=action,
            in_policy=evaluation.in_policy,
            policy_reason=evaluation.reason,
            evidence_hash=evidence_hash,
            evidence=evidence,
            observed_at=observed_at,
            signature="",
            previous_receipt_hash=prev_hash,
            plan_signature=plan.signature,
            key_id=self._key_id,
            agent_signature=agent_sig,
            agent_key_id=agent_kid,
            policy_hash=policy_hash,
            output_hash=output_hash,
            session_id=self._session_id,
            session_trajectory=tuple(recent_trajectory),
            session_escalation=session_escalation,
            reasoning_hash=reasoning_hash,
        )'''

if old_unsigned_build in src:
    src = src.replace(old_unsigned_build, new_unsigned_build)
    print("  ✓ Added policy_hash, output_hash, session context, reasoning to receipt construction")
else:
    print("  ⚠ Receipt construction patch target not found")

# --- Add post-sign: record circuit breaker, emit sink, update session counters ---

old_post_sign = '''        if self._package and self._package.plan.id == plan.id:
            self._package.add(receipt)

        return receipt'''

new_post_sign = '''        if self._package and self._package.plan.id == plan.id:
            self._package.add(receipt)

        # Feature 2: record call in circuit breaker
        if self._circuit_breaker is not None:
            self._circuit_breaker.record(agent)

        # Feature 3: emit to sink
        if self._sink is not None:
            self._sink.emit(receipt)

        # Feature 5: update session counters
        if self._session_policy:
            for pattern in self._session_policy:
                if matches_pattern(action, pattern):
                    self._session_counters[pattern] = self._session_counters.get(pattern, 0) + 1

        # Feature 6: store reasoning in evidence if provided
        if reasoning is not None and self._package and self._package.plan.id == plan.id:
            pass  # reasoning text stays in caller's scope; hash is in receipt

        return receipt'''

if old_post_sign in src:
    src = src.replace(old_post_sign, new_post_sign)
    print("  ✓ Added post-sign: circuit breaker record, sink emit, session counter update")
else:
    print("  ⚠ Post-sign patch target not found")

# --- Add _make_denied_receipt helper and delegate_to_agent and audit_tree ---

old_export_method = '''    def export_evidence('''

new_methods_before_export = '''    def _make_denied_receipt(
        self,
        action: str,
        agent: str,
        plan: PlanReceipt,
        evidence: dict[str, Any],
        reason: str,
        enable_timestamp: bool,
    ) -> NotarisedReceipt:
        """Build a denied receipt (circuit breaker or session deny)."""
        evidence_bytes = _canonical_json(evidence)
        evidence_hash = hashlib.sha512(evidence_bytes).hexdigest()
        observed_at = _utc_now().isoformat()
        receipt_id = str(uuid.uuid4())
        prev_hash = self._chain_hashes.get(plan.id)
        policy_hash = _compute_policy_hash(plan)

        unsigned = NotarisedReceipt(
            id=receipt_id,
            plan_id=plan.id,
            agent=agent,
            action=action,
            in_policy=False,
            policy_reason=reason,
            evidence_hash=evidence_hash,
            evidence=evidence,
            observed_at=observed_at,
            signature="",
            previous_receipt_hash=prev_hash,
            plan_signature=plan.signature,
            key_id=self._key_id,
            policy_hash=policy_hash,
            session_id=self._session_id,
        )
        signature = _sign(self._key, unsigned.signable_dict())

        ts_result = None
        if enable_timestamp:
            signed_payload = _canonical_json({**unsigned.signable_dict(), "signature": signature})
            try:
                ts_result = _timestamp_with_fallback(signed_payload, self._tsa_urls)
            except TimestampError:
                pass  # graceful degradation for denied receipts

        receipt = replace(unsigned, signature=signature, timestamp_result=ts_result)

        signed_payload_bytes = _canonical_json({**unsigned.signable_dict(), "signature": signature})
        self._chain_hashes[plan.id] = hashlib.sha256(signed_payload_bytes).hexdigest()
        _save_chain_state(self._key_dir, self._chain_hashes)

        if self._package and self._package.plan.id == plan.id:
            self._package.add(receipt)

        if self._sink is not None:
            self._sink.emit(receipt)

        return receipt

    # Feature 7: multi-agent delegation

    def delegate_to_agent(
        self,
        parent_plan: PlanReceipt,
        child_agent: str,
        requested_scope: list[str],
        action: str = "",
        checkpoints: list[str] | None = None,
        ttl_seconds: int = DEFAULT_TTL,
    ) -> PlanReceipt:
        """Create a child plan with scope intersected from parent.

        Returns a new PlanReceipt whose scope is the intersection of
        parent_plan.scope and requested_scope. Raises NotaryError if
        the intersection is empty (no delegable permissions).
        """
        child_agent = _require_non_empty_string(child_agent, "child_agent", MAX_IDENTITY_LEN)
        requested_t = _require_string_list(requested_scope, "requested_scope")

        effective_scope = intersect_scopes(parent_plan.scope, requested_t)
        if not effective_scope:
            raise NotaryError(
                f"scope intersection is empty — parent scope {list(parent_plan.scope)} "
                f"does not overlap with requested {list(requested_t)}"
            )

        child_plan = self.create_plan(
            user=parent_plan.user,
            action=action or parent_plan.action,
            scope=list(effective_scope),
            checkpoints=checkpoints or list(parent_plan.checkpoints),
            delegates_to=[child_agent],
            ttl_seconds=ttl_seconds,
        )

        # Track parent → child relationship
        if parent_plan.id not in self._child_plans:
            self._child_plans[parent_plan.id] = []
        self._child_plans[parent_plan.id].append(child_plan.id)

        return child_plan

    def audit_tree(self, plan_id: str) -> dict[str, Any]:
        """Return the delegation tree rooted at plan_id."""
        children = self._child_plans.get(plan_id, [])
        return {
            "plan_id": plan_id,
            "children": [self.audit_tree(cid) for cid in children],
        }

    @property
    def session_id(self) -> str:
        """Current session identifier."""
        return self._session_id

    def export_evidence('''

if old_export_method in src:
    src = src.replace(old_export_method, new_methods_before_export)
    print("  ✓ Added _make_denied_receipt, delegate_to_agent, audit_tree, session_id property")
else:
    print("  ⚠ export_evidence insertion point not found")

# --- Add intersect_scopes to __all__ ---

old_all = '''    "verify_chain",
]'''

new_all = '''    "verify_chain",
    "intersect_scopes",
]'''

if old_all in src:
    src = src.replace(old_all, new_all)
    print("  ✓ Added intersect_scopes to __all__")

# ══════════════════════════════════════════════════════════════
# Write the patched file
# ══════════════════════════════════════════════════════════════

notary_path.write_text(src)
print("\n  ✓ notary.py patched successfully")
PATCHER_EOF

python3 "$REPO_ROOT/_patch_notary.py"
rm "$REPO_ROOT/_patch_notary.py"
echo ""

# ------------------------------------------------------------------
# Update __init__.py — add new public exports
# ------------------------------------------------------------------
cat > "$REPO_ROOT/agentmint/__init__.py" << 'INIT_EOF'
"""
AgentMint — Independent notary for AI agent actions.
Produces cryptographic receipts proving what an agent was authorized
to do, and that the record was not altered after the fact.

Quickstart (Notary — primary interface):
    from agentmint.notary import Notary
    notary = Notary()
    plan = notary.create_plan(user="admin@co.com", action="ops", scope=["tts:*"])
    receipt = notary.notarise(action="tts:standard:abc", agent="voice-agent",
                              plan=plan, evidence={"voice_id": "abc"})
    notary.export_evidence(Path("./evidence"))

Scope layer (lightweight authorization checks):
    from agentmint import AgentMint
    mint = AgentMint()
    receipt = mint.issue("deploy", "alice@co.com")
    assert mint.verify(receipt)
"""

from .core import AgentMint, Receipt, JtiStore
from .errors import (
    AgentMintError,
    ValidationError,
    SignatureError,
    ExpiredError,
    ReplayError,
    DeniedError,
)
from .types import DelegationStatus, DelegationResult
from .decorator import (
    AuthorizationError,
    require_receipt,
    set_receipt,
    get_receipt,
    clear_receipt,
)
from .circuit_breaker import CircuitBreaker, BreakerResult
from .sinks import FileSink, Sink
from .shield import scan, ShieldResult, Threat

__version__ = "0.1.0"

__all__ = [
    # Core
    "AgentMint",
    "Receipt",
    "JtiStore",
    # Types
    "DelegationStatus",
    "DelegationResult",
    # Errors
    "AgentMintError",
    "ValidationError",
    "SignatureError",
    "ExpiredError",
    "ReplayError",
    "DeniedError",
    "AuthorizationError",
    # Decorator
    "require_receipt",
    "set_receipt",
    "get_receipt",
    "clear_receipt",
    # Shield
    "scan",
    "ShieldResult",
    "Threat",
    # Circuit breaker
    "CircuitBreaker",
    "BreakerResult",
    # Sinks
    "FileSink",
    "Sink",
]
INIT_EOF
echo "  ✓ agentmint/__init__.py"

# ------------------------------------------------------------------
# Feature 10: tests/test_receipt_upgrades.py
# ------------------------------------------------------------------
cat > "$REPO_ROOT/tests/test_receipt_upgrades.py" << 'TRU_EOF'
"""Tests for Feature 4: receipt upgrades (policy_hash, output_hash)."""

from __future__ import annotations

import hashlib
import json

import pytest

from agentmint.notary import Notary, _canonical_json


class TestPolicyHash:
    """policy_hash is SHA-256 of canonical(scope + checkpoints + delegates_to)."""

    def test_policy_hash_present(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="test",
            scope=["read:*"], checkpoints=["delete:*"],
            delegates_to=["agent-1"],
        )
        receipt = notary.notarise(
            "read:file.txt", "agent-1", plan,
            evidence={"f": "v"}, enable_timestamp=False,
        )
        assert receipt.policy_hash != ""

    def test_policy_hash_is_deterministic(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="test",
            scope=["read:*", "write:*"], checkpoints=[],
            delegates_to=["a"],
        )
        r1 = notary.notarise("read:x", "a", plan, evidence={"k": "1"}, enable_timestamp=False)
        r2 = notary.notarise("write:y", "a", plan, evidence={"k": "2"}, enable_timestamp=False)
        assert r1.policy_hash == r2.policy_hash

    def test_policy_hash_changes_with_scope(self) -> None:
        notary = Notary()
        plan1 = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        plan2 = notary.create_plan(
            user="u@test.com", action="t", scope=["write:*"], delegates_to=["a"],
        )
        r1 = notary.notarise("read:x", "a", plan1, evidence={"k": "1"}, enable_timestamp=False)
        r2 = notary.notarise("write:y", "a", plan2, evidence={"k": "2"}, enable_timestamp=False)
        assert r1.policy_hash != r2.policy_hash

    def test_policy_hash_in_signable_dict(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise("read:x", "a", plan, evidence={"k": "v"}, enable_timestamp=False)
        sd = receipt.signable_dict()
        assert "policy_hash" in sd
        assert sd["policy_hash"] == receipt.policy_hash


class TestOutputHash:
    """output_hash is SHA-256 of canonical(output) when provided."""

    def test_no_output_means_empty_hash(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise("read:x", "a", plan, evidence={"k": "v"}, enable_timestamp=False)
        assert receipt.output_hash == ""

    def test_output_hash_computed(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        output = {"result": "success", "data": [1, 2, 3]}
        receipt = notary.notarise(
            "read:x", "a", plan, evidence={"k": "v"},
            enable_timestamp=False, output=output,
        )
        expected = hashlib.sha256(_canonical_json(output)).hexdigest()
        assert receipt.output_hash == expected

    def test_output_hash_deterministic(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        output = {"a": 1}
        r1 = notary.notarise("read:x", "a", plan, evidence={"k": "1"}, enable_timestamp=False, output=output)
        r2 = notary.notarise("read:y", "a", plan, evidence={"k": "2"}, enable_timestamp=False, output=output)
        assert r1.output_hash == r2.output_hash

    def test_output_hash_in_signable_dict(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise(
            "read:x", "a", plan, evidence={"k": "v"},
            enable_timestamp=False, output={"r": 1},
        )
        sd = receipt.signable_dict()
        assert "output_hash" in sd
TRU_EOF
echo "  ✓ tests/test_receipt_upgrades.py"

# ------------------------------------------------------------------
# Feature 10: tests/test_session.py
# ------------------------------------------------------------------
cat > "$REPO_ROOT/tests/test_session.py" << 'TSESS_EOF'
"""Tests for Feature 5: session context threading."""

from __future__ import annotations

import pytest

from agentmint.notary import Notary


class TestSessionId:
    """Every receipt carries the notary's session_id."""

    def test_session_id_present(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise("read:x", "a", plan, evidence={"k": "v"}, enable_timestamp=False)
        assert receipt.session_id != ""
        assert receipt.session_id == notary.session_id

    def test_session_id_stable_within_notary(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        r1 = notary.notarise("read:x", "a", plan, evidence={"k": "1"}, enable_timestamp=False)
        r2 = notary.notarise("read:y", "a", plan, evidence={"k": "2"}, enable_timestamp=False)
        assert r1.session_id == r2.session_id

    def test_different_notaries_different_sessions(self) -> None:
        n1 = Notary()
        n2 = Notary()
        assert n1.session_id != n2.session_id


class TestSessionTrajectory:
    """Receipt carries recent action trajectory."""

    def test_first_receipt_has_one_entry(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise("read:x", "a", plan, evidence={"k": "v"}, enable_timestamp=False)
        assert len(receipt.session_trajectory) == 1
        assert receipt.session_trajectory[0]["action"] == "read:x"

    def test_trajectory_grows_to_five(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        for i in range(7):
            receipt = notary.notarise(
                f"read:file{i}", "a", plan,
                evidence={"i": str(i)}, enable_timestamp=False,
            )
        # Last receipt should have exactly 5 trajectory entries (last 5 of 7)
        assert len(receipt.session_trajectory) == 5

    def test_trajectory_in_signable_dict(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise("read:x", "a", plan, evidence={"k": "v"}, enable_timestamp=False)
        sd = receipt.signable_dict()
        assert "session_trajectory" in sd


class TestSessionPolicy:
    """Session policy can escalate or deny based on action counts."""

    def test_escalation_after_threshold(self) -> None:
        notary = Notary(session_policy={"read:*": {"escalate_after": 2}})
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        r1 = notary.notarise("read:a", "a", plan, evidence={"k": "1"}, enable_timestamp=False)
        r2 = notary.notarise("read:b", "a", plan, evidence={"k": "2"}, enable_timestamp=False)
        assert r1.session_escalation is None
        assert r2.session_escalation is None
        # Third call — counter is now 2 (from first two), should trigger
        r3 = notary.notarise("read:c", "a", plan, evidence={"k": "3"}, enable_timestamp=False)
        assert r3.session_escalation is not None
        assert "escalate" in r3.session_escalation

    def test_deny_after_threshold(self) -> None:
        notary = Notary(session_policy={"read:*": {"deny_after": 3}})
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        for i in range(3):
            notary.notarise(f"read:{i}", "a", plan, evidence={"k": str(i)}, enable_timestamp=False)
        r4 = notary.notarise("read:x", "a", plan, evidence={"k": "x"}, enable_timestamp=False)
        assert r4.session_escalation is not None
        assert "denied" in r4.session_escalation

    def test_no_policy_means_no_escalation(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        for i in range(10):
            receipt = notary.notarise(
                f"read:{i}", "a", plan,
                evidence={"k": str(i)}, enable_timestamp=False,
            )
        assert receipt.session_escalation is None
TSESS_EOF
echo "  ✓ tests/test_session.py"

# ------------------------------------------------------------------
# Feature 10: tests/test_reasoning.py
# ------------------------------------------------------------------
cat > "$REPO_ROOT/tests/test_reasoning.py" << 'TREAS_EOF'
"""Tests for Feature 6: reasoning capture."""

from __future__ import annotations

import hashlib

import pytest

from agentmint.notary import Notary


class TestReasoningCapture:
    """Reasoning hash is included in receipt when provided."""

    def test_no_reasoning_means_none(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise("read:x", "a", plan, evidence={"k": "v"}, enable_timestamp=False)
        assert receipt.reasoning_hash is None

    def test_reasoning_hash_computed(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        reasoning = "I chose to read this file because the user asked for a summary."
        receipt = notary.notarise(
            "read:x", "a", plan, evidence={"k": "v"},
            enable_timestamp=False, reasoning=reasoning,
        )
        expected = hashlib.sha256(reasoning.encode("utf-8")).hexdigest()
        assert receipt.reasoning_hash == expected

    def test_reasoning_hash_in_signable_dict(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        receipt = notary.notarise(
            "read:x", "a", plan, evidence={"k": "v"},
            enable_timestamp=False, reasoning="some reasoning",
        )
        sd = receipt.signable_dict()
        assert "reasoning_hash" in sd
        assert sd["reasoning_hash"] == receipt.reasoning_hash
TREAS_EOF
echo "  ✓ tests/test_reasoning.py"

# ------------------------------------------------------------------
# Feature 10: tests/test_delegation_v2.py
# ------------------------------------------------------------------
cat > "$REPO_ROOT/tests/test_delegation_v2.py" << 'TDEL_EOF'
"""Tests for Feature 7: multi-agent delegation with scope intersection."""

from __future__ import annotations

import pytest

from agentmint.notary import Notary, NotaryError, intersect_scopes


class TestIntersectScopes:
    """Scope intersection logic."""

    def test_exact_match_kept(self) -> None:
        result = intersect_scopes(["read:public:file"], ["read:public:file"])
        assert result == ("read:public:file",)

    def test_child_more_specific_than_parent_wildcard(self) -> None:
        result = intersect_scopes(["read:*"], ["read:public:file"])
        assert result == ("read:public:file",)

    def test_parent_more_specific_than_child_wildcard(self) -> None:
        result = intersect_scopes(["read:public:file"], ["read:*"])
        assert result == ("read:public:file",)

    def test_no_overlap_returns_empty(self) -> None:
        result = intersect_scopes(["read:*"], ["write:file"])
        assert result == ()

    def test_multiple_patterns(self) -> None:
        result = intersect_scopes(
            ["read:*", "write:summary:*"],
            ["read:reports:q3", "write:summary:draft", "delete:all"],
        )
        assert "read:reports:q3" in result
        assert "write:summary:draft" in result
        assert "delete:all" not in result

    def test_star_parent_matches_everything(self) -> None:
        result = intersect_scopes(["*"], ["read:file", "write:file"])
        assert "read:file" in result
        assert "write:file" in result

    def test_both_wildcards_keeps_more_specific(self) -> None:
        result = intersect_scopes(["read:public:*"], ["read:*"])
        # parent is more specific, child is broader — keep parent
        assert "read:public:*" in result

    def test_no_duplicates(self) -> None:
        result = intersect_scopes(["read:*", "read:public:*"], ["read:public:file"])
        assert result.count("read:public:file") == 1


class TestDelegateToAgent:
    """Notary.delegate_to_agent creates child plans with intersected scope."""

    def test_child_plan_created(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="analysis",
            scope=["read:*", "write:summary:*"],
            delegates_to=["parent-agent"],
        )
        child = notary.delegate_to_agent(
            parent, "child-agent",
            requested_scope=["read:reports:*"],
        )
        assert "read:reports:*" in child.scope
        assert child.delegates_to == ("child-agent",)

    def test_empty_intersection_raises(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*"], delegates_to=["p"],
        )
        with pytest.raises(NotaryError, match="scope intersection is empty"):
            notary.delegate_to_agent(parent, "c", requested_scope=["write:file"])

    def test_child_inherits_checkpoints(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*"], checkpoints=["read:secret:*"],
            delegates_to=["p"],
        )
        child = notary.delegate_to_agent(parent, "c", requested_scope=["read:public:*"])
        assert "read:secret:*" in child.checkpoints


class TestAuditTree:
    """audit_tree returns delegation hierarchy."""

    def test_no_children(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        tree = notary.audit_tree(plan.id)
        assert tree["plan_id"] == plan.id
        assert tree["children"] == []

    def test_one_child(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*"], delegates_to=["p"],
        )
        child = notary.delegate_to_agent(parent, "c", requested_scope=["read:file"])
        tree = notary.audit_tree(parent.id)
        assert len(tree["children"]) == 1
        assert tree["children"][0]["plan_id"] == child.id

    def test_two_children(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*", "write:*"], delegates_to=["p"],
        )
        c1 = notary.delegate_to_agent(parent, "c1", requested_scope=["read:*"])
        c2 = notary.delegate_to_agent(parent, "c2", requested_scope=["write:*"])
        tree = notary.audit_tree(parent.id)
        child_ids = {c["plan_id"] for c in tree["children"]}
        assert c1.id in child_ids
        assert c2.id in child_ids
TDEL_EOF
echo "  ✓ tests/test_delegation_v2.py"

# ------------------------------------------------------------------
echo ""
echo "All Feature 4-7 files written. Run:"
echo "  uv run pytest tests/ -v"