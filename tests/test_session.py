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
