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
