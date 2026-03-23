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
