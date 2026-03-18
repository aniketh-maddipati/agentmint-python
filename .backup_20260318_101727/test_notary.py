"""Tests for the AgentMint Notary."""

import json
import zipfile
import time
from pathlib import Path

import pytest

from agentmint.notary import (
    Notary,
    NotaryError,
    PolicyEvaluation,
    evaluate_policy,
    _matches_pattern,
    _canonical_json,
)


class TestPatternMatching:
    def test_exact_match(self):
        assert _matches_pattern("tts:standard", "tts:standard")

    def test_exact_no_match(self):
        assert not _matches_pattern("tts:stream", "tts:standard")

    def test_wildcard_all(self):
        assert _matches_pattern("anything", "*")

    def test_wildcard_prefix(self):
        assert _matches_pattern("tts:standard:abc", "tts:*")

    def test_wildcard_prefix_exact(self):
        assert _matches_pattern("tts", "tts:*")

    def test_wildcard_no_match(self):
        assert not _matches_pattern("voice:clone:x", "tts:*")

    def test_nested_wildcard(self):
        assert _matches_pattern("voice:clone:ceo:v2", "voice:clone:*")


class TestPolicyEvaluation:
    def test_in_scope(self):
        result = evaluate_policy(
            action="tts:standard:abc",
            agent="voice-agent",
            plan_scope=["tts:standard:*"],
            plan_checkpoints=[],
            plan_delegates=["voice-agent"],
            plan_expired=False,
        )
        assert result.in_policy is True

    def test_checkpoint_blocks(self):
        result = evaluate_policy(
            action="voice:clone:ceo",
            agent="voice-agent",
            plan_scope=["*"],
            plan_checkpoints=["voice:clone:*"],
            plan_delegates=["voice-agent"],
            plan_expired=False,
        )
        assert result.in_policy is False
        assert "checkpoint" in result.reason

    def test_checkpoint_checked_before_scope(self):
        result = evaluate_policy(
            action="voice:clone:ceo",
            agent="voice-agent",
            plan_scope=["voice:clone:*"],
            plan_checkpoints=["voice:clone:*"],
            plan_delegates=["voice-agent"],
            plan_expired=False,
        )
        assert result.in_policy is False

    def test_unauthorized_agent(self):
        result = evaluate_policy(
            action="tts:standard:abc",
            agent="rogue-agent",
            plan_scope=["tts:*"],
            plan_checkpoints=[],
            plan_delegates=["voice-agent"],
            plan_expired=False,
        )
        assert result.in_policy is False
        assert "not in delegates_to" in result.reason

    def test_expired_plan(self):
        result = evaluate_policy(
            action="tts:standard:abc",
            agent="voice-agent",
            plan_scope=["*"],
            plan_checkpoints=[],
            plan_delegates=[],
            plan_expired=True,
        )
        assert result.in_policy is False
        assert "expired" in result.reason

    def test_no_scope_match(self):
        result = evaluate_policy(
            action="voice:delete:abc",
            agent="voice-agent",
            plan_scope=["tts:*"],
            plan_checkpoints=[],
            plan_delegates=["voice-agent"],
            plan_expired=False,
        )
        assert result.in_policy is False
        assert "no scope" in result.reason

    def test_empty_delegates_allows_anyone(self):
        result = evaluate_policy(
            action="tts:standard:abc",
            agent="any-agent",
            plan_scope=["tts:*"],
            plan_checkpoints=[],
            plan_delegates=[],
            plan_expired=False,
        )
        assert result.in_policy is True


class TestCanonicalJson:
    def test_deterministic(self):
        d = {"b": 2, "a": 1}
        assert _canonical_json(d) == _canonical_json(d)

    def test_key_order(self):
        assert _canonical_json({"b": 2, "a": 1}) == b'{"a":1,"b":2}'

    def test_no_spaces(self):
        result = _canonical_json({"key": "value"})
        assert b" " not in result


class TestNotaryPlan:
    def test_create_plan(self):
        notary = Notary()
        plan = notary.create_plan(
            user="admin@co.com",
            action="voice-ops",
            scope=["tts:*"],
        )
        assert plan.user == "admin@co.com"
        assert plan.scope == ("tts:*",)
        assert len(plan.id) == 36
        assert len(plan.signature) == 128

    def test_plan_signature_verifies(self):
        notary = Notary()
        plan = notary.create_plan(
            user="admin@co.com",
            action="voice-ops",
            scope=["tts:*"],
        )
        assert notary.verify_plan(plan) is True

    def test_empty_user_rejected(self):
        notary = Notary()
        with pytest.raises(NotaryError):
            notary.create_plan(user="", action="x", scope=["*"])

    def test_empty_action_rejected(self):
        notary = Notary()
        with pytest.raises(NotaryError):
            notary.create_plan(user="admin", action="", scope=["*"])

    def test_ttl_clamped(self):
        notary = Notary()
        plan = notary.create_plan(
            user="admin",
            action="x",
            scope=["*"],
            ttl_seconds=99999,
        )
        assert not plan.is_expired


class TestNotariseReceipt:
    def test_in_policy_receipt(self):
        notary = Notary()
        plan = notary.create_plan(
            user="admin", action="ops",
            scope=["tts:*"], delegates_to=["agent-1"],
        )
        receipt = notary.notarise(
            action="tts:standard:abc",
            agent="agent-1",
            plan=plan,
            evidence={"voice_id": "abc"},
            enable_timestamp=False,
        )
        assert receipt.in_policy is True
        assert notary.verify_receipt(receipt) is True

    def test_out_of_policy_receipt(self):
        notary = Notary()
        plan = notary.create_plan(
            user="admin", action="ops",
            scope=["tts:*"],
            checkpoints=["voice:clone:*"],
            delegates_to=["agent-1"],
        )
        receipt = notary.notarise(
            action="voice:clone:ceo",
            agent="agent-1",
            plan=plan,
            evidence={"clone_name": "ceo"},
            enable_timestamp=False,
        )
        assert receipt.in_policy is False
        assert notary.verify_receipt(receipt) is True

    def test_evidence_hash_deterministic(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(
            action="test", agent="a", plan=plan,
            evidence={"key": "value"}, enable_timestamp=False,
        )
        r2 = notary.notarise(
            action="test", agent="a", plan=plan,
            evidence={"key": "value"}, enable_timestamp=False,
        )
        assert r1.evidence_hash == r2.evidence_hash

    def test_invalid_evidence_rejected(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        with pytest.raises(NotaryError):
            notary.notarise(
                action="test", agent="a", plan=plan,
                evidence="not a dict", enable_timestamp=False,
            )

    def test_receipt_json_roundtrip(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(
            action="test", agent="a", plan=plan,
            evidence={"k": 1}, enable_timestamp=False,
        )
        parsed = json.loads(receipt.to_json())
        assert parsed["id"] == receipt.id
        assert parsed["in_policy"] == receipt.in_policy
        assert parsed["signature"] == receipt.signature

    def test_aiuc_controls_present(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(
            action="test", agent="a", plan=plan,
            evidence={}, enable_timestamp=False,
        )
        assert "E015" in receipt.aiuc_controls
        assert "D003" in receipt.aiuc_controls


class TestEvidencePackage:
    def test_export_creates_zip(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["tts:*"])
        notary.notarise(
            action="tts:standard:abc", agent="a", plan=plan,
            evidence={"v": 1}, enable_timestamp=False,
        )
        zip_path = notary.export_evidence(tmp_path)
        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

    def test_zip_contains_required_files(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["tts:*"])
        notary.notarise(
            action="tts:ok", agent="a", plan=plan,
            evidence={}, enable_timestamp=False,
        )
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "receipt_index.json" in names
            assert "plan.json" in names
            assert "VERIFY.sh" in names

    def test_index_has_correct_counts(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(
            user="a", action="x",
            scope=["tts:*"], checkpoints=["voice:*"],
        )
        notary.notarise(
            action="tts:ok", agent="a", plan=plan,
            evidence={}, enable_timestamp=False,
        )
        notary.notarise(
            action="voice:clone:bad", agent="a", plan=plan,
            evidence={}, enable_timestamp=False,
        )
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            index = json.loads(zf.read("receipt_index.json"))
            assert index["total_receipts"] == 2
            assert index["in_policy_count"] == 1
            assert index["out_of_policy_count"] == 1

    def test_export_without_plan_raises(self, tmp_path):
        notary = Notary()
        with pytest.raises(NotaryError):
            notary.export_evidence(tmp_path)

    def test_verify_script_is_executable(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(
            action="test", agent="a", plan=plan,
            evidence={}, enable_timestamp=False,
        )
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            info = zf.getinfo("VERIFY.sh")
            unix_perms = (info.external_attr >> 16) & 0o777
            assert unix_perms & 0o111 != 0
