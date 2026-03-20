"""Tests for the AgentMint Notary — including all improvements (4.1-4.7)."""

import json
import zipfile
import base64
from pathlib import Path

import pytest

from agentmint.notary import (
    Notary,
    NotaryError,
    PolicyEvaluation,
    evaluate_policy,
    _canonical_json,
    ChainVerification,
    verify_chain,
)
from agentmint.patterns import matches_pattern


# ── 4.3: Unified pattern matching ─────────────────────────

class TestPatternMatching:
    def test_exact_match(self):
        assert matches_pattern("tts:standard", "tts:standard")

    def test_exact_no_match(self):
        assert not matches_pattern("tts:stream", "tts:standard")

    def test_wildcard_all(self):
        assert matches_pattern("anything", "*")

    def test_wildcard_prefix(self):
        assert matches_pattern("tts:standard:abc", "tts:*")

    def test_wildcard_prefix_exact(self):
        assert matches_pattern("tts", "tts:*")

    def test_wildcard_no_match(self):
        assert not matches_pattern("voice:clone:x", "tts:*")

    def test_nested_wildcard(self):
        assert matches_pattern("voice:clone:ceo:v2", "voice:clone:*")

    def test_bare_star_suffix_not_supported(self):
        """Improvement 4.3: bare * suffix (e.g. tts:standard*) is NOT supported."""
        assert not matches_pattern("tts:standardabc", "tts:standard*")

    def test_colon_star_matches_prefix_only(self):
        assert matches_pattern("read:reports:quarterly", "read:reports:*")
        assert not matches_pattern("read:reportsx", "read:reports:*")


class TestPolicyEvaluation:
    def test_in_scope(self):
        result = evaluate_policy(
            action="tts:standard:abc", agent="voice-agent",
            plan_scope=["tts:standard:*"], plan_checkpoints=[],
            plan_delegates=["voice-agent"], plan_expired=False,
        )
        assert result.in_policy is True

    def test_checkpoint_blocks(self):
        result = evaluate_policy(
            action="voice:clone:ceo", agent="voice-agent",
            plan_scope=["*"], plan_checkpoints=["voice:clone:*"],
            plan_delegates=["voice-agent"], plan_expired=False,
        )
        assert result.in_policy is False
        assert "checkpoint" in result.reason

    def test_checkpoint_checked_before_scope(self):
        result = evaluate_policy(
            action="voice:clone:ceo", agent="voice-agent",
            plan_scope=["voice:clone:*"], plan_checkpoints=["voice:clone:*"],
            plan_delegates=["voice-agent"], plan_expired=False,
        )
        assert result.in_policy is False

    def test_unauthorized_agent(self):
        result = evaluate_policy(
            action="tts:standard:abc", agent="rogue-agent",
            plan_scope=["tts:*"], plan_checkpoints=[],
            plan_delegates=["voice-agent"], plan_expired=False,
        )
        assert result.in_policy is False
        assert "not in delegates_to" in result.reason

    def test_expired_plan(self):
        result = evaluate_policy(
            action="tts:standard:abc", agent="voice-agent",
            plan_scope=["*"], plan_checkpoints=[],
            plan_delegates=[], plan_expired=True,
        )
        assert result.in_policy is False
        assert "expired" in result.reason

    def test_no_scope_match(self):
        result = evaluate_policy(
            action="voice:delete:abc", agent="voice-agent",
            plan_scope=["tts:*"], plan_checkpoints=[],
            plan_delegates=["voice-agent"], plan_expired=False,
        )
        assert result.in_policy is False
        assert "no scope" in result.reason

    def test_empty_delegates_allows_anyone(self):
        result = evaluate_policy(
            action="tts:standard:abc", agent="any-agent",
            plan_scope=["tts:*"], plan_checkpoints=[],
            plan_delegates=[], plan_expired=False,
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
        plan = notary.create_plan(user="admin@co.com", action="voice-ops", scope=["tts:*"])
        assert plan.user == "admin@co.com"
        assert plan.scope == ("tts:*",)
        assert len(plan.id) == 36
        assert len(plan.signature) == 128

    def test_plan_signature_verifies(self):
        notary = Notary()
        plan = notary.create_plan(user="admin@co.com", action="voice-ops", scope=["tts:*"])
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
        plan = notary.create_plan(user="admin", action="x", scope=["*"], ttl_seconds=99999)
        assert not plan.is_expired


class TestNotariseReceipt:
    def test_in_policy_receipt(self):
        notary = Notary()
        plan = notary.create_plan(user="admin", action="ops", scope=["tts:*"], delegates_to=["agent-1"])
        receipt = notary.notarise(
            action="tts:standard:abc", agent="agent-1", plan=plan,
            evidence={"voice_id": "abc"}, enable_timestamp=False,
        )
        assert receipt.in_policy is True
        assert notary.verify_receipt(receipt) is True

    def test_out_of_policy_receipt(self):
        notary = Notary()
        plan = notary.create_plan(
            user="admin", action="ops", scope=["tts:*"],
            checkpoints=["voice:clone:*"], delegates_to=["agent-1"],
        )
        receipt = notary.notarise(
            action="voice:clone:ceo", agent="agent-1", plan=plan,
            evidence={"clone_name": "ceo"}, enable_timestamp=False,
        )
        assert receipt.in_policy is False
        assert notary.verify_receipt(receipt) is True

    def test_evidence_hash_deterministic(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="test", agent="a", plan=plan, evidence={"key": "value"}, enable_timestamp=False)
        plan2 = notary.create_plan(user="a", action="x", scope=["*"])
        r2 = notary.notarise(action="test", agent="a", plan=plan2, evidence={"key": "value"}, enable_timestamp=False)
        assert r1.evidence_hash == r2.evidence_hash

    def test_invalid_evidence_rejected(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        with pytest.raises(NotaryError):
            notary.notarise(action="test", agent="a", plan=plan, evidence="not a dict", enable_timestamp=False)

    def test_receipt_json_roundtrip(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={"k": 1}, enable_timestamp=False)
        parsed = json.loads(receipt.to_json())
        assert parsed["id"] == receipt.id
        assert parsed["in_policy"] == receipt.in_policy
        assert parsed["signature"] == receipt.signature

    def test_aiuc_controls_present(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert "E015" in receipt.aiuc_controls
        assert "D003" in receipt.aiuc_controls


# ── 4.4: Plan signature in receipt ────────────────────────

class TestPlanSignatureInReceipt:
    def test_plan_signature_present(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert receipt.plan_signature == plan.signature
        assert len(receipt.plan_signature) == 128

    def test_plan_signature_in_signable_dict(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        signable = receipt.signable_dict()
        assert "plan_signature" in signable
        assert signable["plan_signature"] == plan.signature

    def test_plan_signature_in_json(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        parsed = json.loads(receipt.to_json())
        assert "plan_signature" in parsed

    def test_signature_valid_with_plan_signature(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert notary.verify_receipt(receipt) is True


# ── Receipt chain (including 4.2: per-plan isolation) ─────

class TestReceiptChain:
    def test_first_receipt_has_no_chain_hash(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="step:one", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False)
        assert r1.previous_receipt_hash is None

    def test_second_receipt_has_chain_hash(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="step:one", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False)
        r2 = notary.notarise(action="step:two", agent="a", plan=plan, evidence={"n": 2}, enable_timestamp=False)
        assert r2.previous_receipt_hash is not None
        assert len(r2.previous_receipt_hash) == 64  # SHA-256 hex

    def test_chain_of_three(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="s:1", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={"n": 2}, enable_timestamp=False)
        r3 = notary.notarise(action="s:3", agent="a", plan=plan, evidence={"n": 3}, enable_timestamp=False)
        assert r1.previous_receipt_hash is None
        assert r2.previous_receipt_hash is not None
        assert r3.previous_receipt_hash is not None
        assert r2.previous_receipt_hash != r3.previous_receipt_hash

    def test_chain_hash_in_signable_dict(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        signable = r2.signable_dict()
        assert "previous_receipt_hash" in signable
        assert signable["previous_receipt_hash"] == r2.previous_receipt_hash

    def test_chain_hash_in_json(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        parsed = json.loads(r2.to_json())
        assert "previous_receipt_hash" in parsed

    def test_chain_resets_on_new_plan(self):
        notary = Notary()
        plan1 = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan1, evidence={}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan1, evidence={}, enable_timestamp=False)
        assert r2.previous_receipt_hash is not None

        plan2 = notary.create_plan(user="a", action="y", scope=["*"])
        r3 = notary.notarise(action="s:3", agent="a", plan=plan2, evidence={}, enable_timestamp=False)
        assert r3.previous_receipt_hash is None

    def test_signature_valid_with_chain_hash(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert r2.previous_receipt_hash is not None
        assert notary.verify_receipt(r2) is True

    def test_per_plan_chain_isolation(self):
        """Improvement 4.2: interleaved plans maintain separate chains."""
        notary = Notary()
        plan_a = notary.create_plan(user="a", action="x", scope=["*"])
        plan_b = notary.create_plan(user="b", action="y", scope=["*"])

        # Interleave receipts
        ra1 = notary.notarise(action="a:1", agent="a", plan=plan_a, evidence={"p": "a"}, enable_timestamp=False)
        rb1 = notary.notarise(action="b:1", agent="b", plan=plan_b, evidence={"p": "b"}, enable_timestamp=False)
        ra2 = notary.notarise(action="a:2", agent="a", plan=plan_a, evidence={"p": "a"}, enable_timestamp=False)
        rb2 = notary.notarise(action="b:2", agent="b", plan=plan_b, evidence={"p": "b"}, enable_timestamp=False)

        # Plan A chain
        assert ra1.previous_receipt_hash is None
        assert ra2.previous_receipt_hash is not None

        # Plan B chain
        assert rb1.previous_receipt_hash is None
        assert rb2.previous_receipt_hash is not None

        # Chains are independent
        assert ra2.previous_receipt_hash != rb2.previous_receipt_hash

        # All signatures valid
        assert notary.verify_receipt(ra1)
        assert notary.verify_receipt(ra2)
        assert notary.verify_receipt(rb1)
        assert notary.verify_receipt(rb2)


# ── 4.1: Notary uses KeyStore ─────────────────────────────

class TestNotaryKeyStore:
    def test_ephemeral_key_default(self):
        """Default Notary() still works with ephemeral key."""
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert notary.verify_receipt(receipt) is True

    def test_persistent_key(self, tmp_path):
        """Improvement 4.1: Notary(key=path) uses KeyStore."""
        key_dir = tmp_path / "keys"
        notary1 = Notary(key=key_dir)
        plan1 = notary1.create_plan(user="a", action="x", scope=["*"])
        receipt1 = notary1.notarise(action="test", agent="a", plan=plan1, evidence={}, enable_timestamp=False)

        # Second notary with same key dir should verify the first's receipts
        notary2 = Notary(key=key_dir)
        assert notary2.verify_receipt(receipt1) is True

    def test_different_keys_fail_verification(self, tmp_path):
        """Different key dirs produce different keys."""
        notary1 = Notary(key=tmp_path / "keys1")
        notary2 = Notary(key=tmp_path / "keys2")
        plan = notary1.create_plan(user="a", action="x", scope=["*"])
        receipt = notary1.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert notary2.verify_receipt(receipt) is False


# ── 4.6: verify_chain() API ───────────────────────────────

class TestVerifyChain:
    def test_empty_chain(self):
        result = verify_chain([])
        assert result.valid is True
        assert result.length == 0
        assert result.root_hash == ""

    def test_single_receipt_chain(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        result = verify_chain([r1])
        assert result.valid is True
        assert result.length == 1
        assert len(result.root_hash) == 64

    def test_valid_chain_of_three(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="s:1", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={"n": 2}, enable_timestamp=False)
        r3 = notary.notarise(action="s:3", agent="a", plan=plan, evidence={"n": 3}, enable_timestamp=False)
        result = verify_chain([r1, r2, r3])
        assert result.valid is True
        assert result.length == 3
        assert result.root_hash != ""

    def test_broken_chain_detects_gap(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="s:1", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={"n": 2}, enable_timestamp=False)
        r3 = notary.notarise(action="s:3", agent="a", plan=plan, evidence={"n": 3}, enable_timestamp=False)
        # Skip r2 — chain should break at r3
        result = verify_chain([r1, r3])
        assert result.valid is False
        assert result.break_at_index == 1

    def test_first_receipt_must_have_null_hash(self):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        # Starting with r2 (which has a previous hash) should fail
        result = verify_chain([r2])
        assert result.valid is False
        assert result.break_at_index == 0


# ── Public key PEM ─────────────────────────────────────────

class TestPublicKeyPem:
    def test_pem_format(self):
        notary = Notary()
        from agentmint.notary import _public_key_pem
        pem = _public_key_pem(notary.verify_key)
        assert pem.startswith("-----BEGIN PUBLIC KEY-----\n")
        assert pem.endswith("-----END PUBLIC KEY-----\n")

    def test_pem_contains_valid_der(self):
        notary = Notary()
        from agentmint.notary import _public_key_pem
        pem = _public_key_pem(notary.verify_key)
        lines = pem.strip().split("\n")
        b64 = "".join(lines[1:-1])
        der = base64.b64decode(b64)
        assert len(der) == 44

    def test_public_key_in_evidence_zip(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "public_key.pem" in names
            pem_content = zf.read("public_key.pem").decode()
            assert "BEGIN PUBLIC KEY" in pem_content


# ── Evidence package (including 4.7: chain root) ──────────

class TestEvidencePackage:
    def test_export_creates_zip(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["tts:*"])
        notary.notarise(action="tts:standard:abc", agent="a", plan=plan, evidence={"v": 1}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        assert zip_path.exists()
        assert zip_path.suffix == ".zip"

    def test_zip_contains_required_files(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["tts:*"])
        notary.notarise(action="tts:ok", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "receipt_index.json" in names
            assert "plan.json" in names
            assert "VERIFY.sh" in names
            assert "public_key.pem" in names

    def test_index_has_correct_counts(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["tts:*"], checkpoints=["voice:*"])
        notary.notarise(action="tts:ok", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        notary.notarise(action="voice:clone:bad", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            index = json.loads(zf.read("receipt_index.json"))
            assert index["total_receipts"] == 2
            assert index["in_policy_count"] == 1
            assert index["out_of_policy_count"] == 1

    def test_index_has_chain_hashes(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        notary.notarise(action="s:2", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            index = json.loads(zf.read("receipt_index.json"))
            assert index["receipts"][0]["previous_receipt_hash"] is None
            assert index["receipts"][1]["previous_receipt_hash"] is not None

    def test_index_has_chain_root(self, tmp_path):
        """Improvement 4.7: chain root hash in receipt_index.json."""
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="s:1", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        notary.notarise(action="s:2", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            index = json.loads(zf.read("receipt_index.json"))
            assert "chain" in index
            chain = index["chain"]
            assert chain["valid"] is True
            assert chain["length"] == 2
            assert len(chain["root_hash"]) == 64
            assert "root_signature" in chain

    def test_export_without_plan_raises(self, tmp_path):
        notary = Notary()
        with pytest.raises(NotaryError):
            notary.export_evidence(tmp_path)

    def test_verify_script_is_executable(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            info = zf.getinfo("VERIFY.sh")
            unix_perms = (info.external_attr >> 16) & 0o777
            assert unix_perms & 0o111 != 0

    def test_verify_script_contains_signature_check(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        with zipfile.ZipFile(zip_path) as zf:
            names = zf.namelist()
            assert "verify_sigs.py" in names
            sigs_script = zf.read("verify_sigs.py").decode()
            assert "VerifyKey" in sigs_script
            assert "BadSignatureError" in sigs_script


# ── Key ID (revocation support) ──────────────────────────

class TestKeyId:
    def test_key_id_present_and_consistent(self):
        """key_id flows from Notary → plan → receipt → evidence index."""
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        kid = notary.key_id
        assert len(kid) == 16
        assert plan.key_id == kid
        assert receipt.key_id == kid
        assert receipt.signable_dict()["key_id"] == kid

    def test_key_id_in_evidence_package(self, tmp_path):
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        zip_path = notary.export_evidence(tmp_path)
        import json, zipfile
        with zipfile.ZipFile(zip_path) as zf:
            index = json.loads(zf.read("receipt_index.json"))
        assert index["key_id"] == notary.key_id

    def test_persistent_key_stable_id(self, tmp_path):
        """Same key dir → same key_id. Different dir → different key_id."""
        n1 = Notary(key=tmp_path / "k1")
        n2 = Notary(key=tmp_path / "k1")
        n3 = Notary(key=tmp_path / "k2")
        assert n1.key_id == n2.key_id
        assert n1.key_id != n3.key_id


# ── Chain state persistence (crash recovery) ─────────────

class TestChainPersistence:
    def test_chain_survives_restart(self, tmp_path):
        """Persistent notary resumes chain after restart."""
        key_dir = tmp_path / "keys"
        notary1 = Notary(key=key_dir)
        plan = notary1.create_plan(user="a", action="x", scope=["*"])
        r1 = notary1.notarise(action="s:1", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False)
        assert r1.previous_receipt_hash is None

        # "Crash" — new Notary instance, same key dir
        notary2 = Notary(key=key_dir)
        plan2 = notary2.create_plan(user="a", action="x", scope=["*"], )
        # Old plan's chain should still be loadable
        r2 = notary2.notarise(action="s:2", agent="a", plan=plan, evidence={"n": 2}, enable_timestamp=False)
        assert r2.previous_receipt_hash is not None
        assert notary2.verify_receipt(r2)

    def test_ephemeral_no_file_written(self, tmp_path):
        """Ephemeral notary never touches disk."""
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        # No chain_state.json anywhere
        assert not list(tmp_path.glob("**/chain_state.json"))

    def test_chain_state_file_permissions(self, tmp_path):
        """Chain state file is owner-only (0o600)."""
        key_dir = tmp_path / "keys"
        notary = Notary(key=key_dir)
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        state_file = key_dir / "chain_state.json"
        assert state_file.exists()
        import stat
        perms = stat.S_IMODE(state_file.stat().st_mode)
        assert perms == 0o600


# ── Agent co-signature ───────────────────────────────────

class TestAgentCoSignature:
    def test_no_agent_key_is_noop(self):
        """Without agent_key, receipts work exactly as before."""
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        receipt = notary.notarise(action="test", agent="a", plan=plan, evidence={}, enable_timestamp=False)
        assert receipt.agent_signature == ""
        assert receipt.agent_key_id == ""
        assert notary.verify_receipt(receipt)

    def test_agent_cosigns_evidence(self):
        """Agent key produces a verifiable co-signature on the evidence."""
        from nacl.signing import SigningKey as SK
        from agentmint.notary import _canonical_json
        agent_sk = SK.generate()
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        evidence = {"tool": "tts", "result": "ok"}
        receipt = notary.notarise(
            action="test", agent="a", plan=plan,
            evidence=evidence, enable_timestamp=False, agent_key=agent_sk)
        # Both signatures present
        assert len(receipt.agent_signature) == 128
        assert len(receipt.agent_key_id) == 16
        # Notary sig valid
        assert notary.verify_receipt(receipt)
        # Agent sig independently verifiable
        agent_sk.verify_key.verify(_canonical_json(evidence), bytes.fromhex(receipt.agent_signature))

    def test_same_agent_key_same_id_across_receipts(self):
        """Same agent key produces same agent_key_id — auditors can track continuity."""
        from nacl.signing import SigningKey as SK
        agent_sk = SK.generate()
        notary = Notary()
        plan = notary.create_plan(user="a", action="x", scope=["*"])
        r1 = notary.notarise(action="s:1", agent="a", plan=plan, evidence={"n": 1}, enable_timestamp=False, agent_key=agent_sk)
        r2 = notary.notarise(action="s:2", agent="a", plan=plan, evidence={"n": 2}, enable_timestamp=False, agent_key=agent_sk)
        assert r1.agent_key_id == r2.agent_key_id
        assert r1.agent_signature != r2.agent_signature  # different evidence, different sig
