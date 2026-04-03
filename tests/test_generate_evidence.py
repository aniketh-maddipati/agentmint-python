"""
Tests for generate_evidence.py output.

Validates structure, crypto integrity, field alignment with notary.py,
privacy-preserving design, tamper detection.

Run:  uv run pytest tests/test_generate_evidence.py -v
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


# ── Helpers ───────────────────────────────────────────────

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


UNSIGNED = {"signature", "timestamp", "output"}

REQUIRED_SIGNABLE = {
    "id", "type", "plan_id", "agent", "action", "in_policy",
    "policy_reason", "evidence_hash_sha512", "evidence",
    "observed_at", "aiuc_controls", "key_id", "agent_key_id",
}
CONDITIONAL_SIGNABLE = {
    "policy_hash", "output_hash", "session_id",
    "session_trajectory", "session_escalation",
    "reasoning_hash", "previous_receipt_hash", "plan_signature",
}
ALL_KNOWN = REQUIRED_SIGNABLE | CONDITIONAL_SIGNABLE | UNSIGNED | {"signature"}

PLAN_FIELDS = {
    "id", "type", "user", "action", "scope", "checkpoints",
    "delegates_to", "issued_at", "expires_at", "key_id",
}

REASONINGS = [
    "Patient PT-4821 is listed in today's claims batch; "
    "reading demographics to verify identity before claim submission.",
    "Insurance eligibility must be confirmed before "
    "submitting claim CLM-9920 for patient PT-4821.",
    "Patient identity and insurance verified; "
    "submitting claim CLM-9920 with CPT codes 99213 and 85025.",
    "Claim CLM-9920 was denied by payer with code CO-50; "
    "attempting to file appeal for medical necessity review.",
    "Supervisor delegated summary-write scope to claims-agent; "
    "writing session summary under narrowed child plan.",
    "All actions complete for today's batch; "
    "writing session summary with claims processed and outcomes.",
]

HAS_OUTPUT = [True, True, True, False, True, True]


# ── Fixtures ──────────────────────────────────────────────

@pytest.fixture(scope="session")
def evidence_dir():
    """Run the generator once, return path to output dir."""
    gen = Path(__file__).parent.parent / "generate_evidence.py"
    if not gen.exists():
        pytest.skip("generate_evidence.py not found at repo root")

    result = subprocess.run(
        [sys.executable, str(gen)],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, "Generator failed:\n" + result.stderr[:500]

    # Find the output dir (agentmint_evidence or agentmint-evidence)
    for name in ["agentmint_evidence", "agentmint-evidence"]:
        d = gen.parent / name
        if d.exists():
            return d

    pytest.fail("No evidence output directory found")


@pytest.fixture(scope="session")
def plan(evidence_dir):
    return json.loads((evidence_dir / "plan.json").read_text())


@pytest.fixture(scope="session")
def child_plan(evidence_dir):
    return json.loads((evidence_dir / "child_plan.json").read_text())


@pytest.fixture(scope="session")
def receipts(evidence_dir):
    return [
        json.loads(f.read_text())
        for f in sorted((evidence_dir / "receipts").glob("*.json"))
    ]


@pytest.fixture(scope="session")
def index(evidence_dir):
    return json.loads((evidence_dir / "receipt_index.json").read_text())


# ── File Structure ────────────────────────────────────────

class TestFileStructure:
    def test_plan_exists(self, evidence_dir):
        assert (evidence_dir / "plan.json").exists()

    def test_child_plan_exists(self, evidence_dir):
        assert (evidence_dir / "child_plan.json").exists()

    def test_index_exists(self, evidence_dir):
        assert (evidence_dir / "receipt_index.json").exists()

    def test_public_key_exists(self, evidence_dir):
        assert (evidence_dir / "public_key.pem").exists()

    def test_verify_sh_exists(self, evidence_dir):
        assert (evidence_dir / "VERIFY.sh").exists()

    def test_verify_sigs_exists(self, evidence_dir):
        assert (evidence_dir / "verify_sigs.py").exists()

    def test_e015_exists(self, evidence_dir):
        assert (evidence_dir / "E015_CONTROL_MAP.md").exists()

    def test_trust_model_exists(self, evidence_dir):
        assert (evidence_dir / "TRUST_MODEL.md").exists()

    def test_readme_exists(self, evidence_dir):
        assert (evidence_dir / "README.md").exists()

    def test_six_receipt_files(self, evidence_dir):
        rfs = sorted((evidence_dir / "receipts").glob("*.json"))
        assert len(rfs) == 6

    def test_receipts_sequence_prefixed(self, evidence_dir):
        for f in sorted((evidence_dir / "receipts").glob("*.json")):
            assert f.name[:3].isdigit(), f"Not prefixed: {f.name}"

    def test_verify_sh_executable(self, evidence_dir):
        assert os.access(evidence_dir / "VERIFY.sh", os.X_OK)

    def test_verify_sigs_executable(self, evidence_dir):
        assert os.access(evidence_dir / "verify_sigs.py", os.X_OK)


# ── Plan ──────────────────────────────────────────────────

class TestPlan:
    @pytest.mark.parametrize("field", sorted(PLAN_FIELDS))
    def test_plan_has_field(self, plan, field):
        assert field in plan

    def test_plan_has_signature(self, plan):
        assert "signature" in plan

    def test_plan_type(self, plan):
        assert plan["type"] == "plan"

    def test_plan_sig_length(self, plan):
        assert len(plan["signature"]) == 128

    def test_plan_key_id_length(self, plan):
        assert len(plan["key_id"]) == 16


# ── Field Alignment ──────────────────────────────────────

class TestFieldAlignment:
    def test_all_have_required_fields(self, receipts):
        for r in receipts:
            missing = REQUIRED_SIGNABLE - set(r.keys())
            assert not missing, "Receipt %s missing: %s" % (r["id"][:8], missing)

    def test_all_have_signature(self, receipts):
        for r in receipts:
            assert len(r.get("signature", "")) == 128

    def test_all_correct_type(self, receipts):
        for r in receipts:
            assert r["type"] == "notarised_evidence"

    @pytest.mark.parametrize("bad_name", ["receipt_id", "status", "reason", "timestamp"])
    def test_no_wrong_field_names(self, receipts, bad_name):
        for r in receipts:
            assert bad_name not in r, "Receipt %s has wrong name '%s'" % (r["id"][:8], bad_name)

    def test_no_unknown_fields(self, receipts):
        for r in receipts:
            unknown = set(r.keys()) - ALL_KNOWN
            assert not unknown, "Receipt %s has unknown: %s" % (r["id"][:8], unknown)


# ── output_hash ──────────────────────────────────────────

class TestOutputHash:
    def test_present_when_output_exists(self, receipts):
        for i, r in enumerate(receipts):
            if HAS_OUTPUT[i]:
                assert "output_hash" in r, "Receipt %s should have output_hash" % r["id"][:8]
                assert len(r["output_hash"]) == 64

    def test_omitted_when_blocked(self, receipts):
        for i, r in enumerate(receipts):
            if not HAS_OUTPUT[i]:
                assert "output_hash" not in r, "Blocked receipt should omit output_hash"
                assert "output" not in r, "Blocked receipt should have no output"

    def test_cross_verification(self, receipts):
        for r in receipts:
            if "output" in r and "output_hash" in r:
                computed = hashlib.sha256(canonical(r["output"])).hexdigest()
                assert computed == r["output_hash"], "output_hash mismatch on %s" % r["id"][:8]


# ── reasoning_hash ───────────────────────────────────────

class TestReasoningHash:
    def test_present_on_all(self, receipts):
        for r in receipts:
            assert "reasoning_hash" in r
            assert len(r["reasoning_hash"]) == 64

    def test_matches_scenario_text(self, receipts):
        for i, r in enumerate(receipts):
            expected = hashlib.sha256(REASONINGS[i].encode("utf-8")).hexdigest()
            assert r["reasoning_hash"] == expected, "reasoning_hash mismatch on %s" % r["id"][:8]

    def test_raw_text_not_in_receipt(self, receipts):
        for i, r in enumerate(receipts):
            rj = json.dumps(r)
            assert REASONINGS[i] not in rj, "Raw reasoning leaked into receipt %s" % r["id"][:8]

    def test_no_reasoning_field(self, receipts):
        for r in receipts:
            assert "reasoning" not in r, "Receipt should not have 'reasoning' field"


# ── Signed/Unsigned Boundary ─────────────────────────────

class TestBoundary:
    def test_output_excluded_from_signable(self, receipts):
        for r in receipts:
            sd = {k: v for k, v in r.items() if k not in UNSIGNED}
            assert "output" not in sd

    def test_output_hash_in_signable_when_present(self, receipts):
        for r in receipts:
            if "output" in r:
                sd = {k: v for k, v in r.items() if k not in UNSIGNED}
                assert "output_hash" in sd


# ── Chain ─────────────────────────────────────────────────

class TestChain:
    def test_first_receipt_has_no_prev(self, receipts):
        assert "previous_receipt_hash" not in receipts[0]

    def test_child_plan_receipt_has_no_prev(self, receipts):
        # Receipt 005 (index 4) is first receipt under child plan — no prev hash
        assert "previous_receipt_hash" not in receipts[4], \
            "First receipt under child plan should have no previous_receipt_hash"

    def test_parent_chain_links_correct(self, receipts, plan):
        # Verify chain for parent plan receipts only (indices 0-3, 5)
        parent_receipts = [r for r in receipts if r["plan_id"] == plan["id"]]
        prev = None
        for r in parent_receipts:
            assert r.get("previous_receipt_hash") == prev, \
                "Parent chain break at %s" % r["id"][:8]
            sd = {k: v for k, v in r.items() if k not in UNSIGNED}
            prev = hashlib.sha256(
                canonical(dict(**sd, signature=r["signature"]))
            ).hexdigest()

    def test_child_chain_links_correct(self, receipts, child_plan):
        # Verify chain for child plan receipts (just index 4)
        child_receipts = [r for r in receipts if r["plan_id"] == child_plan["id"]]
        assert len(child_receipts) == 1
        assert "previous_receipt_hash" not in child_receipts[0]


# ── Evidence Hash ─────────────────────────────────────────

class TestEvidenceHash:
    def test_all_match(self, receipts):
        for r in receipts:
            computed = hashlib.sha512(canonical(r["evidence"])).hexdigest()
            assert computed == r["evidence_hash_sha512"], \
                "evidence_hash mismatch on %s" % r["id"][:8]


# ── Policy Hash ──────────────────────────────────────────

class TestPolicyHash:
    def test_parent_plan_receipts_same_hash(self, receipts, plan):
        parent = [r for r in receipts if r["plan_id"] == plan["id"]]
        hashes = {r.get("policy_hash") for r in parent if "policy_hash" in r}
        assert len(hashes) == 1, "Parent plan receipts should share policy_hash"

    def test_child_plan_receipt_different_hash(self, receipts, plan, child_plan):
        parent_r = [r for r in receipts if r["plan_id"] == plan["id"]]
        child_r = [r for r in receipts if r["plan_id"] == child_plan["id"]]
        if parent_r and child_r:
            assert parent_r[0].get("policy_hash") != child_r[0].get("policy_hash"), \
                "Different plans should have different policy_hash"


# ── Scenario ─────────────────────────────────────────────

class TestScenario:
    def test_six_receipts(self, receipts):
        assert len(receipts) == 6

    def test_five_in_policy(self, receipts):
        assert sum(1 for r in receipts if r["in_policy"]) == 5

    def test_one_violation(self, receipts):
        viols = [r for r in receipts if not r["in_policy"]]
        assert len(viols) == 1
        assert viols[0]["action"] == "appeal:claim:CLM-9920"
        assert "checkpoint" in viols[0]["policy_reason"]

    def test_blocked_receipt_has_no_output(self, receipts):
        r004 = receipts[3]
        assert not r004["in_policy"]
        assert "output" not in r004
        assert "output_hash" not in r004

    def test_violation_has_reasoning(self, receipts):
        viols = [r for r in receipts if not r["in_policy"]]
        assert "reasoning_hash" in viols[0]

    def test_005_uses_child_plan(self, receipts, plan, child_plan):
        # Receipt 005 is under the delegated child plan
        assert receipts[4]["plan_id"] == child_plan["id"]
        assert receipts[4]["plan_id"] != plan["id"]
        assert receipts[4]["in_policy"]

    def test_005_006_same_action_different_plans(self, receipts):
        # Both are write:summary:daily-batch but under different plans
        assert receipts[4]["action"] == receipts[5]["action"]
        assert receipts[4]["plan_id"] != receipts[5]["plan_id"]


# ── Delegation ───────────────────────────────────────────

class TestDelegation:
    def test_child_plan_has_write_scope(self, child_plan):
        assert any("write:summary" in s for s in child_plan["scope"])

    def test_child_plan_inherits_checkpoints(self, child_plan):
        # Checkpoints propagate through delegation — by design
        assert child_plan["checkpoints"] == ["appeal:*"]

    def test_child_plan_same_user(self, plan, child_plan):
        assert child_plan["user"] == plan["user"]

    def test_child_plan_delegates_to_agent(self, child_plan):
        assert "claims-agent" in child_plan["delegates_to"]

    def test_child_plan_has_signature(self, child_plan):
        assert len(child_plan.get("signature", "")) == 128

    def test_child_scope_is_subset(self, plan, child_plan):
        # Child scope should be narrower than parent
        assert len(child_plan["scope"]) < len(plan["scope"])

    def test_index_has_delegation_tree(self, index):
        assert "delegation_tree" in index
        tree = index["delegation_tree"]
        assert "plan_id" in tree
        assert len(tree["children"]) == 1

    def test_index_has_child_plan_id(self, index, child_plan):
        assert index["child_plan_id"] == child_plan["id"]

    def test_receipt_005_plan_matches_child(self, receipts, child_plan):
        assert receipts[4]["plan_id"] == child_plan["id"]


# ── Index ─────────────────────────────────────────────────

class TestIndex:
    def test_total(self, index, receipts):
        assert index["total_receipts"] == len(receipts)

    def test_in_policy_count(self, index, receipts):
        assert index["in_policy_count"] == sum(1 for r in receipts if r["in_policy"])

    def test_has_key_id(self, index):
        assert "key_id" in index

    def test_entries_match(self, index, receipts):
        for ie, r in zip(index["receipts"], receipts):
            assert ie["receipt_id"] == r["id"]
            assert ie["action"] == r["action"]


# ── Hash Determinism ─────────────────────────────────────

class TestHashDeterminism:
    def test_output_hash_001(self):
        d = {"patient_id": "PT-4821", "name": "Margaret Chen",
             "dob": "1958-03-14", "insurance_id": "BCBS-IL-98301"}
        assert hashlib.sha256(canonical(d)).hexdigest() == \
            "c6c3a80fa34640dc3f8d7c32d6be072dd71f126e9e5f498c8c087b35aaed3d3b"

    def test_reasoning_hash_001(self):
        r = ("Patient PT-4821 is listed in today's claims batch; "
             "reading demographics to verify identity before claim submission.")
        assert hashlib.sha256(r.encode("utf-8")).hexdigest() == \
            "f769d1bc53b62118979a65700194d40b09319cba574cfb7558114de9028c1dee"


# ── VERIFY.sh Integration ────────────────────────────────

class TestVerifySh:
    def test_exits_zero(self, evidence_dir):
        result = subprocess.run(
            ["bash", str(evidence_dir / "VERIFY.sh")],
            capture_output=True, text=True, timeout=60, cwd=str(evidence_dir),
        )
        assert result.returncode == 0, "VERIFY.sh failed:\n" + result.stdout[-500:]

    def test_all_sigs_pass(self, evidence_dir):
        result = subprocess.run(
            ["bash", str(evidence_dir / "VERIFY.sh")],
            capture_output=True, text=True, timeout=60, cwd=str(evidence_dir),
        )
        # 2 plans + 6 receipts = 8 signatures
        assert "8/8" in result.stdout, "Expected 8/8 signatures in: " + result.stdout[-200:]

    def test_all_chain_pass(self, evidence_dir):
        result = subprocess.run(
            ["bash", str(evidence_dir / "VERIFY.sh")],
            capture_output=True, text=True, timeout=60, cwd=str(evidence_dir),
        )
        assert "6/6" in result.stdout, "Expected 6/6 chain links in: " + result.stdout[-200:]


# ── Tamper Detection ─────────────────────────────────────

class TestTamper:
    def test_flip_in_policy_detected(self, evidence_dir):
        td = Path(tempfile.mkdtemp())
        try:
            shutil.copytree(evidence_dir, td / "e")
            e = td / "e"
            target = sorted((e / "receipts").glob("*.json"))[0]
            original = target.read_text()
            data = json.loads(original)
            data["in_policy"] = not data["in_policy"]
            target.write_text(json.dumps(data, indent=2))

            r = subprocess.run(
                [sys.executable, str(e / "verify_sigs.py")],
                capture_output=True, text=True, timeout=30, cwd=str(e),
            )
            assert r.returncode != 0, "Tampered receipt should fail verification"

            target.write_text(original)
            r = subprocess.run(
                [sys.executable, str(e / "verify_sigs.py")],
                capture_output=True, text=True, timeout=30, cwd=str(e),
            )
            assert r.returncode == 0, "Restored receipt should pass"
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_tampered_output_detected(self, evidence_dir):
        td = Path(tempfile.mkdtemp())
        try:
            shutil.copytree(evidence_dir, td / "e")
            e = td / "e"
            target = sorted((e / "receipts").glob("*.json"))[0]
            original = target.read_text()
            data = json.loads(original)
            if "output" not in data:
                pytest.skip("First receipt has no output display field")
            data["output"]["patient_id"] = "TAMPERED"
            target.write_text(json.dumps(data, indent=2))

            r = subprocess.run(
                [sys.executable, str(e / "verify_sigs.py")],
                capture_output=True, text=True, timeout=30, cwd=str(e),
            )
            assert r.returncode != 0, "Tampered output should fail hash cross-check"
        finally:
            shutil.rmtree(td, ignore_errors=True)


# ── Docs ──────────────────────────────────────────────────

class TestDocs:
    def test_readme_has_verify(self, evidence_dir):
        assert "VERIFY.sh" in (evidence_dir / "README.md").read_text()

    def test_readme_has_delegation_story(self, evidence_dir):
        r = (evidence_dir / "README.md").read_text()
        assert "delegate_to_agent" in r
        assert "child plan" in r.lower()

    def test_trust_model_honest(self, evidence_dir):
        t = (evidence_dir / "TRUST_MODEL.md").read_text()
        assert "output_hash" in t
        assert "reasoning_hash" in t
        assert "Does NOT Prove" in t
        assert "Delegation" in t

    def test_e015_has_gaps(self, evidence_dir):
        e = (evidence_dir / "E015_CONTROL_MAP.md").read_text()
        assert "output_hash" in e
        assert "reasoning_hash" in e
        assert "Honest Gaps" in e
