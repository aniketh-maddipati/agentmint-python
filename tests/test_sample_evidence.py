"""Tests for the committed sample evidence directory."""

import json
import os
from pathlib import Path

import pytest

SAMPLE_DIR = Path(__file__).parent.parent / "examples" / "sample_evidence"


class TestSampleEvidenceExists:
    """Verify all expected files are committed."""

    def test_verify_script_exists(self):
        assert (SAMPLE_DIR / "VERIFY.sh").exists()

    def test_plan_exists(self):
        assert (SAMPLE_DIR / "plan.json").exists()

    def test_index_exists(self):
        assert (SAMPLE_DIR / "receipt_index.json").exists()

    def test_receipts_directory_exists(self):
        assert (SAMPLE_DIR / "receipts").is_dir()

    def test_readme_exists(self):
        assert (SAMPLE_DIR / "README.md").exists()


class TestSampleEvidenceContent:
    """Verify the content is consistent and well-formed."""

    def test_index_has_four_receipts(self):
        index = json.loads((SAMPLE_DIR / "receipt_index.json").read_text())
        assert index["total_receipts"] == 4

    def test_index_counts_match(self):
        index = json.loads((SAMPLE_DIR / "receipt_index.json").read_text())
        assert index["in_policy_count"] == 2
        assert index["out_of_policy_count"] == 2

    def test_each_receipt_has_json(self):
        index = json.loads((SAMPLE_DIR / "receipt_index.json").read_text())
        for entry in index["receipts"]:
            receipt_path = SAMPLE_DIR / "receipts" / f"{entry['receipt_id']}.json"
            assert receipt_path.exists(), f"Missing: {receipt_path}"

    def test_each_receipt_has_tsr(self):
        index = json.loads((SAMPLE_DIR / "receipt_index.json").read_text())
        for entry in index["receipts"]:
            if entry.get("tsr_file"):
                tsr_path = SAMPLE_DIR / entry["tsr_file"]
                assert tsr_path.exists(), f"Missing: {tsr_path}"

    def test_plan_has_required_fields(self):
        plan = json.loads((SAMPLE_DIR / "plan.json").read_text())
        for field in ("id", "user", "action", "scope", "signature"):
            assert field in plan, f"Plan missing field: {field}"

    def test_receipt_json_has_required_fields(self):
        receipts_dir = SAMPLE_DIR / "receipts"
        for f in receipts_dir.glob("*.json"):
            receipt = json.loads(f.read_text())
            for field in ("id", "action", "in_policy", "signature", "evidence_hash_sha512"):
                assert field in receipt, f"{f.name} missing field: {field}"

    def test_verify_script_is_executable(self):
        verify_path = SAMPLE_DIR / "VERIFY.sh"
        assert os.access(verify_path, os.X_OK), "VERIFY.sh is not executable"

    def test_certs_present(self):
        index = json.loads((SAMPLE_DIR / "receipt_index.json").read_text())
        has_timestamps = any(e.get("tsr_file") for e in index["receipts"])
        if has_timestamps:
            certs = list(SAMPLE_DIR.glob("*.pem")) + list(SAMPLE_DIR.glob("*.crt"))
            assert len(certs) >= 1, "Timestamps present but no certificate files found"