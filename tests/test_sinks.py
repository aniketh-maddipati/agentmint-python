"""Tests for agentmint.sinks."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from agentmint.sinks import FileSink, Sink


@dataclass(frozen=True)
class FakeReceipt:
    """Minimal stand-in for NotarisedReceipt."""

    id: str = "receipt-001"
    plan_id: str = "plan-001"
    agent: str = "test-agent"
    action: str = "read:public:file.txt"
    in_policy: bool = True
    policy_reason: str = "scope_match"
    evidence_hash: str = "abc123"
    signature: str = "deadbeef" * 8
    key_id: str = "key-001"
    observed_at: str = "2026-03-23T12:00:00Z"


class TestFileSinkCreation:
    """FileSink creates the file and parent directories."""

    def test_creates_file_on_init(self, tmp_path: Path) -> None:
        path = tmp_path / "logs" / "audit.jsonl"
        sink = FileSink(path)
        sink.close()
        assert path.exists()


class TestJsonlFormat:
    """Each emit writes exactly one JSON line."""

    def test_single_emit_writes_one_line(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = FileSink(path)
        sink.emit(FakeReceipt())
        sink.flush()
        sink.close()
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert isinstance(record, dict)


class TestAppendMode:
    """Multiple emits append — no overwriting."""

    def test_two_emits_produce_two_lines(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = FileSink(path)
        sink.emit(FakeReceipt(id="r1"))
        sink.emit(FakeReceipt(id="r2"))
        sink.flush()
        sink.close()
        lines = path.read_text().strip().split("\n")
        assert len(lines) == 2


class TestSiemFields:
    """SIEM-compatible fields are present in output."""

    def test_required_fields_present(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = FileSink(path)
        sink.emit(FakeReceipt())
        sink.flush()
        sink.close()
        record = json.loads(path.read_text().strip())
        required = {
            "timestamp",
            "observed_at",
            "severity",
            "source",
            "receipt_id",
            "plan_id",
            "agent",
            "action",
            "in_policy",
            "policy_reason",
            "evidence_hash",
            "signature",
            "key_id",
        }
        assert required.issubset(record.keys())
        assert record["source"] == "agentmint"
        assert record["severity"] == "info"

    def test_blocked_receipt_has_warn_severity(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = FileSink(path)
        sink.emit(FakeReceipt(in_policy=False))
        sink.flush()
        sink.close()
        record = json.loads(path.read_text().strip())
        assert record["severity"] == "warn"


class TestProtocolCompliance:
    """FileSink satisfies the Sink protocol."""

    def test_filesink_is_a_sink(self, tmp_path: Path) -> None:
        path = tmp_path / "audit.jsonl"
        sink = FileSink(path)
        assert isinstance(sink, Sink)
        sink.close()
