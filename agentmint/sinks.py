"""Audit log sinks for notarised receipts.

Sinks receive every NotarisedReceipt after signing and persist them
in a format suitable for downstream analysis or SIEM ingestion.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Sink(Protocol):
    """Protocol for receipt sinks."""

    def emit(self, receipt: Any) -> None:
        """Persist a single receipt."""
        ...

    def flush(self) -> None:
        """Flush any buffered data."""
        ...

    def close(self) -> None:
        """Release resources."""
        ...


class FileSink:
    """Append-only JSONL file sink with SIEM-compatible field names.

    Each line is a self-contained JSON object with standardised fields:
    timestamp, severity, source, agent, action, in_policy, policy_reason,
    receipt_id, plan_id, evidence_hash, signature (first 32 hex chars).
    """

    __slots__ = ("_path", "_handle")

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = open(self._path, "a", encoding="utf-8")  # noqa: SIM115

    def emit(self, receipt: Any) -> None:
        """Write one JSONL line from a NotarisedReceipt."""
        record = _to_siem_record(receipt)
        self._handle.write(json.dumps(record, separators=(",", ":")) + "\n")

    def flush(self) -> None:
        """Flush underlying file handle."""
        self._handle.flush()

    def close(self) -> None:
        """Close the file handle."""
        self._handle.close()


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _to_siem_record(receipt: Any) -> dict[str, Any]:
    """Map a NotarisedReceipt to SIEM-friendly flat dict."""
    sig = getattr(receipt, "signature", "") or ""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "observed_at": getattr(receipt, "observed_at", ""),
        "severity": _severity(receipt),
        "source": "agentmint",
        "receipt_id": getattr(receipt, "id", ""),
        "plan_id": getattr(receipt, "plan_id", ""),
        "agent": getattr(receipt, "agent", ""),
        "action": getattr(receipt, "action", ""),
        "in_policy": getattr(receipt, "in_policy", False),
        "policy_reason": getattr(receipt, "policy_reason", ""),
        "evidence_hash": getattr(receipt, "evidence_hash", ""),
        "signature": sig[:32] if sig else "",
        "key_id": getattr(receipt, "key_id", ""),
    }


def _severity(receipt: Any) -> str:
    """Derive SIEM severity from receipt fields."""
    if not getattr(receipt, "in_policy", True):
        return "warn"
    return "info"
