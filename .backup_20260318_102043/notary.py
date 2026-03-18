"""
AgentMint Notary — passive evidence signing for AI agent actions.

AgentMint is a notary, not a gatekeeper. It never touches API calls.
It observes what happened after the fact and produces cryptographically
signed, independently timestamped evidence receipts.

A receipt proves:
    - What action was taken (evidence hash, extracted fields)
    - Whether it was within policy (scope evaluation result)
    - When it was observed (RFC 3161 timestamp via FreeTSA)
    - Who approved the policy (chain to plan receipt)
    - Chain integrity (SHA-256 hash of previous receipt)

Verification requires only OpenSSL. No AgentMint software or account.

AIUC-1 control mapping:
    E015  Log model activity — receipt IS the signed log entry
    D003  Restrict unsafe calls — in_policy proves evaluation happened
    B001  Adversarial testing — evidence package proves controls tested
"""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import stat
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Final, Optional, Sequence

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from .timestamp import (
    TimestampResult,
    TimestampError,
    timestamp as ts_timestamp,
    fetch_ca_certs,
    verify as ts_verify,
)

__all__ = [
    "Notary",
    "PlanReceipt",
    "NotarisedReceipt",
    "EvidencePackage",
    "NotaryError",
    "PolicyEvaluation",
]


# ── Constants ──────────────────────────────────────────────

MAX_ACTION_LEN: Final[int] = 128
MAX_IDENTITY_LEN: Final[int] = 256
MAX_EVIDENCE_BYTES: Final[int] = 1024 * 1024
DEFAULT_TTL: Final[int] = 300
MAX_TTL: Final[int] = 3600
MIN_TTL: Final[int] = 1

AIUC_CONTROLS: Final[tuple[str, ...]] = ("E015", "D003", "B001")

# Ed25519 SPKI prefix (RFC 8410): 302a300506032b6570032100
_SPKI_PREFIX: Final[bytes] = bytes.fromhex("302a300506032b6570032100")


# ── Errors ─────────────────────────────────────────────────

class NotaryError(Exception):
    """Raised when notarisation fails. Message is always actionable."""
    pass


# ── Validation ─────────────────────────────────────────────

def _require_non_empty_string(value: str, name: str, max_len: int) -> str:
    if not isinstance(value, str):
        raise NotaryError(f"{name} must be a string, got {type(value).__name__}")
    stripped = value.strip()
    if not stripped:
        raise NotaryError(f"{name} must not be empty")
    if len(stripped) > max_len:
        raise NotaryError(f"{name} must be at most {max_len} characters, got {len(stripped)}")
    if any(ord(c) < 32 for c in stripped):
        raise NotaryError(f"{name} contains control characters")
    return stripped


def _require_string_list(value: Sequence[str] | None, name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, (list, tuple)):
        raise NotaryError(f"{name} must be a list, got {type(value).__name__}")
    result = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            raise NotaryError(f"{name}[{i}] must be a non-empty string")
        result.append(item.strip())
    return tuple(result)


def _require_evidence(evidence: Any) -> dict[str, Any]:
    if not isinstance(evidence, dict):
        raise NotaryError(f"evidence must be a dict, got {type(evidence).__name__}")
    try:
        raw = json.dumps(evidence, sort_keys=True).encode("utf-8")
    except (TypeError, ValueError) as e:
        raise NotaryError(f"evidence must be JSON-serializable: {e}") from e
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise NotaryError(
            f"serialized evidence is {len(raw):,} bytes, max is {MAX_EVIDENCE_BYTES:,}"
        )
    return evidence


def _clamp_ttl(ttl: int) -> int:
    return max(MIN_TTL, min(MAX_TTL, ttl))


# ── PEM helper ─────────────────────────────────────────────

def _public_key_pem(verify_key: VerifyKey) -> str:
    """Encode an Ed25519 public key as SPKI PEM (RFC 8410)."""
    der = _SPKI_PREFIX + bytes(verify_key)
    b64 = base64.b64encode(der).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + f"\n-----END PUBLIC KEY-----\n"


# ── Policy evaluation ─────────────────────────────────────

@dataclass(frozen=True)
class PolicyEvaluation:
    """Result of evaluating an action against a plan's policy rules."""
    in_policy: bool
    reason: str


def evaluate_policy(
    action: str,
    agent: str,
    plan_scope: Sequence[str],
    plan_checkpoints: Sequence[str],
    plan_delegates: Sequence[str],
    plan_expired: bool,
) -> PolicyEvaluation:
    """Evaluate whether an action is within policy. Pure function."""
    if plan_expired:
        return PolicyEvaluation(False, "plan expired")
    if plan_delegates and agent not in plan_delegates:
        return PolicyEvaluation(False, f"agent '{agent}' not in delegates_to")
    for pattern in plan_checkpoints:
        if _matches_pattern(action, pattern):
            return PolicyEvaluation(False, f"matched checkpoint {pattern}")
    for pattern in plan_scope:
        if _matches_pattern(action, pattern):
            return PolicyEvaluation(True, f"matched scope {pattern}")
    return PolicyEvaluation(False, "no scope pattern matched")


def _matches_pattern(action: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        return action == prefix or action.startswith(prefix + ":")
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return action == prefix or action.startswith(prefix)
    return action == pattern


# ── Signing ────────────────────────────────────────────────

def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(key: SigningKey, data: dict[str, Any]) -> str:
    return key.sign(_canonical_json(data)).signature.hex()


def _verify_signature(verify_key: VerifyKey, data: dict[str, Any], signature_hex: str) -> bool:
    try:
        verify_key.verify(_canonical_json(data), bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError):
        return False


# ── Data classes ───────────────────────────────────────────

@dataclass(frozen=True)
class PlanReceipt:
    """Signed plan defining what actions are allowed."""
    id: str
    user: str
    action: str
    scope: tuple[str, ...]
    checkpoints: tuple[str, ...]
    delegates_to: tuple[str, ...]
    issued_at: str
    expires_at: str
    signature: str

    @property
    def short_id(self) -> str:
        return self.id[:8]

    @property
    def is_expired(self) -> bool:
        return _utc_now() >= datetime.fromisoformat(self.expires_at)

    def signable_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": "plan",
            "user": self.user,
            "action": self.action,
            "scope": list(self.scope),
            "checkpoints": list(self.checkpoints),
            "delegates_to": list(self.delegates_to),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self.signable_dict()
        d["signature"] = self.signature
        return d


@dataclass(frozen=True)
class NotarisedReceipt:
    """Signed, timestamped evidence receipt for a single agent action."""
    id: str
    plan_id: str
    agent: str
    action: str
    in_policy: bool
    policy_reason: str
    evidence_hash: str
    evidence: dict[str, Any]
    observed_at: str
    signature: str
    # NEW: chain linking
    previous_receipt_hash: Optional[str] = None
    timestamp_result: Optional[TimestampResult] = None
    aiuc_controls: tuple[str, ...] = AIUC_CONTROLS

    @property
    def short_id(self) -> str:
        return self.id[:8]

    def signable_dict(self) -> dict[str, Any]:
        d = {
            "id": self.id,
            "type": "notarised_evidence",
            "plan_id": self.plan_id,
            "agent": self.agent,
            "action": self.action,
            "in_policy": self.in_policy,
            "policy_reason": self.policy_reason,
            "evidence_hash_sha512": self.evidence_hash,
            "evidence": self.evidence,
            "observed_at": self.observed_at,
            "aiuc_controls": list(self.aiuc_controls),
        }
        # Chain hash is included in signature if present
        if self.previous_receipt_hash is not None:
            d["previous_receipt_hash"] = self.previous_receipt_hash
        return d

    def to_dict(self) -> dict[str, Any]:
        d = self.signable_dict()
        d["signature"] = self.signature
        if self.timestamp_result:
            d["timestamp"] = {
                "tsa_url": self.timestamp_result.tsa_url,
                "digest_hex": self.timestamp_result.digest_hex,
            }
        return d

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False)


# ── Evidence package ───────────────────────────────────────

class EvidencePackage:
    """Collects receipts into a portable, verifiable zip.

    Contents:
        receipt_index.json    Table of contents
        plan.json             The signed plan receipt
        public_key.pem        Ed25519 public key (SPKI PEM, RFC 8410)
        receipts/{id}.json    Individual signed receipts
        receipts/{id}.tsq     Timestamp queries
        receipts/{id}.tsr     Timestamp responses
        freetsa_cacert.pem    CA certificate for verification
        freetsa_tsa.crt       TSA certificate for verification
        VERIFY.sh             Checks Ed25519 signatures + RFC 3161 timestamps
    """

    __slots__ = ("_plan", "_receipts", "_public_key_pem")

    def __init__(self, plan: PlanReceipt, public_key_pem: str = "") -> None:
        self._plan = plan
        self._receipts: list[NotarisedReceipt] = []
        self._public_key_pem = public_key_pem

    @property
    def plan(self) -> PlanReceipt:
        return self._plan

    @property
    def receipts(self) -> list[NotarisedReceipt]:
        return list(self._receipts)

    def add(self, receipt: NotarisedReceipt) -> None:
        self._receipts.append(receipt)

    def export(self, output_dir: Path, certs_dir: Optional[Path] = None) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = _utc_now().strftime("%Y%m%d_%H%M%S")
        zip_path = output_dir / f"agentmint_evidence_{ts}.zip"

        certs_dir = certs_dir or Path(tempfile.mkdtemp(prefix="agentmint_certs_"))
        ca_paths = self._fetch_certs_safe(certs_dir)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            self._write_plan(zf)
            self._write_receipts(zf)
            self._write_index(zf)
            self._write_public_key(zf)
            self._write_certs(zf, ca_paths)
            self._write_verify_script(zf)

        self._set_verify_executable(zip_path)
        return zip_path

    def _write_plan(self, zf: zipfile.ZipFile) -> None:
        zf.writestr("plan.json", json.dumps(self._plan.to_dict(), indent=2))

    def _write_receipts(self, zf: zipfile.ZipFile) -> None:
        for r in self._receipts:
            zf.writestr(f"receipts/{r.id}.json", r.to_json())
            if r.timestamp_result:
                zf.writestr(f"receipts/{r.id}.tsq", r.timestamp_result.tsq)
                zf.writestr(f"receipts/{r.id}.tsr", r.timestamp_result.tsr)

    def _write_index(self, zf: zipfile.ZipFile) -> None:
        in_count = sum(1 for r in self._receipts if r.in_policy)
        out_count = len(self._receipts) - in_count

        entries = []
        for r in self._receipts:
            has_ts = r.timestamp_result is not None
            entries.append({
                "receipt_id": r.id,
                "short_id": r.short_id,
                "action": r.action,
                "agent": r.agent,
                "in_policy": r.in_policy,
                "policy_reason": r.policy_reason,
                "observed_at": r.observed_at,
                "previous_receipt_hash": r.previous_receipt_hash,
                "tsr_file": f"receipts/{r.id}.tsr" if has_ts else None,
            })

        index = {
            "package_created": _utc_now().isoformat(),
            "plan_id": self._plan.id,
            "plan_user": self._plan.user,
            "total_receipts": len(self._receipts),
            "in_policy_count": in_count,
            "out_of_policy_count": out_count,
            "aiuc_controls": list(AIUC_CONTROLS),
            "receipts": entries,
        }
        zf.writestr("receipt_index.json", json.dumps(index, indent=2))

    def _write_public_key(self, zf: zipfile.ZipFile) -> None:
        if self._public_key_pem:
            zf.writestr("public_key.pem", self._public_key_pem)

    def _write_certs(
        self,
        zf: zipfile.ZipFile,
        ca_paths: Optional[tuple[Path, Path]],
    ) -> None:
        if not ca_paths:
            return
        cacert, tsa_cert = ca_paths
        zf.write(str(cacert), "freetsa_cacert.pem")
        zf.write(str(tsa_cert), "freetsa_tsa.crt")

    def _write_verify_script(self, zf: zipfile.ZipFile) -> None:
        zf.writestr("VERIFY.sh", _build_verify_script(self._receipts))

    @staticmethod
    def _fetch_certs_safe(certs_dir: Path) -> Optional[tuple[Path, Path]]:
        try:
            return fetch_ca_certs(certs_dir)
        except Exception:
            return None

    @staticmethod
    def _set_verify_executable(zip_path: Path) -> None:
        tmp_path = zip_path.with_suffix(".tmp.zip")
        with zipfile.ZipFile(zip_path, "r") as zin:
            with zipfile.ZipFile(tmp_path, "w", zipfile.ZIP_DEFLATED) as zout:
                for item in zin.infolist():
                    data = zin.read(item.filename)
                    if item.filename == "VERIFY.sh":
                        perms = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH
                        item.external_attr = perms << 16
                    zout.writestr(item, data)
        shutil.move(str(tmp_path), str(zip_path))


# ── Notary ─────────────────────────────────────────────────

class Notary:
    """Observe, evaluate, sign, timestamp.

    Usage:
        notary = Notary()
        plan = notary.create_plan(user="admin@co.com", ...)
        receipt = notary.notarise(action="tts:standard:abc", ...)
        zip_path = notary.export_evidence(Path("./evidence"))
    """

    __slots__ = ("_key", "_vk", "_package", "_last_receipt_hash")

    def __init__(self) -> None:
        self._key = SigningKey.generate()
        self._vk = self._key.verify_key
        self._package: Optional[EvidencePackage] = None
        self._last_receipt_hash: Optional[str] = None

    @property
    def verify_key(self) -> VerifyKey:
        return self._vk

    @property
    def verify_key_hex(self) -> str:
        return self._vk.encode(encoder=HexEncoder).decode("ascii")

    def create_plan(
        self,
        user: str,
        action: str,
        scope: list[str],
        checkpoints: list[str] | None = None,
        delegates_to: list[str] | None = None,
        ttl_seconds: int = DEFAULT_TTL,
    ) -> PlanReceipt:
        """Create a signed plan receipt. Resets the receipt chain."""
        user = _require_non_empty_string(user, "user", MAX_IDENTITY_LEN)
        action = _require_non_empty_string(action, "action", MAX_ACTION_LEN)
        scope_t = _require_string_list(scope, "scope")
        checkpoints_t = _require_string_list(checkpoints, "checkpoints")
        delegates_t = _require_string_list(delegates_to, "delegates_to")
        ttl = _clamp_ttl(ttl_seconds)

        now = _utc_now()
        plan_id = str(uuid.uuid4())
        issued_at = now.isoformat()
        expires_at = (now + timedelta(seconds=ttl)).isoformat()

        signable = {
            "id": plan_id,
            "type": "plan",
            "user": user,
            "action": action,
            "scope": list(scope_t),
            "checkpoints": list(checkpoints_t),
            "delegates_to": list(delegates_t),
            "issued_at": issued_at,
            "expires_at": expires_at,
        }
        signature = _sign(self._key, signable)

        plan = PlanReceipt(
            id=plan_id,
            user=user,
            action=action,
            scope=scope_t,
            checkpoints=checkpoints_t,
            delegates_to=delegates_t,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

        # Reset chain and create new evidence package with public key
        self._last_receipt_hash = None
        self._package = EvidencePackage(plan, _public_key_pem(self._vk))
        return plan

    def notarise(
        self,
        action: str,
        agent: str,
        plan: PlanReceipt,
        evidence: dict[str, Any],
        enable_timestamp: bool = True,
    ) -> NotarisedReceipt:
        """Observe an action and produce signed evidence.

        Each receipt includes the SHA-256 hash of the previous receipt's
        signed payload, forming a tamper-evident chain. Deleting or
        reordering any receipt breaks the chain.
        """
        action = _require_non_empty_string(action, "action", MAX_ACTION_LEN)
        agent = _require_non_empty_string(agent, "agent", MAX_IDENTITY_LEN)
        evidence = _require_evidence(evidence)

        evaluation = evaluate_policy(
            action=action,
            agent=agent,
            plan_scope=plan.scope,
            plan_checkpoints=plan.checkpoints,
            plan_delegates=plan.delegates_to,
            plan_expired=plan.is_expired,
        )

        evidence_bytes = _canonical_json(evidence)
        evidence_hash = hashlib.sha512(evidence_bytes).hexdigest()
        observed_at = _utc_now().isoformat()
        receipt_id = str(uuid.uuid4())

        signable = {
            "id": receipt_id,
            "type": "notarised_evidence",
            "plan_id": plan.id,
            "agent": agent,
            "action": action,
            "in_policy": evaluation.in_policy,
            "policy_reason": evaluation.reason,
            "evidence_hash_sha512": evidence_hash,
            "evidence": evidence,
            "observed_at": observed_at,
            "aiuc_controls": list(AIUC_CONTROLS),
        }

        # Chain linking: include hash of previous receipt if it exists
        prev_hash = self._last_receipt_hash
        if prev_hash is not None:
            signable["previous_receipt_hash"] = prev_hash

        signature = _sign(self._key, signable)

        ts_result = None
        if enable_timestamp:
            signed_payload = _canonical_json({**signable, "signature": signature})
            try:
                ts_result = ts_timestamp(signed_payload)
            except TimestampError as e:
                raise NotaryError(
                    f"timestamping failed: {e}\n"
                    f"  Receipt was signed but not anchored to wall-clock time.\n"
                    f"  Pass enable_timestamp=False to skip."
                ) from e

        receipt = NotarisedReceipt(
            id=receipt_id,
            plan_id=plan.id,
            agent=agent,
            action=action,
            in_policy=evaluation.in_policy,
            policy_reason=evaluation.reason,
            evidence_hash=evidence_hash,
            evidence=evidence,
            observed_at=observed_at,
            signature=signature,
            previous_receipt_hash=prev_hash,
            timestamp_result=ts_result,
        )

        # Update chain: hash this receipt's signed payload for next receipt
        signed_payload_bytes = _canonical_json({**signable, "signature": signature})
        self._last_receipt_hash = hashlib.sha256(signed_payload_bytes).hexdigest()

        if self._package and self._package.plan.id == plan.id:
            self._package.add(receipt)

        return receipt

    def verify_receipt(self, receipt: NotarisedReceipt) -> bool:
        return _verify_signature(self._vk, receipt.signable_dict(), receipt.signature)

    def verify_plan(self, plan: PlanReceipt) -> bool:
        return _verify_signature(self._vk, plan.signable_dict(), plan.signature)

    def export_evidence(
        self,
        output_dir: Path,
        certs_dir: Optional[Path] = None,
    ) -> Path:
        if not self._package:
            raise NotaryError("no plan created — call create_plan() first")
        return self._package.export(output_dir, certs_dir)


# ── VERIFY.sh ──────────────────────────────────────────────

def _build_verify_script(receipts: list[NotarisedReceipt]) -> str:
    """Generate a self-contained bash verification script.

    Checks both Ed25519 signatures (if jq + public_key.pem available)
    and RFC 3161 timestamps.
    """
    lines = [
        "#!/bin/bash",
        "#",
        "# AgentMint Evidence Verification",
        "#",
        "# Checks Ed25519 signatures and RFC 3161 timestamps.",
        "# Requires: openssl (any recent version)",
        "# Optional: jq (for Ed25519 signature verification)",
        "# Does NOT require AgentMint software.",
        "#",
        "",
        'set -euo pipefail',
        'SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"',
        'cd "$SCRIPT_DIR"',
        "",
        "VERIFIED=0",
        "FAILED=0",
        "FLAGGED=0",
        "SIG_OK=0",
        "SIG_FAIL=0",
        "SIG_SKIP=0",
        "TOTAL=0",
        "",
        "# Check for jq (needed for signature verification)",
        "HAS_JQ=0",
        "if command -v jq > /dev/null 2>&1; then",
        "  HAS_JQ=1",
        "fi",
        "",
        "# Check for public key",
        "HAS_PK=0",
        'if [ -f "public_key.pem" ]; then',
        "  HAS_PK=1",
        "fi",
        "",
    ]

    for r in receipts:
        rid = r.id
        has_ts = r.timestamp_result is not None

        lines.append(f'echo "── Receipt {r.short_id} ──"')
        lines.append(f'echo "  Action:    {r.action}"')
        lines.append(f'echo "  Agent:     {r.agent}"')
        lines.append(f'echo "  In Policy: {r.in_policy}"')
        lines.append(f'echo "  Observed:  {r.observed_at}"')

        if not r.in_policy:
            reason_escaped = r.policy_reason.replace('"', '\\"').replace("'", "'\\''")
            lines.append(f'echo "  ⚠ FLAGGED: {reason_escaped}"')
            lines.append("FLAGGED=$((FLAGGED + 1))")

        # Ed25519 signature check
        lines.append("")
        lines.append("# Ed25519 signature verification")
        lines.append('if [ "$HAS_JQ" -eq 1 ] && [ "$HAS_PK" -eq 1 ]; then')
        lines.append(f'  SIG_HEX=$(jq -r ".signature" "receipts/{rid}.json")')
        lines.append(f'  # Extract signable fields (everything except signature and timestamp)')
        lines.append(f'  jq -cS "del(.signature, .timestamp)" "receipts/{rid}.json" > "/tmp/agentmint_verify_{rid}.bin"')
        lines.append(f'  echo -n "$SIG_HEX" | xxd -r -p > "/tmp/agentmint_sig_{rid}.bin"')
        lines.append(f'  if openssl pkeyutl -verify -pubin -inkey public_key.pem \\')
        lines.append(f'      -sigfile "/tmp/agentmint_sig_{rid}.bin" \\')
        lines.append(f'      -in "/tmp/agentmint_verify_{rid}.bin" \\')
        lines.append(f'      -rawin > /dev/null 2>&1; then')
        lines.append(f'    echo "  Signature: ✓ Ed25519 verified"')
        lines.append(f'    SIG_OK=$((SIG_OK + 1))')
        lines.append(f'  else')
        lines.append(f'    echo "  Signature: ✗ Ed25519 FAILED"')
        lines.append(f'    SIG_FAIL=$((SIG_FAIL + 1))')
        lines.append(f'  fi')
        lines.append(f'  rm -f "/tmp/agentmint_verify_{rid}.bin" "/tmp/agentmint_sig_{rid}.bin"')
        lines.append(f'else')
        lines.append(f'  echo "  Signature: (skipped — install jq for Ed25519 verification)"')
        lines.append(f'  SIG_SKIP=$((SIG_SKIP + 1))')
        lines.append(f'fi')

        # RFC 3161 timestamp check
        if has_ts:
            lines.append(f'if openssl ts -verify \\')
            lines.append(f'    -in "receipts/{rid}.tsr" \\')
            lines.append(f'    -queryfile "receipts/{rid}.tsq" \\')
            lines.append(f'    -CAfile "freetsa_cacert.pem" \\')
            lines.append(f'    -untrusted "freetsa_tsa.crt" \\')
            lines.append(f'    > /dev/null 2>&1; then')
            lines.append(f'  echo "  Timestamp: ✓ RFC 3161 verified"')
            lines.append(f'  VERIFIED=$((VERIFIED + 1))')
            lines.append(f'else')
            lines.append(f'  echo "  Timestamp: ✗ FAILED"')
            lines.append(f'  FAILED=$((FAILED + 1))')
            lines.append(f'fi')
        else:
            lines.append('echo "  Timestamp: (not requested)"')

        lines.append("TOTAL=$((TOTAL + 1))")
        lines.append('echo ""')
        lines.append("")

    lines.extend([
        'echo "════════════════════════════════════════"',
        'echo "  AgentMint Evidence Package"',
        'echo "  Receipts:            $TOTAL"',
        'echo "  Timestamps verified: $VERIFIED / $TOTAL"',
        'echo "  Timestamp failures:  $FAILED"',
        'echo "  Signatures verified: $SIG_OK"',
        'echo "  Signature failures:  $SIG_FAIL"',
        'echo "  Signatures skipped:  $SIG_SKIP"',
        'echo "  Out-of-policy:       $FLAGGED"',
        'echo "  Verified at:         $(date -u)"',
        'echo "════════════════════════════════════════"',
        "",
        'if [ "$FAILED" -gt 0 ] || [ "$SIG_FAIL" -gt 0 ]; then',
        '  exit 1',
        'fi',
    ])

    return "\n".join(lines) + "\n"


# ── Utilities ──────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
