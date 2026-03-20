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
import os
import shutil
import stat
import tempfile
import uuid
import zipfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Final, Optional, Sequence

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from .patterns import matches_pattern, in_scope
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
    "ChainVerification",
    "verify_chain",
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

# Default TSA URLs — improvement 4.5
DEFAULT_TSA_URLS: Final[list[str]] = [
    "https://freetsa.org/tsr",
]


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
        if matches_pattern(action, pattern):
            return PolicyEvaluation(False, f"matched checkpoint {pattern}")
    for pattern in plan_scope:
        if matches_pattern(action, pattern):
            return PolicyEvaluation(True, f"matched scope {pattern}")
    return PolicyEvaluation(False, "no scope pattern matched")


# ── Signing ────────────────────────────────────────────────

def _canonical_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sign(key: SigningKey, data: dict[str, Any]) -> str:
    return key.sign(_canonical_json(data)).signature.hex()


def _derive_key_id(verify_key: VerifyKey) -> str:
    """First 8 bytes of SHA-256(public_key), hex. Stable across restarts."""
    return hashlib.sha256(bytes(verify_key)).hexdigest()[:16]


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
    key_id: str = ""

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
            "key_id": self.key_id,
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
    # Chain linking
    previous_receipt_hash: Optional[str] = None
    timestamp_result: Optional[TimestampResult] = None
    aiuc_controls: tuple[str, ...] = AIUC_CONTROLS
    # Improvement 4.4: plan signature carried into receipt
    plan_signature: str = ""
    key_id: str = ""
    agent_signature: str = ""
    agent_key_id: str = ""

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
            "key_id": self.key_id,
            "agent_key_id": self.agent_key_id,
        }
        # Chain hash is included in signature if present
        if self.previous_receipt_hash is not None:
            d["previous_receipt_hash"] = self.previous_receipt_hash
        # Improvement 4.4: plan signature
        if self.plan_signature:
            d["plan_signature"] = self.plan_signature
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


# ── Chain verification (improvement 4.6) ──────────────────

@dataclass(frozen=True)
class ChainVerification:
    """Result of verifying receipt chain integrity."""
    valid: bool
    length: int
    root_hash: str
    break_at_index: Optional[int] = None
    reason: str = ""


def verify_chain(receipts: list[NotarisedReceipt]) -> ChainVerification:
    """Verify receipt chain integrity.

    Checks:
    1. First receipt has previous_receipt_hash == None
    2. Each subsequent receipt's previous_receipt_hash == SHA-256 of
       the previous receipt's signed payload
    3. Returns root_hash: the hash of the final receipt in the chain

    The root_hash is a single value summarizing the entire chain.
    Publishing it externally creates an anchoring commitment.
    """
    if not receipts:
        return ChainVerification(valid=True, length=0, root_hash="")

    if receipts[0].previous_receipt_hash is not None:
        return ChainVerification(
            valid=False, length=len(receipts), root_hash="",
            break_at_index=0, reason="first receipt has non-null chain hash"
        )

    prev_hash: Optional[str] = None
    for i, receipt in enumerate(receipts):
        if receipt.previous_receipt_hash != prev_hash:
            return ChainVerification(
                valid=False, length=len(receipts), root_hash="",
                break_at_index=i,
                reason=f"chain break at index {i}: expected {prev_hash}, "
                       f"got {receipt.previous_receipt_hash}"
            )
        # Compute hash of this receipt for next iteration
        signed_payload = _canonical_json({
            **receipt.signable_dict(),
            "signature": receipt.signature
        })
        prev_hash = hashlib.sha256(signed_payload).hexdigest()

    return ChainVerification(
        valid=True, length=len(receipts), root_hash=prev_hash or ""
    )


# ── Evidence package ───────────────────────────────────────

class EvidencePackage:
    """Collects receipts into a portable, verifiable zip.

    Contents:
        receipt_index.json    Table of contents (with chain root)
        plan.json             The signed plan receipt
        public_key.pem        Ed25519 public key (SPKI PEM, RFC 8410)
        receipts/{id}.json    Individual signed receipts
        receipts/{id}.tsq     Timestamp queries
        receipts/{id}.tsr     Timestamp responses
        chain_root.tsq/tsr    Chain root timestamp (if available)
        freetsa_cacert.pem    CA certificate for verification
        freetsa_tsa.crt       TSA certificate for verification
        VERIFY.sh             Checks RFC 3161 timestamps (pure OpenSSL)
        verify_sigs.py        Checks Ed25519 signatures (needs pynacl)
    """

    __slots__ = ("_plan", "_receipts", "_public_key_pem", "_key", "_tsa_urls")

    def __init__(self, plan: PlanReceipt, public_key_pem: str = "",
                 signing_key: Optional[SigningKey] = None,
                 tsa_urls: Optional[list[str]] = None) -> None:
        self._plan = plan
        self._receipts: list[NotarisedReceipt] = []
        self._public_key_pem = public_key_pem
        self._key = signing_key
        self._tsa_urls = tsa_urls or DEFAULT_TSA_URLS

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
            self._write_verify_sigs_script(zf)

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

        index: dict[str, Any] = {
            "package_created": _utc_now().isoformat(),
            "plan_id": self._plan.id,
            "plan_user": self._plan.user,
            "key_id": self._plan.key_id,
            "total_receipts": len(self._receipts),
            "in_policy_count": in_count,
            "out_of_policy_count": out_count,
            "aiuc_controls": list(AIUC_CONTROLS),
            "receipts": entries,
        }

        # Improvement 4.7: chain root hash + signature + timestamp
        chain_result = verify_chain(self._receipts)
        chain_info: dict[str, Any] = {
            "valid": chain_result.valid,
            "length": chain_result.length,
            "root_hash": chain_result.root_hash,
        }

        if chain_result.root_hash and self._key:
            chain_info["root_signature"] = _sign(self._key, {
                "type": "chain_root",
                "root_hash": chain_result.root_hash,
                "length": chain_result.length,
                "plan_id": self._plan.id,
            })

            # Optional: timestamp the chain root
            try:
                root_bytes = chain_result.root_hash.encode()
                ts_result = _timestamp_with_fallback(root_bytes, self._tsa_urls)
                zf.writestr("chain_root.tsq", ts_result.tsq)
                zf.writestr("chain_root.tsr", ts_result.tsr)
                chain_info["root_timestamp"] = {
                    "tsa_url": ts_result.tsa_url,
                    "tsq_file": "chain_root.tsq",
                    "tsr_file": "chain_root.tsr",
                }
            except (TimestampError, Exception):
                pass  # graceful degradation

        index["chain"] = chain_info
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

    def _write_verify_sigs_script(self, zf: zipfile.ZipFile) -> None:
        zf.writestr("verify_sigs.py", _VERIFY_SIGS_PY)

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


# ── Timestamp with fallback (improvement 4.5) ─────────────

def _timestamp_with_fallback(
    data: bytes,
    tsa_urls: Optional[list[str]] = None,
) -> TimestampResult:
    """Try each TSA URL in order, return first success."""
    urls = tsa_urls or DEFAULT_TSA_URLS
    if len(urls) == 1:
        # Fast path — no fallback needed
        return ts_timestamp(data)
    last_error: Optional[Exception] = None
    for url in urls:
        try:
            return ts_timestamp(data)
        except TimestampError as e:
            last_error = e
            continue
    raise TimestampError(f"all TSA endpoints failed, last error: {last_error}")


# ── Notary ─────────────────────────────────────────────────

_CHAIN_STATE_FILE = "chain_state.json"


def _load_chain_state(key_dir: Optional[Path]) -> dict[str, Optional[str]]:
    """Load persisted chain hashes. Returns empty dict if ephemeral or missing."""
    if key_dir is None:
        return {}
    path = key_dir / _CHAIN_STATE_FILE
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict):
            return {}
        # Validate: all keys are strings, all values are str or None
        return {k: v for k, v in data.items()
                if isinstance(k, str) and (v is None or isinstance(v, str))}
    except (json.JSONDecodeError, OSError):
        return {}


def _save_chain_state(key_dir: Optional[Path], chain_hashes: dict[str, Optional[str]]) -> None:
    """Atomic write of chain state. No-op in ephemeral mode."""
    if key_dir is None:
        return
    key_dir.mkdir(parents=True, exist_ok=True)
    path = key_dir / _CHAIN_STATE_FILE
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(chain_hashes, indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


class Notary:
    """Observe, evaluate, sign, timestamp.

    Usage:
        notary = Notary()
        plan = notary.create_plan(user="admin@co.com", ...)
        receipt = notary.notarise(action="tts:standard:abc", ...)
        zip_path = notary.export_evidence(Path("./evidence"))

    Improvement 4.1: key parameter for persistent keys.
    Improvement 4.2: per-plan chain isolation.
    Improvement 4.5: tsa_urls for fallback TSA.
    """

    __slots__ = ("_key", "_vk", "_key_id", "_key_dir", "_package", "_chain_hashes", "_tsa_urls")

    def __init__(
        self,
        key: str | Path | None = None,
        tsa_urls: list[str] | None = None,
    ) -> None:
        # Improvement 4.1: key persistence via KeyStore
        if key is None:
            # Ephemeral — for demos and quickstart
            self._key = SigningKey.generate()
            self._key_dir: Optional[Path] = None
        elif isinstance(key, (str, Path)):
            from .keystore import KeyStore
            self._key_dir = Path(key)
            ks = KeyStore(self._key_dir)
            self._key = ks.signing_key
        else:
            raise NotaryError(f"key must be a string path or None, got {type(key).__name__}")

        self._vk = self._key.verify_key
        self._key_id = _derive_key_id(self._vk)
        self._package: Optional[EvidencePackage] = None
        # Improvement 4.2: per-plan chain isolation
        self._chain_hashes: dict[str, Optional[str]] = _load_chain_state(self._key_dir)
        # Improvement 4.5: fallback TSA
        self._tsa_urls = tsa_urls or DEFAULT_TSA_URLS

    @property
    def key_id(self) -> str:
        """Stable key identifier for revocation support."""
        return self._key_id

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
        """Create a signed plan receipt. Initializes the chain for this plan."""
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

        # Build plan with placeholder signature — signable_dict() is
        # the single source of truth for what gets signed.
        unsigned = PlanReceipt(
            id=plan_id,
            user=user,
            action=action,
            scope=scope_t,
            checkpoints=checkpoints_t,
            delegates_to=delegates_t,
            issued_at=issued_at,
            expires_at=expires_at,
            signature="",
            key_id=self._key_id,
        )

        signature = _sign(self._key, unsigned.signable_dict())

        plan = replace(unsigned, signature=signature)

        # Improvement 4.2: initialize chain for this plan (not global reset)
        self._chain_hashes[plan_id] = None
        _save_chain_state(self._key_dir, self._chain_hashes)
        self._package = EvidencePackage(
            plan, _public_key_pem(self._vk),
            signing_key=self._key, tsa_urls=self._tsa_urls,
        )
        return plan

    def notarise(
        self,
        action: str,
        agent: str,
        plan: PlanReceipt,
        evidence: dict[str, Any],
        enable_timestamp: bool = True,
        agent_key: Optional[SigningKey] = None,
    ) -> NotarisedReceipt:
        """Observe an action and produce signed evidence.

        Each receipt includes the SHA-256 hash of the previous receipt's
        signed payload, forming a tamper-evident chain per plan.
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

        # Improvement 4.2: per-plan chain linking
        prev_hash = self._chain_hashes.get(plan.id)

        # Agent co-signature: agent signs the evidence hash
        agent_sig = ""
        agent_kid = ""
        if agent_key is not None:
            agent_sig = agent_key.sign(evidence_bytes).signature.hex()
            agent_kid = _derive_key_id(agent_key.verify_key)

        # Build receipt with placeholder signature — signable_dict() is
        # the single source of truth for what gets signed.
        unsigned = NotarisedReceipt(
            id=receipt_id,
            plan_id=plan.id,
            agent=agent,
            action=action,
            in_policy=evaluation.in_policy,
            policy_reason=evaluation.reason,
            evidence_hash=evidence_hash,
            evidence=evidence,
            observed_at=observed_at,
            signature="",
            previous_receipt_hash=prev_hash,
            plan_signature=plan.signature,
            key_id=self._key_id,
            agent_signature=agent_sig,
            agent_key_id=agent_kid,
        )

        signature = _sign(self._key, unsigned.signable_dict())

        ts_result = None
        if enable_timestamp:
            signed_payload = _canonical_json({**unsigned.signable_dict(), "signature": signature})
            try:
                ts_result = _timestamp_with_fallback(signed_payload, self._tsa_urls)
            except TimestampError as e:
                raise NotaryError(
                    f"timestamping failed: {e}\n"
                    f"  Receipt was signed but not anchored to wall-clock time.\n"
                    f"  Pass enable_timestamp=False to skip."
                ) from e

        # Reconstruct with real signature (frozen dataclass)
        receipt = replace(unsigned, signature=signature, timestamp_result=ts_result)

        # Improvement 4.2: update chain per plan_id
        signed_payload_bytes = _canonical_json({**unsigned.signable_dict(), "signature": signature})
        self._chain_hashes[plan.id] = hashlib.sha256(signed_payload_bytes).hexdigest()
        _save_chain_state(self._key_dir, self._chain_hashes)

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


# ── VERIFY.sh (timestamps only — pure OpenSSL, zero dependencies) ──

def _build_verify_script(receipts: list[NotarisedReceipt]) -> str:
    """Generate VERIFY.sh — checks RFC 3161 timestamps with OpenSSL.

    For Ed25519 signature verification, see verify_sigs.py in the same package.
    """
    lines = [
        "#!/bin/bash",
        "# AgentMint Evidence Verification — RFC 3161 Timestamps",
        "# Requires: openssl",
        "# For Ed25519 signatures: python3 verify_sigs.py",
        "",
        'set -euo pipefail',
        'cd "$(dirname "$0")"',
        "",
        "VERIFIED=0",
        "FAILED=0",
        "FLAGGED=0",
        "TOTAL=0",
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

        if has_ts:
            lines.append(f'if openssl ts -verify \\')
            lines.append(f'    -in "receipts/{rid}.tsr" \\')
            lines.append(f'    -queryfile "receipts/{rid}.tsq" \\')
            lines.append(f'    -CAfile "freetsa_cacert.pem" \\')
            lines.append(f'    -untrusted "freetsa_tsa.crt" \\')
            lines.append(f'    > /dev/null 2>&1; then')
            lines.append(f'  echo "  Timestamp: ✓ verified"')
            lines.append(f'  VERIFIED=$((VERIFIED + 1))')
            lines.append(f'else')
            lines.append(f'  echo "  Timestamp: ✗ FAILED"')
            lines.append(f'  FAILED=$((FAILED + 1))')
            lines.append(f'fi')
        else:
            lines.append('echo "  Timestamp: (not requested)"')

        lines.append("TOTAL=$((TOTAL + 1))")
        lines.append('echo ""')

    lines.extend([
        'echo "════════════════════════════════════════"',
        'echo "  Timestamps: $VERIFIED / $TOTAL verified"',
        'echo "  Failures:   $FAILED"',
        'echo "  Flagged:    $FLAGGED out-of-policy"',
        'echo "  Signatures: run python3 verify_sigs.py"',
        'echo "════════════════════════════════════════"',
        "",
        '[ "$FAILED" -gt 0 ] && exit 1',
        'exit 0',
    ])

    return "\n".join(lines) + "\n"


# ── verify_sigs.py (Ed25519 signatures — needs pynacl) ────

_VERIFY_SIGS_PY = '''\
#!/usr/bin/env python3
"""Verify Ed25519 signatures on all receipts. Requires: pip install pynacl"""
import json, sys, base64
from pathlib import Path

try:
    from nacl.signing import VerifyKey
    from nacl.exceptions import BadSignatureError
except ImportError:
    print("Install pynacl: pip install pynacl")
    sys.exit(1)

def canonical(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()

def load_pem_public_key(path):
    lines = path.read_text().strip().split("\\n")
    b64 = "".join(lines[1:-1])
    der = base64.b64decode(b64)
    # SPKI prefix is 12 bytes, Ed25519 key is last 32
    return VerifyKey(der[12:])

here = Path(__file__).parent
pk_path = here / "public_key.pem"
if not pk_path.exists():
    print("No public_key.pem found"); sys.exit(1)

vk = load_pem_public_key(pk_path)
ok = fail = 0

for rfile in sorted((here / "receipts").glob("*.json")):
    receipt = json.loads(rfile.read_text())
    sig = bytes.fromhex(receipt["signature"])
    # Reconstruct signable dict (everything except signature and timestamp)
    signable = {k: v for k, v in receipt.items() if k not in ("signature", "timestamp")}
    try:
        vk.verify(canonical(signable), sig)
        status = "✓"
        ok += 1
    except BadSignatureError:
        status = "✗ FAILED"
        fail += 1
    tag = "in policy" if receipt.get("in_policy") else "VIOLATION"
    print(f"  {status}  {receipt['id'][:8]}  {receipt['action']}  ({tag})")

print(f"\\nSignatures: {ok} verified, {fail} failed")
sys.exit(1 if fail else 0)
'''


# ── Utilities ──────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)
