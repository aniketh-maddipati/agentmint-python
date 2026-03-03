"""AgentMint Core - Ed25519 signed authorization receipts."""

from __future__ import annotations
import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import Optional

from nacl.signing import SigningKey
from nacl.exceptions import BadSignatureError

from .errors import ValidationError
from .types import DelegationStatus, DelegationResult
from . import console

# Constants (match Rust)
MAX_TTL = 300
MIN_TTL = 1
DEFAULT_TTL = 60
MAX_SUB_LEN = 256
MAX_ACTION_LEN = 64
MAX_JTI_CAPACITY = 10_000
ALLOWED_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_:-")


def _validate_sub(sub: str) -> None:
    if not sub or len(sub) > MAX_SUB_LEN:
        raise ValidationError("sub", f"must be 1-{MAX_SUB_LEN} characters")
    if any(ord(c) < 32 for c in sub):
        raise ValidationError("sub", "contains control characters")


def _validate_action(action: str) -> None:
    if not action or len(action) > MAX_ACTION_LEN:
        raise ValidationError("action", f"must be 1-{MAX_ACTION_LEN} characters")
    if not all(c in ALLOWED_CHARS for c in action):
        raise ValidationError("action", "must be alphanumeric, underscore, colon, or hyphen")


def _clamp_ttl(ttl: int) -> int:
    return max(MIN_TTL, min(MAX_TTL, ttl))


def _matches_pattern(action: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith(":*"):
        prefix = pattern[:-2]
        return action == prefix or action.startswith(f"{prefix}:")
    return action == pattern


def _in_scope(action: str, scope: list[str]) -> bool:
    return any(_matches_pattern(action, p) for p in scope)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Receipt:
    """A signed authorization receipt."""
    id: str
    sub: str
    action: str
    issued_at: str
    expires_at: str
    signature: str
    receipt_type: Optional[str] = None
    scope: Optional[list[str]] = None
    delegates_to: Optional[list[str]] = None
    requires_checkpoint: Optional[list[str]] = None
    max_delegation_depth: Optional[int] = None
    parent_id: Optional[str] = None
    original_approver: Optional[str] = None
    depth: Optional[int] = None

    @property
    def is_expired(self) -> bool:
        return _utc_now() >= datetime.fromisoformat(self.expires_at)

    @property
    def is_plan(self) -> bool:
        return self.receipt_type == "plan"

    @property
    def is_delegated(self) -> bool:
        return self.receipt_type == "delegated"

    @property
    def short_id(self) -> str:
        return self.id[:8]

    def to_dict(self) -> dict:
        d = {
            "jti": self.id,
            "sub": self.sub,
            "action": self.action,
            "iat": self.issued_at,
            "exp": self.expires_at,
        }
        optionals = [
            ("receipt_type", self.receipt_type),
            ("scope", self.scope),
            ("delegates_to", self.delegates_to),
            ("requires_checkpoint", self.requires_checkpoint),
            ("max_delegation_depth", self.max_delegation_depth),
            ("parent_jti", self.parent_id),
            ("original_approver", self.original_approver),
            ("depth", self.depth),
        ]
        for key, val in optionals:
            if val is not None:
                d[key] = val
        return d

    def __repr__(self) -> str:
        return f"Receipt({self.short_id}, {self.sub}, {self.action})"


class JtiStore:
    """Single-use JTI tracking for replay protection."""
    __slots__ = ("_used", "_capacity")

    def __init__(self, capacity: int = MAX_JTI_CAPACITY):
        self._used: dict[str, float] = {}
        self._capacity = capacity

    def check_and_mark(self, jti: str, expires_at: float) -> bool:
        self._cleanup()
        if len(self._used) >= self._capacity:
            raise RuntimeError("JTI store at capacity")
        if jti in self._used:
            return False
        self._used[jti] = expires_at
        return True

    def _cleanup(self) -> None:
        now = _utc_now().timestamp()
        self._used = {k: v for k, v in self._used.items() if v > now}

    def __len__(self) -> int:
        return len(self._used)


class AgentMint:
    """
    Issue and verify authorization receipts.

    Example:
        mint = AgentMint()
        receipt = mint.issue("deploy", "alice@co.com")
        assert mint.verify(receipt)
    """
    __slots__ = ("_key", "_vk", "_receipts", "_jti", "_quiet")

    def __init__(self, quiet: bool = False):
        self._key = SigningKey.generate()
        self._vk = self._key.verify_key
        self._receipts: dict[str, Receipt] = {}
        self._jti = JtiStore()
        self._quiet = quiet

    def _sign(self, receipt: Receipt) -> str:
        payload = json.dumps(receipt.to_dict(), sort_keys=True).encode()
        return self._key.sign(payload).signature.hex()

    def _make_receipt(self, sub: str, action: str, ttl: int, **kwargs) -> Receipt:
        now = _utc_now()
        exp = now + timedelta(seconds=_clamp_ttl(ttl))
        receipt = Receipt(
            id=str(uuid.uuid4()),
            sub=sub,
            action=action,
            issued_at=now.isoformat(),
            expires_at=exp.isoformat(),
            signature="",
            **kwargs,
        )
        receipt.signature = self._sign(receipt)
        self._receipts[receipt.id] = receipt
        if not self._quiet:
            console.mint(sub, action, receipt.id)
        return receipt

    def issue(self, action: str, user: str, ttl: int = DEFAULT_TTL) -> Receipt:
        """Issue a basic signed receipt."""
        _validate_sub(user)
        _validate_action(action)
        return self._make_receipt(user, action, ttl)

    def issue_plan(
        self,
        action: str,
        user: str,
        scope: list[str],
        delegates_to: list[str],
        requires_checkpoint: Optional[list[str]] = None,
        max_depth: int = 2,
        ttl: int = DEFAULT_TTL,
    ) -> Receipt:
        """Issue a plan receipt with delegation rules."""
        _validate_sub(user)
        _validate_action(action)
        return self._make_receipt(
            user, action, ttl,
            receipt_type="plan",
            scope=scope,
            delegates_to=delegates_to,
            requires_checkpoint=requires_checkpoint or [],
            max_delegation_depth=max_depth,
            depth=0,
        )

    def delegate(self, parent: Receipt, agent: str, action: str) -> DelegationResult:
        """Request delegated receipt from a parent."""
        _validate_sub(agent)
        _validate_action(action)
        chain = self._chain_ids(parent)

        # Check 1: Agent authorized?
        if parent.delegates_to and agent not in parent.delegates_to:
            if not self._quiet:
                console.delegate_deny(agent, action, "agent_not_authorized")
            return DelegationResult(
                DelegationStatus.DENIED_AGENT, None, tuple(chain),
                f"agent '{agent}' not in delegates_to",
            )

        # Check 2: Depth limit?
        depth = parent.depth or 0
        max_depth = parent.max_delegation_depth or 1
        if depth >= max_depth:
            if not self._quiet:
                console.delegate_deny(agent, action, "max_depth_exceeded")
            return DelegationResult(
                DelegationStatus.DENIED_DEPTH, None, tuple(chain),
                f"depth {depth} >= max {max_depth}",
            )

        # Check 3: Checkpoint required?
        if parent.requires_checkpoint and _in_scope(action, parent.requires_checkpoint):
            if not self._quiet:
                console.checkpoint(agent, action)
            return DelegationResult(
                DelegationStatus.CHECKPOINT, None, tuple(chain),
                f"action '{action}' requires human approval",
            )

        # Check 4: In scope?
        if parent.scope and not _in_scope(action, parent.scope):
            if not self._quiet:
                console.delegate_deny(agent, action, "action_not_in_scope")
            return DelegationResult(
                DelegationStatus.DENIED_SCOPE, None, tuple(chain),
                f"action '{action}' not in scope",
            )

        # Issue delegated receipt
        parent_exp = datetime.fromisoformat(parent.expires_at)
        remaining = (parent_exp - _utc_now()).total_seconds()
        ttl = int(max(1, min(300, remaining)))

        receipt = self._make_receipt(
            agent, action, ttl,
            receipt_type="delegated",
            scope=parent.scope,
            delegates_to=parent.delegates_to,
            requires_checkpoint=parent.requires_checkpoint,
            max_delegation_depth=parent.max_delegation_depth,
            parent_id=parent.id,
            original_approver=parent.original_approver or parent.sub,
            depth=depth + 1,
        )
        if not self._quiet:
            console.delegate_ok(agent, action, receipt.id)

        return DelegationResult(DelegationStatus.OK, receipt, tuple(chain + [receipt.id]))

    def _chain_ids(self, receipt: Receipt) -> list[str]:
        chain = []
        current: Optional[Receipt] = receipt
        while current:
            chain.insert(0, current.id)
            current = self._receipts.get(current.parent_id) if current.parent_id else None
        return chain

    def verify(self, receipt: Receipt, consume: bool = True) -> bool:
        """Verify receipt signature, expiry, and single-use."""
        if receipt.is_expired:
            if not self._quiet:
                console.reject("expired")
            return False

        try:
            payload = json.dumps(receipt.to_dict(), sort_keys=True).encode()
            self._vk.verify(payload, bytes.fromhex(receipt.signature))
        except (BadSignatureError, ValueError):
            if not self._quiet:
                console.reject("invalid signature")
            return False

        if consume:
            exp_ts = datetime.fromisoformat(receipt.expires_at).timestamp()
            if not self._jti.check_and_mark(receipt.id, exp_ts):
                if not self._quiet:
                    console.replay(receipt.id)
                return False

        if not self._quiet:
            console.verify_ok(receipt.id)
        return True

    def audit(self, receipt: Receipt) -> list[Receipt]:
        """Get full authorization chain from root to this receipt."""
        chain = []
        current: Optional[Receipt] = receipt
        while current:
            chain.insert(0, current)
            current = self._receipts.get(current.parent_id) if current.parent_id else None
        return chain
