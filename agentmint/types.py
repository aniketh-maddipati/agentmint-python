"""AgentMint types."""

from __future__ import annotations
from dataclasses import dataclass
from typing import Optional, TYPE_CHECKING
from enum import Enum

if TYPE_CHECKING:
    from .core import Receipt


class DelegationStatus(Enum):
    """Status of a delegation request."""
    OK = "ok"
    DENIED_AGENT = "denied:agent_not_authorized"
    DENIED_DEPTH = "denied:max_depth_exceeded"
    DENIED_SCOPE = "denied:action_not_in_scope"
    CHECKPOINT = "checkpoint_required"

    @property
    def is_denied(self) -> bool:
        return self.value.startswith("denied:")


@dataclass(frozen=True)
class DelegationResult:
    """Result of a delegation request."""
    status: DelegationStatus
    receipt: Optional[Receipt]
    chain: tuple[str, ...]
    reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.status == DelegationStatus.OK

    @property
    def denied(self) -> bool:
        return self.status.is_denied

    @property
    def needs_approval(self) -> bool:
        return self.status == DelegationStatus.CHECKPOINT
