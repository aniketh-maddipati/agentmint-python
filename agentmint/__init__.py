"""
AgentMint: Cryptographic proof that a human approved an AI agent action.

Example:
    from agentmint import AgentMint

    mint = AgentMint()
    receipt = mint.issue("deploy", "alice@co.com")
    assert mint.verify(receipt)
"""

from .core import AgentMint, Receipt, JtiStore
from .errors import (
    AgentMintError,
    ValidationError,
    SignatureError,
    ExpiredError,
    ReplayError,
    DeniedError,
)
from .types import DelegationStatus, DelegationResult
from .decorator import (
    AuthorizationError,
    require_receipt,
    set_receipt,
    get_receipt,
    clear_receipt,
)

__version__ = "0.1.0"
__all__ = [
    # Core
    "AgentMint",
    "Receipt",
    "JtiStore",
    # Types
    "DelegationStatus",
    "DelegationResult",
    # Errors
    "AgentMintError",
    "ValidationError",
    "SignatureError",
    "ExpiredError",
    "ReplayError",
    "DeniedError",
    "AuthorizationError",
    # Decorator
    "require_receipt",
    "set_receipt",
    "get_receipt",
    "clear_receipt",
]
