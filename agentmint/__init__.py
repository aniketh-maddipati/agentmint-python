"""
AgentMint — Independent notary for AI agent actions.

Produces cryptographic receipts proving what an agent was authorized
to do, and that the record was not altered after the fact.

Quickstart (Notary — primary interface):
    from agentmint.notary import Notary

    notary = Notary()
    plan = notary.create_plan(user="admin@co.com", action="ops", scope=["tts:*"])
    receipt = notary.notarise(action="tts:standard:abc", agent="voice-agent",
                              plan=plan, evidence={"voice_id": "abc"})
    notary.export_evidence(Path("./evidence"))

Scope layer (lightweight authorization checks):
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
