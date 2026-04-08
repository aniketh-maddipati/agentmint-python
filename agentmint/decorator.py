"""Decorator for protecting functions with receipts."""

from __future__ import annotations
from contextvars import ContextVar
from functools import wraps
from typing import Callable, Optional, TypeVar
try:
    from typing import ParamSpec
except ImportError:
    from typing import TypeVar as ParamSpec  # 3.8 shim

from .core import AgentMint, Receipt
from .errors import AgentMintError
from . import console

P = ParamSpec("P")
T = TypeVar("T")

_current_receipt: ContextVar[Optional[Receipt]] = ContextVar("current_receipt", default=None)


class AuthorizationError(AgentMintError):
    """Raised when action is not authorized."""
    def __init__(self, reason: str, action: str, receipt_id: Optional[str] = None):
        self.reason = reason
        self.action = action
        self.receipt_id = receipt_id
        super().__init__(f"{reason}: {action}")


def set_receipt(receipt: Receipt) -> None:
    """Set the current receipt for authorization."""
    _current_receipt.set(receipt)


def get_receipt() -> Optional[Receipt]:
    """Get the current receipt."""
    return _current_receipt.get()


def clear_receipt() -> None:
    """Clear the current receipt."""
    _current_receipt.set(None)


def require_receipt(mint: AgentMint, action: str) -> Callable[[Callable[P, T]], Callable[P, T]]:
    """
    Decorator that requires a valid receipt for the specified action.

    Example:
        @require_receipt(mint, "write_file")
        def write_file(path: str, content: str) -> None:
            ...
    """
    def decorator(func: Callable[P, T]) -> Callable[P, T]:
        @wraps(func)
        def wrapper(*args: P.args, **kwargs: P.kwargs) -> T:
            receipt = _current_receipt.get()

            if receipt is None:
                console.blocked("No authorization receipt", action, "Human must call mint.issue()")
                raise AuthorizationError("no_receipt", action)

            if receipt.action != action:
                console.blocked("Wrong receipt type", action, f"Have: {receipt.action}")
                raise AuthorizationError("action_mismatch", action, receipt.id)

            if receipt.is_expired:
                console.blocked("Receipt expired", action, f"Expired: {receipt.expires_at[:19]}")
                raise AuthorizationError("expired", action, receipt.id)

            if not mint.verify(receipt, consume=False):
                console.blocked("Invalid signature", action, "Receipt may be tampered")
                raise AuthorizationError("invalid_signature", action, receipt.id)

            console.authorized(action, receipt.sub, receipt.id)
            return func(*args, **kwargs)
        return wrapper
    return decorator
