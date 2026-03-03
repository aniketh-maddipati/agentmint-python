"""AgentMint exceptions."""


class AgentMintError(Exception):
    """Base exception for AgentMint."""
    pass


class ValidationError(AgentMintError):
    """Invalid input provided."""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


class SignatureError(AgentMintError):
    """Signature verification failed."""
    def __init__(self, receipt_id: str):
        self.receipt_id = receipt_id
        super().__init__(f"invalid signature: {receipt_id[:8]}...")


class ExpiredError(AgentMintError):
    """Receipt has expired."""
    def __init__(self, receipt_id: str, expired_at: str):
        self.receipt_id = receipt_id
        self.expired_at = expired_at
        super().__init__(f"expired at {expired_at}: {receipt_id[:8]}...")


class ReplayError(AgentMintError):
    """Receipt has already been used."""
    def __init__(self, receipt_id: str):
        self.receipt_id = receipt_id
        super().__init__(f"already used: {receipt_id[:8]}...")


class DeniedError(AgentMintError):
    """Delegation denied."""
    def __init__(self, reason: str, agent: str, action: str):
        self.reason = reason
        self.agent = agent
        self.action = action
        super().__init__(f"{reason}: {agent} -> {action}")
