"""Tests for AgentMint SDK."""

import time
import pytest
from agentmint import (
    AgentMint,
    Receipt,
    DelegationStatus,
    ValidationError,
    AuthorizationError,
    require_receipt,
    set_receipt,
    clear_receipt,
)


class TestBasicIssueVerify:
    def test_issue_returns_receipt(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("deploy", "alice")
        assert isinstance(r, Receipt)
        assert r.sub == "alice"
        assert r.action == "deploy"
        assert len(r.id) == 36  # UUID

    def test_verify_valid_receipt(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("deploy", "alice")
        assert mint.verify(r) is True

    def test_replay_blocked(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("deploy", "alice")
        assert mint.verify(r) is True
        assert mint.verify(r) is False  # replay

    def test_verify_without_consume(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("deploy", "alice")
        assert mint.verify(r, consume=False) is True
        assert mint.verify(r, consume=False) is True  # still works
        assert mint.verify(r, consume=True) is True
        assert mint.verify(r) is False  # now consumed


class TestValidation:
    def test_empty_sub_rejected(self):
        mint = AgentMint(quiet=True)
        with pytest.raises(ValidationError) as exc:
            mint.issue("deploy", "")
        assert exc.value.field == "sub"

    def test_empty_action_rejected(self):
        mint = AgentMint(quiet=True)
        with pytest.raises(ValidationError) as exc:
            mint.issue("", "alice")
        assert exc.value.field == "action"

    def test_invalid_action_chars(self):
        mint = AgentMint(quiet=True)
        with pytest.raises(ValidationError) as exc:
            mint.issue("deploy prod!", "alice")  # space and !
        assert exc.value.field == "action"

    def test_valid_action_chars(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("build:docker-image_v2", "alice")
        assert r.action == "build:docker-image_v2"


class TestExpiry:
    def test_expired_receipt_rejected(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("deploy", "alice", ttl=1)
        time.sleep(1.1)
        assert r.is_expired is True
        assert mint.verify(r) is False


class TestDelegation:
    def test_delegation_ok(self):
        mint = AgentMint(quiet=True)
        plan = mint.issue_plan(
            "deploy:api", "alice",
            scope=["build:*"], delegates_to=["builder"]
        )
        result = mint.delegate(plan, "builder", "build:docker")
        assert result.ok is True
        assert result.receipt is not None
        assert result.receipt.depth == 1

    def test_unauthorized_agent_denied(self):
        mint = AgentMint(quiet=True)
        plan = mint.issue_plan(
            "deploy:api", "alice",
            scope=["build:*"], delegates_to=["builder"]
        )
        result = mint.delegate(plan, "rogue", "build:docker")
        assert result.status == DelegationStatus.DENIED_AGENT
        assert result.denied is True
        assert result.receipt is None

    def test_out_of_scope_denied(self):
        mint = AgentMint(quiet=True)
        plan = mint.issue_plan(
            "deploy:api", "alice",
            scope=["build:*"], delegates_to=["builder"]
        )
        result = mint.delegate(plan, "builder", "deploy:prod")
        assert result.status == DelegationStatus.DENIED_SCOPE

    def test_checkpoint_required(self):
        mint = AgentMint(quiet=True)
        plan = mint.issue_plan(
            "deploy:api", "alice",
            scope=["*"], delegates_to=["builder"],
            requires_checkpoint=["deploy:*"]
        )
        result = mint.delegate(plan, "builder", "deploy:prod")
        assert result.status == DelegationStatus.CHECKPOINT
        assert result.needs_approval is True

    def test_max_depth_exceeded(self):
        mint = AgentMint(quiet=True)
        plan = mint.issue_plan(
            "deploy:api", "alice",
            scope=["*"], delegates_to=["a", "b"],
            max_depth=1
        )
        r1 = mint.delegate(plan, "a", "build:one")
        assert r1.ok
        r2 = mint.delegate(r1.receipt, "b", "build:two")
        assert r2.status == DelegationStatus.DENIED_DEPTH


class TestDecorator:
    def test_decorator_blocks_without_receipt(self):
        mint = AgentMint(quiet=True)
        clear_receipt()

        @require_receipt(mint, "write_file")
        def write_file():
            return "wrote"

        with pytest.raises(AuthorizationError) as exc:
            write_file()
        assert exc.value.reason == "no_receipt"

    def test_decorator_allows_with_valid_receipt(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("write_file", "alice")
        set_receipt(r)

        @require_receipt(mint, "write_file")
        def write_file():
            return "wrote"

        result = write_file()
        assert result == "wrote"
        clear_receipt()

    def test_decorator_blocks_wrong_action(self):
        mint = AgentMint(quiet=True)
        r = mint.issue("read_file", "alice")
        set_receipt(r)

        @require_receipt(mint, "write_file")
        def write_file():
            return "wrote"

        with pytest.raises(AuthorizationError) as exc:
            write_file()
        assert exc.value.reason == "action_mismatch"
        clear_receipt()


class TestAudit:
    def test_audit_chain(self):
        mint = AgentMint(quiet=True)
        plan = mint.issue_plan(
            "deploy:api", "alice",
            scope=["*"], delegates_to=["a", "b"], max_depth=3
        )
        r1 = mint.delegate(plan, "a", "step:one").receipt
        r2 = mint.delegate(r1, "b", "step:two").receipt
        
        chain = mint.audit(r2)
        assert len(chain) == 3
        assert chain[0].sub == "alice"
        assert chain[1].sub == "a"
        assert chain[2].sub == "b"
