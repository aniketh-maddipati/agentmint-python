"""Tests for Feature 7: multi-agent delegation with scope intersection."""

from __future__ import annotations

import pytest

from agentmint.notary import Notary, NotaryError, intersect_scopes


class TestIntersectScopes:
    """Scope intersection logic."""

    def test_exact_match_kept(self) -> None:
        result = intersect_scopes(["read:public:file"], ["read:public:file"])
        assert result == ("read:public:file",)

    def test_child_more_specific_than_parent_wildcard(self) -> None:
        result = intersect_scopes(["read:*"], ["read:public:file"])
        assert result == ("read:public:file",)

    def test_parent_more_specific_than_child_wildcard(self) -> None:
        result = intersect_scopes(["read:public:file"], ["read:*"])
        assert result == ("read:public:file",)

    def test_no_overlap_returns_empty(self) -> None:
        result = intersect_scopes(["read:*"], ["write:file"])
        assert result == ()

    def test_multiple_patterns(self) -> None:
        result = intersect_scopes(
            ["read:*", "write:summary:*"],
            ["read:reports:q3", "write:summary:draft", "delete:all"],
        )
        assert "read:reports:q3" in result
        assert "write:summary:draft" in result
        assert "delete:all" not in result

    def test_star_parent_matches_everything(self) -> None:
        result = intersect_scopes(["*"], ["read:file", "write:file"])
        assert "read:file" in result
        assert "write:file" in result

    def test_both_wildcards_keeps_more_specific(self) -> None:
        result = intersect_scopes(["read:public:*"], ["read:*"])
        # parent is more specific, child is broader — keep parent
        assert "read:public:*" in result

    def test_no_duplicates(self) -> None:
        result = intersect_scopes(["read:*", "read:public:*"], ["read:public:file"])
        assert result.count("read:public:file") == 1


class TestDelegateToAgent:
    """Notary.delegate_to_agent creates child plans with intersected scope."""

    def test_child_plan_created(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="analysis",
            scope=["read:*", "write:summary:*"],
            delegates_to=["parent-agent"],
        )
        child = notary.delegate_to_agent(
            parent, "child-agent",
            requested_scope=["read:reports:*"],
        )
        assert "read:reports:*" in child.scope
        assert child.delegates_to == ("child-agent",)

    def test_empty_intersection_raises(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*"], delegates_to=["p"],
        )
        with pytest.raises(NotaryError, match="scope intersection is empty"):
            notary.delegate_to_agent(parent, "c", requested_scope=["write:file"])

    def test_child_inherits_checkpoints(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*"], checkpoints=["read:secret:*"],
            delegates_to=["p"],
        )
        child = notary.delegate_to_agent(parent, "c", requested_scope=["read:public:*"])
        assert "read:secret:*" in child.checkpoints


class TestAuditTree:
    """audit_tree returns delegation hierarchy."""

    def test_no_children(self) -> None:
        notary = Notary()
        plan = notary.create_plan(
            user="u@test.com", action="t", scope=["read:*"], delegates_to=["a"],
        )
        tree = notary.audit_tree(plan.id)
        assert tree["plan_id"] == plan.id
        assert tree["children"] == []

    def test_one_child(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*"], delegates_to=["p"],
        )
        child = notary.delegate_to_agent(parent, "c", requested_scope=["read:file"])
        tree = notary.audit_tree(parent.id)
        assert len(tree["children"]) == 1
        assert tree["children"][0]["plan_id"] == child.id

    def test_two_children(self) -> None:
        notary = Notary()
        parent = notary.create_plan(
            user="u@test.com", action="t",
            scope=["read:*", "write:*"], delegates_to=["p"],
        )
        c1 = notary.delegate_to_agent(parent, "c1", requested_scope=["read:*"])
        c2 = notary.delegate_to_agent(parent, "c2", requested_scope=["write:*"])
        tree = notary.audit_tree(parent.id)
        child_ids = {c["plan_id"] for c in tree["children"]}
        assert c1.id in child_ids
        assert c2.id in child_ids
