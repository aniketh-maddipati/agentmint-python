"""Tests for the unified pattern matcher (improvement 4.3)."""

import pytest
from agentmint.patterns import matches_pattern, in_scope


class TestMatchesPattern:
    def test_star_matches_everything(self):
        assert matches_pattern("anything", "*")
        assert matches_pattern("a:b:c:d", "*")
        assert matches_pattern("", "*")

    def test_exact_match(self):
        assert matches_pattern("read:reports", "read:reports")
        assert not matches_pattern("read:reports:quarterly", "read:reports")

    def test_colon_star_wildcard(self):
        assert matches_pattern("read:reports:quarterly", "read:reports:*")
        assert matches_pattern("read:reports:anything:nested", "read:reports:*")
        assert matches_pattern("read:reports", "read:reports:*")

    def test_colon_star_no_match(self):
        assert not matches_pattern("read:other", "read:reports:*")
        assert not matches_pattern("write:reports:quarterly", "read:reports:*")

    def test_bare_star_suffix_rejected(self):
        """Bare * suffix (without colon) is NOT supported — this is the fix for bug 3.2."""
        assert not matches_pattern("tts:standardabc", "tts:standard*")
        assert not matches_pattern("tts:standard", "tts:standard*")

    def test_no_partial_match(self):
        assert not matches_pattern("read:reportsx", "read:reports:*")


class TestInScope:
    def test_any_match_returns_true(self):
        assert in_scope("read:reports:q4", ["write:*", "read:reports:*"])

    def test_no_match_returns_false(self):
        assert not in_scope("delete:everything", ["read:*", "write:*"])

    def test_empty_patterns(self):
        assert not in_scope("anything", [])

    def test_star_in_patterns(self):
        assert in_scope("anything", ["*"])
