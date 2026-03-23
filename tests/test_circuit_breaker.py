"""Tests for agentmint.circuit_breaker."""

from __future__ import annotations

import time

import pytest

from agentmint.circuit_breaker import BreakerResult, CircuitBreaker


class TestClosedState:
    """Breaker stays closed when usage is below 80%."""

    def test_fresh_agent_is_closed(self) -> None:
        cb = CircuitBreaker(max_calls=10, window_seconds=60)
        result = cb.check("agent-a")
        assert result.is_allowed is True
        assert result.state == "closed"

    def test_below_threshold_stays_closed(self) -> None:
        cb = CircuitBreaker(max_calls=10, window_seconds=60)
        for _ in range(7):
            cb.record("agent-a")
        result = cb.check("agent-a")
        assert result.state == "closed"
        assert result.is_allowed is True


class TestHalfOpenState:
    """Breaker moves to half_open at >= 80% capacity."""

    def test_at_eighty_percent_is_half_open(self) -> None:
        cb = CircuitBreaker(max_calls=10, window_seconds=60)
        for _ in range(8):
            cb.record("agent-a")
        result = cb.check("agent-a")
        assert result.is_allowed is True
        assert result.state == "half_open"
        assert "approaching_limit" in result.reason


class TestOpenState:
    """Breaker opens at >= 100% capacity."""

    def test_at_max_is_open(self) -> None:
        cb = CircuitBreaker(max_calls=10, window_seconds=60)
        for _ in range(10):
            cb.record("agent-a")
        result = cb.check("agent-a")
        assert result.is_allowed is False
        assert result.state == "open"
        assert "rate_limit_exceeded" in result.reason

    def test_over_max_stays_open(self) -> None:
        cb = CircuitBreaker(max_calls=5, window_seconds=60)
        for _ in range(8):
            cb.record("agent-a")
        result = cb.check("agent-a")
        assert result.is_allowed is False
        assert result.state == "open"


class TestWindowExpiry:
    """Old timestamps fall out of the sliding window."""

    def test_expired_timestamps_are_discarded(self) -> None:
        cb = CircuitBreaker(max_calls=5, window_seconds=1)
        for _ in range(5):
            cb.record("agent-a")
        assert cb.check("agent-a").state == "open"
        time.sleep(1.1)
        result = cb.check("agent-a")
        assert result.is_allowed is True
        assert result.state == "closed"


class TestPerAgentIsolation:
    """Each agent has independent counters."""

    def test_agents_do_not_share_counters(self) -> None:
        cb = CircuitBreaker(max_calls=5, window_seconds=60)
        for _ in range(5):
            cb.record("agent-a")
        assert cb.check("agent-a").is_allowed is False
        assert cb.check("agent-b").is_allowed is True


class TestReset:
    """Reset clears counters and returns to closed."""

    def test_reset_reopens_breaker(self) -> None:
        cb = CircuitBreaker(max_calls=5, window_seconds=60)
        for _ in range(5):
            cb.record("agent-a")
        assert cb.check("agent-a").state == "open"
        cb.reset("agent-a")
        assert cb.check("agent-a").state == "closed"
        assert cb.state("agent-a") == "closed"


class TestValidation:
    """Constructor rejects invalid parameters."""

    def test_zero_max_calls_raises(self) -> None:
        with pytest.raises(ValueError, match="max_calls"):
            CircuitBreaker(max_calls=0)

    def test_zero_window_raises(self) -> None:
        with pytest.raises(ValueError, match="window_seconds"):
            CircuitBreaker(window_seconds=0)
