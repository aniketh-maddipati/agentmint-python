"""Per-agent sliding window circuit breaker.

Three states:
- closed:    all calls proceed normally
- half_open: calls proceed but a warning is attached (>= 80% threshold)
- open:      calls are blocked (>= 100% threshold)

Window is sliding — timestamps older than window_seconds are discarded.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass


@dataclass(frozen=True)
class BreakerResult:
    """Outcome of a circuit breaker check."""

    is_allowed: bool
    state: str
    reason: str


class CircuitBreaker:
    """Sliding-window rate limiter with per-agent state tracking."""

    __slots__ = ("_max_calls", "_window_seconds", "_counters", "_states")

    def __init__(
        self,
        max_calls: int = 100,
        window_seconds: int = 60,
    ) -> None:
        if max_calls < 1:
            raise ValueError("max_calls must be >= 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be >= 1")
        self._max_calls: int = max_calls
        self._window_seconds: int = window_seconds
        self._counters: dict[str, deque[float]] = {}
        self._states: dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, agent: str) -> BreakerResult:
        """Evaluate whether *agent* is allowed to proceed.

        Returns a BreakerResult with is_allowed, state, and reason.
        """
        self._expire(agent)
        count = len(self._counters.get(agent, deque()))
        ratio = count / self._max_calls

        if ratio >= 1.0:
            self._states[agent] = "open"
            return BreakerResult(
                is_allowed=False,
                state="open",
                reason=(
                    f"rate_limit_exceeded:"
                    f"{count}/{self._max_calls} in {self._window_seconds}s"
                ),
            )

        if ratio >= 0.8:
            self._states[agent] = "half_open"
            return BreakerResult(
                is_allowed=True,
                state="half_open",
                reason=(
                    f"approaching_limit:"
                    f"{count}/{self._max_calls} in {self._window_seconds}s"
                ),
            )

        self._states[agent] = "closed"
        return BreakerResult(
            is_allowed=True,
            state="closed",
            reason="ok",
        )

    def record(self, agent: str) -> None:
        """Record a call timestamp for *agent*."""
        if agent not in self._counters:
            self._counters[agent] = deque()
        self._counters[agent].append(time.monotonic())

    def reset(self, agent: str) -> None:
        """Clear all counters and reset state for *agent*."""
        self._counters.pop(agent, None)
        self._states[agent] = "closed"

    def state(self, agent: str) -> str:
        """Return the current state string for *agent*."""
        self._expire(agent)
        return self._states.get(agent, "closed")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _expire(self, agent: str) -> None:
        """Discard timestamps older than the sliding window."""
        q = self._counters.get(agent)
        if q is None:
            return
        cutoff = time.monotonic() - self._window_seconds
        while q and q[0] < cutoff:
            q.popleft()
