"""
AgentMint brand colors for terminal output.

Single source of truth. All CLI modules import from here.
Uses Rich hex color syntax for 24-bit terminal support.
Falls back gracefully when Rich is not installed.
"""
from __future__ import annotations

__all__ = ["C", "rich_available"]


def rich_available() -> bool:
    """Check if Rich is installed without importing it."""
    try:
        import rich  # noqa: F401
        return True
    except ImportError:
        return False


class C:
    """Brand color constants as Rich markup hex codes.

    Usage in Rich f-strings:
        f"[{C.GREEN}]✓ allowed[/{C.GREEN}]"
        f"[{C.RED}]✗ blocked[/{C.RED}]"
    """

    # Primary accent
    BLUE: str = "#3B82F6"

    # Semantic states
    GREEN: str = "#10B981"
    RED: str = "#EF4444"
    YELLOW: str = "#FBBF24"

    # Text hierarchy
    FG: str = "#E2E8F0"
    SECONDARY: str = "#94A3B8"
    DIM: str = "#64748B"

    # Borders and surfaces
    BORDER: str = "#1E293B"
    SURFACE: str = "#151D2E"

    # Risk level colors (for Rich markup)
    RISK_LOW: str = "#10B981"
    RISK_MEDIUM: str = "#FBBF24"
    RISK_HIGH: str = "#EF4444"
    RISK_CRITICAL: str = "bold #EF4444"

    @staticmethod
    def risk_color(level: str) -> str:
        """Return Rich color string for a risk level."""
        return {
            "LOW": C.RISK_LOW,
            "MEDIUM": C.RISK_MEDIUM,
            "HIGH": C.RISK_HIGH,
            "CRITICAL": C.RISK_CRITICAL,
        }.get(level, C.SECONDARY)

    @staticmethod
    def risk_label(level: str) -> str:
        """Return Rich-formatted risk label."""
        short = {"LOW": "LOW", "MEDIUM": "MED", "HIGH": "HIGH", "CRITICAL": "CRIT"}
        color = C.risk_color(level)
        return f"[{color}]{short.get(level, level)}[/{color}]"
