"""Pretty terminal output with colors and badges."""

import os

# Respect NO_COLOR standard (https://no-color.org/)
NO_COLOR = os.environ.get("NO_COLOR", "") != ""


class Color:
    GREEN = "" if NO_COLOR else "\033[92m"
    RED = "" if NO_COLOR else "\033[91m"
    YELLOW = "" if NO_COLOR else "\033[93m"
    CYAN = "" if NO_COLOR else "\033[96m"
    WHITE = "" if NO_COLOR else "\033[97m"
    DIM = "" if NO_COLOR else "\033[2m"
    BOLD = "" if NO_COLOR else "\033[1m"
    RESET = "" if NO_COLOR else "\033[0m"


def _badge(text: str, color: str) -> str:
    return f"{color}{Color.BOLD} {text} {Color.RESET}"


def _short_id(jti: str) -> str:
    return jti[:8] if len(jti) >= 8 else jti


def mint(sub: str, action: str, jti: str) -> None:
    print(f"{_badge('MINT', Color.GREEN)} {Color.DIM}sub:{Color.RESET}{Color.WHITE}{sub}{Color.RESET} "
          f"{Color.DIM}action:{Color.RESET}{Color.CYAN}{action}{Color.RESET} "
          f"{Color.DIM}jti:{_short_id(jti)}{Color.RESET}")


def verify_ok(jti: str) -> None:
    print(f"{_badge('OK', Color.CYAN)} {Color.WHITE}jti:{_short_id(jti)}{Color.RESET} {Color.GREEN}✓{Color.RESET}")


def reject(reason: str) -> None:
    print(f"{_badge('DENY', Color.RED)} {Color.RED}{reason}{Color.RESET}")


def replay(jti: str) -> None:
    print(f"{_badge('REPLAY', Color.YELLOW)} {Color.WHITE}jti:{_short_id(jti)}{Color.RESET} "
          f"{Color.YELLOW}blocked{Color.RESET}")


def delegate_ok(agent: str, action: str, jti: str) -> None:
    print(f"{_badge('DELEGATE', Color.GREEN)} {Color.DIM}agent:{Color.RESET}{Color.WHITE}{agent}{Color.RESET} "
          f"{Color.DIM}action:{Color.RESET}{Color.CYAN}{action}{Color.RESET} {Color.GREEN}✓{Color.RESET}")


def delegate_deny(agent: str, action: str, reason: str) -> None:
    print(f"{_badge('DELEGATE', Color.RED)} {Color.WHITE}{agent}{Color.RESET} "
          f"{Color.DIM}→{Color.RESET} {Color.YELLOW}{action}{Color.RESET} {Color.RED}{reason}{Color.RESET}")


def checkpoint(agent: str, action: str) -> None:
    print(f"{_badge('CHECKPOINT', Color.YELLOW)} {Color.WHITE}{agent}{Color.RESET} "
          f"{Color.DIM}→{Color.RESET} {Color.YELLOW}{action}{Color.RESET} "
          f"{Color.YELLOW}⚠ requires human approval{Color.RESET}")


def authorized(action: str, user: str, jti: str) -> None:
    print(f"\n  {Color.GREEN}✓ AUTHORIZED{Color.RESET}")
    print(f"    {Color.DIM}action:{Color.RESET} {Color.CYAN}{action}{Color.RESET}")
    print(f"    {Color.DIM}user:{Color.RESET} {Color.WHITE}{user}{Color.RESET}")
    print(f"    {Color.DIM}receipt:{Color.RESET} {Color.DIM}{_short_id(jti)}...{Color.RESET}\n")


def blocked(reason: str, action: str, detail: str = "") -> None:
    r, rst = Color.RED, Color.RESET
    print(f"""
  {r}╔══════════════════════════════════════════╗
  ║  BLOCKED: {reason:<30} ║
  ║  Action: {action:<31} ║
  ║  {detail:<40} ║
  ╚══════════════════════════════════════════╝{rst}
""")
