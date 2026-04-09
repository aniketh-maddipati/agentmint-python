"""
Memory store detector for AI agent codebases.

OWASP AI Agent Security Cheat Sheet §3 (Memory & Context Security):
agents that persist memory can leak PII across sessions, allow
memory poisoning attacks, and create unaudited state mutations.

AgentMint detects these patterns at scan time:

    LangGraph:  MemorySaver, SqliteSaver, PostgresSaver
                (checkpointers that persist graph state to disk/DB)

    CrewAI:     Agent(memory=True), Crew(memory=True)
                LongTermMemory, ShortTermMemory, EntityMemory
                (conversation memory that persists between runs)

    Pickle:     pickle.dump(), pickle.load()
                (arbitrary code execution vector — deserializing
                untrusted pickle data runs attacker-controlled code)

What this does NOT do:

    - Does not wrap memory stores at runtime (too invasive)
    - Does not scan stored data for PII (would require runtime access)
    - Does not modify your code

Each detection produces a MemoryCandidate with a concrete
recommendation. These feed into the OWASP §3 scorecard row.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

try:
    import libcst as cst
    from libcst.metadata import PositionProvider, MetadataWrapper
    _HAS_LIBCST = True
except ImportError:
    _HAS_LIBCST = False

__all__ = ["MemoryCandidate", "scan_file_for_memory", "scan_directory_for_memory"]


# ── Detection result ─────────────────────────────────────────

@dataclass(frozen=True)
class MemoryCandidate:
    """A detected memory store in the codebase.

    Frozen dataclass — immutable after creation, safe to hash and
    deduplicate. Every field is a provable fact from the scan.
    """

    file: str             # relative path from scan root
    line: int             # 1-indexed line number (0 if unavailable)
    store_type: str       # langgraph_checkpointer | crewai_memory | pickle
    symbol: str           # class or function name as found in source
    framework: str        # langgraph | crewai | stdlib
    risk_note: str        # why this matters (shown in CLI output)
    recommendation: str   # concrete next step (shown in CLI output)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for JSON output and evidence packages."""
        return {
            "file": self.file,
            "line": self.line,
            "store_type": self.store_type,
            "symbol": self.symbol,
            "framework": self.framework,
            "risk_note": self.risk_note,
            "recommendation": self.recommendation,
        }


# ── Known memory class names ─────────────────────────────────

_LANGGRAPH_SAVERS: frozenset[str] = frozenset({
    "MemorySaver",         # in-memory checkpointer
    "SqliteSaver",         # SQLite-backed
    "PostgresSaver",       # Postgres-backed
    "AsyncSqliteSaver",    # async variant
    "AsyncPostgresSaver",  # async variant
})

_CREWAI_MEMORY_CLASSES: frozenset[str] = frozenset({
    "LongTermMemory",      # persists across crew runs
    "ShortTermMemory",     # within-run conversation memory
    "EntityMemory",        # entity extraction + storage
})


# ── CST helpers (module-level, used by detector) ─────────────

def _call_name(node: Any) -> Optional[str]:
    """Extract function/class name from a Call node. Returns None if dynamic."""
    func = node.func
    if isinstance(func, cst.Name):
        return func.value
    if isinstance(func, cst.Attribute):
        return func.attr.value
    return None


def _is_pickle_call(node: Any, import_names: frozenset[str]) -> bool:
    """Check if a Call node is pickle.dump() or pickle.load()."""
    func = node.func
    if isinstance(func, cst.Attribute) and isinstance(func.value, cst.Name):
        return func.value.value == "pickle"
    return "pickle" in import_names


# ── LibCST detector ──────────────────────────────────────────

if _HAS_LIBCST:
    class _MemoryDetector(cst.CSTVisitor):
        """Single-pass AST visitor that finds memory store patterns.

        Runs inside MetadataWrapper for line numbers. Falls back to
        plain walk() if metadata resolution fails (line=0 in output).
        """

        METADATA_DEPENDENCIES = (PositionProvider,)

        def __init__(self, file_path: str, import_names: frozenset[str]) -> None:
            self.file_path = file_path
            self.import_names = import_names
            self.candidates: list[MemoryCandidate] = []

        def visit_Call(self, node: cst.Call) -> None:
            """Detect memory store instantiations and pickle calls."""
            name = _call_name(node)
            if name is None:
                return

            if name in _LANGGRAPH_SAVERS:
                self.candidates.append(MemoryCandidate(
                    file=self.file_path,
                    line=self._line(node),
                    store_type="langgraph_checkpointer",
                    symbol=name,
                    framework="langgraph",
                    risk_note=(
                        "Agent state persisted without integrity checks — "
                        "a compromised checkpoint can hijack future runs"
                    ),
                    recommendation=(
                        "Add cryptographic checksums on stored state "
                        "and validate before loading (OWASP §3)"
                    ),
                ))

            elif name in _CREWAI_MEMORY_CLASSES:
                self.candidates.append(MemoryCandidate(
                    file=self.file_path,
                    line=self._line(node),
                    store_type="crewai_memory",
                    symbol=name,
                    framework="crewai",
                    risk_note=(
                        "Agent memory may persist PII from conversations "
                        "and leak it to future sessions or other users"
                    ),
                    recommendation=(
                        "Audit memory contents for sensitive data before "
                        "persistence, set expiration policies"
                    ),
                ))

            elif name in ("dump", "load") and _is_pickle_call(node, self.import_names):
                self.candidates.append(MemoryCandidate(
                    file=self.file_path,
                    line=self._line(node),
                    store_type="pickle",
                    symbol=f"pickle.{name}",
                    framework="stdlib",
                    risk_note=(
                        "Pickle deserialization executes arbitrary code — "
                        "loading untrusted pickle data is a remote code execution vector"
                    ),
                    recommendation=(
                        "Replace pickle with JSON serialization + HMAC "
                        "integrity verification on stored state"
                    ),
                ))

        def visit_Assign(self, node: cst.Assign) -> None:
            """Detect memory=True kwargs in CrewAI Agent() or Crew() calls."""
            if not isinstance(node.value, cst.Call):
                return

            call = _call_name(node.value)
            if call not in ("Agent", "Crew"):
                return

            for arg in node.value.args:
                kw = arg.keyword
                val = arg.value
                if (kw is not None
                        and isinstance(kw, cst.Name)
                        and kw.value == "memory"
                        and isinstance(val, cst.Name)
                        and val.value == "True"):
                    self.candidates.append(MemoryCandidate(
                        file=self.file_path,
                        line=self._line(node),
                        store_type="crewai_memory",
                        symbol=f"{call}(memory=True)",
                        framework="crewai",
                        risk_note=(
                            "CrewAI memory enabled — conversation history "
                            "persists between runs and may contain PII"
                        ),
                        recommendation=(
                            "Set memory expiration, scan for PII before "
                            "storage, isolate memory between users/sessions"
                        ),
                    ))

        def _line(self, node: Any) -> int:
            """Extract source line number. Returns 0 if metadata unavailable."""
            try:
                return self.get_metadata(PositionProvider, node).start.line
            except Exception:
                return 0


# ── Import collector ─────────────────────────────────────────

_IMPORT_RE = re.compile(r"(?:from|import)\s+([\w.]+)")


def _collect_imports(source: str) -> frozenset[str]:
    """Quick regex pass to find imported module names.

    Faster than a full AST parse for this narrow use case.
    Used to confirm whether 'pickle' is actually imported
    before flagging dump/load calls.
    """
    return frozenset(m.group(1) for m in _IMPORT_RE.finditer(source))


# ── Public API ───────────────────────────────────────────────

_SKIP_DIRS: frozenset[str] = frozenset({
    "venv", ".venv", "env", ".env", ".git", "__pycache__",
    ".mypy_cache", ".pytest_cache", "node_modules",
    "dist", "build", ".tox", ".nox",
})


def scan_file_for_memory(file_path: str, source: str) -> list[MemoryCandidate]:
    """Scan a single Python file for memory store patterns.

    Returns empty list if:
        - libcst is not installed (CLI extras not present)
        - File has syntax errors (can't parse)
        - No memory patterns found
    """
    if not _HAS_LIBCST:
        return []

    try:
        tree = cst.parse_module(source)
    except cst.ParserSyntaxError:
        return []

    import_names = _collect_imports(source)
    detector = _MemoryDetector(file_path, import_names)

    try:
        wrapper = MetadataWrapper(tree, unsafe_skip_copy=True)
        wrapper.visit(detector)
    except Exception:
        # Metadata resolution failed — fall back to plain walk.
        # Line numbers will be 0, but detection still works.
        tree.walk(detector)

    return detector.candidates


def scan_directory_for_memory(
    root: str,
    skip_tests: bool = True,
) -> list[MemoryCandidate]:
    """Walk a project tree, scan all .py files for memory stores.

    Skips virtual environments, build artifacts, and optionally test
    directories. Same skip logic as the main tool scanner.
    """
    root_path = Path(root).resolve()
    skip = set(_SKIP_DIRS)
    if skip_tests:
        skip.update({"tests", "test", "testing"})

    results: list[MemoryCandidate] = []

    for dirpath, dirnames, filenames in os.walk(root_path):
        # Prune directories in-place to avoid descending into them
        dirnames[:] = [
            d for d in dirnames
            if d not in skip and not d.endswith(".egg-info")
        ]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            full = Path(dirpath) / fname
            rel = str(full.relative_to(root_path))
            try:
                source = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            results.extend(scan_file_for_memory(rel, source))

    return results
