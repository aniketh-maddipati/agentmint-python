"""
scanner.py — LibCST framework detectors for agentmint init.

Architecture:
  1. ImportCollector does a single pass to catalog all imports
  2. Every detector runs on every file — detectors never skip
  3. Each detector emits ToolCandidates with evidence (import_confirmed, etc.)
  4. Triage layer scores, deduplicates, and resolves conflicts

  Adding a new framework = write a Detector class + register it.
  You never touch triage logic.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Sequence

import libcst as cst
from libcst.metadata import PositionProvider, MetadataWrapper

from .candidates import ToolCandidate


# ═══════════════════════════════════════════════════════════════
# CST helpers
# ═══════════════════════════════════════════════════════════════

def _decorator_name(dec: cst.Decorator) -> Optional[str]:
    node = dec.decorator
    if isinstance(node, cst.Call):
        node = node.func
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return node.attr.value
    return None


def _call_name(node: cst.Call) -> Optional[str]:
    func = node.func
    if isinstance(func, cst.Name):
        return func.value
    if isinstance(func, cst.Attribute):
        return func.attr.value
    return None


def _list_names(node: cst.BaseExpression) -> List[str]:
    """Extract names from [fn1, fn2, function_tool(fn3), SomeTool()] lists."""
    names = []
    if not isinstance(node, (cst.List, cst.Tuple)):
        return names
    for el in node.elements:
        if not isinstance(el, cst.Element):
            continue
        val = el.value
        if isinstance(val, cst.Name):
            names.append(val.value)
        elif isinstance(val, cst.Call):
            cn = _call_name(val)
            if cn in ("function_tool", "wrap"):
                if val.args:
                    a = val.args[0].value
                    if isinstance(a, cst.Name):
                        names.append(a.value)
            elif cn:
                names.append(cn)  # SomeTool() instantiation
    return names


def _base_class_names(bases: Sequence[cst.Arg]) -> List[str]:
    names = []
    for base in bases:
        val = base.value
        if isinstance(val, cst.Name):
            names.append(val.value)
        elif isinstance(val, cst.Attribute):
            names.append(val.attr.value)
    return names


def _has_docstring(node: cst.FunctionDef) -> bool:
    if isinstance(node.body, cst.IndentedBlock) and node.body.body:
        first = node.body.body[0]
        if isinstance(first, cst.SimpleStatementLine):
            for s in first.body:
                if isinstance(s, cst.Expr) and isinstance(
                    s.value, (cst.SimpleString, cst.ConcatenatedString, cst.FormattedString)
                ):
                    return True
    return False


# ═══════════════════════════════════════════════════════════════
# Import analysis (single pass, used by all detectors)
# ═══════════════════════════════════════════════════════════════

@dataclass
class ImportInfo:
    # local_name → (module, original_name)
    names: Dict[str, Tuple[str, str]] = field(default_factory=dict)
    # set of all imported module paths
    modules: Set[str] = field(default_factory=set)

    def has_module_prefix(self, prefix: str) -> bool:
        return any(m.startswith(prefix) for m in self.modules) or any(
            mod.startswith(prefix) for _, (mod, _) in self.names.items()
        )

    def name_comes_from(self, local: str, modules: set) -> bool:
        if local in self.names:
            return self.names[local][0] in modules
        return False


class ImportCollector(cst.CSTVisitor):
    def __init__(self):
        self.info = ImportInfo()

    def visit_ImportFrom(self, node: cst.ImportFrom) -> None:
        module_name = self._module_str(node.module)
        self.info.modules.add(module_name)
        if isinstance(node.names, cst.ImportStar):
            return
        if isinstance(node.names, (list, tuple)):
            for alias in node.names:
                if isinstance(alias, cst.ImportAlias):
                    orig = self._name_str(alias.name)
                    if not orig:
                        continue
                    local = orig
                    if alias.asname and isinstance(alias.asname, cst.AsName):
                        n = alias.asname.name
                        if isinstance(n, cst.Name):
                            local = n.value
                    self.info.names[local] = (module_name, orig)

    def visit_Import(self, node: cst.Import) -> None:
        if isinstance(node.names, (list, tuple)):
            for alias in node.names:
                if isinstance(alias, cst.ImportAlias):
                    self.info.modules.add(self._name_str(alias.name) or "")

    @staticmethod
    def _module_str(mod) -> str:
        if mod is None:
            return ""
        if isinstance(mod, cst.Name):
            return mod.value
        if isinstance(mod, cst.Attribute):
            parts = []
            current = mod
            while isinstance(current, cst.Attribute):
                parts.append(current.attr.value)
                current = current.value
            if isinstance(current, cst.Name):
                parts.append(current.value)
            return ".".join(reversed(parts))
        return ""

    @staticmethod
    def _name_str(node) -> Optional[str]:
        if isinstance(node, cst.Name):
            return node.value
        if isinstance(node, cst.Attribute):
            return node.attr.value
        return None


# ═══════════════════════════════════════════════════════════════
# Detectors — each one ALWAYS runs, emits candidates with evidence
# ═══════════════════════════════════════════════════════════════

class LangGraphDetector(cst.CSTVisitor):
    """@tool (from langgraph/langchain), ToolNode([...])"""
    METADATA_DEPENDENCIES = (PositionProvider,)
    FRAMEWORK = "langgraph"
    TOOL_MODULES = {"langgraph.prebuilt", "langchain_core.tools", "langchain.tools"}

    def __init__(self, file_path: str, imports: ImportInfo):
        self.file_path = file_path
        self.imports = imports
        self.candidates: List[ToolCandidate] = []
        self._import_confirmed = (
            imports.name_comes_from("tool", self.TOOL_MODULES)
            or imports.has_module_prefix("langgraph")
            or imports.has_module_prefix("langchain")
        )

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        for dec in node.decorators:
            if _decorator_name(dec) == "tool":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework=self.FRAMEWORK, symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self._import_confirmed else "low",
                    detection_rule="@tool",
                ))

    def visit_Call(self, node: cst.Call) -> None:
        if _call_name(node) != "ToolNode":
            return
        confirmed = (
            self.imports.name_comes_from("ToolNode", {"langgraph.prebuilt"})
            or self.imports.has_module_prefix("langgraph")
        )
        if node.args:
            names = _list_names(node.args[0].value)
            line = self._line(node)
            for name in names:
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=line,
                    framework=self.FRAMEWORK, symbol=name,
                    boundary="registration",
                    confidence="high" if confirmed else "medium",
                    detection_rule="ToolNode([...])",
                ))
            if not names:
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=line,
                    framework=self.FRAMEWORK, symbol="<dynamic>",
                    boundary="registration", confidence="low",
                    detection_rule="ToolNode(<dynamic>)",
                ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0


class OpenAIAgentsDetector(cst.CSTVisitor):
    """@function_tool, Agent(tools=[...]) from openai agents SDK"""
    METADATA_DEPENDENCIES = (PositionProvider,)
    FRAMEWORK = "openai-sdk"

    def __init__(self, file_path: str, imports: ImportInfo):
        self.file_path = file_path
        self.imports = imports
        self.candidates: List[ToolCandidate] = []
        self._import_confirmed = (
            "agents" in imports.modules
            or imports.has_module_prefix("openai")
            or "function_tool" in imports.names
        )

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        for dec in node.decorators:
            if _decorator_name(dec) == "function_tool":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework=self.FRAMEWORK, symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self._import_confirmed else "medium",
                    detection_rule="@function_tool",
                ))

    def visit_Call(self, node: cst.Call) -> None:
        cn = _call_name(node)
        if cn == "Agent":
            self._extract_tools_kwarg(node, "Agent")
        elif cn == "function_tool":
            if node.args:
                a = node.args[0].value
                if isinstance(a, cst.Name):
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=self._line(node),
                        framework=self.FRAMEWORK, symbol=a.value,
                        boundary="registration",
                        confidence="high" if self._import_confirmed else "medium",
                        detection_rule="function_tool()",
                    ))

    def _extract_tools_kwarg(self, node: cst.Call, ctx: str) -> None:
        for arg in node.args:
            if arg.keyword and isinstance(arg.keyword, cst.Name) and arg.keyword.value == "tools":
                names = _list_names(arg.value)
                line = self._line(node)
                confidence = "high" if self._import_confirmed else "medium"
                for name in names:
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=line,
                        framework=self.FRAMEWORK, symbol=name,
                        boundary="registration", confidence=confidence,
                        detection_rule="tools=[...]",
                    ))
                if not names:
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=line,
                        framework=self.FRAMEWORK, symbol="<dynamic>",
                        boundary="registration", confidence="low",
                        detection_rule=f"{ctx}(tools=<dynamic>)",
                    ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0


class CrewAIDetector(cst.CSTVisitor):
    """@tool (from crewai), BaseTool subclasses, Agent/Task(tools=[...]),
    @before_tool_call gates"""
    METADATA_DEPENDENCIES = (PositionProvider,)
    FRAMEWORK = "crewai"
    BASETOOL_NAMES = {"BaseTool", "StructuredTool"}

    def __init__(self, file_path: str, imports: ImportInfo):
        self.file_path = file_path
        self.imports = imports
        self.candidates: List[ToolCandidate] = []
        self._import_confirmed = imports.has_module_prefix("crewai")

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        for dec in node.decorators:
            dn = _decorator_name(dec)
            if dn == "tool":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework=self.FRAMEWORK, symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self._import_confirmed else "low",
                    detection_rule="@tool",
                ))
            elif dn == "before_tool_call":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework=self.FRAMEWORK, symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self._import_confirmed else "medium",
                    detection_rule="@before_tool_call (gate)",
                    operation_guess="gate", resource_guess="hook",
                    scope_suggestion="hook:before_tool_call",
                ))

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        bases = _base_class_names(node.bases)
        if not any(b in self.BASETOOL_NAMES for b in bases):
            return
        has_run = False
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                if isinstance(stmt, cst.FunctionDef) and stmt.name.value == "_run":
                    has_run = True
                    break
        self.candidates.append(ToolCandidate(
            file=self.file_path, line=self._line(node),
            framework=self.FRAMEWORK, symbol=node.name.value,
            boundary="definition",
            confidence="high" if has_run else "medium",
            detection_rule="BaseTool subclass",
            base_classes=bases,
        ))

    def visit_Call(self, node: cst.Call) -> None:
        cn = _call_name(node)
        if cn not in ("Agent", "Task", "Crew"):
            return
        for arg in node.args:
            if arg.keyword and isinstance(arg.keyword, cst.Name) and arg.keyword.value == "tools":
                names = _list_names(arg.value)
                line = self._line(node)
                confidence = "high" if self._import_confirmed else "medium"
                for name in names:
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=line,
                        framework=self.FRAMEWORK, symbol=name,
                        boundary="registration", confidence=confidence,
                        detection_rule=f"{cn}(tools=[...])",
                    ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0



class MCPDetector(cst.CSTVisitor):
    """@server.tool() decorators on async functions in MCP servers."""
    METADATA_DEPENDENCIES = (PositionProvider,)
    FRAMEWORK = "mcp"

    def __init__(self, file_path: str, imports: ImportInfo):
        self.file_path = file_path
        self.imports = imports
        self.candidates: List[ToolCandidate] = []
        self._import_confirmed = (
            imports.has_module_prefix("mcp")
            or imports.has_module_prefix("fastmcp")
        )

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        for dec in node.decorators:
            # Match @server.tool() — Attribute where attr is "tool"
            dn = _decorator_name(dec)
            if dn == "tool":
                # Check it's method-style: server.tool(), not bare @tool
                raw = dec.decorator
                if isinstance(raw, cst.Call):
                    raw = raw.func
                if isinstance(raw, cst.Attribute):
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=self._line(node),
                        framework=self.FRAMEWORK, symbol=node.name.value,
                        boundary="definition",
                        confidence="high" if self._import_confirmed else "medium",
                        detection_rule="@server.tool()",
                    ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0

class RawToolDetector(cst.CSTVisitor):
    """Fallback: functions with tool-like name prefixes."""
    METADATA_DEPENDENCIES = (PositionProvider,)
    FRAMEWORK = "raw"
    PREFIXES = (
        "fetch_", "search_", "write_", "delete_", "execute_",
        "get_", "create_", "update_", "send_", "read_",
        "query_", "lookup_", "remove_", "upload_", "download_",
    )

    def __init__(self, file_path: str, imports: ImportInfo,
                 seen: Optional[Set[str]] = None):
        self.file_path = file_path
        self.imports = imports
        self.candidates: List[ToolCandidate] = []
        self.seen = seen or set()

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        name = node.name.value
        if name in self.seen:
            return
        if not any(name.startswith(p) for p in self.PREFIXES):
            return
        self.candidates.append(ToolCandidate(
            file=self.file_path, line=self._line(node),
            framework=self.FRAMEWORK, symbol=name,
            boundary="definition",
            confidence="medium" if _has_docstring(node) else "low",
            detection_rule="name heuristic",
        ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0


# ═══════════════════════════════════════════════════════════════
# Triage — scores, deduplicates, resolves conflicts
# ═══════════════════════════════════════════════════════════════

# All registered detectors. Order doesn't matter — triage resolves conflicts.
DETECTOR_REGISTRY: List[type] = [
    LangGraphDetector,
    OpenAIAgentsDetector,
    CrewAIDetector,
    MCPDetector,
]

_CONFIDENCE_SCORE = {"high": 3, "medium": 2, "low": 1}


def _triage(candidates: List[ToolCandidate]) -> List[ToolCandidate]:
    """Score and deduplicate candidates.

    When multiple detectors claim the same (symbol, boundary), the one
    with the highest confidence wins. On ties, the framework whose import
    was confirmed wins. This means:

      - @tool in a crewai file → CrewAI(high) beats LangGraph(low)
      - @tool in a langgraph file → LangGraph(high) beats CrewAI(low)
      - Agent(tools=[...]) in a crewai file → CrewAI(high) beats OpenAI(medium)
      - @function_tool anywhere → only OpenAI emits it, no conflict
      - BaseTool subclass → only CrewAI emits it, no conflict

    Adding a new framework detector never requires changing this function.
    """
    # Group by identity — definitions dedup by (file, symbol, boundary),
    # registrations include line since the same tool can appear in
    # Agent(tools=[...]) and Task(tools=[...]) at different call sites
    groups: Dict[Tuple, List[ToolCandidate]] = {}
    for c in candidates:
        if c.boundary == "registration":
            key = (c.file, c.symbol, c.boundary, c.line)
        else:
            key = (c.file, c.symbol, c.boundary)
        groups.setdefault(key, []).append(c)

    winners = []
    for key, group in groups.items():
        if len(group) == 1:
            winners.append(group[0])
        else:
            # Pick highest confidence. On tie, keep first (stable sort).
            best = max(group, key=lambda c: _CONFIDENCE_SCORE.get(c.confidence, 0))
            winners.append(best)

    return winners


# ═══════════════════════════════════════════════════════════════
# Top-level scanning
# ═══════════════════════════════════════════════════════════════

SKIP_DIRS = {
    "venv", ".venv", "env", ".env", ".git", ".hg", ".svn",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "node_modules", "alembic", "migrations", ".tox", ".nox",
    "dist", "build",
}


def _run_detector(tree: cst.Module, detector_cls: type,
                  file_path: str, imports: ImportInfo,
                  **kwargs) -> List[ToolCandidate]:
    """Run a single detector. Uses MetadataWrapper for line numbers,
    falls back to plain walk() if it fails."""
    det = detector_cls(file_path, imports, **kwargs)
    try:
        wrapper = MetadataWrapper(tree, unsafe_skip_copy=True)
        wrapper.visit(det)
    except Exception:
        det = detector_cls(file_path, imports, **kwargs)
        tree.walk(det)
    return det.candidates


def scan_file(file_path: str, source: str) -> List[ToolCandidate]:
    """Parse one file, run ALL detectors, triage the results."""
    try:
        tree = cst.parse_module(source)
    except cst.ParserSyntaxError:
        return []

    # Single import pass
    ic = ImportCollector()
    MetadataWrapper(tree, unsafe_skip_copy=True).visit(ic)
    imports = ic.info

    # Every detector runs — they self-score based on import evidence
    all_cands: List[ToolCandidate] = []
    for Cls in DETECTOR_REGISTRY:
        all_cands.extend(_run_detector(tree, Cls, file_path, imports))

    # Triage resolves conflicts between detectors
    triaged = _triage(all_cands)

    # Raw detector picks up unclaimed symbols
    claimed = {c.symbol for c in triaged}
    raw_cands = _run_detector(tree, RawToolDetector, file_path, imports, seen=claimed)
    triaged.extend(raw_cands)

    return triaged


def scan_directory(root: str, skip_tests: bool = True) -> List[ToolCandidate]:
    """Walk a project tree, scan all .py files."""
    root_path = Path(root).resolve()
    skip = set(SKIP_DIRS)
    if skip_tests:
        skip.update({"tests", "test", "testing"})

    all_cands = []
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames
                       if d not in skip and not d.endswith(".egg-info")]
        for fname in filenames:
            if not fname.endswith(".py"):
                continue
            full = Path(dirpath) / fname
            rel = str(full.relative_to(root_path))
            try:
                source = full.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            all_cands.extend(scan_file(rel, source))
    return all_cands
