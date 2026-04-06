"""CrewAI detector: @tool, BaseTool, Agent/Task(tools=[...]), @before_tool_call"""
from __future__ import annotations
from typing import List, Sequence

import libcst as cst
from libcst.metadata import PositionProvider

from ..candidates import ToolCandidate
from . import BaseDetector, ImportInfo, register
from .._helpers import decorator_name, call_name, list_names, base_class_names


BASETOOL_NAMES = {"BaseTool", "StructuredTool"}


@register
class CrewAIDetector(BaseDetector):
    FRAMEWORK = "crewai"

    def match_imports(self, imports: ImportInfo) -> bool:
        return imports.has_module_prefix("crewai")

    def detect(self, tree: cst.Module, wrapper=None) -> List[ToolCandidate]:
        visitor = _Visitor(self.file_path, self.imports, self._import_confirmed)
        if wrapper:
            wrapper.visit(visitor)
        return visitor.candidates


class _Visitor(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, file_path, imports, confirmed):
        self.file_path = file_path
        self.imports = imports
        self.confirmed = confirmed
        self.candidates: List[ToolCandidate] = []

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        for dec in node.decorators:
            dn = decorator_name(dec)
            if dn == "tool":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework="crewai", symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self.confirmed else "low",
                    detection_rule="@tool",
                ))
            elif dn == "before_tool_call":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework="crewai", symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self.confirmed else "medium",
                    detection_rule="@before_tool_call (gate)",
                    operation_guess="gate", resource_guess="hook",
                    scope_suggestion="hook:before_tool_call",
                ))

    def visit_ClassDef(self, node: cst.ClassDef) -> None:
        bases = base_class_names(node.bases)
        if not any(b in BASETOOL_NAMES for b in bases):
            return
        has_run = False
        if isinstance(node.body, cst.IndentedBlock):
            for stmt in node.body.body:
                if isinstance(stmt, cst.FunctionDef) and stmt.name.value == "_run":
                    has_run = True
                    break
        self.candidates.append(ToolCandidate(
            file=self.file_path, line=self._line(node),
            framework="crewai", symbol=node.name.value,
            boundary="definition",
            confidence="high" if has_run else "medium",
            detection_rule="BaseTool subclass",
            base_classes=bases,
        ))

    def visit_Call(self, node: cst.Call) -> None:
        cn = call_name(node)
        if cn not in ("Agent", "Task", "Crew"):
            return
        for arg in node.args:
            if arg.keyword and isinstance(arg.keyword, cst.Name) and arg.keyword.value == "tools":
                names = list_names(arg.value)
                line = self._line(node)
                for name in names:
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=line,
                        framework="crewai", symbol=name,
                        boundary="registration",
                        confidence="high" if self.confirmed else "medium",
                        detection_rule=f"{cn}(tools=[...])",
                    ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0
