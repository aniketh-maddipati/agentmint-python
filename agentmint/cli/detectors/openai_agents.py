"""OpenAI Agents SDK detector: @function_tool, Agent(tools=[...])"""
from __future__ import annotations
from typing import List

import libcst as cst
from libcst.metadata import PositionProvider

from ..candidates import ToolCandidate
from . import BaseDetector, ImportInfo, register
from .._helpers import decorator_name, call_name, list_names


@register
class OpenAIAgentsDetector(BaseDetector):
    FRAMEWORK = "openai-sdk"

    def match_imports(self, imports: ImportInfo) -> bool:
        return (
            "agents" in imports.modules
            or imports.has_module_prefix("openai")
            or "function_tool" in imports.names
        )

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
            if decorator_name(dec) == "function_tool":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework="openai-sdk", symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self.confirmed else "medium",
                    detection_rule="@function_tool",
                ))

    def visit_Call(self, node: cst.Call) -> None:
        cn = call_name(node)
        if cn == "Agent":
            self._extract_tools(node)
        elif cn == "function_tool":
            if node.args:
                a = node.args[0].value
                if isinstance(a, cst.Name):
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=self._line(node),
                        framework="openai-sdk", symbol=a.value,
                        boundary="registration",
                        confidence="high" if self.confirmed else "medium",
                        detection_rule="function_tool()",
                    ))

    def _extract_tools(self, node: cst.Call) -> None:
        for arg in node.args:
            if arg.keyword and isinstance(arg.keyword, cst.Name) and arg.keyword.value == "tools":
                names = list_names(arg.value)
                line = self._line(node)
                for name in names:
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=line,
                        framework="openai-sdk", symbol=name,
                        boundary="registration",
                        confidence="high" if self.confirmed else "medium",
                        detection_rule="tools=[...]",
                    ))
                if not names:
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=line,
                        framework="openai-sdk", symbol="<dynamic>",
                        boundary="registration", confidence="low",
                        detection_rule="Agent(tools=<dynamic>)",
                    ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0
