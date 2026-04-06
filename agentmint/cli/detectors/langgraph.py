"""LangGraph detector: @tool, ToolNode([...])"""
from __future__ import annotations
from typing import List

import libcst as cst
from libcst.metadata import PositionProvider, MetadataWrapper

from ..candidates import ToolCandidate
from . import BaseDetector, ImportInfo, register
from .._helpers import decorator_name, call_name, list_names


@register
class LangGraphDetector(BaseDetector):
    FRAMEWORK = "langgraph"
    TOOL_MODULES = {"langgraph.prebuilt", "langchain_core.tools", "langchain.tools"}

    def match_imports(self, imports: ImportInfo) -> bool:
        return (
            imports.name_comes_from("tool", self.TOOL_MODULES)
            or imports.has_module_prefix("langgraph")
            or imports.has_module_prefix("langchain")
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
            if decorator_name(dec) == "tool":
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=self._line(node),
                    framework="langgraph", symbol=node.name.value,
                    boundary="definition",
                    confidence="high" if self.confirmed else "low",
                    detection_rule="@tool",
                ))

    def visit_Call(self, node: cst.Call) -> None:
        if call_name(node) != "ToolNode":
            return
        confirmed = (
            self.imports.name_comes_from("ToolNode", {"langgraph.prebuilt"})
            or self.imports.has_module_prefix("langgraph")
        )
        if node.args:
            names = list_names(node.args[0].value)
            line = self._line(node)
            for name in names:
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=line,
                    framework="langgraph", symbol=name,
                    boundary="registration",
                    confidence="high" if confirmed else "medium",
                    detection_rule="ToolNode([...])",
                ))
            if not names:
                self.candidates.append(ToolCandidate(
                    file=self.file_path, line=line,
                    framework="langgraph", symbol="<dynamic>",
                    boundary="registration", confidence="low",
                    detection_rule="ToolNode(<dynamic>)",
                ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0
