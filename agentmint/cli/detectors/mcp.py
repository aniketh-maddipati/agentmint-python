"""MCP detector: @server.tool() on async functions"""
from __future__ import annotations
from typing import List

import libcst as cst
from libcst.metadata import PositionProvider

from ..candidates import ToolCandidate
from . import BaseDetector, ImportInfo, register
from .._helpers import decorator_name


@register
class MCPDetector(BaseDetector):
    FRAMEWORK = "mcp"

    def match_imports(self, imports: ImportInfo) -> bool:
        return imports.has_module_prefix("mcp") or imports.has_module_prefix("fastmcp")

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
                raw = dec.decorator
                if isinstance(raw, cst.Call):
                    raw = raw.func
                if isinstance(raw, cst.Attribute):
                    self.candidates.append(ToolCandidate(
                        file=self.file_path, line=self._line(node),
                        framework="mcp", symbol=node.name.value,
                        boundary="definition",
                        confidence="high" if self.confirmed else "medium",
                        detection_rule="@server.tool()",
                    ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0
