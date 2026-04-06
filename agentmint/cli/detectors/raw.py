"""Raw fallback detector: tool-like function names"""
from __future__ import annotations
from typing import List, Optional, Set

import libcst as cst
from libcst.metadata import PositionProvider

from ..candidates import ToolCandidate
from . import BaseDetector, ImportInfo, register


PREFIXES = (
    "fetch_", "search_", "write_", "delete_", "execute_",
    "get_", "create_", "update_", "send_", "read_",
    "query_", "lookup_", "remove_", "upload_", "download_",
)


@register
class RawToolDetector(BaseDetector):
    FRAMEWORK = "raw"

    def __init__(self, file_path: str, imports: ImportInfo, seen: Optional[Set[str]] = None):
        super().__init__(file_path, imports)
        self.seen = seen or set()

    def match_imports(self, imports: ImportInfo) -> bool:
        return False  # Raw detector never has import confirmation

    def detect(self, tree: cst.Module, wrapper=None) -> List[ToolCandidate]:
        visitor = _Visitor(self.file_path, self.seen)
        if wrapper:
            wrapper.visit(visitor)
        return visitor.candidates


class _Visitor(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, file_path, seen):
        self.file_path = file_path
        self.seen = seen
        self.candidates: List[ToolCandidate] = []

    def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
        name = node.name.value
        if name in self.seen:
            return
        if not any(name.startswith(p) for p in PREFIXES):
            return
        has_doc = _has_docstring(node)
        self.candidates.append(ToolCandidate(
            file=self.file_path, line=self._line(node),
            framework="raw", symbol=name,
            boundary="definition",
            confidence="medium" if has_doc else "low",
            detection_rule="name heuristic",
        ))

    def _line(self, node) -> int:
        try:
            return self.get_metadata(PositionProvider, node).start.line
        except Exception:
            return 0


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
