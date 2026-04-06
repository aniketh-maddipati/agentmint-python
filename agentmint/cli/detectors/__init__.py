"""
Detector plugin system for agentmint init.

Each detector is a Python file in this directory (or in ~/.agentmint/detectors/)
that defines a class inheriting from BaseDetector. The scanner discovers and
runs all detectors automatically.

Adding a new framework:
  1. Create a .py file in this directory
  2. Define a class that inherits from BaseDetector
  3. Implement detect() and optionally match_imports()
  4. That's it — scanner picks it up on next run

Example (myframework.py):

    from agentmint.cli.detectors import BaseDetector, register

    @register
    class MyFrameworkDetector(BaseDetector):
        FRAMEWORK = "myframework"

        def match_imports(self, imports):
            return imports.has_module_prefix("myframework")

        def detect(self, tree, file_path, imports):
            # Use LibCST visitors or direct tree traversal
            # Return List[ToolCandidate]
            ...
"""
from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Optional, Set, Type

import libcst as cst
from libcst.metadata import PositionProvider

# Registry of all detector classes
_REGISTRY: Dict[str, Type["BaseDetector"]] = {}


def register(cls: Type["BaseDetector"]) -> Type["BaseDetector"]:
    """Decorator to register a detector class."""
    _REGISTRY[cls.FRAMEWORK] = cls
    return cls


def get_registry() -> Dict[str, Type["BaseDetector"]]:
    """Return all registered detectors. Triggers auto-discovery on first call."""
    if not _REGISTRY:
        _discover_builtin_detectors()
        _discover_user_detectors()
    return dict(_REGISTRY)


def _discover_builtin_detectors():
    """Import all .py files in this directory to trigger @register."""
    package_dir = Path(__file__).parent
    for finder, name, ispkg in pkgutil.iter_modules([str(package_dir)]):
        if not name.startswith("_"):
            importlib.import_module(f".{name}", package=__package__)


def _discover_user_detectors():
    """Import detectors from ~/.agentmint/detectors/ if it exists."""
    user_dir = Path.home() / ".agentmint" / "detectors"
    if not user_dir.is_dir():
        return
    import sys
    sys.path.insert(0, str(user_dir))
    for py_file in user_dir.glob("*.py"):
        if not py_file.name.startswith("_"):
            try:
                importlib.import_module(py_file.stem)
            except Exception:
                pass  # Skip broken user detectors silently


class ImportInfo:
    """Import analysis results — shared across all detectors."""

    def __init__(self):
        self.names: Dict[str, tuple] = {}  # local_name → (module, original)
        self.modules: Set[str] = set()

    def has_module_prefix(self, prefix: str) -> bool:
        return any(m.startswith(prefix) for m in self.modules) or any(
            mod.startswith(prefix) for _, (mod, _) in self.names.items()
        )

    def name_comes_from(self, local: str, modules: set) -> bool:
        if local in self.names:
            return self.names[local][0] in modules
        return False


class BaseDetector(ABC):
    """Base class for all framework detectors.

    Subclasses must define:
      FRAMEWORK: str — the framework name (e.g. "langgraph")
      detect() — the detection logic

    Optionally override:
      match_imports() — return True if this file uses your framework
                        (affects confidence, not whether detector runs)
    """
    FRAMEWORK: str = ""
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, file_path: str, imports: ImportInfo):
        self.file_path = file_path
        self.imports = imports
        self._import_confirmed = self.match_imports(imports)

    def match_imports(self, imports: ImportInfo) -> bool:
        """Override to check if this file imports from your framework.
        Returns True → confidence boost for all candidates from this detector."""
        return False

    @abstractmethod
    def detect(self, tree: cst.Module) -> List:
        """Run detection on a parsed CST tree. Return List[ToolCandidate]."""
        ...

    def _confidence(self) -> str:
        """Default confidence based on import match."""
        return "high" if self._import_confirmed else "low"

    def _line(self, node, metadata_wrapper=None) -> int:
        """Extract line number from a CST node."""
        try:
            if metadata_wrapper:
                return metadata_wrapper.resolve(PositionProvider)[node].start.line
        except Exception:
            pass
        return 0
