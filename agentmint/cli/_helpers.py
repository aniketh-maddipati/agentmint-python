"""Shared CST helper functions used by all detectors.

Single source of truth for extracting names from LibCST nodes.
Every detector imports from here — no duplicate implementations.
"""
from __future__ import annotations
from typing import List, Optional, Sequence

import libcst as cst


def decorator_name(dec: cst.Decorator) -> Optional[str]:
    """Extract the simple name from a decorator.
    @tool → "tool", @tool() → "tool", @module.tool → "tool"
    """
    node = dec.decorator
    if isinstance(node, cst.Call):
        node = node.func
    if isinstance(node, cst.Name):
        return node.value
    if isinstance(node, cst.Attribute):
        return node.attr.value
    return None


def call_name(node: cst.Call) -> Optional[str]:
    """Extract function name from a Call node.
    ToolNode([...]) → "ToolNode", Agent() → "Agent"
    """
    func = node.func
    if isinstance(func, cst.Name):
        return func.value
    if isinstance(func, cst.Attribute):
        return func.attr.value
    return None


def list_names(node: cst.BaseExpression) -> List[str]:
    """Extract names from [fn1, fn2, SomeTool(), function_tool(fn3)].
    Handles plain names, class instantiations, and wrapper calls.
    """
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
            cn = call_name(val)
            if cn in ("function_tool", "wrap"):
                if val.args:
                    a = val.args[0].value
                    if isinstance(a, cst.Name):
                        names.append(a.value)
            elif cn:
                names.append(cn)
    return names


def base_class_names(bases: Sequence[cst.Arg]) -> List[str]:
    """Extract base class names from a ClassDef's bases."""
    names = []
    for base in bases:
        val = base.value
        if isinstance(val, cst.Name):
            names.append(val.value)
        elif isinstance(val, cst.Attribute):
            names.append(val.attr.value)
    return names


def module_str(mod) -> str:
    """Extract dotted module name from a CST import node."""
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
