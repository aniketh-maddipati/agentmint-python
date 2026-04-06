"""
test_cli_scanner.py — Tests for agentmint init scanner.

Validates all framework detectors against fixture files that mirror
the real integration patterns from examples/ and docs/.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from agentmint.cli.candidates import (
    ToolCandidate, guess_operation, guess_resource, suggest_scope,
)
from agentmint.cli.scanner import scan_file
from agentmint.cli.patcher import generate_yaml, generate_patch_instructions

FIXTURES = Path(__file__).parent / "cli_fixtures"


def load(name: str) -> str:
    return (FIXTURES / name).read_text()


def find(candidates: List[ToolCandidate], symbol: str,
         boundary: Optional[str] = None) -> Optional[ToolCandidate]:
    for c in candidates:
        if c.symbol == symbol:
            if boundary is None or c.boundary == boundary:
                return c
    return None


# ═══════════════════════════════════════════════════════════════
# Heuristic tests
# ═══════════════════════════════════════════════════════════════

class TestHeuristics:
    @pytest.mark.parametrize("name,expected", [
        ("search_docs", "read"),
        ("fetch_market_data", "read"),
        ("save_results", "write"),
        ("delete_old_index", "delete"),
        ("execute_trade", "exec"),
        ("send_notification", "exec"),
        ("http_request", "network"),
        ("helper_function", "unknown"),
        ("process_data", "unknown"),
    ])
    def test_guess_operation(self, name, expected):
        assert guess_operation(name) == expected

    @pytest.mark.parametrize("name,expected", [
        ("search_docs", "docs"),
        ("fetch_market_data", "market:data"),
        ("save_results", "results"),
        ("delete_old_index", "old:index"),
        ("execute_trade", "trade"),
        ("S3Reader", "s3:reader"),
        ("FileWriterTool", "file:writer"),
        ("helper_function", "*"),
    ])
    def test_guess_resource(self, name, expected):
        assert guess_resource(name) == expected

    def test_scope_uses_tool_prefix(self):
        """Scopes should match SDK's tool:<name> format."""
        assert suggest_scope("search_docs", "read", "docs") == "tool:search_docs"
        assert suggest_scope("execute_trade", "exec", "trade") == "tool:execute_trade"


# ═══════════════════════════════════════════════════════════════
# LangGraph
# ═══════════════════════════════════════════════════════════════

class TestLangGraph:
    @pytest.fixture
    def candidates(self):
        return scan_file("langgraph_agent.py", load("langgraph_agent.py"))

    def test_finds_tool_definitions(self, candidates):
        for name in ["search_docs", "save_results", "delete_old_index"]:
            c = find(candidates, name, "definition")
            assert c is not None, f"Missing: {name}"
            assert c.framework == "langgraph"
            assert c.confidence == "high"
            assert c.detection_rule == "@tool"

    def test_finds_toolnode_registrations(self, candidates):
        regs = [c for c in candidates if c.boundary == "registration"]
        reg_names = {c.symbol for c in regs}
        assert {"search_docs", "save_results", "delete_old_index"} <= reg_names
        for c in regs:
            if c.symbol in ("search_docs", "save_results", "delete_old_index"):
                assert c.detection_rule == "ToolNode([...])"

    def test_no_false_positives(self, candidates):
        lg_symbols = {c.symbol for c in candidates if c.framework == "langgraph"}
        assert "helper_function" not in lg_symbols

    def test_scope_guesses(self, candidates):
        c = find(candidates, "search_docs")
        assert c.operation_guess == "read"
        c = find(candidates, "save_results")
        assert c.operation_guess == "write"
        c = find(candidates, "delete_old_index")
        assert c.operation_guess == "delete"


# ═══════════════════════════════════════════════════════════════
# OpenAI Agents SDK
# ═══════════════════════════════════════════════════════════════

class TestOpenAI:
    @pytest.fixture
    def candidates(self):
        return scan_file("openai_agent.py", load("openai_agent.py"))

    def test_finds_function_tool_decorators(self, candidates):
        """@function_tool decorated functions should be detected."""
        for name in ["get_weather", "lookup_account", "send_notification"]:
            c = find(candidates, name, "definition")
            assert c is not None, f"Missing @function_tool definition: {name}"
            assert c.framework == "openai-sdk"
            assert c.detection_rule == "@function_tool"

    def test_finds_agent_registrations(self, candidates):
        """Agent(tools=[...]) should detect all registered tools."""
        regs = [c for c in candidates
                if c.boundary == "registration" and c.detection_rule == "tools=[...]"]
        reg_names = {c.symbol for c in regs}
        # main_agent has get_weather, lookup_account
        # trading_agent has fetch_market_data, execute_trade
        # notification_agent has send_notification
        assert {"get_weather", "lookup_account", "fetch_market_data",
                "execute_trade", "send_notification"} <= reg_names

    def test_all_openai_framework(self, candidates):
        """Everything in this file should be openai-sdk or raw."""
        for c in candidates:
            assert c.framework in ("openai-sdk", "raw"), f"{c.symbol} is {c.framework}"


# ═══════════════════════════════════════════════════════════════
# CrewAI
# ═══════════════════════════════════════════════════════════════

class TestCrewAI:
    @pytest.fixture
    def candidates(self):
        return scan_file("crewai_agent.py", load("crewai_agent.py"))

    def test_finds_tool_decorator(self, candidates):
        c = find(candidates, "search_web", "definition")
        assert c is not None
        assert c.framework == "crewai"
        assert c.detection_rule == "@tool"

    def test_finds_basetool_subclasses(self, candidates):
        for cls_name in ["S3Reader", "FileWriterTool"]:
            c = find(candidates, cls_name, "definition")
            assert c is not None, f"Missing BaseTool: {cls_name}"
            assert c.framework == "crewai"
            assert c.detection_rule == "BaseTool subclass"
            assert "BaseTool" in c.base_classes

    def test_basetool_with_run_is_high_confidence(self, candidates):
        c = find(candidates, "S3Reader", "definition")
        assert c.confidence == "high"  # has _run()

    def test_finds_agent_registration(self, candidates):
        regs = [c for c in candidates
                if c.boundary == "registration" and c.framework == "crewai"]
        reg_names = {c.symbol for c in regs}
        assert "search_web" in reg_names

    def test_finds_before_tool_call_gate(self, candidates):
        c = find(candidates, "gate", "definition")
        assert c is not None
        assert c.detection_rule == "@before_tool_call (gate)"

    def test_task_registration(self, candidates):
        """Task(tools=[...]) should be detected as a separate registration site."""
        regs = [c for c in candidates
                if c.boundary == "registration"
                and c.detection_rule == "Task(tools=[...])"]
        assert len(regs) > 0
        assert regs[0].symbol == "FileWriterTool"
        # Should be on a different line than the Agent registration
        agent_regs = [c for c in candidates
                      if c.boundary == "registration"
                      and c.detection_rule == "Agent(tools=[...])"
                      and c.symbol == "FileWriterTool"]
        assert agent_regs[0].line != regs[0].line


# ═══════════════════════════════════════════════════════════════
# Raw / fallback detector
# ═══════════════════════════════════════════════════════════════

class TestRawDetector:
    @pytest.fixture
    def candidates(self):
        return scan_file("edge_cases.py", load("edge_cases.py"))

    def test_catches_tool_prefixed_functions(self, candidates):
        c = find(candidates, "fetch_user_profile")
        assert c is not None
        assert c.framework == "raw"

        c = find(candidates, "delete_account")
        assert c is not None
        assert c.framework == "raw"

    def test_skips_non_tool_functions(self, candidates):
        assert find(candidates, "process_data") is None

    def test_skips_non_tool_classes(self, candidates):
        assert find(candidates, "HelperClass") is None

    def test_docstring_boosts_confidence(self, candidates):
        c = find(candidates, "fetch_user_profile")
        assert c.confidence == "medium"  # has docstring


# ═══════════════════════════════════════════════════════════════
# Deduplication
# ═══════════════════════════════════════════════════════════════

class TestDeduplication:
    def test_no_duplicates(self):
        source = load("langgraph_agent.py")
        candidates = scan_file("test.py", source)
        seen = set()
        for c in candidates:
            key = (c.file, c.symbol, c.boundary)
            assert key not in seen, f"Duplicate: {key}"
            seen.add(key)


# ═══════════════════════════════════════════════════════════════
# YAML generation
# ═══════════════════════════════════════════════════════════════

class TestYAML:
    def test_generates_valid_yaml(self):
        import yaml
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        content = generate_yaml(candidates)
        parsed = yaml.safe_load(content)
        assert parsed["version"] == 1
        assert parsed["mode"] == "audit"
        assert "search_docs" in parsed["tools"]
        assert parsed["tools"]["search_docs"]["scope"] == "tool:search_docs"
        assert parsed["tools"]["search_docs"]["framework"] == "langgraph"

    def test_yaml_contains_only_facts(self):
        """YAML should contain provable facts, no heuristic guesses."""
        import yaml
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        content = generate_yaml(candidates)
        parsed = yaml.safe_load(content)
        for name, tool in parsed["tools"].items():
            # Every tool has scope, framework, file, line — all facts
            assert "scope" in tool
            assert "framework" in tool
            assert "file" in tool
            assert "line" in tool
            # No rate_limit guesses in v0
            assert "rate_limit" not in tool


# ═══════════════════════════════════════════════════════════════
# Patch instructions
# ═══════════════════════════════════════════════════════════════

class TestPatchInstructions:
    def test_definitions_get_notarise(self):
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        instructions = generate_patch_instructions(candidates)
        defs = [i for i in instructions if i.get("action") == "add_notarise_to_body"]
        symbols = {i["symbol"] for i in defs}
        assert "search_docs" in symbols

    def test_registrations_get_scope(self):
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        instructions = generate_patch_instructions(candidates)
        regs = [i for i in instructions if i.get("action") == "add_to_plan_scope"]
        assert len(regs) > 0

    def test_low_confidence_gets_manual_review(self):
        candidates = [ToolCandidate(
            file="test.py", line=1, framework="raw",
            symbol="ambiguous", boundary="definition",
            confidence="low", detection_rule="name heuristic",
        )]
        instructions = generate_patch_instructions(candidates)
        assert instructions[0]["action"] == "manual_review"


# ═══════════════════════════════════════════════════════════════
# MCP detector
# ═══════════════════════════════════════════════════════════════

class TestMCP:
    @pytest.fixture
    def candidates(self):
        return scan_file("mcp_agent.py", load("mcp_agent.py"))

    def test_finds_server_tool_decorators(self, candidates):
        for name in ["read_receipt", "list_receipts", "verify_chain"]:
            c = find(candidates, name, "definition")
            assert c is not None, f"Missing MCP tool: {name}"
            assert c.framework == "mcp"
            assert c.detection_rule == "@server.tool()"
            assert c.confidence == "high"

    def test_no_false_positives(self, candidates):
        assert find(candidates, "helper") is None or \
            find(candidates, "helper").framework != "mcp"

    def test_scope_guesses(self, candidates):
        c = find(candidates, "read_receipt")
        assert c.operation_guess == "read"
        c = find(candidates, "list_receipts")
        assert c.operation_guess == "read"
        c = find(candidates, "verify_chain")
        assert c.operation_guess == "unknown"


# ═══════════════════════════════════════════════════════════════
# Extended CrewAI coverage
# ═══════════════════════════════════════════════════════════════

class TestCrewAIExtended:
    def test_crew_tools_registration(self):
        """Crew(agents=[...]) doesn't directly register tools,
        but Agent(tools=[...]) inside it should still be detected."""
        source = '''
from crewai import Agent, Crew

def my_search(q): return q

agent = Agent(role="r", tools=[my_search])
crew = Crew(agents=[agent])
'''
        candidates = scan_file("test.py", source)
        regs = [c for c in candidates
                if c.symbol == "my_search" and c.boundary == "registration"]
        assert len(regs) == 1
        assert regs[0].framework == "crewai"

    def test_basetool_with_args_schema(self):
        """BaseTool with Pydantic args_schema should still be detected."""
        source = '''
from crewai.tools import BaseTool
from pydantic import BaseModel

class MyInput(BaseModel):
    query: str

class SearchTool(BaseTool):
    name: str = "search"
    description: str = "Search"
    args_schema: type = MyInput

    def _run(self, query: str) -> str:
        return query
'''
        candidates = scan_file("test.py", source)
        c = find(candidates, "SearchTool", "definition")
        assert c is not None
        assert c.framework == "crewai"
        assert c.confidence == "high"

    def test_structured_tool_subclass(self):
        """StructuredTool should also be detected."""
        source = '''
from crewai.tools import StructuredTool

class MyTool(StructuredTool):
    name: str = "my_tool"
    def _run(self): pass
'''
        candidates = scan_file("test.py", source)
        c = find(candidates, "MyTool", "definition")
        assert c is not None
        assert c.detection_rule == "BaseTool subclass"

    def test_multiple_agents_separate_registrations(self):
        """Each Agent(tools=[...]) call is a separate registration site."""
        source = '''
from crewai import Agent

def t1(): pass
def t2(): pass

a1 = Agent(role="a", tools=[t1])
a2 = Agent(role="b", tools=[t1, t2])
'''
        candidates = scan_file("test.py", source)
        t1_regs = [c for c in candidates
                   if c.symbol == "t1" and c.boundary == "registration"]
        # t1 registered in both Agent calls at different lines
        assert len(t1_regs) == 2
        assert t1_regs[0].line != t1_regs[1].line


# ═══════════════════════════════════════════════════════════════
# E2E: scan → yaml → notary produces receipts
# ═══════════════════════════════════════════════════════════════

class TestEndToEnd:
    """Verify that the scan output can actually drive the real AgentMint SDK.
    This tests the full loop: scan detects tools → yaml has correct scopes →
    those scopes work with the real Notary to produce valid receipts."""

    def test_scanned_scopes_work_with_notary(self):
        """Scopes from scan results should be valid for Notary.create_plan."""
        from agentmint.notary import Notary

        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        scopes = [c.scope_suggestion for c in candidates
                  if c.symbol != "<dynamic>"]

        notary = Notary()
        plan = notary.create_plan(
            user="test@test.com",
            action="test-scan",
            scope=scopes,
            delegates_to=["test-agent"],
            ttl_seconds=60,
        )
        assert plan is not None
        assert list(plan.scope) == scopes

    def test_scanned_tools_produce_valid_receipts(self):
        """Each scanned tool scope should produce a verifiable receipt."""
        from agentmint.notary import Notary

        candidates = scan_file("openai_agent.py", load("openai_agent.py"))
        definitions = [c for c in candidates
                       if c.boundary == "definition" and c.confidence == "high"]

        notary = Notary()
        scopes = [c.scope_suggestion for c in definitions]
        plan = notary.create_plan(
            user="ops@company.com",
            action="agent-ops",
            scope=scopes,
            delegates_to=["test-agent"],
        )

        # Simulate each tool producing a receipt
        for c in definitions:
            receipt = notary.notarise(
                action=c.scope_suggestion,
                agent="test-agent",
                plan=plan,
                evidence={"tool": c.symbol, "test": True},
            )
            assert receipt is not None
            assert notary.verify_receipt(receipt)
            assert receipt.in_policy

    def test_yaml_round_trip(self):
        """Generated YAML should be loadable and contain all tool scopes."""
        import yaml as pyyaml
        from agentmint.cli.patcher import generate_yaml

        candidates = scan_file("crewai_agent.py", load("crewai_agent.py"))
        yaml_str = generate_yaml(candidates)
        parsed = pyyaml.safe_load(yaml_str)

        # All non-dynamic symbols should be in the yaml
        expected_symbols = {c.symbol for c in candidates
                           if not c.symbol.startswith("<")}
        yaml_symbols = set(parsed["tools"].keys())
        assert expected_symbols <= yaml_symbols

        # Global mode should be audit
        assert parsed["mode"] == "audit"

    def test_write_produces_working_import(self):
        """After --write, the injected import should be usable."""
        from agentmint.cli.patcher import generate_import_patch
        import ast

        source = load("langgraph_agent.py")
        patched = generate_import_patch(source)

        # Parse and verify the import is there
        tree = ast.parse(patched)
        import_names = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                if node.module and "agentmint" in node.module:
                    import_names.extend(a.name for a in node.names)
        assert "Notary" in import_names

    def test_out_of_scope_tool_blocked(self):
        """A tool NOT in the plan scope should produce an out-of-policy receipt."""
        from agentmint.notary import Notary

        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        # Only allow search_docs in scope
        notary = Notary()
        plan = notary.create_plan(
            user="ops@company.com",
            action="agent-ops",
            scope=["tool:search_docs"],
            delegates_to=["test-agent"],
        )

        # save_results is NOT in scope — should be out of policy
        receipt = notary.notarise(
            action="tool:save_results",
            agent="test-agent",
            plan=plan,
            evidence={"tool": "save_results"},
        )
        assert not receipt.in_policy


class TestQuickstart:
    def test_generates_runnable_quickstart(self):
        from agentmint.cli.patcher import generate_quickstart
        import ast
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        script = generate_quickstart(candidates)
        assert script != ""
        ast.parse(script)  # must be valid python

    def test_quickstart_references_real_tool(self):
        from agentmint.cli.patcher import generate_quickstart
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        script = generate_quickstart(candidates)
        # Should reference an actual tool from the scan
        assert any(c.symbol in script for c in candidates
                   if not c.symbol.startswith("<"))

    def test_quickstart_contains_notary(self):
        from agentmint.cli.patcher import generate_quickstart
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        script = generate_quickstart(candidates)
        assert "Notary()" in script
        assert "notarise" in script
        assert "verify_receipt" in script or "verify" in script

    def test_shield_check_generated(self):
        from agentmint.cli.patcher import generate_shield_check
        candidates = scan_file("langgraph_agent.py", load("langgraph_agent.py"))
        snippet = generate_shield_check(candidates)
        assert "from agentmint.shield import scan" in snippet
        assert "search_docs" in snippet

    def test_empty_candidates_no_quickstart(self):
        from agentmint.cli.patcher import generate_quickstart
        assert generate_quickstart([]) == ""

