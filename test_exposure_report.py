"""Tests for the new agentmint init exposure report."""

import subprocess
import sys
import unittest

from agentmint.cli.candidates import ToolCandidate
from agentmint.cli.display import print_full_report


class TestExposureReport(unittest.TestCase):
    """Tests for print_full_report()."""

    def _capture(self, candidates):
        """Run print_full_report and capture stdout."""
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            print_full_report(candidates)
        return buf.getvalue()

    def test_empty_candidates(self):
        output = self._capture([])
        self.assertIn("No tool calls found", output)

    def test_single_safe_tool(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="get_weather", boundary="definition",
        )
        output = self._capture([c])
        self.assertIn("get_weather", output)
        self.assertIn("1 tool", output)

    def test_dangerous_tool_shows_all_exposure_lines(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="send_email", boundary="definition",
            operation_guess="exec",
        )
        output = self._capture([c])
        self.assertIn("UNSCANNED", output)
        self.assertIn("UNRESTRICTED", output)
        self.assertIn("NONE", output)  # audit: NONE

    def test_network_tool_mentions_injection_vector(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="mcp",
            symbol="fetch_page", boundary="definition",
            operation_guess="network",
        )
        output = self._capture([c])
        self.assertIn("injection", output.lower())

    def test_summary_shows_zero_counts(self):
        candidates = [
            ToolCandidate(file="a.py", line=1, framework="openai-sdk",
                         symbol="send_email", boundary="definition",
                         operation_guess="exec"),
            ToolCandidate(file="a.py", line=2, framework="openai-sdk",
                         symbol="get_weather", boundary="definition",
                         operation_guess="read"),
        ]
        output = self._capture(candidates)
        self.assertIn("0 inputs scanned", output)
        self.assertIn("0 outputs scanned", output)

    def test_discovery_phase_shows_frameworks(self):
        candidates = [
            ToolCandidate(file="a.py", line=1, framework="openai-sdk",
                         symbol="send_email", boundary="definition",
                         operation_guess="exec"),
            ToolCandidate(file="b.py", line=1, framework="mcp",
                         symbol="fetch_page", boundary="definition",
                         operation_guess="network"),
        ]
        output = self._capture(candidates)
        self.assertIn("SCAN", output)
        self.assertIn("openai-sdk", output)
        self.assertIn("mcp", output)

    def test_enforcement_preview_shows_table(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="charge_customer", boundary="definition",
            operation_guess="write",
        )
        output = self._capture([c])
        self.assertIn("WITH AGENTMINT", output)
        self.assertIn("scanned", output)
        self.assertIn("receipts", output)

    def test_safe_tool_shows_passthrough(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="get_weather", boundary="definition",
            operation_guess="read",
        )
        output = self._capture([c])
        self.assertIn("passthrough", output)

    def test_multiple_files_grouped(self):
        candidates = [
            ToolCandidate(file="agent.py", line=1, framework="openai-sdk",
                         symbol="send_email", boundary="definition",
                         operation_guess="exec"),
            ToolCandidate(file="tools.py", line=5, framework="langgraph",
                         symbol="query_db", boundary="definition",
                         operation_guess="read"),
        ]
        output = self._capture(candidates)
        self.assertIn("agent.py", output)
        self.assertIn("tools.py", output)
        self.assertIn("2 files", output)

    def test_identity_first_occurrence_is_full(self):
        """First dangerous tool gets full audit description."""
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="send_email", boundary="definition",
            operation_guess="exec",
        )
        output = self._capture([c])
        self.assertIn("no receipt, no proof of what happened", output)

    def test_delete_tool_classified_dangerous(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="delete_user", boundary="definition",
            operation_guess="delete",
        )
        output = self._capture([c])
        # Should appear in exposure section with warning marker
        self.assertIn("delete", output.lower())
        self.assertIn("UNSCANNED", output)

    def test_next_steps_shown(self):
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="get_weather", boundary="definition",
        )
        output = self._capture([c])
        self.assertIn("enforce_demo.py", output)
        self.assertIn("agentmint verify", output)

    def test_json_output_unaffected(self):
        """Verify that ToolCandidate.to_dict() still returns candidate dicts."""
        c = ToolCandidate(
            file="test.py", line=10, framework="openai-sdk",
            symbol="send_email", boundary="definition",
        )
        d = c.to_dict()
        self.assertIn("file", d)
        self.assertIn("symbol", d)
        self.assertEqual(d["symbol"], "send_email")


class TestEnforceDemo(unittest.TestCase):
    """Test that enforce_demo.py runs without errors."""

    def test_enforce_demo_runs(self):
        result = subprocess.run(
            [sys.executable, "enforce_demo.py"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, f"enforce_demo failed:\n{result.stderr}")
        self.assertIn("ALLOWED", result.stdout)
        self.assertIn("BLOCKED", result.stdout)
        self.assertIn("Receipt", result.stdout)

    def test_enforce_demo_six_receipts(self):
        result = subprocess.run(
            [sys.executable, "enforce_demo.py"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("6 receipts signed", result.stdout)

    def test_enforce_demo_shows_supply_chain_block(self):
        result = subprocess.run(
            [sys.executable, "enforce_demo.py"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("supply chain", result.stdout.lower())

    def test_enforce_demo_receipt_verified(self):
        result = subprocess.run(
            [sys.executable, "enforce_demo.py"],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("True", result.stdout)  # verified: True


if __name__ == "__main__":
    unittest.main()
