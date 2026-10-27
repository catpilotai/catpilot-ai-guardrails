"""Tests for tools/evidence_summary.py and syslog emission in hooks and MCP server."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import evidence_summary

ROOT = Path(__file__).resolve().parents[1]


class EvidenceSummaryTests(unittest.TestCase):
    def test_summarizes_hooks_and_mcp_events_in_markdown_and_json(self):
        events = [
            {"ts": "2026-09-20T10:00:00+00:00", "source": "claude-code-hook", "hook": "pretooluse-secrets", "event": "deny", "tool": "Bash", "label": "AWS access key ID", "session_id": "s1"},
            {"ts": "2026-09-20T10:01:00+00:00", "source": "claude-code-hook", "hook": "pretooluse-write-private-key", "event": "deny", "tool": "Write", "label": "private-key-block", "session_id": "s1"},
            {"ts": "2026-09-20T10:02:00+00:00", "source": "claude-code-hook", "hook": "pretooluse-destructive-ops", "event": "deny", "tool": "Bash", "label": "terraform auto-approve apply or destroy", "session_id": "s2"},
            {"ts": "2026-09-20T10:03:00+00:00", "source": "claude-code-hook", "hook": "pretooluse-secrets", "event": "input_error"},
            {"ts": "2026-09-20T10:04:00+00:00", "source": "mcp-server", "release": "2026.09.18", "tool": "list_approved", "category": "hosting", "policy_status": "approved", "unknown_policy": False, "error": None},
            {"ts": "2026-09-20T10:05:00+00:00", "source": "mcp-server", "release": "2026.09.18", "tool": "check_plan", "outcome": "requires_review", "ask_a_human": True, "fields": ["audience", "data_classes"], "policy_status": "approved", "unknown_policy": False, "error": None},
            {"ts": "2026-09-20T10:06:00+00:00", "source": "mcp-server", "release": "2026.09.18", "tool": "check_plan", "outcome": "permitted", "ask_a_human": False, "fields": ["audience", "hosting"], "policy_status": "none", "unknown_policy": True, "error": None},
        ]
        lines = [json.dumps(e) for e in events] + ["not valid json", ""]
        summary = evidence_summary.summarize_lines(lines)
        self.assertEqual(summary["total_events"], 7)
        self.assertEqual(summary["invalid_lines"], 1)
        self.assertEqual(summary["hooks"]["total_denials"], 3)
        self.assertEqual(summary["hooks"]["unique_sessions_with_denials"], 2)
        self.assertEqual(summary["hooks"]["total_input_errors"], 1)
        self.assertEqual(summary["hooks"]["denials_by_label"]["AWS access key ID"], 1)
        self.assertEqual(summary["mcp_server"]["total_calls"], 3)
        self.assertEqual(summary["mcp_server"]["unknown_policy"], {"true": 1, "false": 2})
        self.assertEqual(summary["mcp_server"]["check_plan"]["outcomes"], {"permitted": 1, "requires_review": 1})
        self.assertEqual(summary["mcp_server"]["check_plan"]["ask_a_human"], {"true": 1, "false": 1})
        self.assertEqual(summary["mcp_server"]["check_plan"]["supplied_fields"]["audience"], 2)

        md = evidence_summary.render_markdown(summary)
        self.assertIn("# Catpilot Evidence Summary", md)
        self.assertIn("`AWS access key ID`", md)
        self.assertIn("`terraform auto-approve apply or destroy`", md)
        self.assertIn("`requires_review`", md)

    def test_cli_json_and_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "evidence.jsonl"
            log.write_text(json.dumps({"ts": "2026-09-20T10:00:00+00:00", "source": "claude-code-hook", "hook": "pretooluse-secrets", "event": "deny", "tool": "Bash", "label": "AWS access key ID"}) + "\n")
            self.assertEqual(evidence_summary.main(["--format", "json", str(log)]), 0)
            self.assertEqual(evidence_summary.main([str(Path(tmp) / "missing.jsonl")]), 2)

    def test_syslog_sink_receives_content_free_event_and_never_fails_decision(self):
        from hooks.harness import secret_gate
        from hooks.harness import destructive_gate
        emitted: list[tuple[object, str]] = []

        class FakeSysLogHandler:
            def __init__(self, address):
                self.address = address

            def emit(self, record):
                emitted.append((self.address, record.getMessage()))

            def close(self):
                pass

        with mock.patch("logging.handlers.SysLogHandler", FakeSysLogHandler), \
             mock.patch.dict(os.environ, {"CATPILOT_EVIDENCE_SYSLOG": "127.0.0.1:5514"}, clear=False):
            reason = secret_gate.gate_shell_command("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
            self.assertIsNotNone(reason)
            w_reason = secret_gate.gate_file_write("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE")
            self.assertIsNotNone(w_reason)
            d_reason = destructive_gate.gate_destructive_command("terraform apply -auto-approve")
            self.assertIsNotNone(d_reason)

        self.assertEqual(len(emitted), 3)
        for address, msg in emitted:
            self.assertEqual(address, ("127.0.0.1", 5514))
            self.assertTrue(msg.startswith("catpilot-guardrails: {"))
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", msg)
            self.assertNotIn("-auto-approve", msg.split('"label":')[0])

        # Even if SysLogHandler raises, the decision still succeeds (fails closed on the command, never crashes).
        with mock.patch("logging.handlers.SysLogHandler", side_effect=OSError("syslog down")), \
             mock.patch.dict(os.environ, {"CATPILOT_EVIDENCE_SYSLOG": "1"}, clear=False):
            self.assertIsNotNone(secret_gate.gate_shell_command("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))


if __name__ == "__main__":
    unittest.main()
