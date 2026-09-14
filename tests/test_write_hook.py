"""Claude Code PreToolUse write hook: protocol-level behavior with synthetic key blocks.

These tests prove what the script returns for a given event. They do not prove
that a host ran it; see evals/reports/ for the recorded host verification.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-write-private-key.py"
# Synthetic: a header line and a body that is not key material.
KEY_BLOCK = "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END RSA PRIVATE KEY-----\n"


def run_hook(payload: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, timeout=10)


def event(tool: str, tool_input: dict) -> str:
    return json.dumps({"tool_name": tool, "tool_input": tool_input})


class WriteHookTests(unittest.TestCase):
    def assert_denied(self, proc: subprocess.CompletedProcess) -> None:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertNotIn("SYNTHETIC-NOT-A-KEY", proc.stdout)
        self.assertNotIn("BEGIN RSA", proc.stdout)

    def assert_no_decision(self, proc: subprocess.CompletedProcess) -> None:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout), {})

    def test_denies_private_key_blocks_in_every_supported_tool(self):
        cases = {
            "Write": {"file_path": "key.pem", "content": KEY_BLOCK},
            "Edit": {"file_path": "config.py", "old_string": "KEY = None", "new_string": f'KEY = """{KEY_BLOCK}"""'},
            "MultiEdit": {"file_path": "a.txt", "edits": [{"old_string": "x", "new_string": "y"}, {"old_string": "z", "new_string": KEY_BLOCK}]},
            "NotebookEdit": {"notebook_path": "n.ipynb", "new_source": KEY_BLOCK},
        }
        for tool, tool_input in cases.items():
            with self.subTest(tool=tool):
                self.assert_denied(run_hook(event(tool, tool_input)))

    def test_header_variants(self):
        for header in ("-----BEGIN PRIVATE KEY-----", "-----BEGIN EC PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----", "-----BEGIN ENCRYPTED PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----"):
            with self.subTest(header=header):
                self.assert_denied(run_hook(event("Write", {"file_path": "k", "content": header + "\nSYNTHETIC-NOT-A-KEY\n"})))

    def test_ordinary_writes_get_no_decision(self):
        for content in ("print('hello')\n", "PRIVATE_KEY_PATH = os.environ['PRIVATE_KEY_PATH']\n", "-----BEGIN CERTIFICATE-----\nnot a private key\n", "See the key in the secret store, never in this file.\n"):
            with self.subTest(content=content[:30]):
                self.assert_no_decision(run_hook(event("Write", {"file_path": "f", "content": content})))

    def test_tools_outside_scope_get_no_decision(self):
        self.assert_no_decision(run_hook(event("Bash", {"command": "printf -- '-----BEGIN RSA PRIVATE KEY-----' > k"})))
        self.assert_no_decision(run_hook(event("Read", {"file_path": "key.pem"})))

    def test_malformed_input_exits_two_without_echoing(self):
        for payload in ("not json", "[]", json.dumps({"tool_name": "Write", "tool_input": "x"}), json.dumps({"tool_name": "Write", "tool_input": {"content": None}}), json.dumps({"tool_name": "MultiEdit", "tool_input": {"edits": "bad"}})):
            with self.subTest(payload=payload[:20]):
                proc = run_hook(payload)
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")
                self.assertNotIn("bad", proc.stderr)

    def test_oversized_input_exits_two(self):
        proc = run_hook(json.dumps({"tool_name": "Write", "tool_input": {"file_path": "f", "content": "a" * 1_100_000}}))
        self.assertEqual(proc.returncode, 2)
