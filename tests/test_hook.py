"""Claude Code PreToolUse hook: protocol-level behavior with synthetic credentials.

These tests prove what the script returns for a given event. They do not prove
that a host ran it, and they are not a live enforcement test; see the README's
tested-runtimes table for host verification.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-secrets.py"

# Documentation-only or obviously fake values; none is a working credential.
DENIED = {
    "aws example key": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && ./deploy.sh",
    "stripe test-shaped key": "STRIPE_API_KEY=sk_test_" + "x" * 24 + " node app.js",
    "github token-shaped": 'curl -H "Authorization: Bearer ghp_' + "a" * 36 + '" https://api.github.com/user',
    "database url": "psql postgres://app:hunter2@db.internal:5432/prod",
    "private key header": 'printf -- "-----BEGIN RSA PRIVATE KEY-----" > key.pem',
    "literal password": 'mysql -u root --password="hunter22" -e "select 1"',
    "slack token-shaped": "export SLACK_TOKEN=xoxb-1234567890-abcdefghijk",
}
ALLOWED = {
    "env reference": 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user',
    "braced env reference": 'export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}"',
    "plain command": "ls -la && git status",
    "placeholder": "STRIPE_API_KEY=REPLACE_ME node app.js",
    "short value": 'export TOKEN="abc"',
}


def run_hook(payload: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, timeout=10)


def event(command: str, tool: str = "Bash") -> str:
    return json.dumps({"tool_name": tool, "tool_input": {"command": command}})


class HookTests(unittest.TestCase):
    def test_denies_literal_credentials_without_echoing_them(self):
        for label, command in DENIED.items():
            with self.subTest(label=label):
                proc = run_hook(event(command))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                out = json.loads(proc.stdout)
                self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
                secret_fragment = command.split("=")[-1].split()[0].strip('"')[:12]
                self.assertNotIn(secret_fragment, proc.stdout)

    def test_allows_env_references_and_ordinary_commands(self):
        for label, command in ALLOWED.items():
            with self.subTest(label=label):
                proc = run_hook(event(command))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(json.loads(proc.stdout), {})

    def test_never_returns_allow(self):
        for command in list(DENIED.values()) + list(ALLOWED.values()):
            self.assertNotIn('"allow"', run_hook(event(command)).stdout)

    def test_other_tools_are_ignored(self):
        proc = run_hook(json.dumps({"tool_name": "Write", "tool_input": {"content": "AKIAIOSFODNN7EXAMPLE"}}))
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(json.loads(proc.stdout), {})

    def test_malformed_input_fails_closed(self):
        for payload in ("not json", "[]", json.dumps({"tool_name": "Bash", "tool_input": "x"}), json.dumps({"tool_name": "Bash", "tool_input": {"command": 5}})):
            with self.subTest(payload=payload):
                proc = run_hook(payload)
                self.assertEqual(proc.returncode, 2)
                self.assertIn("not allowed", proc.stderr)
                self.assertNotIn(payload, proc.stderr + proc.stdout)

    def test_settings_example_targets_bash_only(self):
        settings = json.loads((ROOT / "hooks" / "claude-code" / "settings.example.json").read_text())
        entry = settings["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Bash")
        self.assertIn("pretooluse-secrets.py", entry["hooks"][0]["command"])


if __name__ == "__main__":
    unittest.main()
