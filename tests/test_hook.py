"""Claude Code PreToolUse hook: protocol-level behavior with synthetic credentials.

These tests prove what the script returns for a given event. They do not prove
that a host ran it, and they are not a live enforcement test; see the README's
tested-runtimes table for host verification.
"""

import json
import os
import tempfile
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
    # Unquoted forms of the same shapes above; the quoted form was already denied, the
    # bare CLI/env-assignment form was not.
    "unquoted --password flag": 'mysql -u root --password=hunter22 -e "select 1"',
    "PGPASSWORD assignment": 'PGPASSWORD=hunter22 psql -h db.internal -U app -c "select 1"',
    # Fine-grained GitHub PATs (github_pat_<22 chars>_<59 chars>) are a different shape
    # than the classic ghp_/gho_/ghu_/ghs_/ghr_ tokens and need their own pattern.
    "GitHub fine-grained token-shaped": "GH_TOKEN=github_pat_" + "1" * 22 + "_" + "a" * 59 + " gh api user",
    # The private-key header must match the same BLOCK-suffixed PGP variant the write hook covers.
    "PGP private key block header": 'printf -- "-----BEGIN PGP PRIVATE KEY BLOCK-----" > key.asc',
    # A quoted assignment with a realistic value must still be denied; only the
    # placeholder value itself is allowed (see the ALLOWED cases below).
    "quoted password realistic value": 'echo password="Sup3rSecretValue1"',
}
ALLOWED = {
    "env reference": 'curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user',
    "braced env reference": 'export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID}"',
    "plain command": "ls -la && git status",
    "placeholder": "STRIPE_API_KEY=REPLACE_ME node app.js",
    "short value": 'export TOKEN="abc"',
    "unquoted --password with env var": 'mysql -u root --password=$DB_PASSWORD -e "select 1"',
    "quoted --password with env var": 'mysql -u root --password="$DB_PASSWORD" -e "select 1"',
    "mysql -p with no attached value (prompts)": 'mysql -u root -p -e "select 1"',
    "PGPASSWORD with env var": "PGPASSWORD=$DB_PASSWORD psql -c \"select 1\"",
    "PGPASSWORD with braced env var, quoted": 'PGPASSWORD="${DB_PASSWORD}" psql -c "select 1"',
    "PGPASSWORD placeholder": "PGPASSWORD=REPLACE_ME psql -c \"select 1\"",
    "JSON credential placeholder": '{"api_key": "REPLACE_ME"}',
    "JSON credential short value": '{"token": "abc"}',
    # The placeholder allowance must apply to the quoted assignment forms exactly like
    # the unquoted ones above (mysql --password=, PGPASSWORD=): quoted or not, one rule.
    "quoted password placeholder": 'echo password="REPLACE_ME"',
    "quoted API key placeholder": 'echo api_key="' + "X" * 16 + '"',
    "quoted client secret placeholder": 'echo client_secret="' + "X" * 16 + '"',
    "quoted auth token placeholder": 'echo token="' + "X" * 16 + '"',
    "DATABASE_URL placeholder password": "DATABASE_URL=postgres://user:REPLACE_ME@host/db node app.js",
}


def run_hook(payload: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = {k: v for k, v in os.environ.items() if k != "CATPILOT_EVIDENCE_LOG"}
    full_env.update(env or {})
    return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, timeout=10, env=full_env)


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

    def test_denies_unquoted_and_json_forms_the_split_heuristic_cannot_isolate(self):
        """mysql's attached -p<value> and JSON-style "key": "value" have no '=' to split on."""
        cases = {
            "mysql -p<password> attached": ('mysql -u root -phunter22secret -e "select 1"', "hunter22secret"),
            "JSON api_key property": ('{"api_key": "abcdef1234567890"}', "abcdef1234567890"),
            "JSON password property": ('{"password": "hunter22ABC"}', "hunter22ABC"),
            "JSON token property": ('{"token": "abcdef123456"}', "abcdef123456"),
            "JSON secret property": ('{"secret": "abcdef123456"}', "abcdef123456"),
        }
        for label, (command, secret) in cases.items():
            with self.subTest(label=label):
                proc = run_hook(event(command))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                out = json.loads(proc.stdout)
                self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
                self.assertNotIn(secret, proc.stdout)

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

    def test_evidence_log_records_denials_without_the_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "nested" / "evidence.jsonl"
            env = {"CATPILOT_EVIDENCE_LOG": str(log)}
            payload = json.dumps({"session_id": "sess-123", "tool_name": "Bash", "tool_input": {"command": DENIED["aws example key"]}})
            proc = run_hook(payload, env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual(entry["event"], "deny")
            self.assertEqual(entry["hook"], "pretooluse-secrets")
            self.assertEqual(entry["tool"], "Bash")
            self.assertEqual(entry["session_id"], "sess-123")
            self.assertIn("label", entry)
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", lines[0])
            self.assertNotIn("deploy.sh", lines[0])
            # An allowed command leaves no line; a run without the variable writes nothing.
            run_hook(event(ALLOWED["env reference"]), env)
            self.assertEqual(len(log.read_text().splitlines()), 1)
            run_hook(event(DENIED["aws example key"]))
            self.assertEqual(len(log.read_text().splitlines()), 1)
            # Malformed input is recorded as an input_error alongside the fail-closed exit.
            proc = run_hook("not json", env)
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(json.loads(log.read_text().splitlines()[-1])["event"], "input_error")

    def test_evidence_log_failure_never_changes_the_decision(self):
        # /dev/null is a file, so no directory can be created beneath it and the append fails.
        env = {"CATPILOT_EVIDENCE_LOG": "/dev/null/evidence.jsonl"}
        proc = run_hook(event(DENIED["aws example key"]), env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        proc = run_hook(event(ALLOWED["env reference"]), env)
        self.assertEqual(json.loads(proc.stdout), {})

    def test_settings_example_targets_bash_only(self):
        settings = json.loads((ROOT / "hooks" / "claude-code" / "settings.example.json").read_text())
        entry = settings["hooks"]["PreToolUse"][0]
        self.assertEqual(entry["matcher"], "Bash")
        self.assertIn("pretooluse-secrets.py", entry["hooks"][0]["command"])


if __name__ == "__main__":
    unittest.main()


class HarnessGateTests(unittest.TestCase):
    def test_gate_refuses_literal_credentials_and_allows_references(self):
        from hooks.harness.secret_gate import gate_shell_command, gate_tool_call
        reason = gate_shell_command("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && ./deploy.sh")
        self.assertIsNotNone(reason)
        self.assertIn("AWS access key ID", reason)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", reason)
        self.assertIsNone(gate_shell_command('curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/user'))
        self.assertIsNone(gate_tool_call("shell", {"command": "ls -la"}))
        self.assertIsNotNone(gate_tool_call("run_command", {"command": "psql postgres://app:hunter2@db.internal:5432/prod"}))
        with self.assertRaises(ValueError):
            gate_shell_command(None)

    def test_gate_cli_exit_codes(self):
        script = ROOT / "hooks" / "harness" / "secret_gate.py"
        denied = subprocess.run([sys.executable, str(script), "export", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"], capture_output=True, text=True, timeout=10)
        self.assertEqual(denied.returncode, 2)
        allowed = subprocess.run([sys.executable, str(script), "ls", "-la"], capture_output=True, text=True, timeout=10)
        self.assertEqual(allowed.returncode, 0)
        self.assertIn("allowed", allowed.stdout)

    def test_gate_tool_call_fails_closed_on_missing_or_invalid_command_field(self):
        """A missing/null/non-string command must be refused, not silently treated as ''."""
        from hooks.harness.secret_gate import gate_tool_call
        cases = {
            "missing field": {},
            "null command": {"command": None},
            "non-string command": {"command": 5},
        }
        for label, tool_input in cases.items():
            with self.subTest(label=label):
                reason = gate_tool_call("run_command", tool_input)
                self.assertIsNotNone(reason)
                self.assertIn("command", reason)

    def test_gate_tool_call_custom_field_name(self):
        from hooks.harness.secret_gate import gate_tool_call
        reason = gate_tool_call("run_command", {"cmd": "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"}, field="cmd")
        self.assertIsNotNone(reason)
        self.assertIn("AWS access key ID", reason)
        self.assertIsNone(gate_tool_call("run_command", {"cmd": "ls -la"}, field="cmd"))
        # The default field name is not consulted once a different one is requested.
        missing = gate_tool_call("run_command", {"command": "ls -la"}, field="cmd")
        self.assertIsNotNone(missing)
        self.assertIn("cmd", missing)
