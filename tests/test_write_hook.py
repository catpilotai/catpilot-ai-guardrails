"""Claude Code PreToolUse write hook: protocol-level behavior with synthetic key blocks and literal credentials.

These tests prove what the script returns for a given event. They do not prove
that a host ran it; see evals/reports/ for the recorded host verification.
"""

import json
import os
import tempfile
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-write-secrets.py"
LEGACY_HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-write-private-key.py"
# Built at run time so no credential-shaped literal sits in this file.
SYNTHETIC_GITHUB_TOKEN = "ghp" + "_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3z5A"
# Synthetic: a header line and a body that is not key material.
KEY_BLOCK = "-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n-----END RSA PRIVATE KEY-----\n"


def run_hook(payload: str, env: dict | None = None) -> subprocess.CompletedProcess:
    full_env = {k: v for k, v in os.environ.items() if k not in ("CATPILOT_EVIDENCE_LOG", "CATPILOT_EVIDENCE_SYSLOG")}
    full_env.update(env or {})
    return subprocess.run([sys.executable, str(HOOK)], input=payload, capture_output=True, text=True, timeout=10, env=full_env)


def event(tool: str, tool_input: dict) -> str:
    return json.dumps({"tool_name": tool, "tool_input": tool_input})


class WriteHookTests(unittest.TestCase):
    def assert_denied(self, proc: subprocess.CompletedProcess, forbidden_fragment: str = "SYNTHETIC-NOT-A-KEY") -> None:
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "PreToolUse")
        self.assertNotIn(forbidden_fragment, proc.stdout)
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

    def test_denies_literal_credentials_across_supported_write_tools(self):
        cases = {
            "aws access key in Write": ("Write", {"file_path": ".env", "content": "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"}, "AKIAIOSFODNN7EXAMPLE"),
            "stripe key in Edit": ("Edit", {"file_path": "config.ts", "old_string": "const k = ''", "new_string": 'const k = "sk_test_' + "x" * 24 + '"'}, "sk_test_"),
            "github token in MultiEdit": ("MultiEdit", {"file_path": "ci.yml", "edits": [{"old_string": "a", "new_string": "GH_TOKEN=ghp_" + "a" * 36}]}, "ghp_aaaa"),
            "db url with password in NotebookEdit": ("NotebookEdit", {"notebook_path": "etl.ipynb", "new_source": 'conn = "postgres://app:hunter22@db.internal:5432/prod"'}, "hunter22"),
            "json api_key in Write": ("Write", {"file_path": "settings.json", "content": '{"api_key": "abcdef1234567890"}'}, "abcdef1234567890"),
        }
        for label, (tool, tool_input, secret) in cases.items():
            with self.subTest(label=label):
                self.assert_denied(run_hook(event(tool, tool_input)), forbidden_fragment=secret)

    def test_allows_placeholders_and_env_references_in_writes(self):
        safe_contents = (
            "print('hello')\n",
            "PRIVATE_KEY_PATH = os.environ['PRIVATE_KEY_PATH']\n",
            "-----BEGIN CERTIFICATE-----\nnot a private key\n",
            "See the key in the secret store, never in this file.\n",
            'STRIPE_API_KEY="REPLACE_ME"\n',
            '{"api_key": "YOUR_API_KEY"}\n',
            'DATABASE_URL="postgres://user:${DB_PASSWORD}@localhost:5432/app"\n',
            "DATABASE_URL=postgres://user:s3cr3t-local-pw@localhost:5432/app\n",
            "REDIS_URL=redis://default:s3cr3t-local-pw@127.0.0.1:6379\n",
            "DATABASE_URL=postgres://postgres:postgres@db:5432/app\n",
            'password: "password"\n',
        )
        for content in safe_contents:
            with self.subTest(content=content[:30]):
                self.assert_no_decision(run_hook(event("Write", {"file_path": "f", "content": content})))

    def test_still_denies_real_looking_values_the_allowances_do_not_cover(self):
        for content in (
            f'TOKEN = "{SYNTHETIC_GITHUB_TOKEN}"\n',
            "DATABASE_URL=postgres://app:s3cr3t-prod-pw@db.internal:5432/prod\n",
            # No in-content marker is honored: a host test showed an agent adds one and retries.
            f'TOKEN = "{SYNTHETIC_GITHUB_TOKEN}"  # pragma: allowlist secret\n',
            f"| GitHub token | `{SYNTHETIC_GITHUB_TOKEN}` | <!-- pragma: allowlist secret -->\n",
        ):
            with self.subTest(content=content[:30]):
                self.assert_denied(run_hook(event("Write", {"file_path": "f", "content": content})), forbidden_fragment="s3cr3t")

    def test_legacy_file_name_gives_identical_decisions(self):
        payloads = (
            event("Write", {"file_path": "f", "content": KEY_BLOCK}),
            event("Write", {"file_path": "f", "content": f'TOKEN = "{SYNTHETIC_GITHUB_TOKEN}"'}),
            event("Write", {"file_path": "f", "content": "print('hello')"}),
        )
        for payload in payloads:
            new = run_hook(payload)
            old = subprocess.run([sys.executable, str(LEGACY_HOOK)], input=payload, capture_output=True, text=True, timeout=10)
            self.assertEqual((old.returncode, old.stdout), (new.returncode, new.stdout))
        self.assertEqual(subprocess.run([sys.executable, str(LEGACY_HOOK)], input="not json", capture_output=True, text=True, timeout=10).returncode, 2)

    def test_missing_sibling_module_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            alone = Path(tmp) / "pretooluse-write-secrets.py"
            alone.write_text(HOOK.read_text())
            proc = subprocess.run([sys.executable, str(alone)], input=event("Write", {"file_path": "f", "content": "print('hello')"}),
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 2)
            legacy = Path(tmp) / "pretooluse-write-private-key.py"
            legacy.write_text(LEGACY_HOOK.read_text())
            alone.unlink()
            proc = subprocess.run([sys.executable, str(legacy)], input=event("Write", {"file_path": "f", "content": "x"}),
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 2)

    def test_evidence_log_records_denials_without_the_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "evidence.jsonl"
            env = {"CATPILOT_EVIDENCE_LOG": str(log)}
            proc = run_hook(event("Write", {"file_path": "key.pem", "content": KEY_BLOCK}), env)
            self.assert_denied(proc)
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertEqual((entry["event"], entry["hook"], entry["tool"], entry["label"]), ("deny", "pretooluse-write-secrets", "Write", "private-key-block"))
            self.assertNotIn("SYNTHETIC-NOT-A-KEY", lines[0])
            self.assertNotIn("key.pem", lines[0])
            # Non-private-key credential logs its specific label without content.
            proc2 = run_hook(event("Edit", {"file_path": "app.py", "old_string": "x", "new_string": "AKIAIOSFODNN7EXAMPLE"}), env)
            self.assert_denied(proc2, forbidden_fragment="AKIAIOSFODNN7EXAMPLE")
            lines = log.read_text().splitlines()
            self.assertEqual(len(lines), 2)
            entry2 = json.loads(lines[1])
            self.assertEqual((entry2["event"], entry2["hook"], entry2["tool"], entry2["label"]), ("deny", "pretooluse-write-secrets", "Edit", "AWS access key ID"))
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", lines[1])
            self.assert_no_decision(run_hook(event("Write", {"file_path": "notes.txt", "content": "plain text"}), env))
            self.assertEqual(len(log.read_text().splitlines()), 2)
        # An unwritable log path changes nothing about the decision.
        self.assert_denied(run_hook(event("Write", {"file_path": "key.pem", "content": KEY_BLOCK}), {"CATPILOT_EVIDENCE_LOG": "/dev/null/evidence.jsonl"}))

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

    def test_harness_file_write_gates(self):
        from hooks.harness.secret_gate import gate_file_write, gate_write_tool_call
        self.assertIsNotNone(gate_file_write(KEY_BLOCK))
        self.assertIn("AWS access key ID", gate_file_write("export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"))
        self.assertIsNone(gate_file_write("export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID"))
        self.assertIsNotNone(gate_write_tool_call("Edit", {"old_string": "a", "new_string": "AKIAIOSFODNN7EXAMPLE"}))
        self.assertIsNone(gate_write_tool_call("Edit", {"old_string": "a", "new_string": "REPLACE_ME"}))
        self.assertIsNotNone(gate_write_tool_call("write_file", {}, field="body"))
        with self.assertRaises(ValueError):
            gate_file_write(None)



def patch(*body: str) -> str:
    """A Codex apply_patch patch from its lines."""
    return "\n".join(("*** Begin Patch",) + body + ("*** End Patch",)) + "\n"


def codex_event(command, host_shape: bool = True) -> str:
    value = {"tool_name": "apply_patch", "tool_input": {"command": command}}
    if host_shape:
        value.update({"session_id": "sess-patch", "hook_event_name": "PreToolUse", "turn_id": "turn-1", "cwd": str(ROOT), "model": "example-model"})
    return json.dumps(value)


KEY_LINES = tuple("+" + line for line in KEY_BLOCK.splitlines())


class CodexApplyPatchTests(unittest.TestCase):
    """Codex sends file edits as apply_patch, with the patch in tool_input.command."""

    def assert_denied(self, proc: subprocess.CompletedProcess) -> None:
        WriteHookTests.assert_denied(self, proc)

    def assert_no_decision(self, proc: subprocess.CompletedProcess) -> None:
        WriteHookTests.assert_no_decision(self, proc)

    def test_denies_a_key_block_in_a_new_file(self):
        self.assert_denied(run_hook(codex_event(patch("*** Add File: deploy/key.pem", *KEY_LINES))))

    def test_denies_a_key_block_or_credential_added_in_a_hunk(self):
        for added in (KEY_LINES, ('+GITHUB_TOKEN = "' + SYNTHETIC_GITHUB_TOKEN + '"',)):
            with self.subTest(added=added[0][:20]):
                proc = run_hook(codex_event(patch("*** Update File: app/config.py", "@@ def settings():", " DEBUG = False", "-TOKEN = None", *added)))
                self.assert_denied(proc)
                self.assertNotIn(SYNTHETIC_GITHUB_TOKEN, proc.stdout)

    def test_denies_added_lines_however_the_patch_is_wrapped(self):
        body = ("*** Add File: k.pem",) + KEY_LINES
        wrapped = {
            "heredoc": "apply_patch <<'PATCH'\n" + patch(*body) + "PATCH\n",
            "no begin or end markers": "\n".join(body) + "\n",
            "second of two files": patch("*** Add File: README.md", "+hello", *body),
        }
        for label, command in wrapped.items():
            with self.subTest(label=label):
                self.assert_denied(run_hook(codex_event(command)))

    def test_removed_and_context_lines_are_not_added_text(self):
        removed = tuple("-" + line for line in KEY_BLOCK.splitlines())
        context = tuple(" " + line for line in KEY_BLOCK.splitlines())
        for label, body in {
            "deleting a key": ("*** Update File: k.pem", "@@", *removed),
            "a key already in the file, as context": ("*** Update File: k.pem", "@@", *context, "+# rotated, see the secret store"),
            "deleting the file": ("*** Delete File: k.pem",),
            "a harmless new file": ("*** Add File: notes.md", "+# Notes", "+Read the key from the secret store at runtime."),
            "placeholders and environment references": ("*** Add File: .env.example", "+STRIPE_API_KEY=REPLACE_ME", "+DATABASE_URL=${DATABASE_URL}"),
        }.items():
            with self.subTest(label=label):
                self.assert_no_decision(run_hook(codex_event(patch(*body))))

    def test_a_patch_that_is_not_text_fails_closed(self):
        for command in (None, 42, ["*** Begin Patch"]):
            with self.subTest(command=command):
                proc = run_hook(codex_event(command))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, "")

    def test_evidence_names_apply_patch_and_never_the_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "evidence.jsonl"
            env = {"CATPILOT_EVIDENCE_LOG": str(log)}
            full_env = {k: v for k, v in os.environ.items() if k not in ("CATPILOT_EVIDENCE_LOG", "CATPILOT_EVIDENCE_SYSLOG")}
            full_env.update(env)
            proc = subprocess.run([sys.executable, str(HOOK), "--host", "codex"], input=codex_event(patch("*** Add File: secret-dir/key.pem", *KEY_LINES)),
                                  capture_output=True, text=True, timeout=10, env=full_env)
            self.assert_denied(proc)
            (line,) = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual((line["event"], line["tool"], line["label"], line["host"], line["session_id"]), ("deny", "apply_patch", "private-key-block", "codex", "sess-patch"))
            text = log.read_text(encoding="utf-8")
            for fragment in ("SYNTHETIC-NOT-A-KEY", "secret-dir", "key.pem", "BEGIN RSA"):
                self.assertNotIn(fragment, text)

    def test_line_separators_codex_does_not_split_on_hide_nothing(self):
        # Codex splits a patch on "\n" only; these are ordinary characters inside a line it writes.
        for sep in ("\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"):
            for hidden in ('GITHUB_TOKEN="' + SYNTHETIC_GITHUB_TOKEN + '"', KEY_BLOCK.splitlines()[0]):
                with self.subTest(sep=repr(sep), hidden=hidden[:12]):
                    self.assert_denied(run_hook(codex_event(patch("*** Add File: notes.md", "+# note" + sep + hidden))))
                    self.assert_denied(run_hook(codex_event(patch("*** Update File: a.py", "@@", " x = 1", "+y = 2" + sep + hidden))))

    def test_crlf_patches(self):
        crlf = lambda text: text.replace("\n", "\r\n")
        self.assert_denied(run_hook(codex_event(crlf(patch("*** Add File: k.pem", *KEY_LINES)))))
        self.assert_no_decision(run_hook(codex_event(crlf(patch("*** Add File: notes.md", "+# Notes", "+hello")))))

    def test_a_moved_file_with_an_added_key_is_denied(self):
        self.assert_denied(run_hook(codex_event(patch("*** Update File: old.txt", "*** Move to: new.pem", "@@", " header", *KEY_LINES))))

    def test_a_value_split_across_added_lines_is_still_one_match(self):
        # Codex can write these halves next to each other: a removed line (including one that starts with ---),
        # a blank context line, separate add-only chunks and *** End of File all leave them adjacent in the file.
        value = '+  "hunter2hunter2"'
        for label, between in {
            "adjacent": (),
            "a removed line": ("-old: 1",),
            "a removed YAML separator": ("----",),
            "a removed SQL comment": ("--- comment",),
            "a blank context line": (" ",),
            "an empty context line": ("",),
            "two add-only chunks": ("@@",),
            "end of file, then another chunk": ("*** End of File", "@@"),
        }.items():
            with self.subTest(between=label):
                self.assert_denied(run_hook(codex_event(patch("*** Update File: config.yaml", "@@", "+password:", *between, value))))

    def test_added_lines_in_one_file_are_checked_together_even_across_kept_text(self):
        # The cost of the test above: two fragments a kept line separates can match together. A person resolves it.
        self.assert_denied(run_hook(codex_event(patch(
            "*** Update File: docs.md", "@@", "+See Authorization: Bearer", " unrelated", "+some_long_identifier_name_here"))))
        # Lines added to different files are never joined.
        self.assert_no_decision(run_hook(codex_event(patch(
            "*** Update File: a.md", "@@", "+See Authorization: Bearer", "*** Update File: b.md", "@@", "+some_long_identifier_name_here"))))

    def test_an_oversized_patch_exits_two(self):
        proc = run_hook(codex_event(patch("*** Add File: big.txt", "+" + "a" * 1_100_000)))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")


if __name__ == "__main__":
    unittest.main()
