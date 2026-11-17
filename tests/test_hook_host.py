"""The PreToolUse checks name the tool they ran on in their evidence lines, from --host. Offline.

Codex runs the same hook files on its own PreToolUse event, which has the same Bash shape
(tool_input.command). Before --host, every line said host "claude-code", even on Codex.
The argument changes the evidence label only: every decision, message and exit code must be
the same with or without it.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import catpilot_guard
from catpilot_guard import evidence

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "hooks" / "claude-code"
SCHEMA = json.loads((ROOT / "docs" / "spec" / "evidence-event.schema.json").read_text(encoding="utf-8"))
try:
    import jsonschema

    VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
except ImportError:  # pragma: no cover - the CI install has it
    VALIDATOR = None

AWS_DOC_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documentation example, assembled so this file holds no literal
KEY_BLOCK = "-----BEGIN " + "RSA PRIVATE KEY-----\nSYNTHETIC-NOT-A-KEY\n"


def event(tool: str, tool_input: dict, codex: bool = False) -> dict:
    value = {"session_id": "sess-host-1", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tool_input, "cwd": str(ROOT)}
    if codex:
        # Codex's extensions to the common input (developers.openai.com/codex/hooks, read 2026-11-16).
        value.update({"turn_id": "turn-1", "model": "example-model", "permission_mode": "default", "transcript_path": None})
    return value


# hook file -> (an event it denies, an event it allows)
CASES = {
    "pretooluse-secrets.py": (
        ("Bash", {"command": "export AWS_ACCESS_KEY_ID=" + AWS_DOC_KEY + " && echo ok"}),
        ("Bash", {"command": "ls -la"}),
    ),
    "pretooluse-write-secrets.py": (
        ("Write", {"file_path": "key.pem", "content": KEY_BLOCK}),
        ("Write", {"file_path": "notes.txt", "content": "hello\n"}),
    ),
    "pretooluse-write-private-key.py": (
        ("Write", {"file_path": "key.pem", "content": KEY_BLOCK}),
        ("Write", {"file_path": "notes.txt", "content": "hello\n"}),
    ),
    "pretooluse-destructive-ops.py": (
        ("Bash", {"command": "git push --force origin main"}),
        ("Bash", {"command": "git status"}),
    ),
}
# argument list -> the host the line must carry (None: the line leaves host out)
ARGS = {
    (): "claude-code",
    ("--host", "claude-code"): "claude-code",
    ("--host", "codex"): "codex",
    ("--host=codex",): "codex",
    ("--host", "cursor"): None,
    ("--host",): None,
    ("--host", ""): None,
    ("--hots", "codex"): None,
    ("--host", "codex", "--host", "claude-code"): None,
}


def run(hook: str, args: tuple, payload: str, log: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k not in (evidence.EVIDENCE_ENV, evidence.SYSLOG_ENV)}
    env[evidence.EVIDENCE_ENV] = str(log)
    return subprocess.run([sys.executable, str(HOOKS / hook), *args], input=payload, capture_output=True, text=True, timeout=30, env=env, cwd=ROOT)


def lines(log: Path) -> list:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


class HookHostFunctionTests(unittest.TestCase):
    def test_reads_the_host_argument(self):
        for args, expected in ARGS.items():
            with self.subTest(args=args):
                self.assertEqual(catpilot_guard.hook_host(list(args)), expected)

    def test_never_raises(self):
        self.assertIsNone(catpilot_guard.hook_host([None, None]))
        self.assertIsNone(catpilot_guard.hook_host([1]))

    def test_hosts_match_the_schema(self):
        self.assertEqual(list(catpilot_guard.HOOK_HOSTS), SCHEMA["properties"]["host"]["enum"])
        self.assertIn(catpilot_guard.DEFAULT_HOOK_HOST, catpilot_guard.HOOK_HOSTS)


class HookHostRunTests(unittest.TestCase):
    def test_host_argument_labels_the_line_and_changes_no_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            n = 0
            for hook, (denied, allowed) in CASES.items():
                for codex in (False, True):
                    for verdict, (tool, tool_input) in (("deny", denied), ("allow", allowed)):
                        payload = json.dumps(event(tool, tool_input, codex=codex))
                        baseline = None
                        for args, expected in ARGS.items():
                            n += 1
                            log = Path(tmp) / f"{n}.jsonl"
                            with self.subTest(hook=hook, codex_event=codex, verdict=verdict, args=args):
                                proc = run(hook, args, payload, log)
                                if baseline is None:
                                    baseline = proc
                                self.assertEqual((proc.returncode, proc.stdout, proc.stderr), (baseline.returncode, baseline.stdout, baseline.stderr))
                                self.assertEqual(proc.returncode, 0)
                                written = lines(log)
                                if verdict == "allow":
                                    self.assertEqual(json.loads(proc.stdout), {})
                                    self.assertEqual(written, [])
                                    continue
                                self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
                                self.assertEqual(len(written), 1)
                                line = written[0]
                                self.assertEqual((line["event"], line["source"], line["session_id"]), ("deny", evidence.HOOK_SOURCE, "sess-host-1"))
                                if expected is None:
                                    self.assertNotIn("host", line)
                                else:
                                    self.assertEqual(line["host"], expected)
                                if VALIDATOR is not None:
                                    VALIDATOR.validate(line)

    def test_unreadable_input_still_blocks_and_carries_the_host(self):
        with tempfile.TemporaryDirectory() as tmp:
            for hook in CASES:
                for args, expected in ARGS.items():
                    log = Path(tmp) / (hook + "-" + "-".join(args or ("none",)) + ".jsonl")
                    with self.subTest(hook=hook, args=args):
                        proc = run(hook, args, "{not json", log)
                        self.assertEqual(proc.returncode, 2)
                        written = lines(log)
                        self.assertEqual([line["event"] for line in written], ["input_error"])
                        if expected is None:
                            self.assertNotIn("host", written[0])
                        else:
                            self.assertEqual(written[0]["host"], expected)
                        if VALIDATOR is not None:
                            VALIDATOR.validate(written[0])


if __name__ == "__main__":
    unittest.main()
