"""The hooks on GitHub Copilot CLI: catpilot_guard/copilot.py reads Copilot's PascalCase PreToolUse event in the Claude
Code shape and writes the decision with the fields Copilot reads, and deploy/org places them as policy hooks in
<copilot dir>/policy.d/. Offline, in temporary directories.

Copilot CLI's event and decision format, from https://docs.github.com/en/copilot/reference/hooks-reference (read on
2026-11-17): under the event name PreToolUse it sends hook_event_name, session_id, timestamp, cwd, tool_name (the
Claude tool name: Bash for bash and powershell, Write for create, Edit for edit, str_replace_editor and apply_patch;
write_bash and write_powershell keep their names) and tool_input (the runtime tool's arguments, parsed from JSON when
possible); a hook decides with permissionDecision and permissionDecisionReason on stdout.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catpilot_guard import copilot  # noqa: E402

HOOKS = ROOT / "hooks" / "claude-code"
ORG = ROOT / "deploy" / "org"
HELPER = ORG / "session_start_files.py"
EXAMPLE_V2 = ROOT / "docs" / "spec" / "overlay.v2.example.yaml"
URL = "https://mcp.internal.example.org/mcp"
DOC_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documentation-only example key
PATCH = "*** Begin Patch\n*** Add File: probe.env\n+AWS_ACCESS_KEY_ID=%s\n*** End Patch\n" % DOC_KEY
TEST_SALT = "5f0c9a1e7d3b4c2a8e6f1d0b9a7c5e3f"
EXAMPLE_SALT = "0123456789abcdef0123456789abcdef"


def event(tool, tool_input, cwd="/tmp"):
    return {"hook_event_name": "PreToolUse", "session_id": "copilot-1", "timestamp": "2026-11-17T12:00:00Z",
            "cwd": cwd, "tool_name": tool, "tool_input": tool_input}


class ToClaudeTests(unittest.TestCase):
    def test_shell_tools(self):
        self.assertEqual(copilot.to_claude(event("Bash", {"command": "ls", "description": "x"}))["tool_input"],
                         {"command": "ls", "description": "x"})
        for name in ("write_bash", "write_powershell"):
            out = copilot.to_claude(event(name, {"shellId": "1", "input": "git push -f origin main\n"}))
            self.assertEqual((out["tool_name"], out["tool_input"]), ("Bash", {"command": "git push -f origin main\n"}))
        with self.assertRaises(ValueError):
            copilot.to_claude(event("write_bash", {"shellId": "1"}))

    def test_shell_input_key_tokens(self):
        # {enter} submits the line; other keys can change which command runs, so they fail closed.
        out = copilot.to_claude(event("write_bash", {"shellId": "1", "input": "rm -rf ~{enter}"}))
        self.assertEqual(out["tool_input"], {"command": "rm -rf ~\n"})
        out = copilot.to_claude(event("write_bash", {"shellId": "1", "input": "echo $HOME {a,b} @{upstream}{ENTER}"}))
        self.assertEqual(out["tool_input"], {"command": "echo $HOME {a,b} @{upstream}\n"})
        # ${enter} is read as $ and a line break, so what follows it is checked as its own command.
        out = copilot.to_claude(event("write_bash", {"shellId": "1", "input": "echo ${enter}rm -rf ~ ${enter}"}))
        self.assertEqual(out["tool_input"], {"command": "echo $\nrm -rf ~ $\n"})
        out = copilot.to_claude(event("write_bash", {"shellId": "1", "input": "echo hi\rrm -rf ~\r\n"}))
        self.assertEqual(out["tool_input"], {"command": "echo hi\nrm -rf ~\n"})
        for text in ("ls{up}{enter}", "rm -rf ~x{backspace}{enter}", "git pu{tab}", "x{ctrl+c}", "x{Left}",
                     "${up} --force{enter}", "echo safe${home}rm -rf ~ #{enter}",
                     "echo safe\x01rm -rf ~ #\r", "ls\x1b[A\n", "git push origin main\x1b[D+\n", "git pu\tsh\n", "x\x7f\n",
                     "{{end}}\n", "cd ${HOME}/x\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                copilot.to_claude(event("write_bash", {"shellId": "1", "input": text}))

    def test_an_event_without_a_tool_name_fails_closed(self):
        # The camelCase preToolUse shape (toolName, toolArgs) is not the one the hooks are registered for.
        with self.assertRaises(ValueError):
            copilot.to_claude({"sessionId": "s", "toolName": "bash", "toolArgs": '{"command": "rm -rf ~"}'})

    def test_file_writes(self):
        cases = [
            (("Write", {"path": "a", "file_text": "x"}), ("Write", {"content": "x"})),
            (("Edit", {"path": "a", "old_str": "o", "new_str": "n"}), ("Edit", {"new_string": "n"})),
            (("Edit", {"command": "create", "path": "a", "file_text": "x"}), ("Edit", {"new_string": "x"})),
            (("Edit", {"command": "insert", "path": "a", "insert_line": 1, "new_str": "n"}), ("Edit", {"new_string": "n"})),
            (("Write", {"file_path": "a", "content": "x"}), ("Write", {"content": "x"})),  # Claude's own shape
            (("Edit", {"command": "view", "path": "a"}), ("Edit", {"new_string": ""})),  # nothing is written
            (("Edit", {"command": "view", "path": "a", "view_range": [1, 5]}), ("Edit", {"new_string": ""})),
            (("Edit", {"command": "undo_edit", "path": "a"}), ("Edit", {"new_string": ""})),
            (("Edit", {"path": "a", "old_str": "o"}), ("Edit", {"new_string": ""})),  # only removes text
            (("Edit", {"path": "a", "old_str": "o", "new_str": None}), ("Edit", {"new_string": ""})),
            (("Edit", {"command": "insert", "path": "a", "insert_line": 1, "insert_text": "n"}), ("Edit", {"new_string": "n"})),
            (("Edit", PATCH), ("apply_patch", {"command": PATCH})),
            (("Edit", {"input": PATCH}), ("apply_patch", {"command": PATCH})),
            (("Edit", {"patch": PATCH}), ("apply_patch", {"command": PATCH})),
        ]
        for (name, tool_input), (want_name, want_input) in cases:
            with self.subTest(tool=name, tool_input=tool_input):
                out = copilot.to_claude(event(name, tool_input))
                self.assertEqual((out["tool_name"], out["tool_input"]), (want_name, want_input))
                self.assertEqual(out["session_id"], "copilot-1")

    def test_a_patch_beside_text_fields_is_checked_with_them(self):
        out = copilot.to_claude(event("Edit", {"command": "create", "path": "a.env", "file_text": "A=1",
                                               "input": "*** Begin Patch\n*** Add File: b\n+B=2\n*** End Patch"}))
        self.assertEqual(out["tool_name"], "Edit")
        self.assertIn("A=1", out["tool_input"]["new_string"])
        self.assertIn("B=2", out["tool_input"]["new_string"])

    def test_a_write_of_unknown_shape_fails_closed(self):
        for name, tool_input in (("Write", {"path": "a"}), ("Edit", {"weird": 1}), ("Write", "text"),
                                 ("Write", {"file_text": 3}), ("Edit", None),
                                 ("Edit", {"path": "a", "old_str": "o", "edits": [{"new_str": "x"}]}),
                                 ("Edit", {"path": "a", "old_str": "o", "new_text": "x"}),
                                 ("Edit", {"input": PATCH, "edits": [{"new_str": "x"}]}),
                                 ("Edit", {"patch": PATCH, "new_text": "x"}),
                                 ("Edit", {"path": "a", "old_str": "o", "new_str": "y", "edits": [{"new_str": "x"}]})):
            with self.subTest(tool=name, tool_input=tool_input), self.assertRaises(ValueError):
                copilot.to_claude(event(name, tool_input))

    def test_other_tools_pass_unchanged(self):
        original = event("Read", {"path": "a"})
        self.assertEqual(copilot.to_claude(original), original)
        self.assertEqual(copilot.to_claude([]), [])

    def test_decisions_gain_copilots_fields(self):
        deny = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "r"}}
        out = copilot.with_copilot_fields(deny)
        self.assertEqual((out["permissionDecision"], out["permissionDecisionReason"]), ("deny", "r"))
        self.assertEqual(out["hookSpecificOutput"], deny["hookSpecificOutput"])
        self.assertEqual(copilot.with_copilot_fields({}), {})


class HookProcessTests(unittest.TestCase):
    """Each check, run as Copilot runs it: the event on stdin, --host copilot-cli."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.log = self.tmp / "evidence.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def run_hook(self, name, payload, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        env["CATPILOT_EVIDENCE_LOG"] = str(self.log)
        return subprocess.run([sys.executable, str(HOOKS / name), *args], input=json.dumps(payload), capture_output=True,
                              text=True, env=env, timeout=30)

    def assertDecision(self, proc, want):
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        if want == "none":
            self.assertEqual(out, {})
        else:
            self.assertEqual(out["permissionDecision"], want)
            self.assertEqual(out["hookSpecificOutput"]["permissionDecision"], want)
            self.assertTrue(out["permissionDecisionReason"])

    def test_each_check_denies_its_probe_and_passes_a_harmless_call(self):
        cases = [
            ("pretooluse-secrets.py", event("Bash", {"command": "export AWS_ACCESS_KEY_ID=%s" % DOC_KEY}), "deny"),
            ("pretooluse-secrets.py", event("write_bash", {"shellId": "1", "input": "export AWS_ACCESS_KEY_ID=%s\n" % DOC_KEY}), "deny"),
            ("pretooluse-secrets.py", event("Bash", {"command": "ls"}), "none"),
            ("pretooluse-destructive-ops.py", event("Bash", {"command": "git push --force origin main"}), "deny"),
            ("pretooluse-destructive-ops.py", event("write_bash", {"shellId": "1", "input": "rm -rf ~\n"}), "deny"),
            ("pretooluse-destructive-ops.py", event("write_bash", {"shellId": "1", "input": "git push --force origin main{enter}"}), "deny"),
            # Each line of shell input is its own command (the destructive check splits on newlines).
            ("pretooluse-destructive-ops.py", event("write_bash", {"shellId": "1", "input": "echo hi\rrm -rf ~\r"}), "deny"),
            ("pretooluse-destructive-ops.py", event("write_bash", {"shellId": "1", "input": "echo ${enter}rm -rf ~ ${enter}"}), "deny"),
            ("pretooluse-destructive-ops.py", event("Bash", {"command": "git status"}), "none"),
            ("pretooluse-write-secrets.py", event("Write", {"path": "a.env", "file_text": "AWS_ACCESS_KEY_ID=%s\n" % DOC_KEY}), "deny"),
            ("pretooluse-write-secrets.py", event("Edit", {"path": "a.env", "old_str": "x", "new_str": "AWS_ACCESS_KEY_ID=%s" % DOC_KEY}), "deny"),
            ("pretooluse-write-secrets.py", event("Edit", PATCH), "deny"),
            ("pretooluse-write-secrets.py", event("Write", {"path": "a.md", "file_text": "# Notes\n"}), "none"),
            ("pretooluse-write-secrets.py", event("Edit", {"command": "view", "path": "a.env"}), "none"),
        ]
        for name, payload, want in cases:
            with self.subTest(hook=name, tool=payload["tool_name"], want=want):
                self.assertDecision(self.run_hook(name, payload, "--host", "copilot-cli"), want)
        lines = [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual({line["host"] for line in lines}, {"copilot-cli"})
        self.assertEqual([line["event"] for line in lines], ["deny"] * 10)
        self.assertNotIn(DOC_KEY, self.log.read_text(encoding="utf-8"))

    def test_a_write_of_unknown_shape_blocks(self):
        proc = self.run_hook("pretooluse-write-secrets.py", event("Edit", {"weird": 1}), "--host", "copilot-cli")
        self.assertEqual(proc.returncode, 2)

    def test_without_the_host_argument_a_copilot_write_is_not_read_and_blocks(self):
        # Why install.sh and verify.sh insist on --host copilot-cli: the Claude shape has no file_text.
        proc = self.run_hook("pretooluse-write-secrets.py", event("Write", {"path": "a.md", "file_text": "# Notes\n"}))
        self.assertEqual(proc.returncode, 2)

    def test_the_company_rules_hook_returns_ask_for_copilot_to_decide(self):
        policy_dir = self.tmp / "policy"
        policy_dir.mkdir()
        os.chmod(policy_dir, 0o755)
        policy = policy_dir / "company-policy.json"
        policy.write_text(json.dumps({
            "format": "catpilot-company-policy", "format_version": 1, "source_sha256": "b" * 64, "expires_on": "2099-01-01",
            "rules": [{"id": "confirm-main", "kind": "protected_branch", "mode": "ask", "values": ["main"]}],
        }), encoding="utf-8")
        os.chmod(policy, 0o644)
        proc = self.run_hook("pretooluse-company-rules.py", event("Bash", {"command": "git push -f origin main"}),
                             "--host", "copilot-cli", "--policy", str(policy), "--ask")
        self.assertDecision(proc, "ask")
        proc = self.run_hook("pretooluse-company-rules.py", event("write_bash", {"shellId": "1", "input": "git push -f origin main{enter}"}),
                             "--host", "copilot-cli", "--policy", str(policy), "--ask")
        self.assertDecision(proc, "ask")
        # Without --ask, ask acts as block (decision 2), on Copilot as everywhere.
        proc = self.run_hook("pretooluse-company-rules.py", event("Bash", {"command": "git push -f origin main"}),
                             "--host", "copilot-cli", "--policy", str(policy))
        self.assertDecision(proc, "deny")


def load_helper():
    import importlib.util

    spec = importlib.util.spec_from_file_location("session_start_files", HELPER)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


helper = load_helper()


class PolicyFileTests(unittest.TestCase):
    def test_the_policy_file_declares_each_check(self):
        data = json.loads(helper.copilot_policy_json("/etc/github-copilot"))
        self.assertEqual(data["version"], 1)
        self.assertEqual(list(data["hooks"]), ["PreToolUse"])  # the PascalCase name selects the Claude Code shape
        entries = data["hooks"]["PreToolUse"]
        by_file = {Path(e["bash"].split('"')[3]).name: e for e in entries}
        self.assertEqual(sorted(by_file), ["pretooluse-destructive-ops.py", "pretooluse-secrets.py", "pretooluse-write-secrets.py"])
        for name, entry in by_file.items():
            self.assertEqual(entry["type"], "command")
            self.assertEqual(entry["timeoutSec"], 30)
            self.assertTrue(entry["bash"].endswith("--host copilot-cli"))
            self.assertIn('"/etc/github-copilot/catpilot-guardrails/hooks/%s"' % name, entry["bash"])
        self.assertEqual(by_file["pretooluse-write-secrets.py"]["matcher"], "Write|Edit")
        self.assertEqual(by_file["pretooluse-secrets.py"]["matcher"], "Bash|write_bash|write_powershell")

    def test_enforce_adds_the_company_rules_hook(self):
        entries = json.loads(helper.copilot_policy_json("/etc/github-copilot", enforce=True))["hooks"]["PreToolUse"]
        company = [e for e in entries if "pretooluse-company-rules.py" in e["bash"]]
        self.assertEqual(len(company), 1)
        self.assertTrue(company[0]["bash"].endswith(
            '--host copilot-cli --policy "/etc/github-copilot/catpilot-guardrails/policy/company-policy.json"'))

    def test_the_matcher_reading_follows_copilots_claude_format(self):
        cases = [("Bash|write_bash", "write_bash", True), ("Bash", "Bash", True), ("Bash", "Bashful", False),
                 ("Write|Edit", "Write", True), ("", "Edit", True), ("*", "x", True), ("B.*", "Bash", True),
                 ("B.*", "xBash", False), (None, "Bash", True), (3, "Bash", False)]
        for matcher, tool, want in cases:
            with self.subTest(matcher=matcher, tool=tool):
                self.assertIs(helper.copilot_covers(matcher, tool), want)


class DeployTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cc, self.codex, self.copilot = self.tmp / "claude-code", self.tmp / "codex", self.tmp / "copilot"
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        self.env.update(CATPILOT_ALLOW_NONROOT="1", CATPILOT_CC_DIR=str(self.cc), CATPILOT_CODEX_DIR=str(self.codex),
                        CATPILOT_COPILOT_DIR=str(self.copilot), PYTHON_BIN=sys.executable, HOME=str(self.home))

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, name, *args):
        return subprocess.run(["bash", str(ORG / name), *args], env=self.env, capture_output=True, text=True, timeout=180)

    def policy_file(self):
        return self.copilot / "policy.d" / "catpilot-guardrails.json"

    def test_install_verify_uninstall(self):
        proc = self.run_script("install.sh", "--server-url", URL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.policy_file().read_text(encoding="utf-8"), helper.copilot_policy_json(str(self.copilot)) + "\n")
        self.assertEqual(stat.S_IMODE(self.policy_file().stat().st_mode), 0o644)
        self.assertTrue((self.copilot / "catpilot-guardrails" / "hooks" / "catpilot_guard" / "copilot.py").exists())
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertRegex(verify.stdout, r"wired\s+\S+catpilot-guardrails.json runs pretooluse-write-secrets.py at PreToolUse and it denies its probe")
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        self.assertFalse(self.policy_file().exists())
        self.assertFalse((self.copilot / "catpilot-guardrails").exists())

    def test_with_enforcement_rules_the_company_hook_is_registered_and_verified(self):
        today = dt.date.today()
        text = EXAMPLE_V2.read_text(encoding="utf-8").replace(EXAMPLE_SALT, TEST_SALT)
        text = text.replace("reviewed_on: 2026-11-17", "reviewed_on: %s" % (today - dt.timedelta(days=1)).isoformat())
        text = text.replace("expires_on: 2027-05-17", "expires_on: %s" % (today + dt.timedelta(days=180)).isoformat())
        rules = self.tmp / "rules.yaml"
        rules.write_text(text, encoding="utf-8")
        proc = self.run_script("install.sh", "--server-url", URL, "--overlay", str(rules))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.policy_file().read_text(encoding="utf-8"),
                         helper.copilot_policy_json(str(self.copilot), enforce=True) + "\n")
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertRegex(verify.stdout, r"denies\s+pretooluse-company-rules.py --host copilot-cli denies a force push")
        # A company-rules entry without --host copilot-cli decides without the fields Copilot reads.
        original = self.policy_file().read_text(encoding="utf-8")
        self.policy_file().write_text(original.replace(' --host copilot-cli --policy', ' --policy'), encoding="utf-8")
        broken = self.run_script("verify.sh")
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn("runs pretooluse-company-rules.py without --host copilot-cli", broken.stdout)
        self.policy_file().write_text(original, encoding="utf-8")
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        self.assertFalse(self.policy_file().exists())

    def test_an_edited_policy_file_is_kept_with_the_hooks_it_runs(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL).returncode, 0)
        self.policy_file().write_text(self.policy_file().read_text(encoding="utf-8").replace('"timeoutSec": 30', '"timeoutSec": 20'),
                                      encoding="utf-8")
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertIn("kept    %s (edited since install" % self.policy_file(), uninstall.stdout)
        self.assertTrue((self.copilot / "catpilot-guardrails" / "hooks" / "pretooluse-secrets.py").exists())

    def test_verify_fails_a_write_matcher_that_misses_edit(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL).returncode, 0)
        self.policy_file().write_text(self.policy_file().read_text(encoding="utf-8").replace('"Write|Edit"', '"Write"'), encoding="utf-8")
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("pretooluse-write-secrets.py under a matcher that does not cover Edit", verify.stdout)

    def test_uninstall_keeps_the_hooks_another_policy_file_runs(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL).returncode, 0)
        moved = self.copilot / "policy.d" / "company.json"
        moved.write_text(self.policy_file().read_text(encoding="utf-8"), encoding="utf-8")
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        self.assertTrue((self.copilot / "catpilot-guardrails" / "hooks" / "pretooluse-secrets.py").exists())

    def test_verify_fails_a_registration_without_the_host_argument(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL).returncode, 0)
        self.policy_file().write_text(self.policy_file().read_text(encoding="utf-8").replace(" --host copilot-cli", ""), encoding="utf-8")
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("without --host copilot-cli", verify.stdout)


if __name__ == "__main__":
    unittest.main()
