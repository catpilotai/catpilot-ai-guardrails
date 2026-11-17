"""Managed Codex PreToolUse hooks through deploy/org: install.sh places the secret, file-write and
destructive-operation hooks under /etc/codex/catpilot-guardrails/hooks/ and declares them in
/etc/codex/requirements.toml, verify.sh runs them, uninstall.sh removes them. Offline, in temporary directories,
through the CATPILOT_CC_DIR, CATPILOT_CODEX_DIR and CATPILOT_ALLOW_NONROOT overrides.

What Codex reads, from its hook documentation (https://learn.chatgpt.com/docs/hooks, read on 2026-11-16):
"Managed hooks in local Codex": [hooks] in requirements.toml, an absolute managed_dir that exists, absolute
script paths under it, and [features].hooks = true to keep managed hooks on for people who turned hooks off.
PreToolUse: Bash and apply_patch both carry tool_input.command; a file edit reports tool_name "apply_patch"
whichever of apply_patch, Edit or Write the matcher names.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORG = ROOT / "deploy" / "org"
URL = "https://mcp.internal.example.org/mcp"
HOOK_FILES = ("pretooluse-secrets.py", "pretooluse-destructive-ops.py", "pretooluse-write-secrets.py")
DOC_KEY = "AKIA" + "IOSFODNN7EXAMPLE"  # AWS's documentation example, assembled so this file holds no literal

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None


def load_helper():
    spec = importlib.util.spec_from_file_location("session_start_files_codex", ORG / "session_start_files.py")
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


helper = load_helper()


def parse_toml(text: str) -> dict:
    return tomllib.loads(text) if tomllib is not None else helper.minimal_toml(text)


class CodexManagedHookTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cc = self.tmp / "claude-code"
        self.codex = self.tmp / "codex"
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        self.env.update({"CATPILOT_ALLOW_NONROOT": "1", "CATPILOT_CC_DIR": str(self.cc), "CATPILOT_CODEX_DIR": str(self.codex),
                         "PYTHON_BIN": sys.executable, "HOME": str(self.home)})

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, name: str, *args: str, env=None) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(ORG / name), *args], env=env or self.env, capture_output=True, text=True, timeout=120)

    def install(self) -> subprocess.CompletedProcess:
        proc = self.run_script("install.sh", "--server-url", URL, "--skills", "")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    @property
    def hooks(self) -> Path:
        return self.codex / "catpilot-guardrails" / "hooks"

    @property
    def requirements(self) -> Path:
        return self.codex / "requirements.toml"

    def command(self, name: str) -> str:
        return f'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" python3 "{self.hooks / name}" --host codex'

    def snapshot(self) -> dict:
        files = {}
        for top in (self.cc, self.codex):
            if top.exists():
                for path in top.rglob("*"):
                    if path.is_file():
                        files[str(path.relative_to(self.tmp))] = path.read_bytes()
        return files

    # --- install -------------------------------------------------------------------------------------------------

    def test_install_places_the_hooks_and_declares_them_as_managed_pretooluse_hooks(self):
        proc = self.install()
        self.assertIn(f"hooks   {self.hooks}/", proc.stdout)
        for name in HOOK_FILES:
            self.assertEqual((self.hooks / name).read_bytes(), (ROOT / "hooks" / "claude-code" / name).read_bytes(), name)
            self.assertEqual((self.hooks / name).stat().st_mode & 0o777, 0o644, name)
        self.assertFalse((self.hooks / "pretooluse-write-private-key.py").exists())
        self.assertFalse((self.hooks / "catpilot-company-rules.py").exists())
        for module in ("__init__", "secrets", "write_secrets", "destructive", "evidence"):
            self.assertTrue((self.hooks / "catpilot_guard" / f"{module}.py").is_file(), module)
        self.assertEqual(list(self.hooks.rglob("__pycache__")), [])

        text = self.requirements.read_text(encoding="utf-8")
        self.assertEqual(text, helper.requirements_toml(str(self.codex), rules=False) + "\n")
        self.assertEqual(self.requirements.stat().st_mode & 0o777, 0o644)
        data = parse_toml(text)
        self.assertEqual(data["features"], {"hooks": True})
        self.assertEqual(data["hooks"]["managed_dir"], str(self.hooks))
        self.assertNotIn("SessionStart", data["hooks"])
        self.assertNotIn("allow_managed_hooks_only", data)
        self.assertEqual(data["hooks"]["PreToolUse"], [
            {"matcher": "^Bash$", "hooks": [
                {"type": "command", "command": self.command("pretooluse-secrets.py"), "timeout": 10},
                {"type": "command", "command": self.command("pretooluse-destructive-ops.py"), "timeout": 10}]},
            {"matcher": "^apply_patch$", "hooks": [
                {"type": "command", "command": self.command("pretooluse-write-secrets.py"), "timeout": 10}]},
        ])

        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertIn("0 missing, 0 failed", verify.stdout)
        for name in HOOK_FILES:
            self.assertIn(f"wired    requirements.toml runs {name} at PreToolUse and it denies its probe", verify.stdout)
            self.assertIn(f"denies   {name} --host codex:", verify.stdout)
            self.assertIn(f"passes   {name} --host codex:", verify.stdout)
        self.assertFalse((self.home / ".catpilot-guardrails").exists(), "verify.sh wrote an evidence line")

    def test_the_registered_commands_deny_codex_events_and_label_their_evidence_codex(self):
        self.install()
        data = parse_toml(self.requirements.read_text(encoding="utf-8"))
        project = self.tmp / "project"
        project.mkdir()
        events = {
            "^Bash$": [("Bash", "export AWS_ACCESS_KEY_ID=" + DOC_KEY + " && echo ok", "AWS access key ID"),
                       ("Bash", "git push --force origin main", "git force-push, mirror, or deletion aimed at a protected branch")],
            "^apply_patch$": [("apply_patch", "*** Begin Patch\n*** Add File: deploy/key.pem\n+-----BEGIN " + "RSA PRIVATE KEY-----\n+SYNTHETIC\n*** End Patch\n", "private-key-block")],
        }
        expected = []
        for group in data["hooks"]["PreToolUse"]:
            for tool, command, label in events[group["matcher"]]:
                event = json.dumps({"session_id": "e2e-codex", "turn_id": "t1", "hook_event_name": "PreToolUse", "tool_name": tool,
                                    "tool_input": {"command": command}, "cwd": str(project), "model": "example-model"})
                denied = 0
                for handler in group["hooks"]:
                    proc = subprocess.run(["/bin/sh", "-c", handler["command"]], input=event, env=self.env, cwd=str(project),
                                          capture_output=True, text=True, timeout=30)
                    self.assertEqual(proc.returncode, 0, proc.stderr)
                    output = json.loads(proc.stdout)
                    if output:
                        self.assertEqual(output["hookSpecificOutput"]["permissionDecision"], "deny")
                        self.assertNotIn(DOC_KEY, proc.stdout)
                        denied += 1
                self.assertEqual(denied, 1, (tool, label))
                expected.append((tool, label))
        log = self.home / ".catpilot-guardrails" / "evidence.jsonl"
        lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(line["tool"], line["label"]) for line in lines], expected)
        for line in lines:
            self.assertEqual((line["event"], line["host"], line["session_id"]), ("deny", "codex", "e2e-codex"))
        self.assertNotIn(DOC_KEY, log.read_text(encoding="utf-8"))
        self.assertNotIn("key.pem", log.read_text(encoding="utf-8"))

    def test_install_needs_a_working_python_and_writes_nothing_without_one(self):
        env = dict(self.env, PYTHON_BIN="/usr/bin/false")
        proc = self.run_script("install.sh", "--server-url", URL, "--skills", "", env=env)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("did not run as Python 3.8 or later", proc.stderr)
        self.assertEqual(self.snapshot(), {})

    # --- verify --------------------------------------------------------------------------------------------------

    def assert_verify_fails(self, *expected: str) -> None:
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        for line in expected:
            self.assertIn(line, verify.stdout)

    def test_verify_fails_when_hooks_are_turned_off_or_miss_their_tool(self):
        self.install()
        text = self.requirements.read_text(encoding="utf-8")
        self.requirements.write_text(text.replace("hooks = true", "hooks = false"), encoding="utf-8")
        self.assert_verify_fails(f"FAIL     {self.requirements} sets [features].hooks = false, which turns every hook off")
        self.requirements.write_text(text.replace('matcher = "^apply_patch$"', 'matcher = "^Bash$"'), encoding="utf-8")
        self.assert_verify_fails("FAIL     requirements.toml runs pretooluse-write-secrets.py under a matcher that does not cover apply_patch")

    def test_verify_accepts_the_matcher_names_codex_documents_for_file_edits(self):
        self.install()
        text = self.requirements.read_text(encoding="utf-8")
        for matcher in ("^Write$", "Edit|Write", "^(apply_patch|Edit)$"):
            with self.subTest(matcher=matcher):
                self.requirements.write_text(text.replace('matcher = "^apply_patch$"', 'matcher = "%s"' % matcher), encoding="utf-8")
                verify = self.run_script("verify.sh")
                self.assertEqual(verify.returncode, 0, verify.stdout)
                self.assertNotIn("does not cover apply_patch", verify.stdout)

    def test_the_minimal_reader_fails_on_features_it_cannot_read(self):
        self.install()
        text = self.requirements.read_text(encoding="utf-8").replace("[features]\nhooks = true\n\n", "")
        for features in ("features.hooks = false\n", "features = { hooks = false }\n"):
            with self.subTest(features=features):
                self.requirements.write_text(features + text, encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    helper.verify_codex_hooks(self.codex, self.home, 10, prefer_tomllib=False)
                self.assertIn("sets features as a dotted key or an inline table, which this reader cannot read", out.getvalue())
                if tomllib is not None:
                    out = io.StringIO()
                    with contextlib.redirect_stdout(out):
                        helper.verify_codex_hooks(self.codex, self.home, 10)
                    self.assertIn("sets [features].hooks = false, which turns every hook off", out.getvalue())

    def test_verify_fails_a_registered_command_that_denies_everything(self):
        self.install()
        deny_all = self.tmp / "deny-all.sh"
        deny_all.write_text('#!/bin/sh\ncat >/dev/null\necho \'{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"x"}}\'\n', encoding="utf-8")
        deny_all.chmod(0o755)
        text = self.requirements.read_text(encoding="utf-8")
        self.requirements.write_text(text.replace(self.command("pretooluse-destructive-ops.py"),
                                                  f'"{deny_all}" # pretooluse-destructive-ops.py'), encoding="utf-8")
        self.assert_verify_fails("FAIL     requirements.toml command for pretooluse-destructive-ops.py denied ls, which it must let through")

    def test_verify_fails_on_a_missing_hook_or_package_module(self):
        self.install()
        (self.hooks / "pretooluse-destructive-ops.py").unlink()
        (self.hooks / "catpilot_guard" / "write_secrets.py").unlink()
        self.assert_verify_fails(
            f"MISSING  {self.hooks / 'pretooluse-destructive-ops.py'}",
            f"MISSING  {self.hooks / 'catpilot_guard' / 'write_secrets.py'}",
            "FAIL     pretooluse-write-secrets.py --host codex exited 2 instead of returning a decision",
            "FAIL     requirements.toml command for pretooluse-destructive-ops.py exited 2 instead of returning a decision",
        )

    def test_an_existing_requirements_file_is_kept_and_verify_names_what_is_not_registered(self):
        self.codex.mkdir(parents=True)
        self.requirements.write_text('allowed_sandbox_modes = ["read-only", "workspace-write"]\n', encoding="utf-8")
        before = self.requirements.read_bytes()
        proc = self.install()
        self.assertEqual(self.requirements.read_bytes(), before)
        self.assertIn(f"exists  {self.requirements} (not overwritten); merge this into it, keeping one [features] and one [hooks] table:", proc.stdout)
        self.assertIn('matcher = "^apply_patch$"', proc.stdout)
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("note     %s does not pin [features].hooks = true" % self.requirements, verify.stdout)
        for name in HOOK_FILES:
            self.assertIn(f"FAIL     requirements.toml does not run {name} at PreToolUse", verify.stdout)
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
        self.assertEqual(self.requirements.read_bytes(), before)
        self.assertFalse((self.codex / "catpilot-guardrails").exists())

    def test_a_command_without_the_host_argument_is_noted(self):
        self.install()
        text = self.requirements.read_text(encoding="utf-8")
        self.requirements.write_text(text.replace('pretooluse-secrets.py" --host codex', 'pretooluse-secrets.py"'), encoding="utf-8")
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout)
        self.assertIn("note     requirements.toml runs pretooluse-secrets.py without --host codex, so its evidence lines say claude-code", verify.stdout)

    # --- uninstall -----------------------------------------------------------------------------------------------

    def test_uninstall_keeps_the_hooks_a_kept_requirements_file_still_runs(self):
        for label, env in (("edited file", None), ("no working python", dict(self.env, PYTHON_BIN="/usr/bin/false"))):
            with self.subTest(label):
                self.install()
                if env is None:
                    self.requirements.write_text(self.requirements.read_text(encoding="utf-8") + "# ours\n", encoding="utf-8")
                uninstall = self.run_script("uninstall.sh", "--server-url", URL, env=env)
                self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
                self.assertTrue(self.requirements.exists())
                for name in HOOK_FILES:
                    self.assertTrue((self.hooks / name).is_file(), name)
                self.assertIn(f"kept    {self.hooks} ({self.requirements}, kept above, still runs hooks from it", uninstall.stdout)
                # The declared commands still run their hooks.
                data = parse_toml(self.requirements.read_text(encoding="utf-8"))
                command = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
                proc = subprocess.run(["/bin/sh", "-c", command], input=json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
                                      env=self.env, capture_output=True, text=True, timeout=30)
                self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "{}"))
                # Once the file is gone, a second uninstall removes the directory.
                self.requirements.unlink()
                uninstall = self.run_script("uninstall.sh", "--server-url", URL)
                self.assertFalse((self.codex / "catpilot-guardrails").exists())

    def test_a_dangling_symlink_at_requirements_is_not_written_through(self):
        self.codex.mkdir(parents=True)
        target = self.tmp / "elsewhere.toml"
        self.requirements.symlink_to(target)
        proc = self.install()
        self.assertFalse(target.exists())
        self.assertTrue(self.requirements.is_symlink())
        self.assertIn(f"exists  {self.requirements} (not overwritten)", proc.stdout)

    def test_uninstall_removes_the_hooks_and_requirements_and_keeps_an_edited_file(self):
        self.install()
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
        self.assertIn(f"removed {self.requirements}", uninstall.stdout)
        self.assertIn(f"removed {self.codex / 'catpilot-guardrails'}", uninstall.stdout)
        self.assertEqual(self.snapshot(), {})

        self.install()
        self.requirements.write_text(self.requirements.read_text(encoding="utf-8") + 'allowed_web_search_modes = ["cached"]\n', encoding="utf-8")
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertTrue(self.requirements.exists())
        self.assertIn(f"kept    {self.requirements} (edited since install; remove by hand the [hooks] managed_dir that names "
                      "catpilot-guardrails, the [[hooks.PreToolUse]] entries", uninstall.stdout)
        self.assertTrue((self.hooks / "pretooluse-secrets.py").exists(), "the kept file still runs it")

    # --- the generated file ----------------------------------------------------------------------------------------

    def test_the_minimal_reader_reads_both_variants_as_tomllib_does(self):
        if tomllib is None:
            self.skipTest("tomllib needs Python 3.11 or later")
        for rules in (False, True):
            text = helper.requirements_toml("/etc/codex", rules=rules)
            self.assertEqual(helper.minimal_toml(text), tomllib.loads(text))

    def test_the_hook_table_matches_the_files_install_copies(self):
        install = (ORG / "install.sh").read_text(encoding="utf-8")
        for name in helper.CODEX_HOOK_FILES:
            self.assertIn(f'"$REPO/hooks/claude-code/{name}"', install)
            self.assertTrue((ROOT / "hooks" / "claude-code" / name).is_file())
        self.assertEqual(set(helper.CODEX_HOOK_FILES), set(HOOK_FILES))


if __name__ == "__main__":
    unittest.main()
