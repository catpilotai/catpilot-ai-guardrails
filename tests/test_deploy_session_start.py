"""Company rules at session start through deploy/org: install.sh --overlay places them, verify.sh checks them,
uninstall.sh removes them. Offline, in temporary directories, through the CATPILOT_CC_DIR, CATPILOT_CODEX_DIR and
CATPILOT_ALLOW_NONROOT overrides.

What each host reads, from the vendors' documentation (read on 2026-11-16):
  Claude Code  https://code.claude.com/docs/en/memory: the managed CLAUDE.md is <managed dir>/CLAUDE.md
               (/Library/Application Support/ClaudeCode/ on macOS, /etc/claude-code/ on Linux and WSL), and
               block-level HTML comments are stripped before the content reaches the model.
               https://code.claude.com/docs/en/hooks: SessionStart matchers startup, resume, clear, compact, fork.
  Codex        https://learn.chatgpt.com/docs/hooks, "Managed hooks in local Codex": [hooks] in
               /etc/codex/requirements.toml, an absolute managed_dir that exists, absolute script paths under it.

The rules are docs/spec/overlay.example.yaml with its two dates moved around today, so the tests do not depend on
the day they run.
"""

from __future__ import annotations

import ast
import contextlib
import datetime as dt
import hashlib
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
INSTALL_SH = ORG / "install.sh"
VERIFY_SH = ORG / "verify.sh"
UNINSTALL_SH = ORG / "uninstall.sh"
HELPER_PATH = ORG / "session_start_files.py"
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
SCRIPT = ROOT / "hooks" / "session-start" / "catpilot-company-rules.py"
URL = "https://mcp.internal.example.org/mcp"
OWNER = "security-review@example.org"
SOURCES = ("startup", "resume", "clear", "compact", "fork")

try:
    import tomllib
except ImportError:  # pragma: no cover - Python < 3.11
    tomllib = None


def load_helper():
    spec = importlib.util.spec_from_file_location("session_start_files", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True  # no __pycache__ in deploy/org
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


helper = load_helper()


def dated_example(directory: Path, reviewed: dt.date, expires: dt.date) -> Path:
    """The example rules file with its review and expiry dates replaced."""
    text = EXAMPLE.read_text(encoding="utf-8")
    for key, value in (("reviewed_on", "2026-09-13"), ("expires_on", "2027-03-13")):
        assert f"{key}: {value}\n" in text, key
    text = text.replace("reviewed_on: 2026-09-13\n", f"reviewed_on: {reviewed.isoformat()}\n")
    text = text.replace("expires_on: 2027-03-13\n", f"expires_on: {expires.isoformat()}\n")
    path = directory / "rules.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def parse_toml(text: str) -> dict:
    return tomllib.loads(text) if tomllib is not None else helper.minimal_toml(text)


class SessionStartDeployTests(unittest.TestCase):
    # These tests check the package-tree layout, which install.sh keeps behind --package-tree for one release;
    # tests/test_deploy_zipapp.py runs the layout-agnostic ones again with the zipapp, the default.
    PACKAGE_TREE = "1"

    @staticmethod
    def expected(function, *args, **kwargs):
        """What install.sh writes: the helper's output with the interpreter it records (PYTHON_BIN)."""
        with helper.interpreter(sys.executable):
            return function(*args, **kwargs)

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cc = self.tmp / "claude-code"
        self.codex = self.tmp / "codex"
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.today = dt.date.today()
        self.reviewed = self.today - dt.timedelta(days=1)
        self.expires = self.today + dt.timedelta(days=365)
        self.rules = dated_example(self.tmp, self.reviewed, self.expires)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        self.env.update(
            {
                "CATPILOT_ALLOW_NONROOT": "1",
                "CATPILOT_CC_DIR": str(self.cc),
                "CATPILOT_CODEX_DIR": str(self.codex),
                "CATPILOT_COPILOT_DIR": str(self.tmp / "copilot"),
                "PYTHON_BIN": sys.executable,
                "HOME": str(self.home),
                "CATPILOT_PACKAGE_TREE": self.PACKAGE_TREE,
            }
        )

    def tearDown(self):
        self._tmp.cleanup()

    # --- running the scripts -------------------------------------------------------------------------------------

    def run_script(self, script: Path, *args: str, env=None, timeout=60) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(script), *args], env=env or self.env, capture_output=True, text=True, timeout=timeout)

    def install(self, overlay: bool = True) -> subprocess.CompletedProcess:
        args = ["--server-url", URL]
        if overlay:
            args += ["--overlay", str(self.rules)]
        proc = self.run_script(INSTALL_SH, *args)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def verify(self) -> subprocess.CompletedProcess:
        return self.run_script(VERIFY_SH, timeout=120)

    def uninstall(self) -> subprocess.CompletedProcess:
        proc = self.run_script(UNINSTALL_SH, "--server-url", URL)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    # --- what install.sh placed ----------------------------------------------------------------------------------

    def instructions(self, managed_dir: Path) -> Path:
        return managed_dir / "catpilot-guardrails" / "instructions"

    def block(self) -> bytes:
        return (self.instructions(self.cc) / "company-checklist.md").read_bytes()

    def sidecar(self) -> dict:
        return json.loads((self.instructions(self.cc) / "company-checklist.json").read_text(encoding="utf-8"))

    def command(self, managed_dir: Path, host: str) -> str:
        script = managed_dir / "catpilot-guardrails" / "hooks" / "catpilot-company-rules.py"
        return f'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" "{sys.executable}" "{script}" --evidence-default --host {host}'

    def base_settings(self) -> str:
        text = (ORG / "claude-code" / "managed-settings.json").read_text(encoding="utf-8")
        text = text.replace("https://mcp.example.com/mcp", URL).replace("/Library/Application Support/ClaudeCode", str(self.cc))
        # install.sh records the interpreter it proved (PYTHON_BIN) in place of the template's python3.
        return text.replace(' python3 \\"', ' \\"%s\\" \\"' % sys.executable)

    def set_dates(self, reviewed: dt.date, expires: dt.date) -> None:
        for managed_dir in (self.cc, self.codex):
            path = self.instructions(managed_dir) / "company-checklist.json"
            data = json.loads(path.read_text(encoding="utf-8"))
            data.update(reviewed_on=reviewed.isoformat(), expires_on=expires.isoformat())
            path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def snapshot(self) -> dict:
        files = {}
        for top in (self.cc, self.codex):
            if top.exists():
                for path in top.rglob("*"):
                    if path.is_symlink():
                        files[str(path.relative_to(self.tmp))] = ("link", os.readlink(path))
                    elif path.is_file():
                        files[str(path.relative_to(self.tmp))] = (path.read_bytes(), path.stat().st_mode & 0o777)
        return files

    def registered_commands(self) -> dict:
        settings = json.loads((self.cc / "managed-settings.json").read_text(encoding="utf-8"))
        requirements = parse_toml((self.codex / "requirements.toml").read_text(encoding="utf-8"))
        return {
            "claude-code": settings["hooks"]["SessionStart"][0]["hooks"][0]["command"],
            "codex": requirements["hooks"]["SessionStart"][0]["hooks"][0]["command"],
        }

    def run_registered(self, command: str, project: Path) -> dict:
        """Run a registered command line as written, through a shell, the way the host does."""
        event = json.dumps({"session_id": "e2e-0001", "hook_event_name": "SessionStart", "source": "startup", "cwd": str(project)})
        proc = subprocess.run(["/bin/sh", "-c", command], input=event, env=self.env, cwd=str(project),
                              capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    # --- install -------------------------------------------------------------------------------------------------

    def test_without_overlay_nothing_about_session_start_is_placed(self):
        proc = self.install(overlay=False)
        self.assertFalse((self.cc / "CLAUDE.md").exists())
        self.assertEqual((self.cc / "managed-settings.json").read_text(encoding="utf-8"), self.base_settings())
        self.assertNotIn("SessionStart", (self.cc / "managed-settings.json").read_text(encoding="utf-8"))
        # Codex gets its PreToolUse hooks (tests/test_deploy_codex_hooks.py) and no session-start hook or rules.
        self.assertEqual((self.codex / "requirements.toml").read_text(encoding="utf-8"),
                         self.expected(helper.requirements_toml, str(self.codex), rules=False) + "\n")
        self.assertNotIn("SessionStart", (self.codex / "requirements.toml").read_text(encoding="utf-8"))
        self.assertFalse((self.codex / "catpilot-guardrails" / "hooks" / "catpilot-company-rules.py").exists())
        self.assertFalse(self.instructions(self.codex).exists())
        self.assertFalse((self.cc / "catpilot-guardrails" / "hooks" / "catpilot-company-rules.py").exists())
        self.assertFalse(self.instructions(self.cc).exists())
        self.assertNotIn("rules   ", proc.stdout)

        verify = self.verify()
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertIn("absent   company rules at session start (install.sh places them only with --overlay)", verify.stdout)
        self.assertIn("present  " + str(self.cc / "catpilot-guardrails" / "hooks" / "catpilot_guard" / "session_start.py"), verify.stdout)

    def test_overlay_places_the_rules_the_hook_and_its_registration_on_each_tool(self):
        self.install()
        block = self.block()
        sidecar = self.sidecar()
        self.assertEqual(hashlib.sha256(block).hexdigest(), sidecar["block_sha256"])
        self.assertEqual((sidecar["owner"], sidecar["expires_on"]), (OWNER, self.expires.isoformat()))

        # Claude Code: the block in the managed CLAUDE.md between the markers, and nothing else in it.
        claude_md = self.cc / "CLAUDE.md"
        self.assertEqual(claude_md.read_bytes(), helper.BEGIN.encode() + b"\n" + block + helper.END.encode() + b"\n")
        self.assertEqual(claude_md.stat().st_mode & 0o777, 0o644)
        # The SessionStart hook in managed-settings.json, added to the template's own JSON layout.
        settings_text = (self.cc / "managed-settings.json").read_text(encoding="utf-8")
        settings = json.loads(settings_text)
        base = json.loads(self.base_settings())
        self.assertEqual(settings["hooks"]["PreToolUse"], base["hooks"]["PreToolUse"])
        self.assertEqual(settings["managedMcpServers"], base["managedMcpServers"])
        self.assertEqual(
            settings["hooks"]["SessionStart"],
            [{"matcher": "startup|resume|clear|compact|fork",
              "hooks": [{"type": "command", "command": self.command(self.cc, "claude-code"), "timeout": 10}]}],
        )
        base["hooks"]["SessionStart"] = settings["hooks"]["SessionStart"]
        self.assertEqual(settings_text, json.dumps(base, indent=2) + "\n")
        # The same evidence prefix as the PreToolUse hooks.
        for group in settings["hooks"]["PreToolUse"]:
            for handler in group["hooks"]:
                self.assertTrue(handler["command"].startswith(helper.EVIDENCE_PREFIX + ' "%s" ' % sys.executable), handler["command"])

        # Each tool has its own copy: the script, the package it imports, and the rules.
        for managed_dir in (self.cc, self.codex):
            hooks = managed_dir / "catpilot-guardrails" / "hooks"
            self.assertEqual((hooks / "catpilot-company-rules.py").read_bytes(), SCRIPT.read_bytes())
            self.assertEqual(sorted(p.name for p in (hooks / "catpilot_guard").iterdir()),
                             sorted(p.name for p in (ROOT / "catpilot_guard").glob("*.py")))
            self.assertEqual((self.instructions(managed_dir) / "company-checklist.md").read_bytes(), block)
            for path in (managed_dir / "catpilot-guardrails", hooks, self.instructions(managed_dir), hooks / "catpilot_guard"):
                self.assertEqual(path.stat().st_mode & 0o777, 0o755, path)
            for path in [hooks / "catpilot-company-rules.py", *self.instructions(managed_dir).glob("company-checklist.*")]:
                self.assertEqual(path.stat().st_mode & 0o777, 0o644, path)
        self.assertEqual((self.instructions(self.codex) / "company-checklist.json").read_bytes(),
                         (self.instructions(self.cc) / "company-checklist.json").read_bytes())

        # Codex: requirements.toml declares the managed session-start hook beside the PreToolUse hooks, keeps hooks
        # on, and switches nothing else on or off.
        text = (self.codex / "requirements.toml").read_text(encoding="utf-8")
        self.assertEqual(text, self.expected(helper.requirements_toml, str(self.codex)) + "\n")
        requirements = parse_toml(text)
        self.assertEqual(set(requirements), {"features", "hooks"})
        self.assertEqual(requirements["features"], {"hooks": True})
        self.assertEqual(set(requirements["hooks"]), {"managed_dir", "PreToolUse", "SessionStart"})
        self.assertEqual(requirements["hooks"]["managed_dir"], str(self.codex / "catpilot-guardrails" / "hooks"))
        self.assertTrue(Path(requirements["hooks"]["managed_dir"]).is_dir())
        self.assertEqual(
            requirements["hooks"]["SessionStart"],
            [{"matcher": "startup|resume|clear|compact|fork",
              "hooks": [{"type": "command", "command": self.command(self.codex, "codex"), "timeout": 10}]}],
        )
        self.assertEqual((self.codex / "requirements.toml").stat().st_mode & 0o777, 0o644)

        verify = self.verify()
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        out = verify.stdout
        self.assertIn("0 missing, 0 failed", out)
        self.assertNotIn("FAIL", out)
        self.assertIn(f"valid    company rules from {OWNER}, reviewed {self.reviewed.isoformat()}, valid until {self.expires.isoformat()}", out)
        self.assertIn("matches  the marked section in CLAUDE.md is company-checklist.md (same SHA-256)", out)
        self.assertEqual(out.count("matches  company-checklist.md has the SHA-256 in company-checklist.json"), 2)
        self.assertIn("runs     catpilot-company-rules.py --host claude-code, run directly, gives the model the one-line status", out)
        self.assertIn("runs     catpilot-company-rules.py --host codex, run directly, gives the model the whole block", out)
        self.assertIn("wired    managed-settings.json runs it at SessionStart", out)
        self.assertIn("wired    requirements.toml runs it at SessionStart", out)
        self.assertIn("/context all", out)
        # verify.sh writes no evidence line: not in the real home, not anywhere an environment variable names.
        self.assertFalse((self.home / ".catpilot-guardrails").exists())

    def test_the_registered_commands_run_as_written_end_to_end(self):
        self.install()
        commands = self.registered_commands()
        project = self.tmp / "project"
        project.mkdir()
        block = self.block().decode("utf-8")
        sidecar = self.sidecar()
        log = self.home / ".catpilot-guardrails" / "evidence.jsonl"

        current = {host: self.run_registered(command, project) for host, command in commands.items()}
        self.assertEqual(
            current["claude-code"],
            {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext":
                f"Company rules from {OWNER}, reviewed {self.reviewed.isoformat()}, valid until {self.expires.isoformat()}, are current."}},
        )
        self.assertEqual(current["codex"], {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": block}})
        self.assertIn("Overlay SHA-256: " + sidecar["policy_sha256"], current["codex"]["hookSpecificOutput"]["additionalContext"])
        lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([(l["event"], l["host"], l["source"], l["session_source"]) for l in lines],
                         [("rules_delivered", "claude-code", "session-start", "startup"),
                          ("rules_delivered", "codex", "session-start", "startup")])
        for line in lines:
            self.assertEqual(line["policy_sha256"], sidecar["policy_sha256"])
            self.assertNotIn(OWNER, json.dumps(line))
            self.assertNotIn("Internal App Platform", json.dumps(line))

        # Expired: each host gets a notice, as a warning and to the model, that names the date and the owner.
        self.set_dates(self.today - dt.timedelta(days=60), self.today - dt.timedelta(days=1))
        expired_on = (self.today - dt.timedelta(days=1)).isoformat()
        for host, command in commands.items():
            output = self.run_registered(command, project)
            context = output["hookSpecificOutput"]["additionalContext"]
            self.assertEqual(output["systemMessage"], context)
            self.assertIn(f"The company rules expired on {expired_on} and are not in force.", context)
            self.assertIn(f"Ask {OWNER} for current rules.", context)
            self.assertNotIn("Internal App Platform", context)
        lines = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()][2:]
        self.assertEqual([(l["event"], l["host"]) for l in lines], [("rules_expired", "claude-code"), ("rules_expired", "codex")])

    def test_an_existing_claude_md_without_markers_is_left_alone_and_the_section_printed(self):
        self.cc.mkdir(parents=True)
        claude_md = self.cc / "CLAUDE.md"
        original = "# Our standards\n\nUse the internal linter.\n"
        claude_md.write_text(original, encoding="utf-8")
        proc = self.install()
        self.assertEqual(claude_md.read_text(encoding="utf-8"), original)
        self.assertIn(f"exists  {claude_md} (not modified: it has no catpilot-company-rules markers); add this section to it", proc.stdout)
        printed = helper.section(self.block().decode("utf-8"))
        self.assertIn(printed.rstrip("\n"), proc.stdout)

        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"FAIL     {claude_md} has no single catpilot-company-rules section", verify.stdout)

        # The administrator merges the printed section; verify.sh then passes.
        claude_md.write_text(original + "\n" + printed, encoding="utf-8")
        verify = self.verify()
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

        uninstall = self.uninstall()
        self.assertIn(f"removed the company rules section from {claude_md} (the rest of the file is kept)", uninstall.stdout)
        self.assertEqual(claude_md.read_text(encoding="utf-8"), original + "\n")

    def test_an_existing_claude_md_with_markers_has_only_the_marked_section_replaced(self):
        self.cc.mkdir(parents=True)
        claude_md = self.cc / "CLAUDE.md"
        before = "# Our standards\n\nUse the internal linter.\n\n"
        after = "\n## Reviews\n\nAsk the platform team.\n"
        claude_md.write_text(before + helper.BEGIN + "\nLast year's rules.\n" + helper.END + "\n" + after, encoding="utf-8")
        claude_md.chmod(0o664)

        proc = self.install()
        self.assertIn(f"rules   {claude_md} (marked section replaced; the rest of the file is unchanged)", proc.stdout)
        self.assertEqual(claude_md.read_text(encoding="utf-8"), before + helper.section(self.block().decode("utf-8")) + after)
        self.assertEqual(claude_md.stat().st_mode & 0o777, 0o664)
        self.assertEqual([p.name for p in self.cc.iterdir() if p.name.startswith(".CLAUDE.md")], [])

        again = self.install()
        self.assertIn(f"rules   {claude_md} (marked section unchanged)", again.stdout)
        verify = self.verify()
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

        uninstall = self.uninstall()
        self.assertIn(f"removed the company rules section from {claude_md}", uninstall.stdout)
        self.assertEqual(claude_md.read_text(encoding="utf-8"), before + after)

    def test_markers_that_are_not_one_pair_and_a_linked_claude_md_are_left_alone(self):
        self.cc.mkdir(parents=True)
        claude_md = self.cc / "CLAUDE.md"
        doubled = f"{helper.BEGIN}\none\n{helper.END}\n{helper.BEGIN}\ntwo\n{helper.END}\n"
        claude_md.write_text(doubled, encoding="utf-8")
        proc = self.install()
        self.assertEqual(claude_md.read_text(encoding="utf-8"), doubled)
        self.assertIn("not modified: its catpilot-company-rules markers are not one begin line followed by one end line", proc.stdout)
        uninstall = self.uninstall()
        self.assertEqual(claude_md.read_text(encoding="utf-8"), doubled)
        self.assertIn(f"kept    {claude_md} (its catpilot-company-rules markers are unbalanced", uninstall.stdout)

        claude_md.unlink()
        target = self.tmp / "elsewhere.md"
        target.write_text(f"{helper.BEGIN}\nold\n{helper.END}\n", encoding="utf-8")
        claude_md.symlink_to(target)
        proc = self.install()
        self.assertTrue(claude_md.is_symlink())
        self.assertEqual(target.read_text(encoding="utf-8"), f"{helper.BEGIN}\nold\n{helper.END}\n")
        self.assertIn(f"exists  {claude_md} (not modified: it is not a regular file)", proc.stdout)

    def test_existing_managed_files_are_not_overwritten_and_uninstall_restores_the_starting_state(self):
        self.cc.mkdir(parents=True)
        self.codex.mkdir(parents=True)
        (self.cc / "managed-settings.json").write_text('{"permissions": {"deny": ["Bash(curl:*)"]}}\n', encoding="utf-8")
        (self.codex / "requirements.toml").write_text('allowed_sandbox_modes = ["read-only", "workspace-write"]\n', encoding="utf-8")
        (self.cc / "CLAUDE.md").write_text("# Our standards\n", encoding="utf-8")
        (self.codex / "notes.txt").write_text("not ours\n", encoding="utf-8")
        start = self.snapshot()

        proc = self.install()
        for name in ("claude-code/managed-settings.json", "codex/requirements.toml", "claude-code/CLAUDE.md"):
            self.assertEqual(self.snapshot()[name], start[name], name)
        self.assertIn(f"exists  {self.cc / 'managed-settings.json'} (not overwritten); merge these keys into it:", proc.stdout)
        self.assertIn('"SessionStart": [', proc.stdout)
        self.assertIn(f"exists  {self.codex / 'requirements.toml'} (not overwritten); merge this into it", proc.stdout)
        self.assertIn("[[hooks.SessionStart.hooks]]", proc.stdout)

        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn("FAIL     managed-settings.json does not run catpilot-company-rules.py at SessionStart", verify.stdout)
        self.assertIn("FAIL     requirements.toml does not run catpilot-company-rules.py at SessionStart", verify.stdout)

        uninstall = self.uninstall()
        self.assertEqual(self.snapshot(), start)
        self.assertNotIn("kept", uninstall.stdout)

    def test_uninstall_from_a_machine_with_none_of_the_files_leaves_none(self):
        self.install()
        uninstall = self.uninstall()
        self.assertEqual(self.snapshot(), {})
        for path in (self.cc / "CLAUDE.md", self.codex / "requirements.toml", self.codex / "catpilot-guardrails",
                     self.cc / "managed-settings.json"):
            self.assertIn(f"removed {path}", uninstall.stdout)

    def test_uninstall_keeps_edited_managed_files_and_says_what_to_remove(self):
        self.install()
        settings = self.cc / "managed-settings.json"
        data = json.loads(settings.read_text(encoding="utf-8"))
        data["cleanupPeriodDays"] = 30
        settings.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        requirements = self.codex / "requirements.toml"
        requirements.write_text(requirements.read_text(encoding="utf-8") + 'allowed_web_search_modes = ["cached"]\n', encoding="utf-8")

        uninstall = self.uninstall()
        self.assertTrue(settings.exists())
        self.assertTrue(requirements.exists())
        self.assertIn(f"kept    {settings} (edited since install; remove the catpilot keys by hand: the hooks entries that run "
                      "catpilot-guardrails/hooks/, SessionStart and the company-rules hook included", uninstall.stdout)
        self.assertIn(f"kept    {requirements} (edited since install; remove by hand the [hooks] managed_dir", uninstall.stdout)
        self.assertFalse((self.cc / "CLAUDE.md").exists())
        # The kept files still run hooks from these directories, so they stay until those entries are removed.
        for managed_dir, kept in ((self.cc, settings), (self.codex, requirements)):
            self.assertTrue((managed_dir / "catpilot-guardrails" / "hooks").is_dir(), managed_dir)
            self.assertFalse((managed_dir / "catpilot-guardrails" / "instructions").exists(), managed_dir)
            self.assertIn(f"kept    {managed_dir / 'catpilot-guardrails' / 'hooks'} ({kept} still runs hooks from it", uninstall.stdout)

    def test_reinstalling_without_overlay_leaves_earlier_rules_alone_and_says_so(self):
        self.install()
        before = self.snapshot()
        proc = self.install(overlay=False)
        self.assertIn("note    company rules at session start from an earlier --overlay install are still in place", proc.stdout)
        after = self.snapshot()
        for name in ("claude-code/CLAUDE.md", "codex/requirements.toml", "claude-code/managed-settings.json"):
            self.assertEqual(after[name], before[name], name)

    def test_an_unsafe_managed_directory_stops_the_install_before_anything_is_written(self):
        self.env["CATPILOT_CODEX_DIR"] = str(self.tmp / "co$dex")
        proc = self.run_script(INSTALL_SH, "--server-url", URL, "--overlay", str(self.rules))
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("must be an absolute path without quotes", proc.stderr)
        self.assertFalse(self.cc.exists())
        self.assertFalse((self.tmp / "co$dex").exists())

    # --- verify.sh failing ---------------------------------------------------------------------------------------

    def test_verify_fails_on_a_missing_block(self):
        self.install()
        block = self.instructions(self.cc) / "company-checklist.md"
        block.unlink()
        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"MISSING  {block}", verify.stdout)
        self.assertIn("notice   catpilot-company-rules.py --host claude-code, run directly, prints that the company rules could not be loaded", verify.stdout)
        # Codex's copy is its own and still delivers.
        self.assertIn("runs     catpilot-company-rules.py --host codex, run directly, gives the model the whole block", verify.stdout)

    def test_verify_fails_without_the_marked_section_in_claude_md(self):
        self.install()
        (self.cc / "CLAUDE.md").unlink()
        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"MISSING  {self.cc / 'CLAUDE.md'}", verify.stdout)

    def test_verify_fails_on_a_hash_mismatch(self):
        self.install()
        block = self.instructions(self.codex) / "company-checklist.md"
        block.write_bytes(block.read_bytes() + b"- Also approved: anything.\n")
        claude_md = self.cc / "CLAUDE.md"
        claude_md.write_text(claude_md.read_text(encoding="utf-8").replace("Free-tier hosting", "Paid hosting"), encoding="utf-8")
        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"FAIL     {block} has SHA-256", verify.stdout)
        self.assertIn("the hook prints that the rules could not be loaded", verify.stdout)
        self.assertIn("FAIL     the marked section in", verify.stdout)
        self.assertIn("notice   requirements.toml runs it at SessionStart, and its command, run through a shell, prints that the company rules could not be loaded", verify.stdout)

    def test_verify_fails_on_expired_rules_and_sees_each_notice(self):
        self.install()
        expired_on = self.today - dt.timedelta(days=1)
        self.set_dates(self.today - dt.timedelta(days=90), expired_on)
        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"FAIL     company rules from {OWNER} expired on {expired_on.isoformat()}", verify.stdout)
        self.assertEqual(verify.stdout.count("prints the expired notice, as a warning and to the model, and no rules"), 4)
        self.assertIn("1 failed", verify.stdout)

    def test_verify_reports_a_matcher_that_misses_a_start_source(self):
        self.install()
        path = self.cc / "managed-settings.json"
        settings = json.loads(path.read_text(encoding="utf-8"))
        settings["hooks"]["SessionStart"][0]["matcher"] = "startup|resume"
        path.write_text(json.dumps(settings), encoding="utf-8")
        verify = self.verify()
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn("matcher that does not cover clear,compact,fork", verify.stdout)

    def test_verify_reads_requirements_without_tomllib(self):
        self.install()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            helper.verify(self.cc, self.codex, self.home, 10, prefer_tomllib=False)
        self.assertIn("(read with a minimal reader; this Python has no tomllib)", out.getvalue())
        self.assertIn("wired    requirements.toml runs it at SessionStart", out.getvalue())
        self.assertNotIn("FAIL", out.getvalue())


class SessionStartFilesHelperTests(unittest.TestCase):
    MERGED = (
        'allowed_sandbox_modes = ["read-only"]  # an administrator\'s own key\n'
        "allow_managed_hooks_only = false\n\n"
        "[features]\nhooks = true\n\n"
        "[mcp_servers.docs.identity]\nurl = \"https://docs.example.org/mcp\"\n\n"
    )

    def test_the_minimal_reader_reads_the_hooks_tomllib_reads(self):
        if tomllib is None:
            self.skipTest("tomllib needs Python 3.11 or later")
        generated = helper.requirements_toml("/etc/codex")
        # Merged by hand into a file that already pins [features].hooks: one [features] table.
        merged = self.MERGED + generated.replace("[features]\nhooks = true\n\n", "")
        for text in (generated, merged):
            self.assertEqual(helper.minimal_toml(text)["hooks"], tomllib.loads(text)["hooks"])
        self.assertEqual(helper.minimal_toml(self.MERGED)["features"], {"hooks": True})
        escaped = '[hooks]\nmanaged_dir = "/opt/\\u00e9t\\U0001F600/\\"q\\"\\\\"\n'
        self.assertEqual(helper.minimal_toml(escaped)["hooks"], tomllib.loads(escaped)["hooks"])

    def test_the_markers_are_block_level_comments_around_the_block(self):
        text = helper.section("Rules.\n")
        self.assertEqual(text, "<!-- catpilot-company-rules:begin -->\nRules.\n<!-- catpilot-company-rules:end -->\n")
        self.assertEqual(helper.section_body("# Ours\n\n" + text + "\nMore.\n"), "Rules.\n")
        self.assertIsNone(helper.section_body("# Ours\n"))
        self.assertIsNone(helper.section_body(text + text))

    def test_an_unsafe_managed_directory_is_refused(self):
        for value in ('/etc/co"dex', "/etc/co'dex", "/etc/co$dex", "/etc/co`x`", "/etc/co\\dex", "/etc/co\ndex", "etc/codex"):
            with self.subTest(value=value), self.assertRaises(helper.UsageError):
                helper.requirements_toml(value)
            with self.subTest(value=value), self.assertRaises(helper.UsageError):
                helper.settings_with_session_start("{}", value)

    def test_the_docs_show_what_install_writes(self):
        doc = (ROOT / "docs" / "DEPLOY_ORG.md").read_text(encoding="utf-8")
        # The file without --overlay in full, then the session-start tables --overlay adds after it.
        hooks_only = helper.requirements_toml("/etc/codex", rules=False)
        self.assertIn(hooks_only[hooks_only.index("[features]"):], doc)
        toml = helper.requirements_toml("/etc/codex")
        self.assertIn(toml[toml.index("[[hooks.SessionStart]]"):], doc)
        group = json.dumps(helper.session_start_group("/Library/Application Support/ClaudeCode"), indent=2)
        self.assertIn(group, doc)

    def test_the_helper_parses_as_python_3_8_and_imports_only_the_standard_library(self):
        tree = ast.parse(HELPER_PATH.read_text(encoding="utf-8"), filename=str(HELPER_PATH), feature_version=(3, 8))
        stdlib = getattr(sys, "stdlib_module_names", None)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module.split(".")[0]]
            for name in names:
                if stdlib is not None:
                    self.assertIn(name, stdlib | {"__future__"}, name)


if __name__ == "__main__":
    unittest.main()
