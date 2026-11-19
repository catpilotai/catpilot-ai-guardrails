"""deploy/org/windows_files.py and install.ps1, verify.ps1, uninstall.ps1 (docs/spec/WINDOWS.md §3.3).

The generators and the verify probes run everywhere. The PowerShell scripts run only on Windows: the windows-latest
CI job runs this module through tests/windows_suite.py, with -PythonPath and, when CATPILOT_TEST_EMBEDDED_PYTHON=1,
with the pinned embeddable interpreter install.ps1 downloads. That verifies the scripts on a runner. It runs no
tool: not Claude Code, Codex or Copilot CLI. Python 3.8 compatible.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ORG = ROOT / "deploy" / "org"
sys.path.insert(0, str(ORG))
import session_start_files as ssf  # noqa: E402
import windows_files as wf  # noqa: E402

PY = "C:\\Program Files\\ClaudeCode\\catpilot-guardrails\\python\\python.exe"
CC = "C:\\Program Files\\ClaudeCode"
CODEX = "C:\\ProgramData\\OpenAI\\Codex"
COPILOT = "C:\\ProgramData\\GitHub\\Copilot"
URL = "https://mcp.internal.example.org/mcp"


class GeneratorTests(unittest.TestCase):
    def test_claude_code_settings_run_each_hook_in_exec_form_with_on_failure_block(self):
        data = json.loads(wf.cc_settings(CC, PY, URL))
        self.assertEqual(data["managedMcpServers"]["catpilot-guardrails"]["url"], URL)
        names = []
        for group in data["hooks"]["PreToolUse"]:
            for entry in group["hooks"]:
                self.assertEqual(entry["command"], PY)
                self.assertEqual(entry["onFailure"], "block")
                self.assertEqual(entry["args"][1:], ["--evidence-default"])
                self.assertTrue(entry["args"][0].startswith(CC + "\\catpilot-guardrails\\hooks\\"), entry["args"][0])
                names.append(entry["args"][0].rsplit("\\", 1)[1])
        self.assertEqual(sorted(names), ["pretooluse-destructive-ops.py", "pretooluse-secrets.py", "pretooluse-write-secrets.py"])
        self.assertEqual(data["hooks"]["PreToolUse"][0]["matcher"], "Bash|PowerShell")

    def test_codex_requirements_name_the_windows_managed_dir_and_command_windows(self):
        text = wf.codex_requirements(CODEX, PY)
        data = ssf.minimal_toml(text)
        self.assertEqual(data["hooks"]["windows_managed_dir"], CODEX + "\\catpilot-guardrails\\hooks")
        commands = [h["command_windows"] for g in data["hooks"]["PreToolUse"] for h in g["hooks"]]
        self.assertEqual(len(commands), 3)
        for command in commands:
            words = wf.split_windows(command)
            self.assertEqual(words[0], PY)
            self.assertTrue(words[1].startswith(CODEX + "\\catpilot-guardrails\\hooks\\"))
            self.assertEqual(words[2:], ["--evidence-default", "--host", "codex"])

    def test_copilot_policy_uses_exec_and_args(self):
        entries = json.loads(wf.copilot_policy(COPILOT, PY))["hooks"]["PreToolUse"]
        self.assertEqual(len(entries), 3)
        for entry in entries:
            self.assertEqual(entry["exec"], PY)
            self.assertNotIn("bash", entry)
            self.assertEqual(entry["args"][1:], ["--evidence-default", "--host", "copilot-cli"])

    def test_unsafe_paths_and_urls_are_refused(self):
        for bad in ("relative\\python.exe", "/usr/bin/python3", 'C:\\a"b\\python.exe', "C:\\%TEMP%\\python.exe", "C:\\a$b"):
            with self.assertRaises(wf.UsageError, msg=bad):
                wf.cc_settings(CC, bad, URL)
        with self.assertRaises(wf.UsageError):
            wf.cc_settings(CC, PY, 'https://x"y')


class VerifyProbeTests(unittest.TestCase):
    """windows_files.py verify against managed files whose commands name this interpreter and the repository's hooks."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.cc, self.codex, self.copilot = self.tmp / "cc", self.tmp / "codex", self.tmp / "copilot"
        hooks = ROOT / "hooks" / "claude-code"
        settings = json.loads((ORG / "claude-code" / "managed-settings.json").read_text(encoding="utf-8"))
        for group in settings["hooks"]["PreToolUse"]:
            for entry in group["hooks"]:
                name = entry["command"].split("/hooks/")[1].split('"')[0]
                entry["command"] = sys.executable
                entry["args"] = [str(hooks / name), "--evidence-default"]
        self.cc.mkdir()
        (self.cc / "managed-settings.json").write_text(json.dumps(settings), encoding="utf-8")
        entries = []
        for matcher, _, names in ssf.COPILOT_PRETOOLUSE:
            for name in names:
                entries.append({"type": "command", "matcher": matcher, "exec": sys.executable,
                                "args": [str(hooks / name), "--evidence-default", "--host", "copilot-cli"]})
        (self.copilot / "policy.d").mkdir(parents=True)
        (self.copilot / "policy.d" / "catpilot-guardrails.json").write_text(json.dumps({"version": 1, "hooks": {"PreToolUse": entries}}), encoding="utf-8")
        lines = ["[hooks]"]
        for matcher, _, names in ssf.CODEX_PRETOOLUSE:
            lines += ["[[hooks.PreToolUse]]", 'matcher = "%s"' % matcher]
            for name in names:
                lines += ["[[hooks.PreToolUse.hooks]]", 'type = "command"',
                          "command_windows = '\"%s\" \"%s\" --evidence-default --host codex'" % (sys.executable, hooks / name)]
        self.codex.mkdir()
        (self.codex / "requirements.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def verify(self):
        out = io.StringIO()
        with redirect_stdout(out):
            code = wf.main(["verify", "--cc-dir", str(self.cc), "--codex-dir", str(self.codex), "--copilot-dir", str(self.copilot)])
        return code, out.getvalue()

    def test_every_hook_denies_its_probes_and_passes_a_harmless_call(self):
        code, out = self.verify()
        self.assertEqual(code, 0, out)
        self.assertIn("runs     %s" % sys.executable, out)
        self.assertIn("denies   pretooluse-destructive-ops.py (exec form): Remove-Item -Recurse -Force C:\\Windows", out)
        self.assertIn("denies   pretooluse-secrets.py (exec form): a PowerShell command carrying the same key", out)
        self.assertIn("passes   pretooluse-destructive-ops.py (exec form): Get-ChildItem", out)
        self.assertIn("denies   requirements.toml pretooluse-write-secrets.py", out)
        self.assertIn("denies   policy.d pretooluse-secrets.py", out)
        self.assertNotIn("FAIL", out)

    def test_an_interpreter_that_cannot_start_fails(self):
        path = self.cc / "managed-settings.json"
        missing = str(self.tmp / "no-such-python")
        path.write_text(path.read_text(encoding="utf-8").replace(json.dumps(sys.executable)[1:-1], json.dumps(missing)[1:-1]), encoding="utf-8")
        code, out = self.verify()
        self.assertNotEqual(code, 0)
        self.assertIn("FAIL     %s could not start" % missing, out)

    def test_a_hook_missing_from_the_settings_fails(self):
        path = self.cc / "managed-settings.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        del data["hooks"]["PreToolUse"][1]
        path.write_text(json.dumps(data), encoding="utf-8")
        code, out = self.verify()
        self.assertNotEqual(code, 0)
        self.assertIn("does not run pretooluse-write-secrets.py in exec form", out)


@unittest.skipUnless(os.name == "nt", "install.ps1, verify.ps1 and uninstall.ps1 run on Windows (the windows-latest CI job)")
class PowerShellScriptTests(unittest.TestCase):
    def setUp(self):
        # Not under C:\Users: install.ps1 refuses an interpreter there, and the pinned one goes under CATPILOT_CC_DIR.
        self.tmp = Path(tempfile.mkdtemp(prefix="catpilot-ps-", dir=os.environ.get("RUNNER_TEMP")))
        self.addCleanup(self.cleanup)
        self.env = dict(os.environ, CATPILOT_CC_DIR=str(self.tmp / "ClaudeCode"), CATPILOT_CODEX_DIR=str(self.tmp / "Codex"),
                        CATPILOT_COPILOT_DIR=str(self.tmp / "Copilot"))

    def cleanup(self):
        subprocess.run(["icacls", str(self.tmp), "/reset", "/T", "/C", "/Q"], capture_output=True)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def ps(self, script: str, *args: str, timeout: int = 300) -> subprocess.CompletedProcess:
        return subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(ORG / script)] + list(args),
                              env=self.env, capture_output=True, text=True, timeout=timeout)

    def assert_ok(self, proc):
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def round_trip(self, *python_args: str) -> str:
        install = self.ps("install.ps1", "-ServerUrl", URL, *python_args)
        self.assert_ok(install)
        settings = self.tmp / "ClaudeCode" / "managed-settings.json"
        data = json.loads(settings.read_text(encoding="utf-8"))
        python = data["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        self.assertTrue(python.lower().endswith("python.exe"), python)
        for name in ("requirements.toml",):
            self.assertIn(python, (self.tmp / "Codex" / name).read_text(encoding="utf-8"))
        before = settings.read_bytes()

        verify = self.ps("verify.ps1")
        self.assert_ok(verify)
        self.assertIn("denies   pretooluse-destructive-ops.py (exec form): Remove-Item -Recurse -Force C:\\Windows", verify.stdout)
        self.assertIn("locked   ", verify.stdout)
        self.assertNotIn("FAIL", verify.stdout)

        again = self.ps("install.ps1", "-ServerUrl", URL, *python_args)
        self.assert_ok(again)
        self.assertIn("current %s" % settings, again.stdout)
        self.assertEqual(settings.read_bytes(), before)

        uninstall = self.ps("uninstall.ps1", "-ServerUrl", URL)
        self.assert_ok(uninstall)
        self.assertFalse(settings.exists(), uninstall.stdout)
        self.assertFalse((self.tmp / "Codex" / "requirements.toml").exists(), uninstall.stdout)
        self.assertFalse((self.tmp / "Copilot" / "policy.d" / "catpilot-guardrails.json").exists(), uninstall.stdout)
        for root in ("ClaudeCode", "Codex", "Copilot"):
            self.assertFalse((self.tmp / root / "catpilot-guardrails").exists(), uninstall.stdout)
        return python

    def test_with_python_path(self):
        self.assertEqual(self.round_trip("-PythonPath", sys.executable), sys.executable)

    @unittest.skipUnless(os.environ.get("CATPILOT_TEST_EMBEDDED_PYTHON") == "1", "downloads the pinned interpreter")
    def test_with_the_pinned_embeddable_interpreter(self):
        python = self.round_trip()
        self.assertEqual(python, str(self.tmp / "ClaudeCode" / "catpilot-guardrails" / "python" / "python.exe"))

    def test_refuses_an_interpreter_that_does_not_run_python(self):
        proc = self.ps("install.ps1", "-ServerUrl", URL, "-PythonPath", "C:\\Windows\\System32\\whoami.exe")
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("Not installed:", proc.stderr)
        self.assertFalse((self.tmp / "ClaudeCode").exists())


if __name__ == "__main__":
    unittest.main()
