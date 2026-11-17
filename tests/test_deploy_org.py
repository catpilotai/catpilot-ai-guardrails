"""End-to-end tests for deploy/org/{install,verify,uninstall}.sh in isolated directories."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "deploy" / "org" / "install.sh"
VERIFY_SH = ROOT / "deploy" / "org" / "verify.sh"
UNINSTALL_SH = ROOT / "deploy" / "org" / "uninstall.sh"
EXAMPLE_OVERLAY = ROOT / "docs" / "spec" / "overlay.example.yaml"
HOOK_NAMES = (
    "pretooluse-secrets.py",
    "pretooluse-write-secrets.py",
    "pretooluse-write-private-key.py",
    "pretooluse-destructive-ops.py",
)


class DeployOrgScriptTests(unittest.TestCase):
    def _env(self, cc_dir: Path, codex_dir: Path) -> dict[str, str]:
        env = dict(os.environ)
        env.update(
            {
                "CATPILOT_ALLOW_NONROOT": "1",
                "CATPILOT_CC_DIR": str(cc_dir),
                "CATPILOT_CODEX_DIR": str(codex_dir),
                "PYTHON_BIN": sys.executable,
            }
        )
        return env

    def test_standard_install_verify_and_uninstall(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            codex_dir = Path(tmp) / "codex"
            env = self._env(cc_dir, codex_dir)
            url = "https://mcp.internal.example.org/mcp"

            proc = subprocess.run(
                ["bash", str(INSTALL_SH), "--server-url", url, "--managed-mcp-json"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

            settings = json.loads((cc_dir / "managed-settings.json").read_text(encoding="utf-8"))
            self.assertEqual(settings["managedMcpServers"]["catpilot-guardrails"]["url"], url)
            for hook_name in (
                "pretooluse-secrets.py",
                "pretooluse-write-secrets.py",
                "pretooluse-write-private-key.py",
                "pretooluse-destructive-ops.py",
            ):
                self.assertTrue((cc_dir / "catpilot-guardrails" / "hooks" / hook_name).is_file())

            verify = subprocess.run(
                ["bash", str(VERIFY_SH)],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            self.assertIn("0 missing", verify.stdout)

            uninstall = subprocess.run(
                ["bash", str(UNINSTALL_SH), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
            self.assertFalse((cc_dir / "managed-settings.json").exists())
            self.assertFalse((cc_dir / "managed-mcp.json").exists())
            self.assertFalse((cc_dir / "catpilot-guardrails").exists())
            self.assertFalse((codex_dir / "managed_config.toml").exists())

    def _install(self, env: dict[str, str]) -> None:
        proc = subprocess.run(
            ["bash", str(INSTALL_SH), "--server-url", "https://mcp.internal.example.org/mcp"],
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def _verify(self, env: dict[str, str]) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(VERIFY_SH)], env=env, capture_output=True, text=True, timeout=120)

    def test_verify_runs_each_installed_hook_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp) / "claude-code", Path(tmp) / "codex")
            home = Path(tmp) / "home"
            home.mkdir()
            env["HOME"] = str(home)
            env["CATPILOT_EVIDENCE_LOG"] = str(Path(tmp) / "evidence-from-env.jsonl")
            self._install(env)

            verify = self._verify(env)
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            out = verify.stdout
            self.assertIn("runs     ", out)
            for hook_name in (
                "pretooluse-secrets.py",
                "pretooluse-destructive-ops.py",
                "pretooluse-write-secrets.py",
                "pretooluse-write-private-key.py",
            ):
                self.assertIn(f"denies   {hook_name}", out)
            self.assertIn("passes   pretooluse-secrets.py", out)
            self.assertIn("passes   pretooluse-destructive-ops.py", out)
            for hook_name in ("pretooluse-secrets.py", "pretooluse-destructive-ops.py", "pretooluse-write-secrets.py"):
                self.assertIn(f"wired    managed-settings.json runs {hook_name}", out)
            self.assertIn("0 missing, 0 failed", out)
            self.assertNotIn("FAIL", out)
            # The probes are content-free and leave nothing behind: no evidence line in the user's real log
            # (the managed command's inline CATPILOT_EVIDENCE_LOG points at $HOME) or in one named by the
            # environment.
            self.assertFalse((home / ".catpilot-guardrails").exists())
            self.assertFalse((Path(tmp) / "evidence-from-env.jsonl").exists())
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", out)

    def test_verify_fails_when_python3_cannot_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = self._env(Path(tmp) / "claude-code", Path(tmp) / "codex")
            self._install(env)
            fake_bin = Path(tmp) / "bin"
            fake_bin.mkdir()
            fake = fake_bin / "python3"
            fake.write_text("#!/bin/sh\nexit 127\n", encoding="utf-8")
            fake.chmod(0o755)
            env.pop("PYTHON_BIN")
            env["PATH"] = f"{fake_bin}{os.pathsep}{env['PATH']}"

            verify = self._verify(env)
            self.assertNotEqual(verify.returncode, 0, verify.stdout)
            fail_lines = [line for line in verify.stdout.splitlines() if line.startswith("FAIL") and "python3" in line]
            self.assertTrue(fail_lines, verify.stdout)
            self.assertIn("non-blocking error", fail_lines[0])
            self.assertIn("unchecked", fail_lines[0])
            # With no working interpreter the JSON check is skipped, not reported as a parse failure.
            self.assertNotIn("INVALID", verify.stdout)

    def test_verify_reports_a_hook_that_does_not_deny(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            env = self._env(cc_dir, Path(tmp) / "codex")
            self._install(env)
            hook = cc_dir / "catpilot-guardrails" / "hooks" / "pretooluse-secrets.py"
            hook.write_text('print("{}")\n', encoding="utf-8")

            verify = self._verify(env)
            self.assertNotEqual(verify.returncode, 0, verify.stdout)
            self.assertIn("FAIL     pretooluse-secrets.py did not deny", verify.stdout)
            self.assertNotIn("denies   pretooluse-secrets.py:", verify.stdout)  # the Claude Code copy; the Codex copy prints "--host codex:"
            self.assertIn("denies   pretooluse-destructive-ops.py", verify.stdout)

    def test_verify_reports_managed_settings_that_do_not_run_the_hooks(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            env = self._env(cc_dir, Path(tmp) / "codex")
            self._install(env)
            # An administrator kept an existing managed-settings.json and never merged the hooks block.
            (cc_dir / "managed-settings.json").write_text('{"permissions": {}}\n', encoding="utf-8")

            verify = self._verify(env)
            self.assertNotEqual(verify.returncode, 0, verify.stdout)
            for hook_name in ("pretooluse-secrets.py", "pretooluse-destructive-ops.py", "pretooluse-write-secrets.py"):
                self.assertIn(f"FAIL     managed-settings.json does not run {hook_name}", verify.stdout)

    def test_verify_reports_a_matcher_that_misses_a_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            env = self._env(cc_dir, Path(tmp) / "codex")
            self._install(env)
            settings_path = cc_dir / "managed-settings.json"
            settings = json.loads(settings_path.read_text(encoding="utf-8"))
            for group in settings["hooks"]["PreToolUse"]:
                if group["matcher"].startswith("Write"):
                    group["matcher"] = "Write"
            settings_path.write_text(json.dumps(settings), encoding="utf-8")

            verify = self._verify(env)
            self.assertNotEqual(verify.returncode, 0, verify.stdout)
            self.assertIn("does not cover Edit,MultiEdit,NotebookEdit", verify.stdout)

    def test_overlay_install_and_edited_config_preservation(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            codex_dir = Path(tmp) / "codex"
            env = self._env(cc_dir, codex_dir)
            url = "https://mcp.internal.example.org/mcp"

            proc = subprocess.run(
                [
                    "bash",
                    str(INSTALL_SH),
                    "--server-url",
                    url,
                    "--overlay",
                    str(EXAMPLE_OVERLAY),
                    "--allow-host",
                    "intranet.example.org",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)

            # Private overlay bundle and host blocks are installed
            priv_skills = list((cc_dir / ".claude" / "skills").glob("catpilot-safe-building-*"))
            self.assertEqual(len(priv_skills), 1)
            self.assertTrue((cc_dir / "catpilot-guardrails" / "instructions" / "CLAUDE.md").is_file())
            self.assertTrue((cc_dir / "catpilot-guardrails" / "instructions" / "AGENTS.md").is_file())

            # Simulate admin merging an extra key into managed-settings.json after install
            settings_path = cc_dir / "managed-settings.json"
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            data["adminCustomKey"] = True
            settings_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

            uninstall = subprocess.run(
                ["bash", str(UNINSTALL_SH), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
            # Edited file is preserved; private skill and instructions are removed
            self.assertTrue(settings_path.exists())
            self.assertIn("kept", uninstall.stdout)
            self.assertEqual(list((cc_dir / ".claude" / "skills").glob("catpilot-safe-building-*")), [])
            self.assertFalse((cc_dir / "catpilot-guardrails").exists())

    def _checkout_with_bytecode(self, tmp: Path) -> Path:
        """A copy of what install.sh reads, with bytecode planted in catpilot_guard/ that it must not copy."""
        checkout = tmp / "checkout"
        no_bytecode = shutil.ignore_patterns("__pycache__", "*.pyc")
        shutil.copytree(ROOT / "deploy" / "org", checkout / "deploy" / "org")
        shutil.copytree(ROOT / "hooks" / "claude-code", checkout / "hooks" / "claude-code", ignore=no_bytecode)
        shutil.copytree(ROOT / "catpilot_guard", checkout / "catpilot_guard", ignore=no_bytecode)
        (checkout / "skills").symlink_to(ROOT / "skills", target_is_directory=True)
        (checkout / "catpilot_guard" / "__pycache__").mkdir()
        (checkout / "catpilot_guard" / "__pycache__" / "secrets.cpython-38.pyc").write_bytes(b"not bytecode")
        (checkout / "catpilot_guard" / "stray.pyc").write_bytes(b"not bytecode")
        return checkout

    def test_install_places_the_package_beside_the_hooks_and_uninstall_removes_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            checkout = self._checkout_with_bytecode(Path(tmp))
            cc_dir = Path(tmp) / "claude-code"
            env = self._env(cc_dir, Path(tmp) / "codex")
            url = "https://mcp.internal.example.org/mcp"
            install = subprocess.run(
                ["bash", str(checkout / "deploy" / "org" / "install.sh"), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(install.returncode, 0, install.stderr)

            package = cc_dir / "catpilot-guardrails" / "hooks" / "catpilot_guard"
            self.assertIn(f"package {package}/", install.stdout)
            source = sorted(p.name for p in (ROOT / "catpilot_guard").glob("*.py"))
            self.assertIn("__init__.py", source)
            # Exactly the package's .py files: no __pycache__ directory and no .pyc.
            self.assertEqual(sorted(p.relative_to(package).as_posix() for p in package.rglob("*")), source)
            self.assertEqual(package.stat().st_mode & 0o777, 0o755)
            for path in package.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o644, path.name)
                self.assertEqual(path.read_bytes(), (ROOT / "catpilot_guard" / path.name).read_bytes(), path.name)

            verify = self._verify(env)
            self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
            for name in ("__init__.py", "secrets.py", "write_secrets.py", "destructive.py", "evidence.py", "session_start.py"):
                self.assertIn(f"present  {package}/{name}", verify.stdout)
            for hook_name in HOOK_NAMES:
                self.assertIn(f"denies   {hook_name}", verify.stdout)
            # Running the installed hooks leaves no bytecode beside them.
            self.assertEqual(sorted(p.relative_to(package).as_posix() for p in package.rglob("*")), source)

            # Installing again replaces the package, so a module a newer release dropped does not linger.
            (package / "dropped_module.py").write_text("", encoding="utf-8")
            install = subprocess.run(
                ["bash", str(checkout / "deploy" / "org" / "install.sh"), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(install.returncode, 0, install.stderr)
            self.assertEqual(sorted(p.name for p in package.iterdir()), source)

            uninstall = subprocess.run(
                ["bash", str(checkout / "deploy" / "org" / "uninstall.sh"), "--server-url", url],
                env=env,
                capture_output=True,
                text=True,
                timeout=15,
            )
            self.assertEqual(uninstall.returncode, 0, uninstall.stderr)
            self.assertFalse(package.exists())
            self.assertFalse((cc_dir / "catpilot-guardrails").exists())

    def test_deployed_hooks_fail_closed_without_the_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            cc_dir = Path(tmp) / "claude-code"
            env = self._env(cc_dir, Path(tmp) / "codex")
            self._install(env)
            hooks = cc_dir / "catpilot-guardrails" / "hooks"
            shutil.rmtree(hooks / "catpilot_guard")

            marker = "catpilot-probe-5c1e"
            bash = json.dumps({"tool_name": "Bash", "tool_input": {"command": f"echo {marker}"}})
            write = json.dumps({"tool_name": "Write", "tool_input": {"file_path": f"{marker}.txt", "content": marker}})
            for hook_name in HOOK_NAMES:
                with self.subTest(hook=hook_name):
                    proc = subprocess.run(
                        [sys.executable, str(hooks / hook_name)],
                        input=write if "write" in hook_name else bash,
                        env={k: v for k, v in env.items() if not k.startswith("CATPILOT_EVIDENCE")},
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                    self.assertEqual(proc.stdout, "")
                    self.assertIn("catpilot_guard", proc.stderr)
                    self.assertNotIn(marker, proc.stderr)

            verify = self._verify(env)
            self.assertNotEqual(verify.returncode, 0, verify.stdout)
            for name in ("__init__.py", "secrets.py", "write_secrets.py", "destructive.py", "evidence.py", "session_start.py"):
                self.assertIn(f"MISSING  {hooks}/catpilot_guard/{name}", verify.stdout)
            for hook_name in HOOK_NAMES:
                self.assertIn(f"FAIL     {hook_name} exited 2", verify.stdout)
                self.assertNotIn(f"denies   {hook_name}:", verify.stdout)  # the Claude Code copy
            self.assertIn("load the catpilot_guard package", verify.stdout)


if __name__ == "__main__":
    unittest.main()
