"""The hooks as one zipapp, placed by deploy/org/install.sh (issue #97, option 2): the reproducible build, install,
verify and uninstall with it on the three tools, a changed copy failing verify, every check denying from inside it
(the company-rules hook with an enforcement policy included), and switching to and from the package tree
(--package-tree). Offline, in temporary directories, through the CATPILOT_*_DIR and CATPILOT_ALLOW_NONROOT overrides.

The layout-agnostic tests of the package-tree suites run again here with the zipapp, by subclassing them with
PACKAGE_TREE = "0"; the tests those suites hold about the package tree's own files are skipped here, not changed there.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_company_rules  # noqa: E402
import test_copilot_hooks  # noqa: E402
import test_deploy_codex_hooks  # noqa: E402
import test_deploy_org  # noqa: E402
import test_deploy_session_start  # noqa: E402
import validate_overlay as vo  # noqa: E402

ORG = ROOT / "deploy" / "org"
BUILD = ROOT / "tools" / "build_zipapp.py"
URL = "https://mcp.internal.example.org/mcp"
ZIPAPP = "catpilot-guard.pyz"
EXAMPLE_V2 = ROOT / "docs" / "spec" / "overlay.v2.example.yaml"
TEST_SALT = "5f0c9a1e7d3b4c2a8e6f1d0b9a7c5e3f"
TREE_FILES = ("pretooluse-secrets.py", "pretooluse-write-secrets.py", "pretooluse-write-private-key.py",
              "pretooluse-destructive-ops.py", "pretooluse-company-rules.py", "catpilot-company-rules.py")
# Planted in probe commands: none of it may come back in a hook's output.
MARKER = "zq-zipapp-marker"


def load_helper():
    spec = importlib.util.spec_from_file_location("ssf_for_zipapp", ORG / "session_start_files.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


helper = load_helper()


def build(out: Path, root: Path = ROOT) -> str:
    proc = subprocess.run([sys.executable, str(root / "tools" / "build_zipapp.py"), "--out", str(out)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.split()[0]


def bash_event(command: str, cwd: str) -> str:
    return json.dumps({"session_id": "zipapp-test", "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": {"command": command}, "cwd": cwd})


class ReproducibleBuildTests(unittest.TestCase):
    """The same sources give the same bytes, wherever the checkout is and whatever its files' times and modes."""

    def test_a_copy_of_the_checkout_elsewhere_builds_the_same_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "a" / ZIPAPP
            digest = build(first)
            copy = Path(tmp) / "elsewhere" / "checkout"
            shutil.copytree(ROOT / "catpilot_guard", copy / "catpilot_guard",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            shutil.copytree(ROOT / "tools", copy / "tools", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "bench"))
            for path in (copy / "catpilot_guard").iterdir():
                os.utime(path, (1_000_000_000, 1_000_000_000))
                path.chmod(0o600)
            second = Path(tmp) / "b" / ZIPAPP
            self.assertEqual(build(second, copy), digest)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(hashlib.sha256(second.read_bytes()).hexdigest(), digest)

    def test_a_changed_source_changes_the_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            digest = build(Path(tmp) / "a" / ZIPAPP)
            copy = Path(tmp) / "checkout"
            shutil.copytree(ROOT / "catpilot_guard", copy / "catpilot_guard", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            shutil.copytree(ROOT / "tools", copy / "tools", ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "bench"))
            with (copy / "catpilot_guard" / "secrets.py").open("a", encoding="utf-8") as handle:
                handle.write("\n# changed\n")
            self.assertNotEqual(build(Path(tmp) / "b" / ZIPAPP, copy), digest)


class ZipappPathTests(unittest.TestCase):
    """Code that finds files or owners relative to the package, run from inside the archive."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.archive = self.tmp / "hooks" / ZIPAPP
        build(self.archive)

    def test_the_policy_module_names_the_archive_as_what_it_runs_from(self):
        code = ("import sys; sys.path.insert(0, sys.argv[1]); from catpilot_guard import policy; "
                "print(policy.__file__); print(policy.package_location()); print(policy.package_owner())")
        proc = subprocess.run([sys.executable, "-I", "-c", code, str(self.archive)], capture_output=True, text=True,
                              timeout=30, cwd=str(self.tmp))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        module_file, location, owner = proc.stdout.splitlines()
        self.assertTrue(module_file.startswith(str(self.archive)), module_file)  # imported from the zip, not the checkout
        self.assertEqual(Path(location), self.archive.resolve())
        self.assertEqual(int(owner), self.archive.stat().st_uid)

    def test_the_session_start_check_reads_instructions_beside_its_directory(self):
        (self.tmp / "instructions").mkdir()
        proc = subprocess.run([sys.executable, str(self.archive), "session-start", "--host", "codex"],
                              input=json.dumps({"hook_event_name": "SessionStart", "source": "startup"}),
                              capture_output=True, text=True, timeout=30, cwd=str(self.tmp),
                              env={k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")})
        # No rules there: the notice that they could not be loaded, from the module (exit 0, SessionStart JSON).
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["hookSpecificOutput"]["hookEventName"], "SessionStart")
        self.assertIn("could not be loaded", out["hookSpecificOutput"]["additionalContext"])

    def test_a_check_that_cannot_load_blocks_and_echoes_nothing(self):
        broken = self.tmp / "broken.pyz"
        with zipfile.ZipFile(self.archive) as source, zipfile.ZipFile(broken, "w") as target:
            for info in source.infolist():
                # Without each check's own module, as a damaged or partial copy would be.
                if info.filename not in ("catpilot_guard/secrets.py", "catpilot_guard/write_secrets.py",
                                         "catpilot_guard/destructive.py", "catpilot_guard/company_rules.py",
                                         "catpilot_guard/session_start.py"):
                    target.writestr(info, source.read(info))
        env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        for check in ("secrets", "write-secrets", "destructive", "company-rules"):
            with self.subTest(check=check):
                proc = subprocess.run([sys.executable, str(broken), check], input=bash_event("echo %s" % MARKER, str(self.tmp)),
                                      capture_output=True, text=True, timeout=30, env=env, cwd=str(self.tmp))
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertEqual(proc.stdout, "")
                self.assertIn("nothing was allowed", proc.stderr)
                self.assertNotIn(MARKER, proc.stderr)
        start = subprocess.run([sys.executable, str(broken), "session-start", "--host", "codex"], input="{}",
                               capture_output=True, text=True, timeout=30, env=env, cwd=str(self.tmp))
        self.assertEqual(start.returncode, 0, start.stderr)  # SessionStart cannot block: it says the rules are unknown
        self.assertIn("could not be loaded", json.loads(start.stdout)["systemMessage"])


class ZipappEnv:
    """Temporary managed directories for the three tools, and install.sh's default layout."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.cc, self.codex, self.copilot = self.tmp / "claude-code", self.tmp / "codex", self.tmp / "copilot"
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE") and k != "CATPILOT_PACKAGE_TREE"}
        self.env.update(CATPILOT_ALLOW_NONROOT="1", CATPILOT_CC_DIR=str(self.cc), CATPILOT_CODEX_DIR=str(self.codex),
                        CATPILOT_COPILOT_DIR=str(self.copilot), PYTHON_BIN=sys.executable, HOME=str(self.home))

    def run_script(self, name: str, *args: str, env=None) -> subprocess.CompletedProcess:
        return subprocess.run(["bash", str(ORG / name), *args], env=env or self.env, capture_output=True, text=True, timeout=300)

    def install(self, *args: str) -> subprocess.CompletedProcess:
        proc = self.run_script("install.sh", "--server-url", URL, *args)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc

    def hooks_dirs(self) -> list:
        return [d / "catpilot-guardrails" / "hooks" for d in (self.cc, self.codex, self.copilot)]

    def managed_files(self) -> list:
        return [self.cc / "managed-settings.json", self.codex / "requirements.toml",
                self.copilot / "policy.d" / "catpilot-guardrails.json"]

    def enforcement_rules(self) -> Path:
        today = dt.date.today()
        text = EXAMPLE_V2.read_text(encoding="utf-8").replace(f'salt: "{vo.EXAMPLE_SALT}"', f'salt: "{TEST_SALT}"')
        text = text.replace("reviewed_on: 2026-11-17", "reviewed_on: %s" % (today - dt.timedelta(days=1)).isoformat())
        text = text.replace("expires_on: 2027-05-17", "expires_on: %s" % (today + dt.timedelta(days=180)).isoformat())
        rules = self.tmp / "rules.yaml"
        rules.write_text(text, encoding="utf-8")
        return rules


class ZipappDeployTests(ZipappEnv, unittest.TestCase):
    """install.sh's default layout, verify.sh and uninstall.sh, on the three tools."""

    def test_install_places_the_zipapp_with_its_hash_and_every_command_runs_it(self):
        proc = self.install()
        digest = build(self.tmp / "expected" / ZIPAPP)
        self.assertIn(f"SHA-256 {digest}", proc.stdout)
        for hooks in self.hooks_dirs():
            with self.subTest(hooks=str(hooks)):
                # The zipapp and its recorded hash, and nothing of the package tree.
                self.assertEqual(sorted(p.name for p in hooks.iterdir()), [ZIPAPP, ZIPAPP + ".sha256"])
                archive = hooks / ZIPAPP
                self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(), digest)
                self.assertEqual((hooks / (ZIPAPP + ".sha256")).read_text(encoding="utf-8"), f"{digest}  {ZIPAPP}\n")
                for path in (archive, hooks / (ZIPAPP + ".sha256")):
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444, path)
                self.assertEqual(stat.S_IMODE(hooks.stat().st_mode), 0o755)
        for path in self.managed_files():
            text = path.read_text(encoding="utf-8").replace("\\", "")
            with self.subTest(file=path.name):
                managed = path.parent.parent if path.parent.name == "policy.d" else path.parent
                self.assertIn(f'"{sys.executable}" "{managed}/catpilot-guardrails/hooks/{ZIPAPP}" ', text)
                self.assertNotRegex(text, r"pretooluse-[a-z-]+\.py")
                for check in ("secrets", "destructive", "write-secrets"):
                    self.assertIn(f'{ZIPAPP}" {check} --evidence-default', text)
        with helper.interpreter(sys.executable), helper.zipapp_layout(True):
            self.assertEqual((self.codex / "requirements.toml").read_text(encoding="utf-8"),
                             helper.requirements_toml(str(self.codex), rules=False) + "\n")
            self.assertEqual((self.copilot / "policy.d" / "catpilot-guardrails.json").read_text(encoding="utf-8"),
                             helper.copilot_policy_json(str(self.copilot)) + "\n")

        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertNotIn("FAIL", verify.stdout)
        self.assertIn("0 missing, 0 failed", verify.stdout)
        for hooks in self.hooks_dirs():
            self.assertIn(f"matches  {hooks / ZIPAPP} has the SHA-256 install.sh recorded", verify.stdout)
        self.assertEqual(verify.stdout.count("is byte for byte what this checkout builds"), 3)
        for hook in ("pretooluse-secrets.py", "pretooluse-destructive-ops.py", "pretooluse-write-secrets.py"):
            self.assertIn(f"denies   {hook}: ", verify.stdout)
            self.assertIn(f"wired    managed-settings.json runs {hook}", verify.stdout)
            self.assertIn(f"wired    requirements.toml runs {hook}", verify.stdout)
            self.assertIn(f"denies   {hook} --host copilot-cli:", verify.stdout)
        self.assertIn("passes   pretooluse-secrets.py: ls", verify.stdout)
        self.assertFalse((self.home / ".catpilot-guardrails").exists())  # the probes' evidence stays in verify's temp dir

        # Again: nothing changes.
        before = [p.read_bytes() for p in self.managed_files()] + [(h / ZIPAPP).read_bytes() for h in self.hooks_dirs()]
        again = self.install()
        for path in self.managed_files():
            self.assertIn(f"current {path}", again.stdout)
        self.assertEqual([p.read_bytes() for p in self.managed_files()] + [(h / ZIPAPP).read_bytes() for h in self.hooks_dirs()], before)

        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        for path in self.managed_files():
            self.assertFalse(path.exists(), path)
        for managed in (self.cc, self.codex, self.copilot):
            self.assertFalse((managed / "catpilot-guardrails").exists(), managed)

    def tamper(self, archive: Path, data: bytes) -> None:
        archive.chmod(0o644)
        archive.write_bytes(data)
        archive.chmod(0o444)

    def test_a_changed_zipapp_fails_verify(self):
        self.install()
        archive = self.codex / "catpilot-guardrails" / "hooks" / ZIPAPP
        original = archive.read_bytes()
        # One changed byte in a stored module, same length: its hash no longer matches the recorded one.
        index = original.index(b"# ")
        self.tamper(archive, original[:index] + b"#!" + original[index + 2:])
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        failures = [line for line in verify.stdout.splitlines() if line.startswith("FAIL") and str(archive) in line]
        self.assertTrue(failures, verify.stdout)
        self.assertIn("not the", failures[0])
        self.assertIn("install.sh recorded", failures[0])
        self.assertIn("is not what this checkout builds", verify.stdout)
        # The other tools' copies are untouched and still match.
        self.assertIn(f"matches  {self.cc / 'catpilot-guardrails' / 'hooks' / ZIPAPP} has the SHA-256", verify.stdout)

        # The archive restored, a record someone else could rewrite fails, as does one that holds no hash.
        self.tamper(archive, original)
        record = archive.parent / (ZIPAPP + ".sha256")
        record.chmod(0o664)
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"FAIL     {record} must be owned by root and writable by no one else", verify.stdout)

        record.chmod(0o644)
        record.write_text("not a hash\n", encoding="utf-8")
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn(f"INVALID  {record} does not hold one SHA-256", verify.stdout)

    def test_a_missing_zipapp_fails_verify_and_the_commands_block(self):
        self.install()
        archive = self.cc / "catpilot-guardrails" / "hooks" / ZIPAPP
        archive.unlink()
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        # Without the archive, verify falls back to the package tree's files, which are not there either.
        self.assertIn("MISSING", verify.stdout)
        self.assertIn("FAIL     managed-settings.json command for pretooluse-secrets.py exited 2", verify.stdout)

    def test_each_check_denies_from_inside_the_installed_zipapp(self):
        self.install()
        archive = self.cc / "catpilot-guardrails" / "hooks" / ZIPAPP
        env = {k: v for k, v in self.env.items()}
        env["CATPILOT_EVIDENCE_LOG"] = str(self.tmp / "evidence.jsonl")
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        cases = (
            ("secrets", bash_event("export AWS_ACCESS_KEY_ID=%s && echo %s" % (key, MARKER), str(self.tmp))),
            ("destructive", bash_event("git push --force origin main # %s" % MARKER, str(self.tmp))),
            ("write-secrets", json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(self.tmp),
                                          "tool_input": {"file_path": str(self.tmp / "x.env"),
                                                         "content": "AWS_ACCESS_KEY_ID=%s\n# %s\n" % (key, MARKER)}})),
        )
        for check, event in cases:
            with self.subTest(check=check):
                proc = subprocess.run([sys.executable, str(archive), check, "--evidence-default"], input=event,
                                      capture_output=True, text=True, timeout=30, env=env, cwd=str(self.tmp))
                self.assertEqual(proc.returncode, 0, proc.stderr)
                decision = json.loads(proc.stdout)["hookSpecificOutput"]
                self.assertEqual(decision["permissionDecision"], "deny")
                self.assertNotIn(MARKER, proc.stdout + proc.stderr)
                self.assertNotIn(key, proc.stdout + proc.stderr)
            harmless = subprocess.run([sys.executable, str(archive), check], input=bash_event("ls", str(self.tmp)),
                                      capture_output=True, text=True, timeout=30, env=env, cwd=str(self.tmp))
            self.assertEqual(harmless.returncode, 0, harmless.stderr)
            self.assertEqual(json.loads(harmless.stdout), {})  # nothing is ever allowed explicitly
        log = (self.tmp / "evidence.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(MARKER, log)
        self.assertNotIn(key, log)
        self.assertNotIn('"allow"', log)

    def test_the_company_rules_hook_enforces_a_policy_from_inside_the_zipapp(self):
        proc = self.install("--overlay", str(self.enforcement_rules()))
        for managed in (self.cc, self.codex):
            hooks = managed / "catpilot-guardrails" / "hooks"
            self.assertEqual(sorted(p.name for p in hooks.iterdir()), [ZIPAPP, ZIPAPP + ".sha256"])
            self.assertTrue((managed / "catpilot-guardrails" / "policy" / "company-policy.json").is_file())
        settings = (self.cc / "managed-settings.json").read_text(encoding="utf-8")
        self.assertIn(f'{ZIPAPP}\\" company-rules --evidence-default --host claude-code --policy', settings)
        self.assertIn(f'{ZIPAPP}\\" session-start --evidence-default --host claude-code', settings)
        self.assertIn(f'{ZIPAPP}" company-rules --evidence-default --host codex --policy', (self.codex / "requirements.toml").read_text(encoding="utf-8"))
        self.assertIn("company-checklist.md and .json", proc.stdout)

        # Run directly: a force push to a branch the example's block rule protects is denied by the company rule,
        # read from the policy (its evidence line names the rule), not by an error.
        archive = self.cc / "catpilot-guardrails" / "hooks" / ZIPAPP
        policy = self.cc / "catpilot-guardrails" / "policy" / "company-policy.json"
        probe = helper.first_branch_probe(policy)
        self.assertIsNotNone(probe)
        rule_id, mode, command, _, _, _ = probe
        log = self.tmp / "company.jsonl"
        env = dict(self.env, CATPILOT_EVIDENCE_LOG=str(log))
        result = subprocess.run([sys.executable, str(archive), "company-rules", "--host", "claude-code", "--policy", str(policy)],
                                input=bash_event(command, str(self.tmp)), capture_output=True, text=True, timeout=30,
                                env=env, cwd=str(self.tmp))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertTrue([e for e in entries if e.get("rule_id") == rule_id and e.get("event") == "deny"], entries)
        self.assertFalse([e for e in entries if e.get("event") == "policy_error"], entries)

        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertRegex(verify.stdout, r"denies\s+pretooluse-company-rules.py --host claude-code denies a force push")
        self.assertRegex(verify.stdout, r"wired\s+\S*requirements.toml runs pretooluse-company-rules.py, which denies")
        self.assertRegex(verify.stdout, r"wired\s+\S*managed-settings.json runs catpilot-company-rules.py|"
                                        r"wired\s+managed-settings.json runs it at SessionStart")
        self.assertNotIn("policy_error", verify.stdout)

        # The ownership check stays meaningful from inside the zip: a policy directory someone else can write is
        # refused (policy_error, wrong-owner), and the hook applies no company rule.
        policy.parent.chmod(0o775)
        log.unlink()
        refused = subprocess.run([sys.executable, str(archive), "company-rules", "--host", "claude-code", "--policy", str(policy)],
                                 input=bash_event(command, str(self.tmp)), capture_output=True, text=True, timeout=30,
                                 env=env, cwd=str(self.tmp))
        self.assertEqual(refused.returncode, 0, refused.stderr)
        self.assertNotIn('"allow"', refused.stdout)
        entries = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        self.assertEqual([e.get("label") for e in entries if e.get("event") == "policy_error"], ["wrong-owner"])
        policy.parent.chmod(0o755)

        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        for managed in (self.cc, self.codex, self.copilot):
            self.assertFalse((managed / "catpilot-guardrails").exists(), managed)
        for path in self.managed_files():
            self.assertFalse(path.exists(), path)

    def test_switching_layouts_replaces_only_what_the_earlier_install_wrote(self):
        self.install("--package-tree")
        for hooks in self.hooks_dirs():
            self.assertTrue((hooks / "pretooluse-secrets.py").is_file())
            self.assertTrue((hooks / "catpilot_guard").is_dir())
            self.assertFalse((hooks / ZIPAPP).exists())
        (self.cc / "catpilot-guardrails" / "hooks" / "unrelated.txt").write_text("an admin's file\n", encoding="utf-8")

        upgrade = self.install()
        for path in self.managed_files():
            self.assertIn(f"updated {path} (an earlier install's", upgrade.stdout)
        for hooks in self.hooks_dirs():
            names = sorted(p.name for p in hooks.iterdir())
            expected = [ZIPAPP, ZIPAPP + ".sha256"] + (["unrelated.txt"] if hooks.parent.parent == self.cc else [])
            self.assertEqual(names, sorted(expected), hooks)
            self.assertIn(f"removed the package tree an earlier install placed in {hooks}", upgrade.stdout)
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

        back = self.install("--package-tree")
        for hooks in self.hooks_dirs():
            self.assertFalse((hooks / ZIPAPP).exists(), hooks)
            self.assertFalse((hooks / (ZIPAPP + ".sha256")).exists(), hooks)
            self.assertTrue((hooks / "pretooluse-secrets.py").is_file())
            self.assertIn(f"removed {hooks / ZIPAPP} and its SHA-256", back.stdout)
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)

    def test_a_kept_managed_file_keeps_the_hook_files_it_runs(self):
        self.install("--package-tree")
        settings = self.cc / "managed-settings.json"
        data = json.loads(settings.read_text(encoding="utf-8"))
        data["adminCustomKey"] = True  # edited since: install.sh keeps it and prints what to merge
        settings.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

        upgrade = self.install()
        self.assertIn(f"exists  {settings} (not overwritten)", upgrade.stdout)
        cc_hooks = self.cc / "catpilot-guardrails" / "hooks"
        # The kept file still runs the hook files: they stay, beside the zipapp, and the install says why.
        self.assertTrue((cc_hooks / "pretooluse-secrets.py").is_file())
        self.assertTrue((cc_hooks / "catpilot_guard" / "secrets.py").is_file())
        self.assertTrue((cc_hooks / ZIPAPP).is_file())
        self.assertIn(f"kept    the earlier install's files in {cc_hooks} ({settings} still runs them", upgrade.stdout)
        # Codex's file was install.sh's own, so it was replaced and its hook files removed.
        codex_hooks = self.codex / "catpilot-guardrails" / "hooks"
        self.assertEqual(sorted(p.name for p in codex_hooks.iterdir()), [ZIPAPP, ZIPAPP + ".sha256"])
        # The kept file's hooks still deny their probes.
        verify = self.run_script("verify.sh")
        self.assertIn("wired    managed-settings.json runs pretooluse-secrets.py and it denies its probe", verify.stdout)

        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        self.assertTrue(settings.exists())
        self.assertTrue((cc_hooks / "pretooluse-secrets.py").is_file())  # still run by the kept file
        self.assertFalse((self.codex / "catpilot-guardrails").exists())

    def test_a_failed_build_installs_nothing(self):
        checkout = self.tmp / "checkout"
        shutil.copytree(ORG, checkout / "deploy" / "org")
        (checkout / "tools").mkdir()
        (checkout / "tools" / "build_zipapp.py").write_text("import sys\nsys.exit(1)\n", encoding="utf-8")
        proc = subprocess.run(["bash", str(checkout / "deploy" / "org" / "install.sh"), "--server-url", URL], env=self.env,
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("did not build catpilot-guard.pyz", proc.stderr)
        for managed in (self.cc, self.codex, self.copilot):
            self.assertFalse(managed.exists(), managed)

    def test_the_host_check_kit_reads_zipapp_commands(self):
        self.install("--overlay", str(self.enforcement_rules()))
        spec = importlib.util.spec_from_file_location("hostcheck_for_zipapp", ROOT / "evals" / "host-check" / "hostcheck.py")
        kit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(kit)
        data = kit.inspect(self.cc, self.codex, self.copilot)
        self.assertTrue(data["claude_code"]["company_rules_hook"])
        self.assertTrue(data["codex"]["company_rules_hook"])
        self.assertTrue(data["copilot_cli"]["company_rules_hook"])
        self.assertIn("catpilot-company-rules.py", data["claude_code"]["managed_settings_hook_events"]["SessionStart"])
        self.assertIn("pretooluse-secrets.py", data["copilot_cli"]["policy_pretooluse_hooks"])


class StandardZipappCommandTests(unittest.TestCase):
    """verify runs a company-rules command only when it is exactly install.sh's, in the zipapp layout too."""

    def test_each_tool_s_install_command_matches(self):
        for managed in ("/etc/claude-code", "/Library/Application Support/ClaudeCode", "/opt/a (x+y)[1]{2}|b^c*d?.e"):
            root = Path(helper.tree(managed))
            word = '"%s" company-rules' % (root / "hooks" / ZIPAPP)
            policy = root / "policy" / helper.POLICY_NAME
            with helper.zipapp_layout(True):
                commands = (("claude-code", helper.company_hook_command(managed, "claude-code")),
                            ("codex", helper.company_hook_command(managed, "codex")),
                            ("copilot-cli", helper.copilot_command(managed, helper.COMPANY_HOOK, enforce_policy=True)))
            for host, command in commands:
                with self.subTest(managed=managed, host=host):
                    self.assertTrue(helper.standard_company_command(command, word, host, policy))
                    self.assertTrue(helper.standard_company_command(command + " --ask", word, host, policy))
                    self.assertFalse(helper.standard_company_command(command + "; true", word, host, policy))
                    self.assertFalse(helper.standard_company_command(command + " --ask --ask", word, host, policy))
                    self.assertFalse(helper.standard_company_command(command.replace("company-rules", "secrets"), word, host, policy))
                    # The package-tree form is not this layout's command.
                    tree_word = root / "hooks" / helper.COMPANY_HOOK
                    self.assertFalse(helper.standard_company_command(command, tree_word, host, policy))

    def test_runs_hook_reads_the_check_name_as_one_word(self):
        command = '"/usr/bin/python3" "/etc/codex/catpilot-guardrails/hooks/catpilot-guard.pyz" write-secrets --host codex'
        self.assertTrue(helper.runs_hook(command, "pretooluse-write-secrets.py"))
        self.assertFalse(helper.runs_hook(command, "pretooluse-secrets.py"))
        self.assertFalse(helper.runs_hook(command, "pretooluse-destructive-ops.py"))
        self.assertTrue(helper.runs_hook(command.replace("write-secrets", "secrets"), "pretooluse-secrets.py"))
        self.assertFalse(helper.runs_hook(command.replace("write-secrets", "secrets-and-more"), "pretooluse-secrets.py"))


# --- the package-tree suites, run again with the zipapp ---------------------------------------------------------

TREE_ONLY = "checks the package tree's own files; the zipapp's are checked in ZipappDeployTests"


def skip_tree_only(cls, *names):
    for name in names:
        setattr(cls, name, unittest.skip(TREE_ONLY)(getattr(cls, name)))
    return cls


class ZipappDeployOrgScriptTests(test_deploy_org.DeployOrgScriptTests):
    PACKAGE_TREE = "0"


skip_tree_only(ZipappDeployOrgScriptTests,
               "test_standard_install_verify_and_uninstall",
               "test_verify_reports_a_hook_that_does_not_deny",
               "test_overlay_install_and_edited_config_preservation",
               "test_install_places_the_package_beside_the_hooks_and_uninstall_removes_it",
               "test_deployed_hooks_fail_closed_without_the_package",
               "test_verify_runs_each_installed_hook_and_writes_nothing")


class ZipappInterpreterTests(test_deploy_org.InterpreterTests):
    PACKAGE_TREE = "0"


# Tests that select or rewrite a registered command by its hook file's name, or compare with the package-tree text,
# find nothing to change in the zipapp layout; ZipappCommandTests below holds the same checks for zipapp commands.
class ZipappCompanyRulesDeployTests(test_company_rules.DeployTests):
    PACKAGE_TREE = "0"


skip_tree_only(ZipappCompanyRulesDeployTests,
               "test_install_places_and_registers_verify_checks_and_uninstall_removes",
               "test_verify_fails_registered_commands_that_cannot_prove_they_read_the_rule",
               "test_verify_fails_a_registered_command_that_reads_no_rule",
               "test_verify_needs_the_exception_id_on_an_excepted_probe",
               "test_verify_fails_a_hook_that_decides_nothing_without_reading_the_rule",
               "test_verify_fails_a_hook_that_decides_without_reading_the_rule")


class ZipappCodexManagedHookTests(test_deploy_codex_hooks.CodexManagedHookTests):
    PACKAGE_TREE = "0"


skip_tree_only(ZipappCodexManagedHookTests,
               "test_a_command_without_the_host_argument_is_noted",
               "test_install_places_the_hooks_and_declares_them_as_managed_pretooluse_hooks",
               "test_uninstall_keeps_the_hooks_whatever_spelling_the_kept_file_uses",
               "test_uninstall_keeps_the_hooks_a_kept_requirements_file_still_runs",
               "test_uninstall_removes_the_hooks_and_requirements_and_keeps_an_edited_file",
               "test_verify_fails_on_a_missing_hook_or_package_module",
               "test_verify_fails_a_registered_command_that_denies_everything")


class ZipappCopilotDeployTests(test_copilot_hooks.DeployTests):
    PACKAGE_TREE = "0"


skip_tree_only(ZipappCopilotDeployTests,
               "test_with_enforcement_rules_the_company_hook_is_registered_and_verified",
               "test_install_verify_uninstall",
               "test_an_edited_policy_file_is_kept_with_the_hooks_it_runs",
               "test_uninstall_keeps_the_hooks_another_policy_file_runs")


class ZipappSessionStartDeployTests(test_deploy_session_start.SessionStartDeployTests):
    PACKAGE_TREE = "0"


skip_tree_only(ZipappSessionStartDeployTests,
               "test_overlay_places_the_rules_the_hook_and_its_registration_on_each_tool",
               "test_without_overlay_nothing_about_session_start_is_placed",
               # Calls verify in this process, without CATPILOT_ALLOW_NONROOT, so the zipapp's owner check fails.
               "test_verify_reads_requirements_without_tomllib")


class ZipappCommandTests(ZipappEnv, unittest.TestCase):
    """The checks the skipped tests above make, on zipapp commands: verify fails a registered command that cannot
    prove it reads the company rules, one that denies everything, and one without --host; uninstall keeps the zipapp
    a kept file still runs."""

    def rewrite_company_command(self, rewrite) -> None:
        path = self.cc / "managed-settings.json"
        settings = json.loads(path.read_text(encoding="utf-8"))
        changed = 0
        for group in settings["hooks"]["PreToolUse"]:
            for hook in group["hooks"]:
                if helper.runs_hook(hook["command"], helper.COMPANY_HOOK):
                    hook["command"] = rewrite(hook["command"])
                    changed += 1
        self.assertEqual(changed, 1)
        path.write_text(json.dumps(settings), encoding="utf-8")

    def test_verify_fails_company_commands_that_cannot_prove_they_read_the_rule(self):
        rules = self.enforcement_rules()
        rules.write_text(rules.read_text(encoding="utf-8").replace("      mode: block\n", "      mode: monitor\n", 1), encoding="utf-8")
        self.install("--overlay", str(rules))
        original = (self.cc / "managed-settings.json").read_text(encoding="utf-8")
        prefix = helper.EVIDENCE_PREFIX
        for label, rewrite in {
            "a no-op": lambda c: "echo '{}' # %s\" company-rules" % ZIPAPP,
            "the wrong host": lambda c: c.replace("--host claude-code", "--host codex"),
            "another evidence sink": lambda c: c.replace(prefix, 'CATPILOT_EVIDENCE_LOG="$HOME/Library/Logs/catpilot/evidence.jsonl"'),
            "syslog": lambda c: c.replace(prefix, "CATPILOT_EVIDENCE_SYSLOG=1"),
            "a wrapper": lambda c: c.replace(prefix, prefix + " /usr/bin/env"),
            "another check": lambda c: c.replace('" company-rules', '" secrets'),
            "a command after it": lambda c: c + "; true",
        }.items():
            with self.subTest(case=label):
                (self.cc / "managed-settings.json").write_text(original, encoding="utf-8")
                if label == "another check":
                    # Still mentions company-rules after the policy, so it is found as a registration.
                    self.rewrite_company_command(lambda c: rewrite(c) + " # company-rules")
                else:
                    self.rewrite_company_command(rewrite)
                verify = self.run_script("verify.sh")
                self.assertNotEqual(verify.returncode, 0, verify.stdout)
                self.assertRegex(verify.stdout, r"evidence has no would_deny line for|expected it to|verify does not run it|"
                                                r"does not run pretooluse-company-rules.py")
        self.assertFalse((self.home / ".catpilot-guardrails").exists())

    def test_verify_fails_a_codex_command_that_denies_everything_and_notes_a_missing_host(self):
        self.install()
        requirements = self.codex / "requirements.toml"
        original = requirements.read_text(encoding="utf-8")
        deny_all = self.tmp / "deny-all.sh"
        deny_all.write_text('#!/bin/sh\ncat >/dev/null\necho \'{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
                            '"permissionDecision":"deny","permissionDecisionReason":"x"}}\'\n', encoding="utf-8")
        deny_all.chmod(0o755)
        archive = self.codex / "catpilot-guardrails" / "hooks" / ZIPAPP
        line = [l for l in original.splitlines() if f'{ZIPAPP}" destructive' in l][0]
        requirements.write_text(original.replace(line, "command = '\"%s\" # %s\" destructive'" % (deny_all, archive)), encoding="utf-8")
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0, verify.stdout)
        self.assertIn("FAIL     requirements.toml command for pretooluse-destructive-ops.py denied ls, which it must let through", verify.stdout)

        requirements.write_text(original.replace(f'{ZIPAPP}" secrets --evidence-default --host codex', f'{ZIPAPP}" secrets --evidence-default'),
                                encoding="utf-8")
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout)
        self.assertIn("note     requirements.toml runs pretooluse-secrets.py without --host codex", verify.stdout)

    def test_uninstall_keeps_the_zipapp_a_kept_file_still_runs(self):
        self.install()
        requirements = self.codex / "requirements.toml"
        requirements.write_text(requirements.read_text(encoding="utf-8") + "# ours\n", encoding="utf-8")
        policy = self.copilot / "policy.d" / "catpilot-guardrails.json"
        policy.write_text(policy.read_text(encoding="utf-8").replace('"version": 1', '"version": 1, "x": 1'), encoding="utf-8")
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        for managed in (self.codex, self.copilot):
            hooks = managed / "catpilot-guardrails" / "hooks"
            self.assertTrue((hooks / ZIPAPP).is_file(), hooks)
            self.assertIn(f"kept    {hooks} (", uninstall.stdout)
        self.assertFalse((self.cc / "catpilot-guardrails").exists())
        # The kept file's commands still run the checks.
        command = [l for l in requirements.read_text(encoding="utf-8").splitlines() if f'{ZIPAPP}" secrets' in l][0]
        command = command.split("'", 1)[1].rsplit("'", 1)[0]
        proc = subprocess.run(["/bin/sh", "-c", command], input=bash_event("ls", str(self.tmp)), env=self.env,
                              capture_output=True, text=True, timeout=30)
        self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "{}"))


if __name__ == "__main__":
    unittest.main()
