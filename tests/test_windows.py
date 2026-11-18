"""Increment 1 of docs/spec/WINDOWS.md (§3.1): what lets the hooks run on Windows.

  - --evidence-default: evidence under the home directory without a shell to expand $HOME, in every hook
  - the hooks run in exec form (an interpreter and an argument list, no shell), as Claude Code runs a command with args
  - the evidence writer without fcntl
  - the policy check on Windows: the owner and the access list. acl_trusted is plain Python and runs everywhere;
    the tests that set real access lists with icacls run only on Windows (the windows-latest CI job)

None of this runs Claude Code, Codex or Copilot CLI: it verifies the Python, not a tool.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import catpilot_guard  # noqa: E402
from catpilot_guard import evidence  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402

HOOKS = ROOT / "hooks" / "claude-code"
SESSION_START = ROOT / "hooks" / "session-start" / "catpilot-company-rules.py"
ADMINISTRATORS, SYSTEM, USERS, AUTHENTICATED = "S-1-5-32-544", "S-1-5-18", "S-1-5-32-545", "S-1-5-11"
TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
FULL, READ_EXECUTE, MODIFY = 0x1F01FF, 0x1200A9, 0x1301BF
POLICY = json.dumps({
    "format": "catpilot-company-policy", "format_version": 1, "source_sha256": "a" * 64, "expires_on": "2099-01-01",
    "rules": [{"id": "branches", "kind": "protected_branch", "mode": "block", "values": ["main"]}],
}).encode()


def clean_env(home: str, **extra) -> dict:
    """This environment without evidence settings, with the home directory (HOME and USERPROFILE) at home."""
    env = {k: v for k, v in os.environ.items() if k not in ("CATPILOT_EVIDENCE_LOG", "CATPILOT_EVIDENCE_SYSLOG")}
    env.update(HOME=home, USERPROFILE=home, **extra)
    return env


def default_log(home: str) -> Path:
    return Path(home) / ".catpilot-guardrails" / "evidence.jsonl"


def exec_form(hook: Path, args: list, event: dict, env: dict) -> subprocess.CompletedProcess:
    """A hook run as Claude Code's exec form runs it: the interpreter, then each argument exactly as written, no shell."""
    return subprocess.run([sys.executable, str(hook), *args], input=json.dumps(event).encode(), capture_output=True,
                          timeout=30, env=env, shell=False)


class EvidenceDefaultTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.home, True)

    def test_take_evidence_default(self):
        with mock.patch.dict(os.environ, {"HOME": self.home, "USERPROFILE": self.home}, clear=False):
            os.environ.pop("CATPILOT_EVIDENCE_LOG", None)
            self.assertEqual(catpilot_guard.take_evidence_default(["--evidence-default", "--host", "codex"]), ["--host", "codex"])
            self.assertEqual(Path(os.environ["CATPILOT_EVIDENCE_LOG"]), default_log(self.home))
            # A variable already set wins; without the flag nothing is set.
            os.environ["CATPILOT_EVIDENCE_LOG"] = "elsewhere.jsonl"
            catpilot_guard.take_evidence_default(["--evidence-default"])
            self.assertEqual(os.environ["CATPILOT_EVIDENCE_LOG"], "elsewhere.jsonl")
            del os.environ["CATPILOT_EVIDENCE_LOG"]
            self.assertEqual(catpilot_guard.take_evidence_default(["--host", "codex"]), ["--host", "codex"])
            self.assertNotIn("CATPILOT_EVIDENCE_LOG", os.environ)

    def test_a_home_that_is_not_absolute_sets_nothing(self):
        with mock.patch.object(os.path, "expanduser", lambda path: path), mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("CATPILOT_EVIDENCE_LOG", None)
            self.assertEqual(catpilot_guard.take_evidence_default(["--evidence-default"]), [])
            self.assertNotIn("CATPILOT_EVIDENCE_LOG", os.environ)

    def test_every_pretooluse_hook_runs_in_exec_form_and_logs_to_the_default(self):
        key = "AKIA" + "IOSFODNN7EXAMPLE"
        cases = (
            ("pretooluse-destructive-ops.py", {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}}),
            ("pretooluse-destructive-ops.py", {"tool_name": "PowerShell", "tool_input": {"command": "git push -f origin main"}}),
            ("pretooluse-secrets.py", {"tool_name": "PowerShell", "tool_input": {"command": "$env:AWS_ACCESS_KEY_ID = '%s'" % key}}),
            ("pretooluse-write-secrets.py", {"tool_name": "Write", "tool_input": {"file_path": "a.env", "content": "AWS_ACCESS_KEY_ID=%s" % key}}),
        )
        with tempfile.TemporaryDirectory() as cwd:
            for hook, event in cases:
                for args, host in ((["--evidence-default"], "claude-code"), (["--evidence-default", "--host", "codex"], "codex"),
                                   (["--host=codex", "--evidence-default"], "codex")):
                    with self.subTest(hook=hook, tool=event["tool_name"], args=args):
                        log = default_log(self.home)
                        if log.exists():
                            log.unlink()
                        event = dict(event, session_id="sess-win", cwd=cwd)
                        proc = exec_form(HOOKS / hook, args, event, clean_env(self.home))
                        self.assertEqual(proc.returncode, 0, proc.stderr)
                        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
                        line = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
                        self.assertEqual((line["event"], line["host"], line["session_id"]), ("deny", host, "sess-win"))
                        self.assertNotIn(key, log.read_text(encoding="utf-8"))

    def test_a_set_variable_wins_over_the_default(self):
        other = Path(self.home) / "other.jsonl"
        event = {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}}
        proc = exec_form(HOOKS / "pretooluse-destructive-ops.py", ["--evidence-default"], event,
                         clean_env(self.home, CATPILOT_EVIDENCE_LOG=str(other)))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(other.exists())
        self.assertFalse(default_log(self.home).exists())

    def test_the_company_rules_and_session_start_hooks_take_the_option(self):
        event = {"session_id": "sess-win", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "ls"}}
        missing = Path(self.home) / "nowhere" / "company-policy.json"
        proc = exec_form(HOOKS / "pretooluse-company-rules.py",
                         ["--evidence-default", "--host", "claude-code", "--policy", str(missing)], event, clean_env(self.home))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = json.loads(default_log(self.home).read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual((line["event"], line["label"]), ("policy_error", "missing"))  # the option is not a bad argument
        default_log(self.home).unlink()
        start = {"session_id": "sess-win", "hook_event_name": "SessionStart", "source": "startup"}
        proc = exec_form(SESSION_START, ["--evidence-default", "--host", "claude-code", "--dir", str(Path(self.home) / "none")],
                         start, clean_env(self.home))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        line = json.loads(default_log(self.home).read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(line["event"], "policy_error")
        self.assertNotEqual(line.get("label"), "bad-arguments")


class EvidenceWithoutFcntlTests(unittest.TestCase):
    def test_each_line_is_one_write_without_a_lock(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(evidence, "fcntl", None):
            path = Path(tmp) / "sub" / "evidence.jsonl"
            for n in range(3):
                evidence.append_line(str(path), json.dumps({"n": n}))
            self.assertEqual([json.loads(line)["n"] for line in path.read_text(encoding="utf-8").splitlines()], [0, 1, 2])
        if os.name == "nt":
            self.assertIsNone(evidence.fcntl)


class AclTrustedTests(unittest.TestCase):
    """The access-list rule, on entries as GetSecurityInfo reports them: (type, flags, mask, SID)."""

    def test_the_layout_install_ps1_sets_passes(self):
        aces = [(0, 0, FULL, ADMINISTRATORS), (0, 0, FULL, SYSTEM), (0, 0, READ_EXECUTE, USERS)]
        for owner in (ADMINISTRATORS, SYSTEM, TRUSTED_INSTALLER):
            with self.subTest(owner=owner):
                self.assertTrue(pol.acl_trusted(owner, aces))

    def test_refused(self):
        base = [(0, 0, FULL, ADMINISTRATORS), (0, 0, FULL, SYSTEM)]
        cases = {
            "owned by a user": ("S-1-5-21-1-2-3-1001", base),
            "no owner read": (None, base),
            "a NULL DACL": (ADMINISTRATORS, None),
            "users may modify": (ADMINISTRATORS, base + [(0, 0, MODIFY, USERS)]),
            "authenticated users may append": (ADMINISTRATORS, base + [(0, 0, 0x4, AUTHENTICATED)]),
            "a user may delete": (ADMINISTRATORS, base + [(0, 0, 0x10000, "S-1-5-21-1-2-3-1001")]),
            "a user may change the access list": (ADMINISTRATORS, base + [(0, 0, 0x40000, "S-1-5-21-1-2-3-1001")]),
            "a user may take ownership": (ADMINISTRATORS, base + [(0, 0, 0x80000, "S-1-5-21-1-2-3-1001")]),
            "generic write to everyone": (ADMINISTRATORS, base + [(0, 0, 0x40000000, "S-1-1-0")]),
            "a user may delete children": (ADMINISTRATORS, base + [(0, 0, 0x40, "S-1-5-21-1-2-3-1001")]),
            "a callback entry for users": (ADMINISTRATORS, base + [(9, 0, MODIFY, USERS)]),
            "an object entry with a write right": (ADMINISTRATORS, base + [(5, 0, 0x2, None)]),
            "an unknown entry type with a write right": (ADMINISTRATORS, base + [(0x13, 0, 0x2, None)]),
        }
        for label, (owner, aces) in cases.items():
            with self.subTest(label=label):
                self.assertFalse(pol.acl_trusted(owner, aces))

    def test_deny_inherit_only_and_read_entries_are_ignored(self):
        aces = [(0, 0, FULL, ADMINISTRATORS), (1, 0, MODIFY, USERS), (0, 0x08 | 0x01 | 0x02, FULL, "S-1-3-0"),
                (0, 0, READ_EXECUTE, AUTHENTICATED), (6, 0, FULL, "S-1-1-0")]
        self.assertTrue(pol.acl_trusted(ADMINISTRATORS, aces))


@unittest.skipUnless(os.name == "nt", "Windows access lists, set with icacls")
class WindowsPolicyFileTests(unittest.TestCase):
    """read_checked on Windows against files whose owner and access list icacls sets, as install.ps1 will."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(self.cleanup)
        self.dir = self.root / "policy"
        self.dir.mkdir()
        self.file = self.dir / "company-policy.json"
        self.file.write_bytes(POLICY)

    def cleanup(self):
        subprocess.run(["icacls", str(self.root), "/reset", "/T", "/C", "/Q"], capture_output=True)
        shutil.rmtree(self.root, ignore_errors=True)

    def icacls(self, *args):
        proc = subprocess.run(["icacls", *[str(a) for a in args]], capture_output=True, text=True)
        if proc.returncode != 0:
            self.skipTest("icacls could not set this here: %s" % (proc.stdout + proc.stderr).strip())

    def lock_down(self):
        """What install.ps1 sets: owner Administrators; full control to Administrators and SYSTEM, read to Users."""
        for path, inherit in ((self.dir, "(OI)(CI)"), (self.file, "")):
            self.icacls(path, "/setowner", "*" + ADMINISTRATORS)
            self.icacls(path, "/inheritance:r", "/grant:r", "*%s:%sF" % (ADMINISTRATORS, inherit), "*%s:%sF" % (SYSTEM, inherit),
                        "*%s:%sRX" % (USERS, inherit))

    def load(self):
        try:
            return pol.load(self.file)
        except pol.PolicyError as exc:
            if exc.args[0] == "unreadable":
                self.skipTest("this process cannot read a file only Administrators may write (not elevated)")
            raise

    def label(self, path=None) -> str:
        with self.assertRaises(pol.PolicyError) as caught:
            pol.load(path or self.file)
        return caught.exception.args[0]

    def test_the_security_information_is_read(self):
        owner, aces = pol._windows_security(name=str(self.file))
        self.assertTrue(owner.startswith("S-1-"))
        self.assertTrue(aces and all(isinstance(ace, tuple) and len(ace) == 4 for ace in aces))

    def test_a_locked_down_policy_loads(self):
        self.lock_down()
        self.assertEqual(self.load().rules[0].id, "branches")

    def test_a_deny_entry_does_not_refuse_it(self):
        self.lock_down()
        self.icacls(self.file, "/deny", "*%s:(W)" % USERS)
        self.assertEqual(self.load().rules[0].id, "branches")

    def test_a_file_users_can_write_is_refused(self):
        self.lock_down()
        self.icacls(self.file, "/grant", "*%s:(M)" % USERS)
        self.assertEqual(self.label(), "wrong-owner")

    def test_a_directory_users_can_write_is_refused(self):
        self.lock_down()
        self.icacls(self.dir, "/grant", "*%s:(W)" % AUTHENTICATED)
        self.assertEqual(self.label(), "wrong-owner")

    def test_an_owner_that_is_not_trusted_is_refused(self):
        self.lock_down()
        user = subprocess.run(["whoami"], capture_output=True, text=True).stdout.strip()
        self.icacls(self.file, "/setowner", user)
        owner, _ = pol._windows_security(name=str(self.file))
        if owner in pol.TRUSTED_SIDS:
            self.skipTest("this account's own SID is a trusted one")
        self.assertEqual(self.label(), "wrong-owner")

    def test_a_file_as_created_is_refused(self):
        # A temporary file the running user owns or may write: what a person, or an agent, could put in place.
        self.assertEqual(self.label(), "wrong-owner")

    def test_a_symbolic_link_is_refused(self):
        self.lock_down()
        link = self.dir / "link.json"
        try:
            os.symlink(str(self.file), str(link))
        except OSError as exc:
            self.skipTest("cannot create a symbolic link here: %s" % exc)
        self.assertEqual(self.label(link), "wrong-owner")

    def test_a_missing_file(self):
        self.lock_down()
        self.assertEqual(self.label(self.dir / "absent.json"), "missing")


if __name__ == "__main__":
    unittest.main()
