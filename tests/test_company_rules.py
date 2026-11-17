"""The company-rules hook (catpilot_guard/company_rules.py), the compiled policy it reads (catpilot_guard/policy.py),
`tools/validate_overlay.py compile`, and deploy/org placing, checking and removing both (docs/spec/OVERLAY_V2.md §2.2,
§2.3, §6.1). Offline, in temporary directories."""

from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from catpilot_guard import company_rules as cr  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402

import validate_overlay as vo  # noqa: E402

HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-company-rules.py"
ORG = ROOT / "deploy" / "org"
SPEC = ROOT / "docs" / "spec"
EXAMPLE_V2 = SPEC / "overlay.v2.example.yaml"
SCHEMA = SPEC / "evidence-event.schema.json"
TEST_SALT = "5f0c9a1e7d3b4c2a8e6f1d0b9a7c5e3f"
URL = "https://mcp.internal.example.org/mcp"
SHA = "a" * 64
# Values a rule may list. Planted so a test can show none of them leaves the hook or compile's printout.
BRANCH_MARKER = "zq-marker-branch"
HOST_MARKER = "zq-marker.apps.example.org"


def policy_dict(rules=None, expires="2099-01-01", **top) -> dict:
    data = {
        "format": "catpilot-company-policy",
        "format_version": 1,
        "source_sha256": SHA,
        "expires_on": expires,
        "rules": rules if rules is not None else [
            {"id": "protected-branches", "kind": "protected_branch", "mode": "block",
             "values": ["main", "release/*", BRANCH_MARKER + "/*"]},
        ],
    }
    data.update(top)
    return data


def branch_rule(rule_id="protected-branches", mode="block", values=("main", "release/*", BRANCH_MARKER + "/*"), **extra) -> dict:
    return {"id": rule_id, "kind": "protected_branch", "mode": mode, "values": list(values), **extra}


def parsed(rules=None, expires="2099-01-01") -> pol.Policy:
    return pol.parse(json.dumps(policy_dict(rules, expires)).encode())


def bash(command: str, host_mode: str | None = "default", cwd: str | None = None) -> dict:
    event = {"session_id": "sess-1", "hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": command}, "cwd": cwd or tempfile.gettempdir()}
    if host_mode is not None:
        event["permission_mode"] = host_mode
    return event


def effect(result: dict) -> str:
    return result.get("hookSpecificOutput", {}).get("permissionDecision", "none") if result else "none"


class PolicyFormatTests(unittest.TestCase):
    def test_a_policy_compile_writes_parses(self):
        policy = parsed()
        self.assertEqual(policy.source_sha256, SHA)
        self.assertEqual(policy.expires_on, dt.date(2099, 1, 1))
        self.assertEqual([r.id for r in policy.rules], ["protected-branches"])
        self.assertIsNone(policy.rules[0].use_instead_text)

    def test_anything_else_is_malformed(self):
        cases = {
            "not json": b"{",
            "not an object": b"[]",
            "an extra key": json.dumps(policy_dict(extra=1)).encode(),
            "a missing key": json.dumps({k: v for k, v in policy_dict().items() if k != "expires_on"}).encode(),
            "another format": json.dumps(policy_dict(format="other")).encode(),
            "another version": json.dumps(policy_dict(format_version=2)).encode(),
            "version true": json.dumps(policy_dict(format_version=True)).encode(),
            "a short hash": json.dumps(policy_dict(source_sha256="abc")).encode(),
            "an impossible date": json.dumps(policy_dict(expires="2027-13-45")).encode(),
            "no rules": json.dumps(policy_dict(rules=[])).encode(),
            "an unknown kind": json.dumps(policy_dict(rules=[branch_rule(kind="cloud_account")])).encode(),
            "an unknown mode": json.dumps(policy_dict(rules=[branch_rule(mode="warn")])).encode(),
            "a bad id": json.dumps(policy_dict(rules=[branch_rule(rule_id="Bad_Id")])).encode(),
            "a repeated id": json.dumps(policy_dict(rules=[branch_rule(), branch_rule()])).encode(),
            "no values": json.dumps(policy_dict(rules=[branch_rule(values=())])).encode(),
            "a value with a newline": json.dumps(policy_dict(rules=[branch_rule(values=("ma\nin",))])).encode(),
            "free text in a rule": json.dumps(policy_dict(rules=[branch_rule(note="x")])).encode(),
            "too large": b" " * (pol.MAX_POLICY_BYTES + 1),
        }
        for label, raw in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(pol.PolicyError) as caught:
                    pol.parse(raw)
                self.assertEqual(caught.exception.args, ("malformed",))

    def test_a_deploy_host_rule_is_carried_and_not_enforced(self):
        policy = parsed([branch_rule(), {"id": "deploy-hosts", "kind": "deploy_host", "mode": "block", "values": ["apps.example.org"]}])
        self.assertEqual([r.kind for r in policy.rules], ["protected_branch", "deploy_host"])
        self.assertNotIn("deploy_host", pol.ENFORCED_KINDS)

    def test_branch_values_match_like_the_built_in_check(self):
        cases = [("refs/heads/deploy", "deploy", True),("main", "main", True), ("main", "MAIN", True), ("main", "mainline", False), ("main", "", False),
                 ("release/*", "release/2026.11", True), ("release/*", "release/a/b", True), ("release/*", "release/", False),
                 ("release/*", "release", False), ("release/*", "prerelease/x", False), ("Hotfix/*", "hotfix/x", True)]
        for value, branch, expected in cases:
            with self.subTest(value=value, branch=branch):
                self.assertIs(pol.branch_matches(value, branch), expected)


class PolicyLocationTests(unittest.TestCase):
    """Only a file the package's owner placed, and only they can change, is used (§6.1 invariant 6)."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name) / "policy"
        self.dir.mkdir(mode=0o755)
        os.chmod(self.dir, 0o755)
        self.file = self.dir / "company-policy.json"
        self.file.write_text(json.dumps(policy_dict()), encoding="utf-8")
        os.chmod(self.file, 0o644)

    def tearDown(self):
        self._tmp.cleanup()

    def assertLabel(self, label, path=None, owner=None):
        with self.assertRaises(pol.PolicyError) as caught:
            pol.load(path or self.file, owner)
        self.assertEqual(caught.exception.args, (label,))

    def test_a_file_placed_like_the_package_loads(self):
        self.assertEqual(pol.load(self.file).rules[0].id, "protected-branches")

    def test_a_relative_path_is_refused(self):
        self.assertLabel("bad-arguments", Path("policy/company-policy.json"))

    def test_a_missing_file(self):
        self.assertLabel("missing", self.dir / "absent.json")

    def test_a_file_writable_by_group_or_others(self):
        for mode in (0o664, 0o646):
            with self.subTest(mode=oct(mode)):
                os.chmod(self.file, mode)
                self.assertLabel("wrong-owner")
        os.chmod(self.file, 0o644)

    def test_a_directory_writable_by_group_or_others(self):
        os.chmod(self.dir, 0o775)
        self.assertLabel("wrong-owner")
        os.chmod(self.dir, 0o755)

    def test_another_owner(self):
        self.assertLabel("wrong-owner", owner=os.getuid() + 1)

    def test_a_symlink_is_refused(self):
        link = self.dir / "link.json"
        link.symlink_to(self.file)
        self.assertLabel("wrong-owner", link)

    def test_a_fifo_is_refused_without_blocking(self):
        fifo = self.dir / "fifo.json"
        os.mkfifo(fifo, 0o644)
        self.assertLabel("wrong-owner", fifo)

    def test_the_bytes_read_are_from_the_file_checked(self):
        # read_checked opens without following a final symlink and checks the open descriptor.
        self.assertEqual(pol.read_checked(self.file, os.getuid()), self.file.read_bytes())

    def test_the_expected_owner_is_the_package_owner(self):
        self.assertEqual(pol.package_owner(), os.stat(ROOT / "catpilot_guard").st_uid)


class DecisionTests(unittest.TestCase):
    """Modes and hosts (§2.3, decisions 2 and 3)."""

    def setUp(self):
        self.lines = []
        patcher = mock.patch.object(cr, "record_evidence", lambda event, hook_event=None, host=None, **f: self.lines.append((event, host, f)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def decide(self, command, rules=None, host="claude-code", mode="default", expires="2099-01-01", cwd=None, ask=False):
        return cr.decide(bash(command, mode, cwd), host, parsed(rules, expires), ask_enabled=ask)

    def test_block_denies_a_force_push_or_deletion_of_a_listed_branch(self):
        for command in ("git push --force origin main", "git push -f origin release/2026.11", "git push origin +HEAD:release/x",
                        "git push -o ci.skip --force origin main", "git push --force --all origin",
                        "git push --force origin 'refs/heads/*:refs/heads/*'",
                        "git push origin --delete release/x", "git push origin :main", "git push --mirror origin",
                        "git push --force-with-lease origin %s/a" % BRANCH_MARKER, 'bash -lc "git push -f origin main"',
                        "cd repo && sudo git push --force origin MAIN"):
            with self.subTest(command=command):
                self.assertEqual(effect(self.decide(command)), "deny")

    def test_what_the_rule_does_not_cover_passes(self):
        for command in ("git push origin main", "git push --force origin feature/x", "git push -f origin releases/x",
                        "ls", "", "echo git push --force origin main"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), {})
        self.assertEqual(self.lines, [])

    def test_a_bare_force_push_reads_the_checked_out_branch(self):
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / ".git").mkdir()
            head = Path(repo) / ".git" / "HEAD"
            head.write_text("ref: refs/heads/%s/fix\n" % BRANCH_MARKER)
            self.assertEqual(effect(self.decide("git push -f", cwd=repo)), "deny")
            head.write_text("ref: refs/heads/feature/x\n")
            self.assertEqual(self.decide("git push -f", cwd=repo), {})
            head.write_text("0123456789abcdef0123456789abcdef01234567\n")  # detached: the built-in check covers it
            self.assertEqual(self.decide("git push -f", cwd=repo), {})

    def test_monitor_decides_nothing_and_logs_would_deny(self):
        result = self.decide("git push --force origin main", [branch_rule(mode="monitor")])
        self.assertEqual(result, {})
        self.assertEqual([(e, f["rule_id"], f["mode"]) for e, _, f in self.lines], [("would_deny", "protected-branches", "monitor")])

    def test_with_the_ask_flag_claude_code_asks_where_a_person_answers(self):
        for mode in cr.ASK_PERMISSION_MODES:
            with self.subTest(permission_mode=mode):
                result = self.decide("git push --force origin main", [branch_rule(mode="ask")], mode=mode, ask=True)
                self.assertEqual(effect(result), "ask")
                self.assertIn("Approve only if this is intended", result["hookSpecificOutput"]["permissionDecisionReason"])

    def test_without_the_ask_flag_ask_acts_as_block_everywhere(self):
        # A program that approves (claude -p with a permission-prompt tool, an SDK callback) sends the same event as a
        # person's session, so asking is the administrator's opt-in on the root-owned command line (decision 2).
        for mode in cr.ASK_PERMISSION_MODES:
            with self.subTest(permission_mode=mode):
                self.assertEqual(effect(self.decide("git push --force origin main", [branch_rule(mode="ask")], mode=mode)), "deny")

    def test_ask_acts_as_block_where_nobody_can_be_asked(self):
        cases = [("codex", None), ("claude-code", "bypassPermissions"), ("claude-code", "dontAsk"), ("claude-code", "auto"),
                 ("claude-code", None), ("claude-code", "some-future-mode"), (None, "default")]
        for host, mode in cases:
            with self.subTest(host=host, permission_mode=mode):
                self.lines.clear()
                result = self.decide("git push --force origin main", [branch_rule(mode="ask")], host=host, mode=mode, ask=True)
                self.assertEqual(effect(result), "deny")
                self.assertIn("nobody can be asked here", result["hookSpecificOutput"]["permissionDecisionReason"])
                self.assertEqual([(e, f["mode"]) for e, _, f in self.lines], [("deny", "ask")])

    def test_an_expired_policy_acts_in_monitor(self):
        for mode in ("block", "ask"):
            with self.subTest(mode=mode):
                self.lines.clear()
                result = self.decide("git push --force origin main", [branch_rule(mode=mode)], expires="2020-01-01")
                self.assertEqual(result, {})
                self.assertEqual([(e, f["mode"]) for e, _, f in self.lines], [("would_deny", "monitor")])

    def test_the_expiry_day_itself_is_current(self):
        policy = parsed(expires="2027-05-17")
        self.assertFalse(policy.expired(dt.date(2027, 5, 17)))
        self.assertTrue(policy.expired(dt.date(2027, 5, 18)))

    def test_the_strictest_effect_wins_and_each_rule_writes_a_line(self):
        rules = [branch_rule("watch-main", "monitor", ("main",)), branch_rule("ask-main", "ask", ("main",)),
                 branch_rule("block-main", "block", ("main",))]
        result = self.decide("git push --force origin main", rules, ask=True)
        self.assertEqual(effect(result), "deny")
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("`block-main`", reason)
        self.assertNotIn("ask-main", reason)
        self.assertEqual([(e, f["rule_id"]) for e, _, f in self.lines],
                         [("would_deny", "watch-main"), ("deny", "ask-main"), ("deny", "block-main")])
        self.lines.clear()
        result = self.decide("git push --force origin main", rules[:2], ask=True)
        self.assertEqual(effect(result), "ask")
        self.assertEqual([e for e, _, _ in self.lines], ["would_deny", "ask"])

    def test_the_reason_names_the_rule_and_alternative_never_a_value_or_the_command(self):
        rules = [branch_rule(use_instead_text="Internal App Platform (company sign-in)")]
        command = "git push --force origin %s/secret-name" % BRANCH_MARKER
        reason = self.decide(command, rules)["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Catpilot company rule `protected-branches`", reason)
        self.assertIn("Use instead: Internal App Platform (company sign-in).", reason)
        self.assertIn("run it yourself in your own terminal", reason)
        for text in (BRANCH_MARKER, "secret-name", "release", "git push"):
            self.assertNotIn(text, reason)

    def test_evidence_fields_are_content_free(self):
        self.decide("git push --force origin %s/x" % BRANCH_MARKER)
        (event, host, fields), = self.lines
        self.assertEqual((event, host), ("deny", "claude-code"))
        self.assertEqual(fields, {"tool": "Bash", "rule_id": "protected-branches", "mode": "block", "policy_sha256": SHA})

    def test_other_tools_and_no_policy_decide_nothing(self):
        self.assertEqual(cr.decide({"tool_name": "Write", "tool_input": {}}, "claude-code", parsed()), {})
        self.assertEqual(cr.decide(bash("git push --force origin main"), "claude-code", None), {})

    def test_malformed_events_raise(self):
        for event in ([], {"tool_name": "Bash"}, {"tool_name": "Bash", "tool_input": {"command": 3}}):
            with self.subTest(event=event), self.assertRaises(ValueError):
                cr.decide(event, "claude-code", parsed())


class ArgumentTests(unittest.TestCase):
    def test_parse_args(self):
        cases = [
            (["--policy", "/p.json"], ("claude-code", "/p.json", True, False)),
            (["--host", "codex", "--policy", "/p.json"], ("codex", "/p.json", True, False)),
            (["--host=codex", "--policy=/p.json"], ("codex", "/p.json", True, False)),
            (["--policy", "/p.json", "--ask"], ("claude-code", "/p.json", True, True)),
            (["--ask", "--policy", "/p.json", "--ask"], ("claude-code", "/p.json", False, True)),
            (["--host", "codex"], ("codex", None, False, False)),
            (["--host", "other", "--policy", "/p.json"], (None, "/p.json", False, False)),
            (["--policy", "/a", "--policy", "/b"], ("claude-code", "/a", False, False)),
            (["--surprise", "x", "--policy", "/p.json"], ("claude-code", "/p.json", False, False)),
            (["--policy"], (None, None, False, False)),
            ([], ("claude-code", None, False, False)),
        ]
        for argv, expected in cases:
            with self.subTest(argv=argv):
                self.assertEqual(cr.parse_args(argv), expected)


class HookProcessTests(unittest.TestCase):
    """The shim run as the host runs it: a policy it cannot use applies no company rule and logs why."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.policy_dir = self.tmp / "policy"
        self.policy_dir.mkdir()
        os.chmod(self.policy_dir, 0o755)
        self.policy = self.policy_dir / "company-policy.json"
        self.policy.write_text(json.dumps(policy_dict()), encoding="utf-8")
        os.chmod(self.policy, 0o644)
        self.log = self.tmp / "evidence.jsonl"

    def tearDown(self):
        self._tmp.cleanup()

    def run_hook(self, event, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        env["CATPILOT_EVIDENCE_LOG"] = str(self.log)
        payload = event if isinstance(event, (bytes, str)) else json.dumps(event)
        return subprocess.run([sys.executable, str(HOOK), *args], input=payload, capture_output=True,
                              text=isinstance(payload, str), env=env, timeout=30)

    def lines(self):
        return [json.loads(line) for line in self.log.read_text(encoding="utf-8").splitlines()] if self.log.exists() else []

    def test_denies_with_the_policy_and_logs_content_free(self):
        proc = self.run_hook(bash("git push --force origin %s/x" % BRANCH_MARKER), "--host", "codex", "--policy", str(self.policy))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        (line,) = self.lines()
        self.assertEqual({k: line[k] for k in ("event", "hook", "host", "rule_id", "mode", "policy_sha256", "session_id")},
                         {"event": "deny", "hook": "pretooluse-company-rules", "host": "codex", "rule_id": "protected-branches",
                          "mode": "block", "policy_sha256": SHA, "session_id": "sess-1"})
        self.assertNotIn(BRANCH_MARKER, self.log.read_text(encoding="utf-8") + proc.stdout + proc.stderr)

    def test_a_policy_it_cannot_use_applies_no_rule_and_logs_a_label(self):
        os.chmod(self.policy, 0o666)
        cases = [
            (("--policy", str(self.policy)), "wrong-owner"),
            (("--policy", str(self.tmp / "absent.json")), "missing"),
            (("--policy", "relative.json"), "bad-arguments"),
            (("--host", "codex"), "bad-arguments"),
        ]
        for args, label in cases:
            with self.subTest(label=label, args=args):
                self.log.unlink(missing_ok=True)
                proc = self.run_hook(bash("git push --force origin main"), *args)
                self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "{}"), proc.stderr)
                (line,) = self.lines()
                self.assertEqual((line["event"], line["label"]), ("policy_error", label))
                self.assertNotIn(str(self.tmp), json.dumps(line))

    def test_a_malformed_policy(self):
        self.policy.write_text("{", encoding="utf-8")
        proc = self.run_hook(bash("ls"), "--policy", str(self.policy))
        self.assertEqual(proc.stdout.strip(), "{}")
        self.assertEqual([line["label"] for line in self.lines()], ["malformed"])

    def test_other_tools_do_not_load_the_policy(self):
        proc = self.run_hook({"tool_name": "Write", "tool_input": {"file_path": "x", "content": "y"}}, "--policy", str(self.tmp / "absent"))
        self.assertEqual(proc.stdout.strip(), "{}")
        self.assertEqual(self.lines(), [])

    def test_input_it_cannot_read_blocks(self):
        for payload in ("{", "[]", json.dumps({"tool_name": "Bash", "tool_input": "x"}), "x" * (cr.MAX_INPUT_BYTES + 1)):
            with self.subTest(payload=payload[:20]):
                proc = self.run_hook(payload, "--policy", str(self.policy))
                self.assertEqual(proc.returncode, 2)
                self.assertIn("company-rules check could not read the hook input", proc.stderr)

    def test_evidence_lines_match_the_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")
        os.chmod(self.policy, 0o644)
        self.policy.write_text(json.dumps(policy_dict([branch_rule(), branch_rule("watch", "monitor", ("stable",)),
                                                       branch_rule("confirm", "ask", ("trunk",))])), encoding="utf-8")
        for command in ("git push -f origin main", "git push -f origin stable", "git push -f origin trunk"):
            self.run_hook(bash(command), "--policy", str(self.policy), "--ask")
        self.run_hook(bash("ls"), "--policy", str(self.tmp / "absent"))
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        events = []
        for line in self.lines():
            jsonschema.validate(line, schema)
            events.append(line["event"])
        self.assertEqual(events, ["deny", "would_deny", "ask", "policy_error"])


class CompileTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        text = EXAMPLE_V2.read_text(encoding="utf-8").replace(f'salt: "{vo.EXAMPLE_SALT}"', f'salt: "{TEST_SALT}"')
        text = text.replace('values: ["main", "release/*", "hotfix/*"]', 'values: ["main", "release/*", "%s/*"]' % BRANCH_MARKER)
        text = text.replace('values: ["apps.example.org", "*.apps.example.org"]', 'values: ["%s"]' % HOST_MARKER)
        self.rules = self.tmp / "rules.yaml"
        self.rules.write_text(text, encoding="utf-8")
        self.out = self.tmp / "policy.json"
        real = vo.validate_expiry
        patcher = mock.patch.object(vo, "validate_expiry", lambda overlay, today=None: real(overlay, dt.date(2026, 11, 17)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def compile(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vo.main(["compile", str(self.rules), "--out", str(self.out), *extra])
        return code, out.getvalue(), err.getvalue()

    def test_compile_writes_the_policy_the_hook_reads(self):
        code, out, err = self.compile()
        self.assertEqual(code, 0, err)
        raw = self.out.read_bytes()
        policy = pol.parse(raw)
        self.assertEqual(policy.source_sha256, __import__("hashlib").sha256(self.rules.read_bytes()).hexdigest())
        self.assertEqual(policy.expires_on, dt.date(2027, 5, 17))
        self.assertEqual([(r.id, r.kind, r.mode) for r in policy.rules],
                         [("protected-branches", "protected_branch", "block"), ("deploy-hosts", "deploy_host", "monitor")])
        self.assertEqual(policy.rules[1].use_instead_text, "Internal App Platform (company sign-in)")
        self.assertEqual(stat.S_IMODE(os.stat(self.out).st_mode), 0o644)

    def test_compile_is_deterministic_and_copies_nothing_else(self):
        self.compile()
        first = self.out.read_bytes()
        self.compile()
        self.assertEqual(self.out.read_bytes(), first)
        text = first.decode()
        for absent in (TEST_SALT, "security-review@example.org", "Example Org", "Cardholder", "hosting-app-platform"):
            self.assertNotIn(absent, text)

    def test_the_printout_names_rules_and_effects_never_values(self):
        code, out, err = self.compile()
        self.assertIn("protected-branches | protected_branch | block | deny | deny", out)
        self.assertIn("deploy-hosts | deploy_host | monitor | not enforced in this release", out)
        for value in (BRANCH_MARKER, HOST_MARKER, "release/*", TEST_SALT):
            self.assertNotIn(value, out + err)

    def test_ask_is_shown_as_deny_on_codex(self):
        self.rules.write_text(self.rules.read_text(encoding="utf-8").replace("mode: block", "mode: ask"), encoding="utf-8")
        code, out, _ = self.compile()
        self.assertEqual(code, 0)
        self.assertIn("protected-branches | protected_branch | ask | deny; asks the person only if the hook command has --ask | deny (Codex cannot ask)", out)

    def test_no_enforcement_writes_nothing(self):
        text = self.rules.read_text(encoding="utf-8")
        self.rules.write_text(re.sub(r"\n# Machine-only: never rendered.*", "\n", text, flags=re.DOTALL), encoding="utf-8")
        code, _, err = self.compile()
        self.assertEqual(code, 0, err)
        self.assertIn("nothing to compile", err)
        self.assertFalse(self.out.exists())

    def test_an_invalid_or_expired_file_writes_nothing(self):
        self.rules.write_text(self.rules.read_text(encoding="utf-8").replace(TEST_SALT, vo.EXAMPLE_SALT), encoding="utf-8")
        code, _, err = self.compile()
        self.assertEqual(code, 1)
        self.assertFalse(self.out.exists())
        self.assertNotIn(vo.EXAMPLE_SALT, err)

    def test_values_the_hook_cannot_read_are_refused_before_compile(self):
        cases = {
            "a branch over 255 characters": ('"%s/*"' % BRANCH_MARKER, '"%s"' % ("b" * 256)),
            "a refs/heads/ value": ('"%s/*"' % BRANCH_MARKER, '"refs/heads/deploy"'),
            "DEL in a phrase": ('"Internal App Platform (company sign-in)"', '"Internal App Platform\x7f"'),
        }
        original = self.rules.read_text(encoding="utf-8")
        for label, (old, new) in cases.items():
            with self.subTest(case=label):
                self.assertIn(old, original)
                self.rules.write_text(original.replace(old, new, 1), encoding="utf-8")
                code, _, err = self.compile()
                self.assertEqual(code, 1, err)
                self.assertFalse(self.out.exists())
        self.rules.write_text(original, encoding="utf-8")

    def test_compile_refuses_what_the_hook_would_not_load(self):
        with self.assertRaises(vo.OverlayError):
            vo.check_hook_reads(json.dumps(policy_dict()) + " " * pol.MAX_POLICY_BYTES)
        vo.check_hook_reads(json.dumps(policy_dict()))

    def test_non_ascii_names_are_written_as_utf8(self):
        self.rules.write_text(self.rules.read_text(encoding="utf-8").replace('"main", ', '"main", "gr\u00fcn", '), encoding="utf-8")
        code, _, err = self.compile()
        self.assertEqual(code, 0, err)
        self.assertIn("grün".encode("utf-8"), self.out.read_bytes())

    def test_a_symlinked_output_is_refused(self):
        target = self.tmp / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.out.symlink_to(target)
        code, _, err = self.compile()
        self.assertEqual(code, 1)
        self.assertIn("symlinks are not allowed", err)
        self.assertEqual(target.read_text(encoding="utf-8"), "{}")


class DeployTests(unittest.TestCase):
    """install.sh --overlay with an enforcement section, verify.sh and uninstall.sh, as root would run them."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.cc, self.codex, self.home = self.tmp / "claude-code", self.tmp / "codex", self.tmp / "home"
        self.home.mkdir()
        today = dt.date.today()
        text = EXAMPLE_V2.read_text(encoding="utf-8").replace(f'salt: "{vo.EXAMPLE_SALT}"', f'salt: "{TEST_SALT}"')
        text = text.replace("reviewed_on: 2026-11-17", "reviewed_on: %s" % (today - dt.timedelta(days=1)).isoformat())
        text = text.replace("expires_on: 2027-05-17", "expires_on: %s" % (today + dt.timedelta(days=180)).isoformat())
        self.rules = self.tmp / "rules.yaml"
        self.rules.write_text(text, encoding="utf-8")
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
        self.env.update(CATPILOT_ALLOW_NONROOT="1", CATPILOT_CC_DIR=str(self.cc), CATPILOT_CODEX_DIR=str(self.codex),
                        CATPILOT_COPILOT_DIR=str(self.tmp / "copilot"), PYTHON_BIN=sys.executable, HOME=str(self.home))

    def tearDown(self):
        self._tmp.cleanup()

    def run_script(self, name, *args):
        return subprocess.run(["bash", str(ORG / name), *args], env=self.env, capture_output=True, text=True, timeout=180)

    def test_install_places_and_registers_verify_checks_and_uninstall_removes(self):
        proc = self.run_script("install.sh", "--server-url", URL, "--overlay", str(self.rules))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        for managed in (self.cc, self.codex):
            path = managed / "catpilot-guardrails" / "policy" / "company-policy.json"
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o755)
            self.assertEqual(pol.load(path, os.getuid()).rules[0].id, "protected-branches")
            self.assertTrue((managed / "catpilot-guardrails" / "hooks" / "pretooluse-company-rules.py").exists())
        settings = json.loads((self.cc / "managed-settings.json").read_text(encoding="utf-8"))
        commands = [h["command"] for g in settings["hooks"]["PreToolUse"] if g["matcher"] == "Bash" for h in g["hooks"]]
        self.assertTrue(any("pretooluse-company-rules.py" in c and "--policy" in c for c in commands))
        requirements = (self.codex / "requirements.toml").read_text(encoding="utf-8")
        self.assertIn("pretooluse-company-rules.py\" --host codex --policy \"%s" % self.codex, requirements)
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertRegex(verify.stdout, r"denies\s+pretooluse-company-rules.py --host claude-code denies a force push")
        self.assertRegex(verify.stdout, r"wired\s+\S*requirements.toml runs pretooluse-company-rules.py, which denies")
        self.assertNotIn("hotfix", verify.stdout)
        uninstall = self.run_script("uninstall.sh", "--server-url", URL)
        self.assertEqual(uninstall.returncode, 0, uninstall.stdout + uninstall.stderr)
        self.assertFalse((self.cc / "managed-settings.json").exists())
        self.assertFalse((self.codex / "requirements.toml").exists())
        self.assertFalse((self.cc / "catpilot-guardrails").exists())

    def test_verify_expects_the_strictest_of_overlapping_rules(self):
        text = self.rules.read_text(encoding="utf-8").replace(
            "  rules:\n", '  rules:\n    - {id: trial-branches, kind: protected_branch, mode: monitor, values: ["hotfix/*"]}\n', 1)
        self.rules.write_text(text, encoding="utf-8")
        self.assertEqual(self.run_script("install.sh", "--server-url", URL, "--overlay", str(self.rules)).returncode, 0)
        verify = self.run_script("verify.sh")
        self.assertEqual(verify.returncode, 0, verify.stdout + verify.stderr)
        self.assertIn("denies a force push to a branch rule trial-branches protects (monitor)", verify.stdout)

    def test_verify_fails_a_registered_hook_without_a_policy(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL, "--overlay", str(self.rules)).returncode, 0)
        for managed in (self.cc, self.codex):
            (managed / "catpilot-guardrails" / "policy" / "company-policy.json").unlink()
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("and there is no compiled policy at", verify.stdout)

    def test_verify_fails_on_a_policy_the_hook_refuses(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL, "--overlay", str(self.rules)).returncode, 0)
        os.chmod(self.cc / "catpilot-guardrails" / "policy" / "company-policy.json", 0o666)
        verify = self.run_script("verify.sh")
        self.assertNotEqual(verify.returncode, 0)
        self.assertIn("could not use its policy (wrong-owner)", verify.stdout)

    def test_a_rules_file_without_enforcement_registers_nothing_and_removes_an_old_policy(self):
        self.assertEqual(self.run_script("install.sh", "--server-url", URL, "--overlay", str(self.rules)).returncode, 0)
        for name in ("managed-settings.json",):
            (self.cc / name).unlink()
        (self.codex / "requirements.toml").unlink()
        text = self.rules.read_text(encoding="utf-8")
        self.rules.write_text(re.sub(r"\n# Machine-only: never rendered.*", "\n", text, flags=re.DOTALL), encoding="utf-8")
        proc = self.run_script("install.sh", "--server-url", URL, "--overlay", str(self.rules))
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertFalse((self.cc / "catpilot-guardrails" / "policy").exists())
        self.assertNotIn("pretooluse-company-rules", (self.cc / "managed-settings.json").read_text(encoding="utf-8"))
        self.assertNotIn("pretooluse-company-rules", (self.codex / "requirements.toml").read_text(encoding="utf-8"))
        self.assertIn("this rules file has no enforcement rules", proc.stdout)

    def test_verify_matches_branches_as_the_hook_does(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("session_start_files_for_branches", ORG / "session_start_files.py")
        helper = importlib.util.module_from_spec(spec)
        previous = sys.dont_write_bytecode
        sys.dont_write_bytecode = True
        try:
            spec.loader.exec_module(helper)
        finally:
            sys.dont_write_bytecode = previous
        for value in ("main", "MAIN", "release/*", "refs/heads/deploy", "a/b/*"):
            for branch in ("main", "release/x", "release", "deploy", "a/b/c", "a/b/", ""):
                with self.subTest(value=value, branch=branch):
                    self.assertEqual(helper.branch_matches(value, branch), pol.branch_matches(value, branch))

    def test_requirements_refuses_enforce_without_rules(self):
        proc = subprocess.run([sys.executable, str(ORG / "session_start_files.py"), "requirements", "--codex-dir", "/etc/codex",
                               "--no-rules", "--enforce"], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 2)


class SchemaAndDocsTests(unittest.TestCase):
    def test_the_schema_names_the_hook(self):
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        self.assertIn("pretooluse-company-rules", schema["properties"]["hook"]["enum"])
        self.assertEqual(cr.HOOK_NAME, "pretooluse-company-rules")

    def test_the_policy_kinds_follow_the_validator(self):
        self.assertEqual(pol.KINDS, vo.ACCEPTED_KINDS)
        self.assertEqual(pol.ENFORCED_KINDS, vo.ENFORCED_KINDS)
        self.assertEqual(pol.FORMAT, vo.POLICY_FORMAT)
        self.assertEqual(pol.FORMAT_VERSION, vo.POLICY_FORMAT_VERSION)
        self.assertEqual(pol.MODES, vo.MODES)


class SummaryTests(unittest.TestCase):
    def test_company_rule_lines_are_counted_by_rule_and_errors_by_label(self):
        import evidence_summary

        lines = [json.dumps(line) for line in (
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "deny", "rule_id": "protected-branches", "session_id": "a"},
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "would_deny", "rule_id": "protected-branches", "session_id": "b"},
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "ask", "rule_id": "confirm", "session_id": "c"},
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "policy_error", "label": "wrong-owner", "session_id": "d"},
        )]
        summary = evidence_summary.summarize_lines(lines)
        self.assertEqual(summary["company_rules"]["by_rule"], {
            "confirm": {"deny": 0, "ask": 1, "would_deny": 0},
            "protected-branches": {"deny": 1, "ask": 0, "would_deny": 1},
        })
        self.assertEqual(summary["company_rules"]["policy_errors"], {"wrong-owner": 1})
        self.assertEqual(summary["hooks"]["denials_by_label"], {"company rule protected-branches": 1})
        self.assertEqual(summary["hooks"]["unique_sessions_with_denials"], 2)  # a and c; would_deny and policy_error block nothing
        markdown = evidence_summary.render_markdown(summary)
        self.assertIn("| `protected-branches` | 1 | 0 | 1 |", markdown)
        self.assertIn("| `wrong-owner` | 1 |", markdown)

if __name__ == "__main__":
    unittest.main()
