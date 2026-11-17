"""The session-start script: company rules at session start on Claude Code and Codex. Offline.

catpilot_guard/session_start.py is the code; hooks/session-start/catpilot-company-rules.py is the entry
script a hook configuration names. These tests check the current, expired and error paths on both
hosts; that the output is the SessionStart shape each vendor documents; the expiry boundary and the
local date; that evidence lines validate against the schema and carry no rule text, no value from the
rules and no path; the size budgets; the entry script without its package and with a broken stdout or
stderr; that both files parse as Python 3.8; and, end to end, the script against a private build of
the example rules file.

The output format follows the vendors' hook references, read on 2026-11-16:
  Claude Code  https://code.claude.com/docs/en/hooks (SessionStart decision control, JSON output)
  Codex        https://developers.openai.com/codex/hooks (SessionStart, Common output fields,
               Large hook output)
Both document {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ...}} on
stdout as context for the model, and a top-level "systemMessage" as a warning shown to the person.
"""

from __future__ import annotations

import ast
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from catpilot_guard import evidence, session_start
from tools import bundle, company_checklist, targets, validate_overlay

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "hooks" / "session-start" / "catpilot-company-rules.py"
PACKAGE = ROOT / "catpilot_guard"
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
TIER = ROOT / "src" / "skills" / "safe-building"
SCHEMA = json.loads((ROOT / "docs" / "spec" / "evidence-event.schema.json").read_text(encoding="utf-8"))
REVIEW_DAY = dt.date(2026, 9, 13)
EXPIRES = dt.date(2027, 3, 13)
OWNER = "security-review@example.org"
HOSTS = ("claude-code", "codex")
EVENT = {"session_id": "0b1c-2d:3e.4f_5", "source": "startup", "hook_event_name": "SessionStart", "cwd": "/tmp/project"}
CANARY = "zqcanary"  # planted in the rules, the hook event and the arguments; no output or evidence line may carry it
# Claude Code caps a hook's additionalContext at 10,000 characters; longer text becomes a file path and a preview.
CLAUDE_CODE_CONTEXT_CAP = 10_000
# Fields a session-start line may carry beside the envelope.
LINE_FIELDS = {
    "rules_delivered": {"host", "session_id", "session_source", "policy_sha256", "release", "block_chars", "block_lines"},
    "rules_expired": {"host", "session_id", "session_source", "policy_sha256", "release"},
    "policy_error": {"host", "session_id", "session_source", "label"},
}

try:
    import jsonschema

    VALIDATOR = jsonschema.Draft202012Validator(SCHEMA, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER)
except ImportError:  # pragma: no cover
    VALIDATOR = None


def as_of_review_day():
    """Build private bundles as of the example's review day, so the build does not depend on today's date."""
    real = validate_overlay.validate_expiry
    return mock.patch.object(validate_overlay, "validate_expiry", lambda overlay, today=None: real(overlay, REVIEW_DAY))


def build_rules(out: Path, overlay_text: str | None = None) -> Path:
    """A private build of the example rules file (or of overlay_text) under out; returns its hosts directory."""
    out.mkdir(parents=True, exist_ok=True)
    source = EXAMPLE
    if overlay_text is not None:
        source = out / "overlay.yaml"
        source.write_text(overlay_text, encoding="utf-8")
    with as_of_review_day(), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
        code = bundle.cmd_private(source, out / "private", [], None)
    if code != 0:
        raise AssertionError(err.getvalue())
    (hosts,) = (out / "private").glob("*-hosts")
    return hosts


def write_pair(directory: Path, block: str, **sidecar) -> Path:
    """A block and a sidecar that match it, with the given sidecar fields replaced. Returns directory."""
    directory.mkdir(parents=True, exist_ok=True)
    data = block.encode("utf-8")
    (directory / session_start.BLOCK_NAME).write_bytes(data)
    policy = session_start.BLOCK_POLICY_HASH.search(block)
    document = {
        "schema_version": 1,
        "owner": OWNER,
        "reviewed_on": "2026-09-13",
        "expires_on": "2027-03-13",
        "policy_sha256": policy.group(1) if policy else "0" * 64,
        "block_sha256": hashlib.sha256(data).hexdigest(),
        "release": "2026.09.18",
    }
    document.update(sidecar)
    (directory / session_start.SIDECAR_NAME).write_text(json.dumps(document), encoding="utf-8")
    return directory


def synthetic_block(body: str = "Company rules for a test.\n") -> str:
    return body + "\nOverlay SHA-256: " + "ab" * 32 + "\n"


@contextlib.contextmanager
def evidence_env(log: Path | None):
    with mock.patch.dict(os.environ):
        for name in (evidence.EVIDENCE_ENV, evidence.SYSLOG_ENV):
            os.environ.pop(name, None)
        if log is not None:
            os.environ[evidence.EVIDENCE_ENV] = str(log)
        yield


def run_main(argv, stdin: str = "", *, default_dir: Path | None = None, today: dt.date | None = None, log: Path | None = None):
    """main() in this process: (exit code, stdout, stderr)."""
    stream = io.TextIOWrapper(io.BytesIO(stdin.encode("utf-8")), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    with evidence_env(log), mock.patch.object(sys, "stdin", stream), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = session_start.main(list(argv), default_dir=default_dir, today=today)
    return code, out.getvalue(), err.getvalue()


def script_env(**extra) -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_")}
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(extra)
    return env


def run_script(script: Path, args, stdin: bytes = b"", *, close_stdout: bool = False, close_stderr: bool = False, **env):
    """The entry script as a subprocess, optionally writing into a pipe whose reader is already gone."""
    if not (close_stdout or close_stderr):
        return subprocess.run([sys.executable, str(script), *args], input=stdin, capture_output=True, env=script_env(**env), timeout=30)
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    if close_stdout:
        os.close(out_r)
    if close_stderr:
        os.close(err_r)
    try:
        return subprocess.run([sys.executable, str(script), *args], input=stdin, stdout=out_w, stderr=err_w, env=script_env(**env), timeout=30)
    finally:
        os.close(out_w)
        os.close(err_w)
        if not close_stdout:
            os.close(out_r)
        if not close_stderr:
            os.close(err_r)


def read_lines(log: Path) -> list:
    if not log.exists():
        return []
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "evidence.jsonl"

    def assert_host_output(self, host: str, code: int, stdout: str) -> dict:
        """The output each vendor documents for SessionStart, and exit 0."""
        self.assertEqual(code, 0)
        # One JSON object on one line, nothing around it: Claude Code reads anything else as plain text.
        self.assertTrue(stdout.startswith("{") and stdout.endswith("}\n"), stdout[:80])
        self.assertEqual(stdout.count("\n"), 1)
        output = json.loads(stdout)
        self.assertLessEqual(set(output), {"hookSpecificOutput", "systemMessage"})
        specific = output["hookSpecificOutput"]
        self.assertEqual(set(specific), {"hookEventName", "additionalContext"})
        self.assertEqual(specific["hookEventName"], "SessionStart")
        self.assertIsInstance(specific["additionalContext"], str)
        self.assertTrue(specific["additionalContext"])
        if "systemMessage" in output:
            self.assertIsInstance(output["systemMessage"], str)
        if host == "claude-code":
            self.assertLessEqual(len(specific["additionalContext"]), CLAUDE_CODE_CONTEXT_CAP)
        self.assertNotIn("permissionDecision", stdout)
        return output

    def assert_lines_valid(self, lines: list) -> None:
        for line in lines:
            with self.subTest(event=line.get("event")):
                if VALIDATOR is not None:
                    errors = [e.message for e in VALIDATOR.iter_errors(line)]
                    self.assertEqual(errors, [])
                self.assertEqual(line["source"], "session-start")
                self.assertLessEqual(set(line) - set(evidence.ENVELOPE), LINE_FIELDS[line["event"]])


class CurrentRulesTests(Base):
    def setUp(self):
        super().setUp()
        self.hosts = build_rules(self.root)
        self.block = (self.hosts / targets.COMPANY_CHECKLIST_NAME).read_text(encoding="utf-8")

    def run_host(self, host: str, today: dt.date = REVIEW_DAY):
        return run_main(["--host", host, "--dir", str(self.hosts)], json.dumps(EVENT), today=today, log=self.log)

    def test_codex_receives_the_block_as_developer_context(self):
        code, out, err = self.run_host("codex")
        output = self.assert_host_output("codex", code, out)
        self.assertEqual(output["hookSpecificOutput"]["additionalContext"], self.block)
        self.assertEqual(self.block, company_checklist.company_checklist_instruction(EXAMPLE) + "\n")
        self.assertNotIn("systemMessage", output)
        self.assertEqual(err, "")

    def test_claude_code_receives_a_one_line_status(self):
        code, out, err = self.run_host("claude-code")
        output = self.assert_host_output("claude-code", code, out)
        self.assertEqual(
            output["hookSpecificOutput"]["additionalContext"],
            f"Company rules from {OWNER}, reviewed 2026-09-13, valid until 2027-03-13, are loaded.",
        )
        self.assertNotIn("systemMessage", output)
        self.assertNotIn(company_checklist.CHECKLIST_INSTRUCTION[:40], out)
        self.assertEqual(err, "")

    def test_each_host_writes_rules_delivered_with_the_rules_hash_and_release(self):
        policy = hashlib.sha256(EXAMPLE.read_bytes()).hexdigest()
        release = bundle.load_bundle_cfg(TIER)["version"]
        for host in HOSTS:
            self.run_host(host)
        lines = read_lines(self.log)
        self.assert_lines_valid(lines)
        self.assertEqual([(line["event"], line["host"]) for line in lines], [("rules_delivered", h) for h in HOSTS])
        for line in lines:
            self.assertEqual(line["policy_sha256"], policy)
            self.assertEqual(line["release"], release)
            self.assertEqual((line["session_id"], line["session_source"]), (EVENT["session_id"], "startup"))
            self.assertEqual((line["block_chars"], line["block_lines"]), (len(self.block), len(self.block.splitlines())))

    def test_the_expiry_day_is_current_and_the_day_after_is_expired(self):
        for host in HOSTS:
            for today, event in ((REVIEW_DAY, "rules_delivered"), (EXPIRES - dt.timedelta(days=1), "rules_delivered"),
                                 (EXPIRES, "rules_delivered"), (EXPIRES + dt.timedelta(days=1), "rules_expired")):
                with self.subTest(host=host, today=today):
                    before = len(read_lines(self.log))
                    self.run_host(host, today)
                    self.assertEqual([line["event"] for line in read_lines(self.log)[before:]], [event])

    def test_without_a_hook_event_the_rules_are_still_delivered(self):
        for stdin in ("", "not json", "[]", json.dumps({"session_id": 5, "source": ["startup"]}), "{" * 10):
            with self.subTest(stdin=stdin[:20]):
                code, out, _ = run_main(["--host", "codex", "--dir", str(self.hosts)], stdin, today=REVIEW_DAY, log=self.log)
                output = self.assert_host_output("codex", code, out)
                self.assertEqual(output["hookSpecificOutput"]["additionalContext"], self.block)
                line = read_lines(self.log)[-1]
                self.assertEqual(line["event"], "rules_delivered")
                self.assertNotIn("session_id", line)
                self.assertNotIn("session_source", line)

    def test_each_start_source_is_recorded(self):
        for source in session_start.START_SOURCES:
            run_main(["--host", "codex", "--dir", str(self.hosts)], json.dumps({**EVENT, "source": source}), today=REVIEW_DAY, log=self.log)
            self.assertEqual(read_lines(self.log)[-1]["session_source"], source)

    def test_arguments_in_either_form_and_order(self):
        for argv in (["--dir", str(self.hosts), "--host", "codex"], ["--host=codex", f"--dir={self.hosts}"]):
            with self.subTest(argv=argv):
                code, out, _ = run_main(argv, today=REVIEW_DAY)
                self.assertEqual(json.loads(out)["hookSpecificOutput"]["additionalContext"], self.block)

    def test_a_logging_failure_changes_no_output(self):
        expected = {host: self.run_host(host) for host in HOSTS}
        unwritable = self.root / "file"
        unwritable.write_text("x", encoding="utf-8")
        for host in HOSTS:
            with self.subTest(host=host, sink="unwritable path"):
                code, out, err = run_main(["--host", host, "--dir", str(self.hosts)], json.dumps(EVENT), today=REVIEW_DAY, log=unwritable / "evidence.jsonl")
                self.assertEqual((code, out, err), expected[host])
            with self.subTest(host=host, sink="broken writer"), mock.patch.object(evidence, "record", side_effect=RuntimeError("broken")):
                self.assertEqual(self.run_host(host), expected[host])


class ExpiredRulesTests(Base):
    def setUp(self):
        super().setUp()
        self.hosts = build_rules(self.root)
        self.day_after = EXPIRES + dt.timedelta(days=1)

    def test_no_rules_are_printed_and_the_notice_names_the_date_and_the_owner(self):
        for host in HOSTS:
            with self.subTest(host=host):
                code, out, err = run_main(["--host", host, "--dir", str(self.hosts)], json.dumps(EVENT), today=self.day_after, log=self.log)
                output = self.assert_host_output(host, code, out)
                notice = output["hookSpecificOutput"]["additionalContext"]
                self.assertEqual(output["systemMessage"], notice)
                self.assertTrue(notice.startswith("The company rules expired on 2027-03-13 and are not in force."), notice)
                self.assertTrue(notice.endswith(f"Ask {OWNER} for current rules."), notice)
                for rule_text in ("Internal App Platform", "Personal cloud accounts", "Company policy", "Overlay SHA-256", "checklist"):
                    self.assertNotIn(rule_text, out)
                self.assertEqual(err, "")
                instruction_file = "The company rules in the instruction file are out of date and must not be relied on."
                if host == "claude-code":
                    self.assertIn(instruction_file, notice)
                else:
                    self.assertNotIn(instruction_file, notice)

    def test_each_host_writes_rules_expired_without_the_block_size(self):
        for host in HOSTS:
            run_main(["--host", host, "--dir", str(self.hosts)], json.dumps(EVENT), today=self.day_after, log=self.log)
        lines = read_lines(self.log)
        self.assert_lines_valid(lines)
        self.assertEqual([(line["event"], line["host"]) for line in lines], [("rules_expired", h) for h in HOSTS])
        for line in lines:
            self.assertEqual(line["policy_sha256"], hashlib.sha256(EXAMPLE.read_bytes()).hexdigest())
            self.assertNotIn("block_chars", line)


class ErrorTests(Base):
    """Anything wrong prints that company rules could not be loaded, writes policy_error with a fixed label, and exits 0."""

    def assert_error(self, argv, label: str, *, default_dir: Path | None = None, stdin: str = json.dumps(EVENT), host: str | None = "unset"):
        before = len(read_lines(self.log))
        code, out, err = run_main(argv, stdin, default_dir=default_dir, today=REVIEW_DAY, log=self.log)
        for each in HOSTS:
            self.assertEqual(self.assert_host_output(each, code, out), session_start.error_output())
        self.assertEqual(json.loads(out)["systemMessage"], session_start.UNAVAILABLE)
        self.assertEqual(err, "")
        lines = read_lines(self.log)[before:]
        self.assert_lines_valid(lines)
        self.assertEqual([(line["event"], line["label"]) for line in lines], [("policy_error", label)])
        if host != "unset":
            self.assertEqual(lines[0].get("host"), host)
        return lines[0]

    def good_pair(self, name: str = "good") -> Path:
        return write_pair(self.root / name, synthetic_block())

    def test_the_error_text_says_unknown_and_who_to_ask(self):
        self.assertEqual(session_start.UNAVAILABLE, "Company rules could not be loaded and are unknown. Ask your IT or security owner.")

    def test_missing_files(self):
        good = self.good_pair()
        no_block = shutil.copytree(good, self.root / "no-block")
        (no_block / session_start.BLOCK_NAME).unlink()
        no_sidecar = shutil.copytree(good, self.root / "no-sidecar")
        (no_sidecar / session_start.SIDECAR_NAME).unlink()
        for host in HOSTS:
            for directory in (self.root / "absent", no_block, no_sidecar):
                with self.subTest(host=host, directory=directory.name):
                    self.assert_error(["--host", host, "--dir", str(directory)], "missing", host=host)
            with self.subTest(host=host, directory="no --dir and no default"):
                self.assert_error(["--host", host], "missing", host=host)
            with self.subTest(host=host, directory="the default, empty"):
                self.assert_error(["--host", host], "missing", default_dir=self.root / "instructions", host=host)

    def test_unreadable_files(self):
        directory = self.root / "unreadable"
        (directory / session_start.BLOCK_NAME).mkdir(parents=True)
        (directory / session_start.SIDECAR_NAME).write_text("{}", encoding="utf-8")
        not_a_directory = self.root / "a-file"
        not_a_directory.write_text("x", encoding="utf-8")
        for host in HOSTS:
            for path in (directory, not_a_directory):
                with self.subTest(host=host, path=path.name):
                    self.assert_error(["--host", host, "--dir", str(path)], "unreadable", host=host)

    def test_malformed_files(self):
        block = synthetic_block()
        cases = {
            "sidecar not json": lambda d: (d / session_start.SIDECAR_NAME).write_text("{not json", encoding="utf-8"),
            "sidecar a list": lambda d: (d / session_start.SIDECAR_NAME).write_text("[]", encoding="utf-8"),
            "sidecar not utf-8": lambda d: (d / session_start.SIDECAR_NAME).write_bytes(b"\xff\xfe{}"),
            "sidecar too large": lambda d: (d / session_start.SIDECAR_NAME).write_text(" " * (session_start.MAX_SIDECAR_BYTES + 1), encoding="utf-8"),
            "block not utf-8": lambda d: write_pair(d, block) and (d / session_start.BLOCK_NAME).write_bytes(b"\xff" + block.encode()),
            "block too large": lambda d: write_pair(d, block + "x" * session_start.MAX_BLOCK_BYTES),
            "block without its hash line": lambda d: write_pair(d, "Company rules with no hash line.\n"),
        }
        sidecar_fields = {
            "schema version 2": {"schema_version": 2},
            "schema version true": {"schema_version": True},
            "schema version missing": {"schema_version": None},
            "owner missing": {"owner": None},
            "owner too short": {"owner": "ab"},
            "owner too long": {"owner": "a" * 161},
            "owner with a line break": {"owner": "security\nreview"},
            "owner with a line separator": {"owner": "security\u2028review"},
            "owner padded": {"owner": " security-review "},
            "owner not a string": {"owner": ["security-review"]},
            "impossible date": {"expires_on": "2027-02-30"},
            "compact date": {"expires_on": "20270313"},
            "datetime": {"expires_on": "2027-03-13T00:00:00"},
            "date not a string": {"reviewed_on": 20260913},
            "expires before review": {"expires_on": "2026-09-12"},
            "expires on the review day": {"expires_on": "2026-09-13"},
            "policy hash in capitals": {"policy_sha256": "AB" * 32},
            "policy hash short": {"policy_sha256": "ab" * 31},
            "block hash missing": {"block_sha256": None},
            "release with a space": {"release": "2026.09.18 final"},
            "release not a string": {"release": 2026},
        }
        for name, fields in sidecar_fields.items():
            cases[name] = lambda d, fields=fields: write_pair(d, block, **fields)
        for i, (name, make) in enumerate(cases.items()):
            directory = self.root / f"malformed-{i}"
            directory.mkdir()
            make(directory)
            if not (directory / session_start.BLOCK_NAME).exists():
                (directory / session_start.BLOCK_NAME).write_text(block, encoding="utf-8")
            for host in HOSTS:
                with self.subTest(case=name, host=host):
                    self.assert_error(["--host", host, "--dir", str(directory)], "malformed", host=host)

    def test_a_sidecar_that_does_not_match_its_block(self):
        block = synthetic_block()
        edited = write_pair(self.root / "edited", block)
        (edited / session_start.BLOCK_NAME).write_text(block.replace("test", "tEst"), encoding="utf-8")
        other_policy = write_pair(self.root / "other-policy", block, policy_sha256="cd" * 32)
        other_block = write_pair(self.root / "other-block", block, block_sha256="cd" * 32)
        # A block from one build and a sidecar from another: the rules file changed in between.
        first = build_rules(self.root / "first")
        text = EXAMPLE.read_text(encoding="utf-8").replace('"Browser extensions"', '"Desktop add-ons"')
        second = build_rules(self.root / "second", text)
        mixed = self.root / "mixed"
        mixed.mkdir()
        shutil.copy(first / targets.COMPANY_CHECKLIST_NAME, mixed)
        shutil.copy(second / targets.COMPANY_CHECKLIST_SIDECAR_NAME, mixed)
        for host in HOSTS:
            for directory in (edited, other_policy, other_block, mixed):
                with self.subTest(host=host, directory=directory.name):
                    self.assert_error(["--host", host, "--dir", str(directory)], "hash-mismatch", host=host)

    def test_bad_arguments(self):
        good = str(self.good_pair())
        cases = {
            "no host": (["--dir", good], None),
            "unknown host": (["--host", "cursor", "--dir", good], None),
            "host in capitals": (["--host", "Codex", "--dir", good], None),
            "relative dir": (["--host", "codex", "--dir", "instructions"], "codex"),
            "unknown argument": (["--host", "codex", "--dir", good, "--verbose", "1"], "codex"),
            "repeated host": (["--host", "codex", "--host", "claude-code", "--dir", good], "codex"),
            "dir without a value": (["--host", "codex", "--dir"], "codex"),
            "positional": (["codex"], None),
        }
        for name, (argv, host) in cases.items():
            with self.subTest(case=name):
                self.assert_error(argv, "bad-arguments", host=host)

    def test_an_unexpected_error_is_internal_error(self):
        good = str(self.good_pair())
        for host in HOSTS:
            with self.subTest(host=host), mock.patch.object(session_start, "load", side_effect=RuntimeError("zqcanary")):
                line = self.assert_error(["--host", host, "--dir", good], "internal-error", host=host)
                self.assertNotIn(CANARY, json.dumps(line))

    def test_the_schema_lists_the_labels_the_script_writes(self):
        condition = next(c for c in SCHEMA["allOf"] if c["if"]["properties"]["source"]["const"] == "session-start")
        self.assertEqual(condition["then"]["properties"]["label"]["enum"], list(session_start.ERROR_LABELS))
        self.assertEqual(condition["then"]["properties"]["event"]["enum"], ["rules_delivered", "rules_expired", "policy_error"])
        self.assertEqual(SCHEMA["properties"]["session_source"]["enum"], list(session_start.START_SOURCES))
        self.assertEqual(SCHEMA["properties"]["host"]["enum"], list(session_start.HOSTS))
        self.assertEqual((session_start.CLAUDE_CODE, session_start.CODEX), (evidence.CLAUDE_CODE, evidence.CODEX))
        self.assertEqual(
            SCHEMA["properties"]["release"]["pattern"],
            "^" + session_start.EVIDENCE_RELEASE.pattern.replace("(?:", "(") + "$",
        )

    def test_a_release_outside_the_schema_shape_is_left_out_of_the_line(self):
        directory = write_pair(self.root / "build-suffix", synthetic_block(), release="2026.09.18+build.7")
        run_main(["--host", "codex", "--dir", str(directory)], today=REVIEW_DAY, log=self.log)
        line = read_lines(self.log)[-1]
        self.assertEqual(line["event"], "rules_delivered")
        self.assertNotIn("release", line)
        self.assert_lines_valid([line])


class NothingEchoedTests(Base):
    """No value from the hook event, the arguments, the rules or the path reaches the evidence log, and nothing
    from the hook event or the arguments reaches stdout or stderr."""

    def canary_rules(self) -> Path:
        text = EXAMPLE.read_text(encoding="utf-8")
        for old, new in (
            ('"security-review@example.org"', f'"{CANARY}-owner@example.org"'),
            ('"Internal App Platform (company sign-in)"', '"Zqcanary App Platform (company sign-in)"'),
            # The same lengths or shorter: the private paste blocks are close to their size limit.
            ('"Shared passwords"', '"ZQCANARY passwords"'),
            ('"Writes to a system of record"', f'"Writes to a {CANARY} record"'),
        ):
            self.assertIn(old, text)
            text = text.replace(old, new)
        return build_rules(self.root / f"{CANARY}-build", text)

    def test_no_line_carries_rule_text_a_rule_value_or_a_path(self):
        hosts = self.canary_rules()
        event = json.dumps({**EVENT, "cwd": f"/home/{CANARY}", "prompt": CANARY, "transcript_path": f"/tmp/{CANARY}.jsonl"})
        for host in HOSTS:
            for today in (REVIEW_DAY, EXPIRES + dt.timedelta(days=1)):
                run_main(["--host", host, "--dir", str(hosts)], event, today=today, log=self.log)
            run_main(["--host", host, "--dir", str(self.root / f"{CANARY}-absent")], event, today=REVIEW_DAY, log=self.log)
        lines = read_lines(self.log)
        self.assertEqual([line["event"] for line in lines], ["rules_delivered", "rules_expired", "policy_error"] * 2)
        self.assert_lines_valid(lines)
        text = self.log.read_text(encoding="utf-8")
        self.assertNotIn(CANARY, text.lower())
        self.assertNotIn(str(self.root), text)
        self.assertNotIn("security-review", text)
        for line in lines:
            for key in set(line) - {"ts"}:
                self.assertNotIn("2026-09-13", str(line[key]))
                self.assertNotIn("2027-03-13", str(line[key]))

    def test_the_hook_event_and_the_arguments_are_never_printed(self):
        good = write_pair(self.root / "good", synthetic_block())
        event = json.dumps({"session_id": f"{CANARY} with spaces", "source": CANARY, "cwd": f"/{CANARY}"})
        for argv in (["--host", CANARY], ["--host", "codex", "--dir", CANARY], ["--host", "codex", f"--{CANARY}", "x"],
                     ["--host", "codex", "--dir", str(good)], ["--host", "claude-code", "--dir", str(good)]):
            with self.subTest(argv=argv):
                code, out, err = run_main(argv, event, today=REVIEW_DAY, log=self.log)
                self.assertEqual(code, 0)
                self.assertNotIn(CANARY, (out + err).lower())
        self.assertNotIn(CANARY, self.log.read_text(encoding="utf-8").lower())


class SizeBudgetTests(Base):
    """Over the host's budget the block is still delivered; the size goes to stderr and to the evidence line."""

    def block_of(self, chars: int = 0, lines: int = 0) -> str:
        tail = synthetic_block("")
        body = "".join(f"- rule {i}\n" for i in range(lines - tail.count("\n"))) if lines else ""
        if chars:
            body = "r" * (chars - len(tail) - 1) + "\n"
        return body + tail

    def run_pair(self, host: str, block: str):
        directory = write_pair(self.root / f"{host}-{len(block)}-{block.count(chr(10))}", block)
        return run_main(["--host", host, "--dir", str(directory)], json.dumps(EVENT), today=REVIEW_DAY, log=self.log)

    def test_codex_budget_is_about_2500_tokens(self):
        self.assertEqual(session_start.CODEX_TOKEN_BUDGET * session_start.CHARS_PER_TOKEN, 10_000)
        at_budget = self.block_of(chars=10_000)
        over = self.block_of(chars=10_001)
        self.assertEqual((len(at_budget), len(over)), (10_000, 10_001))
        code, out, err = self.run_pair("codex", at_budget)
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["additionalContext"], at_budget)
        self.assertEqual(err, "")
        code, out, err = self.run_pair("codex", over)
        output = self.assert_host_output("codex", code, out)
        self.assertEqual(output["hookSpecificOutput"]["additionalContext"], over)  # still delivered, in full
        self.assertEqual(
            err,
            "Catpilot company rules: the block is 10001 characters, about 2501 tokens. Codex gives the model only a "
            "preview of hook context above about 2,500 tokens unless the hook's additionalContextLimit is raised.\n",
        )
        line = read_lines(self.log)[-1]
        self.assertEqual((line["event"], line["block_chars"]), ("rules_delivered", 10_001))

    def test_claude_code_budget_is_200_lines(self):
        at_budget = self.block_of(lines=200)
        over = self.block_of(lines=201)
        self.assertEqual((len(at_budget.splitlines()), len(over.splitlines())), (200, 201))
        self.assertEqual(self.run_pair("claude-code", at_budget)[2], "")
        code, out, err = self.run_pair("claude-code", over)
        self.assert_host_output("claude-code", code, out)
        self.assertEqual(err, "Catpilot company rules: the block is 201 lines. Claude Code's guidance for a CLAUDE.md file is under 200 lines.\n")
        self.assertNotIn("rule 7", err)
        self.assertEqual(read_lines(self.log)[-1]["block_lines"], 201)

    def test_each_host_checks_only_its_own_budget(self):
        self.assertEqual(self.run_pair("claude-code", self.block_of(chars=12_000))[2], "")
        self.assertEqual(self.run_pair("codex", self.block_of(lines=250))[2], "")

    def test_the_example_block_is_within_both_budgets(self):
        block = (build_rules(self.root) / targets.COMPANY_CHECKLIST_NAME).read_text(encoding="utf-8")
        chars, lines, tokens = session_start.block_size(block)
        self.assertLessEqual(tokens, session_start.CODEX_TOKEN_BUDGET)
        self.assertLessEqual(lines, session_start.CLAUDE_MD_LINE_BUDGET)
        for host in HOSTS:
            self.assertIsNone(session_start.size_note(host, block))


class LocalDateTests(Base):
    """"Today" is the machine's local date, not the UTC date."""

    @unittest.skipIf(sys.platform == "win32", "POSIX TZ strings")
    def test_two_time_zones_a_day_apart_disagree(self):
        # UTC-12 and UTC+14 are 26 hours apart, so their local dates always differ, while the UTC date is
        # the same for both runs. Expiry on today's date in UTC-12: current there, expired in UTC+14.
        expires = dt.datetime.now(dt.timezone(dt.timedelta(hours=-12))).date()
        directory = write_pair(self.root / "tz", synthetic_block(), reviewed_on=(expires - dt.timedelta(days=30)).isoformat(),
                               expires_on=expires.isoformat())
        events = {}
        for tz in ("WEST+12", "EAST-14"):  # POSIX: the offset is hours west of UTC
            log = self.root / f"{tz}.jsonl"
            proc = run_script(ENTRY, ["--host", "codex", "--dir", str(directory)], TZ=tz, CATPILOT_EVIDENCE_LOG=str(log))
            self.assertEqual(proc.returncode, 0, proc.stderr)
            events[tz] = read_lines(log)[0]["event"]
        self.assertEqual(events, {"WEST+12": "rules_delivered", "EAST-14": "rules_expired"})


class EntryScriptTests(Base):
    def deployed(self, with_package: bool = True) -> Path:
        """The deployed layout: <managed>/catpilot-guardrails/{hooks/, instructions/}. Returns the entry script's path."""
        base = self.root / "managed" / "catpilot-guardrails"
        hooks = base / "hooks"
        hooks.mkdir(parents=True)
        shutil.copy2(ENTRY, hooks / ENTRY.name)
        if with_package:
            shutil.copytree(PACKAGE, hooks / "catpilot_guard", ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        source = build_rules(self.root)
        instructions = base / "instructions"
        instructions.mkdir()
        for name in (targets.COMPANY_CHECKLIST_NAME, targets.COMPANY_CHECKLIST_SIDECAR_NAME):
            shutil.copy2(source / name, instructions / name)
        return hooks / ENTRY.name

    def test_the_names_match_the_build(self):
        self.assertEqual(session_start.BLOCK_NAME, targets.COMPANY_CHECKLIST_NAME)
        self.assertEqual(session_start.SIDECAR_NAME, targets.COMPANY_CHECKLIST_SIDECAR_NAME)
        self.assertEqual(session_start.SIDECAR_SCHEMA_VERSION, company_checklist.SIDECAR_SCHEMA_VERSION)

    def test_without_dir_it_reads_instructions_beside_the_hooks_directory(self):
        script = self.deployed()
        for host in HOSTS:
            with self.subTest(host=host):
                # An empty PYTHONDONTWRITEBYTECODE is off: the script itself must keep bytecode out of the managed copy.
                proc = run_script(script, ["--host", host], json.dumps(EVENT).encode(), PYTHONDONTWRITEBYTECODE="")
                output = self.assert_host_output(host, proc.returncode, proc.stdout.decode())
                # Current, or expired once the example's expiry date has passed: never the error notice.
                self.assertNotEqual(output["hookSpecificOutput"]["additionalContext"], session_start.UNAVAILABLE)
        self.assertEqual([p for p in script.parent.rglob("*") if p.name == "__pycache__" or p.suffix == ".pyc"], [])

    def test_without_its_package_it_prints_the_error_notice_and_exits_0(self):
        layouts = {"deployed": self.deployed(with_package=False)}
        checkout = self.root / "checkout" / "hooks" / "session-start"
        checkout.mkdir(parents=True)
        shutil.copy2(ENTRY, checkout / ENTRY.name)
        layouts["checkout"] = checkout / ENTRY.name  # two levels up from it has no package either
        for layout, script in layouts.items():
            for host in HOSTS:
                with self.subTest(layout=layout, host=host):
                    proc = run_script(script, ["--host", host], json.dumps(EVENT).encode())
                    output = self.assert_host_output(host, proc.returncode, proc.stdout.decode())
                    self.assertEqual(output, session_start.error_output())
                    self.assertEqual(proc.stderr, b"")

    def test_with_a_broken_package_it_prints_the_error_notice_and_exits_0(self):
        broken_forms = {
            "empty package": {"__init__.py": ""},
            "syntax error": {"__init__.py": "", "session_start.py": "def broken(:\n"},
            "error at import": {"__init__.py": "raise RuntimeError('zqcanary broken install')\n"},
        }
        for form, files in broken_forms.items():
            hooks = self.root / form.replace(" ", "-") / "hooks"
            hooks.mkdir(parents=True)
            shutil.copy2(ENTRY, hooks / ENTRY.name)
            (hooks / "catpilot_guard").mkdir()
            for name, text in files.items():
                (hooks / "catpilot_guard" / name).write_text(text, encoding="utf-8")
            with self.subTest(form=form):
                proc = run_script(hooks / ENTRY.name, ["--host", "codex"], json.dumps(EVENT).encode())
                self.assertEqual(self.assert_host_output("codex", proc.returncode, proc.stdout.decode()), session_start.error_output())
                self.assertNotIn(CANARY, (proc.stdout + proc.stderr).decode().lower())

    def test_a_broken_stdout_or_stderr_still_exits_0(self):
        deployed = self.deployed()
        no_package = self.root / "bare" / ENTRY.name
        no_package.parent.mkdir()
        shutil.copy2(ENTRY, no_package)
        over_budget = write_pair(self.root / "long", "x\n" * 300 + synthetic_block())
        cases = {
            "current, stdout closed": (deployed, ["--host", "codex"], dict(close_stdout=True)),
            "error, stdout closed": (deployed, ["--host", "codex", "--dir", str(self.root / "absent")], dict(close_stdout=True)),
            "no package, stdout closed": (no_package, ["--host", "codex"], dict(close_stdout=True)),
            "size note, stderr closed": (deployed, ["--host", "claude-code", "--dir", str(over_budget)], dict(close_stderr=True)),
            "both closed": (deployed, ["--host", "claude-code", "--dir", str(over_budget)], dict(close_stdout=True, close_stderr=True)),
        }
        for name, (script, args, streams) in cases.items():
            with self.subTest(case=name):
                proc = run_script(script, args, json.dumps(EVENT).encode(), **streams)
                self.assertEqual(proc.returncode, 0)

    def test_help_prints_usage_and_exits_0(self):
        proc = run_script(ENTRY, ["--help"])
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(proc.stdout.decode().startswith("usage: catpilot-company-rules.py --host claude-code|codex"))


class SourceTests(unittest.TestCase):
    def test_the_module_and_the_entry_script_parse_as_python_3_8(self):
        for path in (PACKAGE / "session_start.py", ENTRY):
            with self.subTest(file=path.relative_to(ROOT).as_posix()):
                tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 8))
                future = any(
                    isinstance(node, ast.ImportFrom) and node.module == "__future__" and any(a.name == "annotations" for a in node.names)
                    for node in tree.body
                )
                self.assertTrue(future, "annotations such as `str | None` are evaluated on 3.8 unless postponed")

    def test_the_entry_script_imports_only_the_standard_library_and_the_package(self):
        stdlib = getattr(sys, "stdlib_module_names", None)
        if stdlib is None:
            self.skipTest("sys.stdlib_module_names needs Python 3.10 or later")
        for node in ast.walk(ast.parse(ENTRY.read_text(encoding="utf-8"))):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) else []
            for name in names:
                self.assertTrue(name.split(".")[0] in stdlib or name.split(".")[0] in ("__future__", "catpilot_guard"), name)

    def test_the_shim_notice_is_the_module_notice(self):
        shim = {}
        for node in ast.parse(ENTRY.read_text(encoding="utf-8")).body:
            if isinstance(node, ast.Assign) and getattr(node.targets[0], "id", None) == "UNAVAILABLE":
                shim["UNAVAILABLE"] = ast.literal_eval(node.value)
        self.assertEqual(shim, {"UNAVAILABLE": session_start.UNAVAILABLE})

    def test_the_script_and_its_readme_say_advice_not_enforcement(self):
        for path in (PACKAGE / "session_start.py", ENTRY, ROOT / "hooks" / "session-start" / "README.md"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(file=path.name):
                self.assertIn("not enforcement" if path.suffix == ".md" else "Advice, not enforcement", text)
                self.assertIn("not a control", text)


class EndToEndTests(Base):
    """Build the private bundle from the example rules file with tools/bundle.py, then run the entry script on it."""

    def test_the_entry_script_on_a_private_build_of_the_example(self):
        hosts = build_rules(self.root)
        block = (hosts / targets.COMPANY_CHECKLIST_NAME).read_text(encoding="utf-8")
        # The build is pinned to the review day; the script uses the real date, so after the example's expiry
        # date this test checks the expired path instead.
        expired = dt.date.today() > EXPIRES
        for host in HOSTS:
            with self.subTest(host=host):
                proc = run_script(ENTRY, ["--host", host, "--dir", str(hosts)], json.dumps(EVENT).encode(), CATPILOT_EVIDENCE_LOG=str(self.log))
                output = self.assert_host_output(host, proc.returncode, proc.stdout.decode("utf-8"))
                context = output["hookSpecificOutput"]["additionalContext"]
                if expired:
                    self.assertIn("expired on 2027-03-13", context)
                elif host == "codex":
                    self.assertEqual(context, block)
                else:
                    self.assertEqual(context, f"Company rules from {OWNER}, reviewed 2026-09-13, valid until 2027-03-13, are loaded.")
                self.assertEqual(proc.stderr, b"")
        lines = read_lines(self.log)
        self.assert_lines_valid(lines)
        self.assertEqual([line["event"] for line in lines], ["rules_expired" if expired else "rules_delivered"] * 2)
        self.assertEqual({line["policy_sha256"] for line in lines}, {hashlib.sha256(EXAMPLE.read_bytes()).hexdigest()})


if __name__ == "__main__":
    unittest.main()
