"""Evidence collection: the OCSF and ECS export, the opt-in hash chain and its verifier, and HTTPS forwarding.

The export is checked against golden files in tests/evidence_golden/ (input.jsonl covers every event, a line
written before schema version 1, an expiring exception and a chained line); regenerate them with
    python3 tools/evidence_export.py --format ocsf tests/evidence_golden/input.jsonl > tests/evidence_golden/expected.ocsf.jsonl
    python3 tools/evidence_export.py --format ecs tests/evidence_golden/input.jsonl > tests/evidence_golden/expected.ecs.jsonl
and read the diff. The chain tests write real lines through evidence.record and then edit, delete, reorder and
truncate them. The forwarding tests run a collector on 127.0.0.1 and check what arrives, that only block and
would-block events are sent, that a canary from the hook's input never is, and that a collector that does not
answer costs the hook at most the timeout.
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from catpilot_guard import evidence, secrets
from tools import evidence_export, evidence_verify

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "tests" / "evidence_golden"
SCHEMA = json.loads((ROOT / "docs" / "spec" / "evidence-event.schema.json").read_text(encoding="utf-8"))
SINK_VARS = (evidence.EVIDENCE_ENV, evidence.SYSLOG_ENV, evidence.CHAIN_ENV, evidence.HTTPS_ENV,
             evidence.HTTPS_TOKEN_FILE_ENV, evidence.HTTPS_TIMEOUT_ENV)

try:
    import jsonschema
    VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)
except ImportError:  # pragma: no cover
    VALIDATOR = None


def clean_env(**values) -> dict:
    env = {key: value for key, value in os.environ.items() if key not in SINK_VARS}
    env.update(values)
    return env


def deny(n: int = 0) -> None:
    evidence.record("deny", evidence.HOOK_SOURCE, {"hook": "pretooluse-secrets", "tool": "Bash", "label": f"label-{n}"})


class ExportGoldenTests(unittest.TestCase):
    def test_every_format_matches_its_golden_file(self):
        lines = (GOLDEN / "input.jsonl").read_text(encoding="utf-8").splitlines()
        for fmt in ("ocsf", "ecs"):
            with self.subTest(fmt=fmt):
                converted, skipped = evidence_export.convert_lines(lines, fmt)
                self.assertEqual(skipped, 0)
                got = [json.dumps(item, sort_keys=True) for item in converted]
                want = (GOLDEN / f"expected.{fmt}.jsonl").read_text(encoding="utf-8").splitlines()
                self.assertEqual(got, want)

    def test_the_golden_input_covers_every_event(self):
        lines = [json.loads(raw) for raw in (GOLDEN / "input.jsonl").read_text(encoding="utf-8").splitlines()]
        self.assertEqual({evidence_export.event_of(line) for line in lines}, set(evidence.EVENTS))
        self.assertEqual(tuple(evidence_export.EVENTS), evidence.EVENTS)

    def test_ocsf_classes_and_required_fields(self):
        lines = (GOLDEN / "input.jsonl").read_text(encoding="utf-8").splitlines()
        converted, _ = evidence_export.convert_lines(lines, "ocsf")
        base = ("class_uid", "category_uid", "activity_id", "type_uid", "time", "severity_id", "metadata")
        per_class = {2004: ("finding_info", "action_id"), 6002: ("app",), 6003: ("api", "actor", "src_endpoint")}
        for item in converted:
            event = item["unmapped"]["catpilot"].get("event", "lookup")
            with self.subTest(event=event):
                for key in base + per_class[item["class_uid"]]:
                    self.assertIn(key, item)
                self.assertEqual(item["type_uid"], item["class_uid"] * 100 + item["activity_id"])
                self.assertEqual(item["metadata"]["version"], "1.3.0")
                self.assertIn("product", item["metadata"])
                if item["class_uid"] == 2004:
                    self.assertTrue({"uid", "title"} <= set(item["finding_info"]))
        classes = {item["unmapped"]["catpilot"].get("event", "lookup"): item["class_uid"] for item in converted}
        self.assertEqual(classes, {"deny": 2004, "ask": 2004, "would_deny": 2004, "input_error": 2004,
                                   "policy_error": 6002, "rules_delivered": 6002, "rules_expired": 6002, "lookup": 6003})

    def test_ecs_never_uses_host_fields(self):
        # host in an evidence line is the AI tool, never the machine; ECS host.* means the machine.
        lines = (GOLDEN / "input.jsonl").read_text(encoding="utf-8").splitlines()
        for item in evidence_export.convert_lines(lines, "ecs")[0]:
            self.assertNotIn("host", item)
            self.assertIn(item["event"]["kind"], ("alert", "event"))

    def test_bad_lines_are_skipped_and_counted(self):
        good = (GOLDEN / "input.jsonl").read_text(encoding="utf-8").splitlines()[0]
        lines = [good, "not json", "[1]", '{"event": "nope", "ts": "2026-11-16T15:04:05+00:00"}', '{"event": "deny", "ts": "yesterday"}', ""]
        converted, skipped = evidence_export.convert_lines(lines, "ecs")
        self.assertEqual((len(converted), skipped), (1, 4))

    def test_cli_exit_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "bad.jsonl"
            bad.write_text("not json\n", encoding="utf-8")
            ok = subprocess.run([sys.executable, str(ROOT / "tools" / "evidence_export.py"), "--format", "ocsf", str(GOLDEN / "input.jsonl")],
                                capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(ok.stdout, (GOLDEN / "expected.ocsf.jsonl").read_text(encoding="utf-8"))
            failed = subprocess.run([sys.executable, str(ROOT / "tools" / "evidence_export.py"), "--format", "ecs", str(bad)],
                                    capture_output=True, text=True)
            self.assertEqual(failed.returncode, 1)
            self.assertNotIn("not json", failed.stderr)


class ChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log = Path(self.tmp.name) / "evidence.jsonl"
        patcher = mock.patch.dict(os.environ, clean_env(**{evidence.EVIDENCE_ENV: str(self.log), evidence.CHAIN_ENV: "1"}), clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.tmp.cleanup)

    def write(self, count: int) -> list:
        for n in range(count):
            deny(n)
        return self.log.read_bytes().split(b"\n")[:-1]

    def verify(self) -> dict:
        return evidence_verify.verify_bytes(self.log.read_bytes())

    def test_each_line_links_to_the_one_before(self):
        lines = self.write(4)
        self.assertEqual(json.loads(lines[0])["prev_sha256"], evidence.GENESIS)
        for before, after in zip(lines, lines[1:]):
            self.assertEqual(json.loads(after)["prev_sha256"], evidence.line_sha256(before))
        report = self.verify()
        self.assertEqual((report["breaks"], report["chained_from"], report["lines"]), ([], 1, 4))
        self.assertEqual(report["head_sha256"], evidence.line_sha256(lines[-1]))

    @unittest.skipUnless(VALIDATOR is not None, "jsonschema is not installed")
    def test_chained_lines_validate_against_schema_version_1(self):
        for raw in self.write(2):
            self.assertEqual(list(VALIDATOR.iter_errors(json.loads(raw))), [])

    def test_a_caller_cannot_set_the_link(self):
        with self.assertRaises(ValueError):
            evidence.build_line("deny", evidence.HOOK_SOURCE, {"hook": "pretooluse-secrets", "prev_sha256": evidence.GENESIS})

    def test_edit_delete_reorder_and_insert_are_found(self):
        lines = self.write(5)
        tampered = {
            "edit": [lines[0], lines[1].replace(b"label-1", b"label-X"), lines[2], lines[3], lines[4]],
            "delete": [lines[0], lines[1], lines[3], lines[4]],
            "reorder": [lines[0], lines[2], lines[1], lines[3], lines[4]],
            "insert": [lines[0], lines[1], lines[1], lines[2], lines[3], lines[4]],
            "strip link": [lines[0], lines[1], json.dumps({k: v for k, v in json.loads(lines[2]).items() if k != "prev_sha256"}, sort_keys=True).encode(), lines[3], lines[4]],
            "delete first": lines[1:],
        }
        for name, body in tampered.items():
            with self.subTest(name):
                report = evidence_verify.verify_bytes(b"\n".join(body) + b"\n")
                self.assertNotEqual(report["breaks"], [], name)

    def test_tail_truncation_and_a_rewritten_chain_need_an_off_box_head(self):
        lines = self.write(3)
        head = evidence.line_sha256(lines[-1])
        self.log.write_bytes(b"\n".join(lines[:2]) + b"\n")  # cut the last line
        self.assertEqual(self.verify()["breaks"], [], "a cut tail is consistent with itself: the limit EVIDENCE.md §8 states")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = evidence_verify.main(["--expect-head", head, str(self.log)])
        self.assertEqual(status, 1)
        self.assertIn("DIFFERS", out.getvalue())

    def test_unchained_lines_before_the_chain_are_reported_not_failed(self):
        with mock.patch.dict(os.environ, {evidence.CHAIN_ENV: ""}):
            deny(0)
            deny(1)
        self.write(2)
        report = self.verify()
        self.assertEqual((report["breaks"], report["chained_from"], report["unchained_before"]), ([], 3, 2))

    def test_a_torn_last_line_stays_its_own_line(self):
        self.write(1)
        with open(self.log, "ab") as fh:
            fh.write(b'{"event": "de')
        deny(9)
        raw = self.log.read_bytes().split(b"\n")
        self.assertEqual(raw[1], b'{"event": "de')
        self.assertEqual(json.loads(raw[2])["prev_sha256"], evidence.line_sha256(b'{"event": "de'))

    def test_the_other_sinks_get_the_line_with_its_link(self):
        sent = []
        with mock.patch.object(evidence, "emit_syslog", lambda payload, spec: sent.append(payload)), \
                mock.patch.dict(os.environ, {evidence.SYSLOG_ENV: "1"}):
            deny(0)
        self.assertEqual(sent[0].encode("utf-8"), self.log.read_bytes().rstrip(b"\n"))

    def test_concurrent_writers_keep_the_chain(self):
        if evidence.fcntl is None:
            self.skipTest("the chain is serialized by fcntl locks; without them concurrent writers can fork it")
        code = "import sys; sys.path.insert(0, sys.argv[1]); from catpilot_guard import evidence\n" \
               "for n in range(20): evidence.record('deny', evidence.HOOK_SOURCE, {'hook': 'pretooluse-secrets', 'label': 'x'})"
        procs = [subprocess.Popen([sys.executable, "-c", code, str(ROOT)], env=dict(os.environ)) for _ in range(4)]
        for proc in procs:
            self.assertEqual(proc.wait(timeout=60), 0)
        report = self.verify()
        self.assertEqual((report["lines"], report["breaks"]), (80, []))

    def test_verify_cli(self):
        self.write(2)
        run = subprocess.run([sys.executable, str(ROOT / "tools" / "evidence_verify.py"), str(self.log)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertIn("chain holds", run.stdout)
        empty = Path(self.tmp.name) / "plain.jsonl"
        empty.write_text('{"event": "deny"}\n', encoding="utf-8")
        run = subprocess.run([sys.executable, str(ROOT / "tools" / "evidence_verify.py"), str(empty)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)


class Collector:
    """An HTTP collector on 127.0.0.1 that keeps each request, or sleeps before answering."""

    def __init__(self, delay: float = 0.0, status: int = 204):
        received = self.received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                received.append((self.path, dict(self.headers), body))
                time.sleep(delay)
                try:
                    self.send_response(status)
                    if status in (301, 302):
                        self.send_header("Location", "http://127.0.0.1:1/elsewhere")
                    self.end_headers()
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/ingest"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-company-rules.py"
PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "no_proxy")


def received_lines(server: Collector) -> list:
    """Every forwarded line, in order, across the collector's requests."""
    return [json.loads(raw) for _, _, body in server.received for raw in body.decode("utf-8").splitlines()]


class ForwardingTests(unittest.TestCase):
    def setUp(self):
        del evidence._PENDING[:]
        self.addCleanup(evidence._PENDING.clear)

    def collector(self, **kwargs) -> Collector:
        server = Collector(**kwargs)
        self.addCleanup(server.close)
        return server

    def env(self, url: str, **extra):
        env = {k: v for k, v in clean_env().items() if k.lower() not in PROXY_VARS}
        env[evidence.HTTPS_ENV] = url
        env.update(extra)
        return mock.patch.dict(os.environ, env, clear=True)

    def test_lines_are_queued_and_sent_in_one_request_after_the_run(self):
        server = self.collector()
        with self.env(server.url):
            deny(0)
            evidence.record("would_deny", evidence.HOOK_SOURCE, {"hook": "pretooluse-company-rules", "rule_id": "r-1", "mode": "monitor"})
            evidence.record("ask", evidence.HOOK_SOURCE, {"hook": "pretooluse-company-rules", "rule_id": "r-1", "mode": "ask"})
            evidence.record("input_error", evidence.HOOK_SOURCE, {"hook": "pretooluse-secrets"})
            evidence.record("rules_delivered", evidence.SESSION_START_SOURCE, {"host": "codex"})
            evidence.record("lookup", evidence.SERVER_SOURCE, {"tool": "get_guidance", "error": None})
            self.assertEqual(server.received, [], "nothing goes out while the hook is deciding")
            evidence.flush_forward()
        self.assertEqual(len(server.received), 1)
        self.assertEqual([line["event"] for line in received_lines(server)], ["deny", "would_deny", "ask", "input_error"])
        path, headers, _ = server.received[0]
        self.assertEqual(path, "/ingest")
        self.assertEqual(headers["Content-Type"], "application/x-ndjson")
        for line in received_lines(server):
            self.assertTrue(set(line) <= set(SCHEMA["properties"]))
        self.assertNotIn("Authorization", headers)
        evidence.flush_forward()
        self.assertEqual(len(server.received), 1, "a flush sends each line once")

    def test_fields_outside_the_schema_are_never_sent(self):
        server = self.collector()
        with self.env(server.url):
            evidence.record("deny", evidence.HOOK_SOURCE, {"hook": "pretooluse-secrets", "command": "CANARY-not-a-field"})
            evidence.flush_forward()
        self.assertEqual(len(server.received), 1)
        self.assertNotIn(b"CANARY", server.received[0][2])

    def test_a_hook_never_sends_its_input(self):
        server = self.collector()
        canary = "CANARYfwd7Q2"
        key = "AKIA" + "IOSFODNN7" + "EXAMPLE"
        payload = json.dumps({"tool_name": "Bash", "session_id": "s-1", "tool_input": {"command": f"echo {canary} {key}"}})
        with self.env(server.url):
            stdin = io.TextIOWrapper(io.BytesIO(payload.encode("utf-8")), encoding="utf-8")
            with mock.patch.object(sys, "stdin", stdin), mock.patch.object(sys, "argv", ["pretooluse-secrets"]), \
                    contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                secrets.main()
            evidence.flush_forward()
        self.assertIn('"deny"', out.getvalue())  # the decision stands
        self.assertEqual([line["event"] for line in received_lines(server)], ["deny"])
        body = server.received[0][2]
        self.assertNotIn(canary.encode(), body)
        self.assertNotIn(key.encode(), body)
        self.assertNotIn(b"echo", body)

    @unittest.skipUnless(os.name == "posix", "the policy is placed with POSIX permissions")
    def test_many_matched_rules_and_a_hanging_collector_keep_the_hook_fast(self):
        # Twelve block rules match one force push, so the company-rules hook writes twelve deny lines. The collector
        # takes the request and does not answer in time. The decision must reach stdout before any network wait, and
        # the whole run must stay well under the host's 10 second hook timeout.
        server = self.collector(delay=30)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "policy"
            directory.mkdir()
            os.chmod(directory, 0o755)
            policy = directory / "company-policy.json"
            rules = [{"id": f"protect-main-{n}", "kind": "protected_branch", "mode": "block", "values": ["main"]} for n in range(12)]
            policy.write_text(json.dumps({"format": "catpilot-company-policy", "format_version": 1, "source_sha256": "e" * 64,
                                          "expires_on": "2099-01-01", "rules": rules}), encoding="utf-8")
            os.chmod(policy, 0o644)
            env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE") and k.lower() not in PROXY_VARS}
            env.update({evidence.EVIDENCE_ENV: str(Path(tmp) / "evidence.jsonl"), evidence.HTTPS_ENV: server.url,
                        evidence.HTTPS_TIMEOUT_ENV: "60"})
            event = {"session_id": "s-1", "hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": tmp,
                     "tool_input": {"command": "git push --force origin main"}}
            started = time.monotonic()
            proc = subprocess.Popen([sys.executable, str(HOOK), "--policy", str(policy)], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
            proc.stdin.write(json.dumps(event).encode("utf-8"))
            proc.stdin.close()
            first = os.read(proc.stdout.fileno(), 65536)
            decided = time.monotonic() - started
            rest = proc.stdout.read()
            proc.wait(timeout=30)
            total = time.monotonic() - started
            proc.stdout.close()
        decision = json.loads(first + rest)
        self.assertEqual(decision["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(proc.returncode, 0)
        self.assertLess(total, evidence.FORWARD_TIMEOUT_MAX + 3.0)
        self.assertLess(decided + 1.0, total, "the decision was out before the forward's wait")
        self.assertEqual(len(server.received), 1, "one request for all the lines")
        self.assertEqual(len(received_lines(server)), 12)

    def test_a_collector_that_hangs_costs_at_most_the_timeout(self):
        server = self.collector(delay=5)
        with self.env(server.url, **{evidence.HTTPS_TIMEOUT_ENV: "0.3"}):
            for n in range(10):
                deny(n)
            started = time.monotonic()
            evidence.flush_forward()
            elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.5)
        self.assertEqual(len(server.received), 1)

    def test_an_unreachable_endpoint_changes_nothing(self):
        with self.env("https://192.0.2.1:9/ingest", **{evidence.HTTPS_TIMEOUT_ENV: "0.2"}):
            deny(0)  # does not raise
            started = time.monotonic()
            evidence.flush_forward()
            self.assertLess(time.monotonic() - started, 1.5)

    def test_the_timeout_is_bounded(self):
        for value, want in (("", 1.0), ("0.25", 0.25), ("60", evidence.FORWARD_TIMEOUT_MAX), ("-1", 1.0), ("nan", 1.0), ("x", 1.0)):
            with self.subTest(value=value), mock.patch.dict(os.environ, {evidence.HTTPS_TIMEOUT_ENV: value}):
                self.assertEqual(evidence.forward_timeout(), want)
        self.assertLessEqual(evidence.FORWARD_TIMEOUT_MAX, 2.0)

    def test_lock_waits_share_one_budget(self):
        if evidence.fcntl is None:
            self.skipTest("no fcntl locks")
        import fcntl
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "evidence.jsonl"
            log.write_text("", encoding="utf-8")
            with open(log, "rb") as holder, mock.patch.object(evidence, "_lock_waited", 0.0), \
                    mock.patch.dict(os.environ, clean_env(**{evidence.EVIDENCE_ENV: str(log)}), clear=True):
                fcntl.flock(holder.fileno(), fcntl.LOCK_EX)
                started = time.monotonic()
                for n in range(8):
                    deny(n)
                elapsed = time.monotonic() - started
            written = len(log.read_text(encoding="utf-8").splitlines())
        self.assertLess(elapsed, evidence.LOCK_BUDGET_SECONDS + 0.5)
        self.assertEqual(written, 8, "every line is still written, without the lock")

    def test_only_https_or_loopback_http_is_used(self):
        for spec, ok in (("https://collector.example/ingest", True), ("http://127.0.0.1:8080/x", True), ("http://localhost/x", True),
                         ("http://collector.example/ingest", False), ("ftp://collector.example/", False), ("collector.example", False),
                         ("https://user:pw@collector.example/", False), ("https://collector.example:99999/", False), ("https://", False)):
            with self.subTest(spec=spec):
                self.assertEqual(evidence.forward_target(spec) is not None, ok)

    def test_loopback_http_never_goes_through_a_proxy(self):
        server = self.collector()
        proxy = self.collector()
        proxy_url = proxy.url.rsplit("/", 1)[0]
        with tempfile.TemporaryDirectory() as tmp:
            token = Path(tmp) / "token"
            token.write_text("secret-ingest-token", encoding="utf-8")
            os.chmod(token, 0o600)
            with self.env(server.url, **{evidence.HTTPS_TOKEN_FILE_ENV: str(token), "HTTP_PROXY": proxy_url, "http_proxy": proxy_url}):
                deny(0)
                evidence.flush_forward()
        self.assertEqual(proxy.received, [])
        self.assertEqual(len(server.received), 1)

    def test_redirects_are_not_followed(self):
        server = self.collector(status=302)
        with self.env(server.url):
            deny(0)
            evidence.flush_forward()
        self.assertEqual(len(server.received), 1)

    def test_bearer_token_from_a_file(self):
        server = self.collector()
        with tempfile.TemporaryDirectory() as tmp:
            good = Path(tmp) / "token"
            good.write_text("ingest-only-token\n", encoding="utf-8")
            os.chmod(good, 0o600)
            bad = Path(tmp) / "bad"
            bad.write_text("two words\nInjected: header\n", encoding="utf-8")
            for path in (good, bad, Path(tmp) / "missing"):
                with self.env(server.url, **{evidence.HTTPS_TOKEN_FILE_ENV: str(path)}):
                    deny(0)
                    evidence.flush_forward()
        self.assertEqual(len(server.received), 1, "an unusable token file sends nothing")
        self.assertEqual(server.received[0][1]["Authorization"], "Bearer ingest-only-token")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions")
    def test_a_shared_token_file_warns_without_content(self):
        server = self.collector()
        with tempfile.TemporaryDirectory() as tmp:
            shared = Path(tmp) / "token"
            shared.write_text("shared-token-value", encoding="utf-8")
            os.chmod(shared, 0o644)
            err = io.StringIO()
            with self.env(server.url, **{evidence.HTTPS_TOKEN_FILE_ENV: str(shared)}), contextlib.redirect_stderr(err):
                deny(0)
                evidence.flush_forward()
        self.assertIn("readable by other accounts", err.getvalue())
        self.assertNotIn("shared-token-value", err.getvalue())
        self.assertNotIn(tmp, err.getvalue())


if __name__ == "__main__":
    unittest.main()
