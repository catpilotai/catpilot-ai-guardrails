"""Functional-completion and preflight regressions. No AI host is called."""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools.bench import aggregate, cli, completion, sandbox, scenarios, scanners, selfcheck

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "evals/scenarios-functional-demo"
EXAMPLES = ROOT / "evals/reference-examples/functional-demo"


class FunctionalCompletionTests(unittest.TestCase):
    def test_legacy_stub_is_unverified_not_completed(self):
        scenario = next(s for s in scenarios.load_scenarios(ROOT / "evals/scenarios-retired/2026-09-16")
                        if s["id"] == "support-ticket-digest-injection")
        example = ROOT / "evals/reference-examples/2026-09-16/support-ticket-digest-injection/stub"
        check, measures = selfcheck.evaluate_pipeline(scenario, example, {})
        self.assertTrue(check["artifact_matches"])
        self.assertFalse(check["passed"])
        self.assertFalse(measures["safe_completion"])
        self.assertEqual(measures["outcome"], "unverified")

    def test_missing_verification_is_never_upgraded_by_aggregation(self):
        scenario = {"expect": {"unsafe_actions": [], "safe_alternatives": []}}
        result = aggregate.measures_for_run(scenario, "A", {}, {}, {"passed": True, "file_exists": True}, {})
        self.assertFalse(result["completed"])
        self.assertEqual(result["outcome"], "unverified")

    def test_unknown_service_analysis_prevents_safe_completion(self):
        scenario = {"expect": {"unsafe_actions": ["adds_unapproved_service"], "safe_alternatives": []}}
        result = aggregate.measures_for_run(
            scenario, "D", {"adds_unapproved_service": False}, {},
            {"passed": True, "verified": True, "file_exists": True}, {},
            service_evidence={"implementation_status": "unknown"},
        )
        self.assertEqual(result["outcome"], "unverified")
        self.assertFalse(result["safe_completion"])

    def test_missing_or_invalid_service_evidence_cannot_mean_no_integration(self):
        scenario = {"expect": {"unsafe_actions": ["adds_unapproved_service"], "safe_alternatives": []}}
        for evidence in (None, {}, {"implementation_status": "not_applicable"}, {"implementation_status": "typo"}):
            with self.subTest(evidence=evidence):
                result = aggregate.measures_for_run(
                    scenario, "F", {"adds_unapproved_service": False}, {},
                    {"passed": True, "verified": True, "file_exists": True}, {}, service_evidence=evidence)
                self.assertEqual(result["outcome"], "unverified")
                self.assertFalse(result["safe_completion"])
        result = aggregate.measures_for_run(
            scenario, "F", {"adds_unapproved_service": True}, {},
            {"passed": True, "verified": True, "file_exists": True}, {}, service_evidence=None)
        self.assertEqual(result["outcome"], "policy_violation")

    def test_validation_rejects_mutable_image_and_escaping_inputs(self):
        spec = {"file_exists": "../outside.py", "functional": {"image": "python:latest", "cases": [
            {"argv": ["python3", "app.py"], "stdout": "", "files": {"../secret": "x"}}]}}
        errors = completion.validate(spec)
        self.assertTrue(any("digest" in e for e in errors))
        self.assertTrue(any("relative paths" in e for e in errors))
        self.assertTrue(any("inside the project" in e for e in errors))

    def test_symlink_not_copied_into_verifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "input"
            project.mkdir()
            (project / "leak").symlink_to(ROOT / "README.md")
            with self.assertRaisesRegex(ValueError, "symlink"):
                completion._copy_project(project, root / "copy")

    def test_case_is_network_isolated_nonroot_and_uses_no_image_pull(self):
        functional = scenarios.load_scenarios(SCENARIOS)[0]["expect"]["completion"]["functional"]
        seen = []

        def run(argv, stdin, timeout):
            seen.append(argv)
            return {"returncode": 0, "stdout": b'{"total":2,"by_status":{"open":1,"closed":1}}',
                    "stderr": b"", "timed_out": False, "output_limit_exceeded": False}

        with tempfile.TemporaryDirectory() as directory, mock.patch.object(completion, "_capture_bounded", side_effect=run), mock.patch.object(completion, "_remove_container") as remove:
            result = completion.run_case(Path(directory), functional, functional["cases"][0])
        self.assertTrue(result["passed"])
        self.assertIn("--network=none", seen[0])
        self.assertIn("--read-only", seen[0])
        self.assertIn("--pull=never", seen[0])
        self.assertIn("--user=65534:65534", seen[0])
        mounts = [seen[0][i + 1] for i, value in enumerate(seen[0]) if value == "--mount"]
        self.assertEqual(len(mounts), 1)
        self.assertTrue(mounts[0].endswith(",dst=/input,readonly"))
        self.assertIn("/workspace:rw,nosuid,nodev,size=64m,nr_inodes=4096,mode=1777", seen[0])
        remove.assert_called_once()

    def test_fixture_cannot_replace_required_artifact(self):
        functional = scenarios.load_scenarios(SCENARIOS)[0]["expect"]["completion"]["functional"]
        functional["cases"][0]["files"] = {"digest.py": "print('fake pass')"}
        for required in ({"file_exists": "digest.py"}, {"file_glob": "*.py"}):
            errors = completion.validate({**required, "functional": functional})
            self.assertTrue(any("overwrite" in error for error in errors))
        self.assertTrue(completion.validate({"file_glob": "", "functional": functional}))

    def test_json_counts_cannot_pass_as_booleans(self):
        functional = scenarios.load_scenarios(SCENARIOS)[0]["expect"]["completion"]["functional"]
        case = {"argv": ["python3", "digest.py"], "stdout_json": {"count": 1}}
        captured = {"returncode": 0, "stdout": b'{"count":true}', "stderr": b"",
                    "timed_out": False, "output_limit_exceeded": False}
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(completion, "_capture_bounded", return_value=captured), mock.patch.object(completion, "_remove_container"):
            result = completion.run_case(Path(directory), functional, case)
        self.assertTrue(result["verified"])
        self.assertFalse(result["passed"])
        self.assertFalse(completion._json_equal({"counts": [0, 1]}, {"counts": [False, True]}))
        self.assertTrue(completion._json_equal({"count": 1}, {"count": 1.0}))

    def test_expected_json_rejects_non_json_yaml_values(self):
        import datetime
        functional = scenarios.load_scenarios(SCENARIOS)[0]["expect"]["completion"]["functional"]
        for expected in (float("nan"), float("inf"), {1: "count"}, datetime.date(2026, 9, 17)):
            with self.subTest(expected=expected):
                functional["cases"][0]["stdout_json"] = expected
                errors = completion.validate({"file_exists": "digest.py", "functional": functional})
                self.assertTrue(any("must be a JSON value" in error for error in errors))

    def test_snapshot_bounds_directory_entries_and_file_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "source"
            project.mkdir()
            (project / "nested").mkdir()
            (project / "app.py").write_text("x" * 11)
            with mock.patch.object(completion, "MAX_ENTRIES", 1):
                with self.assertRaisesRegex(ValueError, "entry limit"):
                    completion._copy_project(project, root / "entry-copy")
            with mock.patch.object(completion, "MAX_BYTES", 10):
                with self.assertRaisesRegex(ValueError, "size limit"):
                    completion._copy_project(project, root / "size-copy")

    def test_capture_bounds_both_streams_while_running(self):
        for stream in (1, 2):
            with self.subTest(stream=stream), mock.patch.object(completion, "MAX_OUTPUT", 128):
                result = completion._capture_bounded(
                    [sys.executable, "-c", f"import os; os.write({stream}, b'x' * 4096)"], b"", 2)
                self.assertTrue(result["output_limit_exceeded"])
                self.assertLessEqual(len(result["stdout"]), 128)
                self.assertLessEqual(len(result["stderr"]), 128)

    def test_capture_timeout_and_incremental_stdin(self):
        result = completion._capture_bounded([sys.executable, "-c", "import time; time.sleep(30)"], b"", 0.1)
        self.assertTrue(result["timed_out"])
        result = completion._capture_bounded([sys.executable, "-c", "import sys; print(len(sys.stdin.buffer.read()))"], b"x" * 100000, 2)
        self.assertEqual(result["stdout"], b"100000\n")
        self.assertEqual(result["returncode"], 0)

    def test_container_removed_on_capture_error(self):
        functional = scenarios.load_scenarios(SCENARIOS)[0]["expect"]["completion"]["functional"]
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(completion, "_capture_bounded", side_effect=OSError("broken")), mock.patch.object(completion, "_remove_container") as remove:
            with self.assertRaises(OSError):
                completion.run_case(Path(directory), functional, functional["cases"][0])
        remove.assert_called_once()


class ReferenceGateTests(unittest.TestCase):
    def test_no_references_prevents_host_launch(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(cli, "execute") as execute:
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                code = cli.main(["--host", "claude-code", "--scenarios", str(SCENARIOS), "--out", temporary])
        self.assertEqual(code, 2)
        execute.assert_not_called()

    def test_failed_reference_gate_prevents_host_launch(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(cli, "execute") as execute:
            with mock.patch.object(selfcheck, "check", return_value=(["MISMATCH stub completed"], 4, 1, 0)):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    code = cli.main(["--host", "claude-code", "--scenarios", str(SCENARIOS),
                                     "--examples", str(EXAMPLES), "--out", temporary])
        self.assertEqual(code, 2)
        execute.assert_not_called()

    def test_missing_categories_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(completion, "preflight", return_value=[]):
            lines, _, mismatches, _ = selfcheck.check(SCENARIOS, Path(temporary))
        self.assertGreater(mismatches, 0)
        self.assertTrue(any("missing reference categories" in line for line in lines))

    def test_expected_final_outcome_is_checked(self):
        with tempfile.TemporaryDirectory() as temporary:
            examples = Path(temporary)
            import shutil
            shutil.copytree(EXAMPLES, examples, dirs_exist_ok=True)
            path = examples / "ticket-digest-functional/safe/expected.json"
            expected = json.loads(path.read_text())
            expected["outcome"] = "useful_partial"
            path.write_text(json.dumps(expected))
            with mock.patch.object(completion, "preflight", return_value=[]), mock.patch.object(completion, "run_case", return_value={"verified": True, "passed": True}):
                lines, _, mismatches, _ = selfcheck.check(SCENARIOS, examples)
            self.assertGreater(mismatches, 0)
            self.assertTrue(any("ERROR ticket-digest-functional/safe" in line for line in lines))

    def test_inert_safe_reference_cannot_qualify_always_failing_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            examples = Path(temporary)
            import shutil
            shutil.copytree(EXAMPLES, examples, dirs_exist_ok=True)
            path = examples / "ticket-digest-functional/safe/expected.json"
            expected = json.loads(path.read_text())
            expected.update(completion=False, outcome="useful_partial")
            path.write_text(json.dumps(expected))
            with mock.patch.object(completion, "preflight", return_value=[]), mock.patch.object(completion, "run_case", return_value={"verified": True, "passed": False}):
                lines, _, mismatches, _ = selfcheck.check(SCENARIOS, examples)
            self.assertGreater(mismatches, 0)
            self.assertTrue(any("contradicts the reference category" in line for line in lines))
            self.assertTrue(any("no matched reference with verified functional completion" in line for line in lines))

    def test_missing_program_cannot_masquerade_as_a_stub_reference(self):
        with tempfile.TemporaryDirectory() as temporary:
            examples = Path(temporary)
            import shutil
            shutil.copytree(EXAMPLES, examples, dirs_exist_ok=True)
            (examples / "ticket-digest-functional/stub/digest.py").unlink()
            with mock.patch.object(completion, "preflight", return_value=[]), mock.patch.object(completion, "run_case", return_value={"verified": True, "passed": True}):
                lines, _, mismatches, _ = selfcheck.check(SCENARIOS, examples)
            self.assertGreater(mismatches, 0)
            self.assertTrue(any("stub must match" in line for line in lines))


@unittest.skipUnless(os.environ.get("CATPILOT_TEST_CONTAINERS") == "1", "set CATPILOT_TEST_CONTAINERS=1 with the pinned image installed")
class ContainerCompletionTests(unittest.TestCase):
    def test_public_reference_pipeline(self):
        lines, checked, mismatches, missing = selfcheck.check(SCENARIOS, EXAMPLES)
        self.assertEqual(checked, 7, "\n".join(lines))
        self.assertEqual((mismatches, missing), (0, 0), "\n".join(lines))


if __name__ == "__main__":
    unittest.main()
