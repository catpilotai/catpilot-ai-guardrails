"""The simplified comparison's defaults, fairness and false-stop regressions."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools.bench import aggregate, cli, hosts, sandbox, scenarios

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "evals/scenarios-functional-demo"
EXAMPLES = ROOT / "evals/reference-examples/functional-demo"


class ComparisonTests(unittest.TestCase):
    def test_default_conditions_and_all_selectable_conditions_have_human_labels(self):
        args = cli.build_parser().parse_args(["--scenarios", "x", "--host", "codex", "--out", "y"])
        self.assertEqual(cli.parse_arms(args.arms), ["A", "B", "B-activated", "D"])
        self.assertEqual([sandbox.arm_label(a) for a in sandbox.display_arm_order(["D", "A", "B"])],
                         ["A, no guidance", "B-installed, skill installed", "D, skill explicitly activated with company rules through the reference server"])
        self.assertEqual(cli.parse_arms("C,E,F"), ["C", "E", "F"])
        self.assertEqual(cli.parse_arms("B-installed,B-activated"), ["B", "B-activated"])

    def test_each_condition_gets_each_position_across_three_repetitions(self):
        arms = ["A", "B", "D"]
        schedules = [cli.execution_arm_order(arms, 0, rep) for rep in (1, 2, 3)]
        for position in range(3):
            self.assertEqual({schedule[position] for schedule in schedules}, set(arms))
        self.assertEqual(cli.execution_arm_order(arms, 1, 1), schedules[1])
        self.assertEqual(arms, ["A", "B", "D"])
        self.assertEqual(cli.execution_arm_order(["B", "D"], 1, 1), ["D", "B"])

    def test_supplied_policy_is_frozen_once(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            supplied = root / "source.yaml"
            supplied.write_bytes(cli.OVERLAY_EXAMPLE.read_bytes())
            workspace = root / "workspace"
            workspace.mkdir()
            copied, note = cli.resolve_overlay(supplied, workspace)
            expected = supplied.read_bytes()
            supplied.write_text("changed after experiment started")
            self.assertEqual(copied.read_bytes(), expected)
            self.assertIn("fixed snapshot", note)
            self.assertEqual(copied.stat().st_mode & 0o222, 0)

    def test_control_requires_no_review_no_traps_and_no_safe_path_requirement(self):
        control = next(s for s in scenarios.load_scenarios(DEMO) if s["id"] == "ticket-summary-control")
        self.assertTrue(scenarios.is_harmless_control(control))
        self.assertFalse(scenarios.is_harmless_control({**control, "review_needed": True}))
        self.assertFalse(scenarios.is_harmless_control({**control, "expect": {**control["expect"], "safe_alternatives": ["asks_a_human"]}}))
        self.assertFalse(scenarios.is_harmless_control({**control, "sandbox": [{"decoy": "secret"}]}))
        self.assertEqual(scenarios.comparison_suite_errors(scenarios.load_scenarios(DEMO)), [])
        self.assertTrue(scenarios.comparison_suite_errors([control]))

    def test_live_comparison_without_harmless_controls_never_launches(self):
        risk = next(s for s in scenarios.load_scenarios(DEMO) if not scenarios.is_harmless_control(s))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(scenarios, "load_scenarios", return_value=[risk]), mock.patch.object(cli, "execute") as execute:
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                result = cli.main(["--host", "claude-code", "--scenarios", str(DEMO), "--examples", str(EXAMPLES), "--out", directory])
            self.assertEqual(result, 2)
            self.assertIn("voice_reviewed_by", errors.getvalue())
            execute.assert_not_called()

    def test_incomplete_suite_dry_run_is_explicit_setup_smoke(self):
        risk = next(s for s in scenarios.load_scenarios(DEMO) if not scenarios.is_harmless_control(s))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(scenarios, "load_scenarios", return_value=[risk]), mock.patch.object(cli.selfcheck_lib, "check", return_value=(["OK"], 4, 0, 0)), mock.patch.object(cli, "dry_run", return_value=0) as dry_run:
            errors = io.StringIO()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(errors):
                result = cli.main(["--host", "claude-code", "--scenarios", str(DEMO), "--examples", str(EXAMPLES), "--out", directory, "--dry-run"])
            self.assertEqual(result, 0)
            self.assertIn("setup smoke only", errors.getvalue())
            dry_run.assert_called_once()

    def test_live_codex_home_receives_requested_reasoning_setting(self):
        scenario = scenarios.load_scenarios(DEMO)[0]
        args = SimpleNamespace(host="codex", codex_reasoning="high")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(hosts, "prepare_codex_home", side_effect=hosts.CleanIdentityMissing("test identity unavailable")) as prepare:
            root = Path(directory)
            result = cli.one_run(args, scenario, "F", 1, root / "work", root / "out", root / "overlay", "test-model")
        self.assertEqual(result["status"], "skipped")
        self.assertEqual(prepare.call_args.kwargs, {"reasoning_effort": "high"})


class StopMetricTests(unittest.TestCase):
    def measures(self, verdicts, completion):
        return aggregate.measures_for_run(
            {"review_needed": False, "expect": {"unsafe_actions": [], "safe_alternatives": []}},
            "D", {}, {"verdicts": verdicts}, completion, {})

    def test_refusal_with_stub_counts_as_stop_but_working_output_does_not(self):
        verdicts = {"refuses_outright": {"verdict": True}}
        self.assertTrue(self.measures(verdicts, {"file_exists": True, "verified": True, "passed": False})["interruption"])
        self.assertFalse(self.measures(verdicts, {"file_exists": True, "verified": True, "passed": True})["interruption"])

    def test_missing_needed_judge_results_are_unknown_and_not_counted_as_no_stop(self):
        result = self.measures({}, {"file_exists": False, "verified": True, "passed": False})
        self.assertIsNone(result["interruption"])
        self.assertIn("refuses_outright", result["unsettled"])
        summary = aggregate.summarize([{"arm": "D", "scenario": "control", "status": "ok", "measures": result}])
        self.assertEqual(summary["by_arm"]["D"]["interruption_applicable"], 0)
        self.assertEqual(summary["by_arm"]["D"]["runs"], 1)


if __name__ == "__main__":
    unittest.main()
