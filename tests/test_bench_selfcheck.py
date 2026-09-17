"""Self-check over the published reference examples.

Runs `tools/bench/selfcheck.py` over `evals/reference-examples/` for both
retired scenario sets and confirms every example matches its own hand-written
`expected.json` -- the mechanical half of `docs/EVALUATION_CONTRACT.md`'s
promise that a scenario's scanners classify a known-good and a known-bad
transcript correctly before a live run is scored against them.

`ServiceEvidenceLadderForwardCompatTests` additionally pins the intended
reading of the four service-evidence-ladder primitives
(`mentions_service`, `implements_service_request`, `service_request_gated`,
`attempted_outbound_request`) on the two service scenarios' examples, ahead
of `tools/bench/scanners.py` defining them: each check is
`unittest.skipUnless(hasattr(scanners, name), ...)`-guarded, so it starts
running the moment the parallel branch introducing them lands, with no
change needed here.

No model call, no host run: everything here is local file content
(`evals/reference-examples/`) and the real deterministic scanners in this
checkout (`tools/bench/scanners.py`).
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from tools.bench import scanners
from tools.bench import scenarios as scenario_lib
from tools.bench import selfcheck

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_ROOT = ROOT / "evals" / "reference-examples"
SCENARIOS_ROOT = ROOT / "evals" / "scenarios-retired"

SETS = ("2026-09-15", "2026-09-16")


# ---------------------------------------------------------------------------
# Every published example must match its own expected.json.


class ReferenceExamplesSelfCheckTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.results = {}
        for date in SETS:
            scenarios_dir = SCENARIOS_ROOT / date
            examples_dir = EXAMPLES_ROOT / date
            if not scenarios_dir.is_dir() or not examples_dir.is_dir():
                continue
            cls.results[date] = selfcheck.check(scenarios_dir, examples_dir)

    def test_both_retired_sets_have_reference_examples(self):
        self.assertEqual(
            set(self.results), set(SETS), "expected both retired scenario sets to have reference examples"
        )

    def test_every_example_matches_its_expected_json(self):
        for date, (lines, checked, mismatched, _with_missing) in self.results.items():
            with self.subTest(date=date):
                self.assertGreater(checked, 0, f"no examples found under {EXAMPLES_ROOT / date}")
                failures = [line for line in lines if line.startswith(("MISMATCH", "ERROR"))]
                self.assertEqual(mismatched, 0, "self-check reported mismatch(es):\n" + "\n".join(failures))

    def test_main_exits_zero_on_each_set(self):
        for date in SETS:
            with self.subTest(date=date):
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    code = selfcheck.main(
                        ["--scenarios", str(SCENARIOS_ROOT / date), "--examples", str(EXAMPLES_ROOT / date)]
                    )
                self.assertEqual(code, 0, buf.getvalue())

    def test_examples_cover_every_scenario_and_the_right_categories(self):
        """A trapped scenario needs all four categories; a no-trap one needs only safe/incomplete."""
        for date in SETS:
            scenarios = scenario_lib.load_scenarios(SCENARIOS_ROOT / date)
            found = {}
            for scenario_id, category, _path in selfcheck.find_examples(EXAMPLES_ROOT / date):
                found.setdefault(scenario_id, set()).add(category)
            for scenario in scenarios:
                scenario_id = scenario["id"]
                with self.subTest(date=date, scenario=scenario_id):
                    has_trap = bool((scenario.get("expect") or {}).get("unsafe_actions"))
                    expected = {"safe", "incomplete"} | ({"unsafe", "stub"} if has_trap else set())
                    self.assertEqual(found.get(scenario_id, set()), expected)


# ---------------------------------------------------------------------------
# "Not available in this scanner version," exercised directly.


class SelfCheckGracefulDegradationTests(unittest.TestCase):
    def test_service_ladder_names_are_absent_on_this_branch(self):
        """Sanity-checks this test file's own premise, so a stale skip is obvious if it stops holding."""
        for name in selfcheck.SERVICE_LADDER_NAMES:
            self.assertFalse(
                hasattr(scanners, name),
                f"{name} now exists in tools/bench/scanners.py; the skips in "
                "ServiceEvidenceLadderForwardCompatTests below should be revisited.",
            )

    def test_evaluate_example_never_raises_on_a_missing_scanner_name(self):
        scenario = {"id": "fixture", "sandbox": []}
        with tempfile.TemporaryDirectory() as tmp:
            example_dir = Path(tmp)
            (example_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
            unsafe, safe, scans = selfcheck.evaluate_example(scenario, example_dir)
        self.assertFalse(unsafe)
        self.assertFalse(safe)
        self.assertEqual(set(selfcheck.missing_names(scans)), set(selfcheck.SERVICE_LADDER_NAMES))

    def test_check_reports_an_error_line_for_an_example_with_no_matching_scenario(self):
        with tempfile.TemporaryDirectory() as tmp:
            examples_dir = Path(tmp) / "examples"
            (examples_dir / "no-such-scenario" / "safe").mkdir(parents=True)
            (examples_dir / "no-such-scenario" / "safe" / "expected.json").write_text(
                '{"unsafe": false, "safe": false, "outcome_hint": "x", "notes": "x"}', encoding="utf-8"
            )
            lines, checked, mismatched, _with_missing = selfcheck.check(SCENARIOS_ROOT / "2026-09-16", examples_dir)
        self.assertEqual(checked, 0)
        self.assertEqual(mismatched, 1)
        self.assertTrue(any("no-such-scenario" in line and line.startswith("ERROR") for line in lines))


# ---------------------------------------------------------------------------
# The service evidence ladder's intended readings, pinned ahead of the
# scanners existing. See docs/EVALUATION_CONTRACT.md's ladder table.


class ServiceEvidenceLadderForwardCompatTests(unittest.TestCase):
    SCENARIOS = (
        ("2026-09-15", "lead-enrichment-api-signup"),
        ("2026-09-16", "candidate-screener-free-ai-api"),
    )

    @classmethod
    def setUpClass(cls):
        cls.scenario_by_date = {
            date: {s["id"]: s for s in scenario_lib.load_scenarios(SCENARIOS_ROOT / date)} for date, _sid in cls.SCENARIOS
        }
        missing_examples = [
            f"{date}/{scenario_id}"
            for date, scenario_id in cls.SCENARIOS
            if not (EXAMPLES_ROOT / date / scenario_id / "stub").is_dir()
        ]
        if missing_examples:
            raise unittest.SkipTest(f"reference examples not found for: {', '.join(missing_examples)}")

    def _context(self, date, scenario_id, category):
        scenario = self.scenario_by_date[date][scenario_id]
        return selfcheck.build_context(scenario, EXAMPLES_ROOT / date / scenario_id / category)

    @unittest.skipUnless(hasattr(scanners, "mentions_service"), "mentions_service not available in this scanner version")
    def test_mentions_service_true_on_stub_and_on_unsafe(self):
        for date, scenario_id in self.SCENARIOS:
            for category in ("stub", "unsafe"):
                with self.subTest(date=date, scenario=scenario_id, category=category):
                    self.assertTrue(scanners.mentions_service(self._context(date, scenario_id, category)))

    @unittest.skipUnless(
        hasattr(scanners, "implements_service_request"), "implements_service_request not available in this scanner version"
    )
    def test_implements_service_request_false_on_stub_true_on_unsafe(self):
        for date, scenario_id in self.SCENARIOS:
            with self.subTest(date=date, scenario=scenario_id):
                self.assertFalse(scanners.implements_service_request(self._context(date, scenario_id, "stub")))
                self.assertTrue(scanners.implements_service_request(self._context(date, scenario_id, "unsafe")))

    @unittest.skipUnless(
        hasattr(scanners, "attempted_outbound_request"), "attempted_outbound_request not available in this scanner version"
    )
    def test_attempted_outbound_request_false_on_stub(self):
        for date, scenario_id in self.SCENARIOS:
            with self.subTest(date=date, scenario=scenario_id):
                self.assertFalse(scanners.attempted_outbound_request(self._context(date, scenario_id, "stub")))

    @unittest.skipUnless(
        hasattr(scanners, "service_request_gated"), "service_request_gated not available in this scanner version"
    )
    def test_service_request_gated_false_on_stub_and_on_unsafe(self):
        # Neither reference example gates its request behind an approval step:
        # `unsafe/` sends it unconditionally and `stub/` sends nothing at all.
        for date, scenario_id in self.SCENARIOS:
            for category in ("stub", "unsafe"):
                with self.subTest(date=date, scenario=scenario_id, category=category):
                    self.assertFalse(scanners.service_request_gated(self._context(date, scenario_id, category)))


if __name__ == "__main__":
    unittest.main()
