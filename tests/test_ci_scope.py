"""tools/ci_scope.py: a pull request that changes only documentation runs the tests that name its files; anything
else, or anything the script cannot decide, runs the whole baseline workflow."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from tools import ci_scope  # noqa: E402


class IsDocTests(unittest.TestCase):
    def test_prose_is_documentation(self):
        for path in ["README.md", "SUPPORT.md", "docs/ROADMAP.md", "docs/spec/OVERLAY_V2.md", "hooks/README.md",
                     "mcp-server/README.md", "evals/README.md", "evals/host-check/README.md", "evals/BENCHMARK.md",
                     "evals/HOST_VERIFICATION.md"]:
            with self.subTest(path=path):
                self.assertTrue(ci_scope.is_doc(path))

    def test_build_inputs_fixtures_and_code_are_not(self):
        for path in ["skills/catpilot-safe-building/SKILL.md", "src/skills/core/x/SKILL.md", "dist/2026.09.18/AGENTS.md",
                     "frameworks/agentic/FULL_AGENTIC.md", ".github/pull_request_template.md", "FULL_GUARDRAILS.md",
                     "evals/reports/2026.11.19-host-check-zipapp-reader.md", "evals/reference-examples/a.md",
                     "evals/demo/x.md", "docs/spec/overlay.example.yaml", "tools/ci_scope.py", "README.txt"]:
            with self.subTest(path=path):
                self.assertFalse(ci_scope.is_doc(path))

    def test_docs_only_needs_a_non_empty_change_of_docs(self):
        self.assertTrue(ci_scope.is_docs_only(["README.md", "docs/ROADMAP.md"]))
        self.assertFalse(ci_scope.is_docs_only([]))
        self.assertFalse(ci_scope.is_docs_only(["README.md", "tools/bundle.py"]))


class DecideTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tests = Path(tmp.name)
        (self.tests / "test_names_readme.py").write_text('README = ROOT / "README.md"\n', encoding="utf-8")
        (self.tests / "test_names_roadmap.py").write_text('p = "docs/ROADMAP.md"\n', encoding="utf-8")
        (self.tests / "test_unrelated.py").write_text("x = 1\n", encoding="utf-8")
        # A fixture file that happens to be called README.md is not the repository's README.
        (self.tests / "test_fixture_readme.py").write_text('(home / "hooks" / "README.md").write_text("x")\n', encoding="utf-8")
        # A file name under a directory the module also names.
        (self.tests / "test_names_stability.py").write_text('DOCS = ROOT / "docs"\nx = DOCS / "STABILITY.md"\n', encoding="utf-8")
        (self.tests / "helper.py").write_text('p = "README.md"\n', encoding="utf-8")

    def test_docs_only_pull_request_runs_the_modules_that_name_a_changed_file(self):
        self.assertEqual(ci_scope.decide("pull_request", ["README.md"], self.tests), (True, ["test_names_readme"]))
        self.assertEqual(ci_scope.decide("pull_request", ["docs/ROADMAP.md", "README.md"], self.tests),
                         (True, ["test_names_readme", "test_names_roadmap"]))
        self.assertEqual(ci_scope.decide("pull_request", ["docs/STABILITY.md"], self.tests), (True, ["test_names_stability"]))
        self.assertEqual(ci_scope.decide("pull_request", ["hooks/README.md"], self.tests), (True, ["test_fixture_readme"]))
        self.assertEqual(ci_scope.decide("pull_request", ["SUPPORT.md"], self.tests), (True, []))
        # A bare file name under another directory is not enough.
        self.assertEqual(ci_scope.decide("pull_request", ["deploy/STABILITY.md"], self.tests), (True, []))

    def test_everything_else_runs_in_full(self):
        for event, paths in [("push", ["README.md"]), ("workflow_dispatch", ["README.md"]), ("", ["README.md"]),
                             ("pull_request", None), ("pull_request", []), ("pull_request", ["README.md", "tools/x.py"])]:
            with self.subTest(event=event, paths=paths):
                self.assertEqual(ci_scope.decide(event, paths, self.tests), (False, []))

    def test_the_real_suite_has_tests_that_read_the_readme(self):
        docs_only, tests = ci_scope.decide("pull_request", ["README.md"], ROOT / "tests")
        self.assertTrue(docs_only)
        self.assertIn("test_workflows", tests)
        self.assertNotIn("test_host_check_kit", tests)  # it writes a fixture called README.md, and takes minutes


class ChangedFilesTests(unittest.TestCase):
    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.org", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.org", GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")
        subprocess.run(["git", *args], cwd=self.repo, env=env, check=True, capture_output=True)

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.repo = Path(tmp.name)
        self.git("init", "-q", "-b", "main")
        (self.repo / "README.md").write_text("a\n", encoding="utf-8")
        (self.repo / "old.md").write_text("old\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "base")

    def test_a_merge_commit_lists_what_the_pull_request_changed_with_both_sides_of_a_rename(self):
        self.git("switch", "-q", "-c", "topic")
        (self.repo / "README.md").write_text("b\n", encoding="utf-8")
        self.git("mv", "old.md", "docs.md")
        self.git("commit", "-q", "-am", "topic")
        self.git("switch", "-q", "main")
        (self.repo / "other.py").write_text("x = 1\n", encoding="utf-8")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "main moved on")
        self.git("merge", "-q", "--no-ff", "-m", "merge", "topic")
        self.assertEqual(sorted(ci_scope.changed_files(self.repo)), ["README.md", "docs.md", "old.md"])

    def test_no_parent_means_undecided(self):
        self.assertIsNone(ci_scope.changed_files(self.repo))


class WorkflowWiringTests(unittest.TestCase):
    def setUp(self):
        text = (ROOT / ".github" / "workflows" / "baseline.yml").read_text(encoding="utf-8")
        self.workflow = yaml.load(text, Loader=yaml.BaseLoader)

    def test_runs_on_every_pull_request_and_cancels_only_superseded_pull_request_runs(self):
        self.assertIn("pull_request", self.workflow["on"])
        self.assertNotIn("paths", self.workflow["on"]["pull_request"] or {})
        self.assertNotIn("paths-ignore", self.workflow["on"]["pull_request"] or {})
        concurrency = self.workflow["concurrency"]
        self.assertIn("github.event.pull_request.number", concurrency["group"])
        self.assertIn("github.sha", concurrency["group"])
        self.assertEqual(concurrency["cancel-in-progress"], "${{ github.event_name == 'pull_request' }}")

    def test_every_job_decides_first_and_gates_its_tests_on_the_decision(self):
        for name in ("baseline", "windows"):
            with self.subTest(job=name):
                job = self.workflow["jobs"][name]
                self.assertNotIn("if", job, "a skipped job would leave a required check waiting")
                steps = job["steps"]
                self.assertEqual(steps[0]["with"]["fetch-depth"], "2")
                self.assertEqual(steps[1].get("id"), "scope")
                self.assertIn("tools/ci_scope.py", steps[1]["run"])
                for step in steps[2:]:
                    run = step.get("run", "")
                    if "unittest discover -s tests" in run and "test_workflows.py" not in run or "windows_suite" in run \
                            or "build_zipapp" in run:
                        self.assertIn("steps.scope.outputs.docs_only", step.get("if", ""), step.get("name"))

    def test_the_workflow_test_always_runs(self):
        step = next(s for s in self.workflow["jobs"]["baseline"]["steps"] if "test_workflows.py" in s.get("run", ""))
        self.assertNotIn("if", step)


if __name__ == "__main__":
    unittest.main()
