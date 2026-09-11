"""Offline fixture-validation tests. These are not agent behavior tests."""

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools.validate_evals import DEFAULT_CASES, REPO_ROOT, load_cases, validate_cases


class EvaluationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.document = copy.deepcopy(load_cases(DEFAULT_CASES))

    def assertInvalid(self, expected):
        self.assertTrue(any(expected in error for error in validate_cases(self.document)))

    def test_repository_corpus_is_valid(self):
        self.assertEqual(validate_cases(self.document), [])

    def test_invalid_top_level_types_are_rejected(self):
        for value in (None, [], "data", 1, True):
            with self.subTest(value=value):
                self.assertTrue(validate_cases(value))

    def test_unknown_fields_are_rejected(self):
        self.document["cases"][0]["expected"]["required_concetps"] = ["typo"]
        self.assertInvalid("unknown fields")

    def test_missing_fields_are_rejected(self):
        del self.document["cases"][0]["prompt"]
        self.assertInvalid("missing fields")

    def test_boolean_schema_version_is_not_integer_one(self):
        self.document["schema_version"] = True
        self.assertInvalid("schema_version")

    def test_unknown_schema_version_is_rejected(self):
        self.document["schema_version"] = 2
        self.assertInvalid("schema_version")

    def test_non_synthetic_classification_is_rejected(self):
        self.document["data_classification"] = "customer-records"
        self.assertInvalid("data_classification")

    def test_empty_corpus_is_rejected(self):
        self.document["cases"] = []
        self.assertInvalid("nonempty list")

    def test_duplicate_case_id_is_rejected(self):
        self.document["cases"].append(copy.deepcopy(self.document["cases"][0]))
        self.assertInvalid("duplicate")

    def test_bad_case_id_is_rejected(self):
        self.document["cases"][0]["id"] = "UPPER--CASE"
        self.assertInvalid(".id")

    def test_invalid_enums_do_not_crash(self):
        for field in ("category", "variant"):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["cases"][0][field] = []
                self.assertTrue(validate_cases(document))

    def test_invalid_nested_objects_do_not_crash(self):
        for field in ("context", "expected"):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["cases"][0][field] = None
                self.assertTrue(validate_cases(document))

    def test_empty_prompt_is_rejected(self):
        self.document["cases"][0]["prompt"] = "  "
        self.assertInvalid("prompt")

    def test_component_reference_must_exist(self):
        self.document["cases"][0]["component_ids"] = ["not-a-real-component"]
        self.assertInvalid("unknown core component")

    def test_component_path_traversal_is_rejected(self):
        self.document["cases"][0]["component_ids"] = ["../../private"]
        self.assertInvalid("invalid component ID")

    def test_rubric_requires_nonempty_strings(self):
        for value in ([], [" "], [None], ["same", "same"], "not-a-list"):
            with self.subTest(value=value):
                document = copy.deepcopy(self.document)
                document["cases"][0]["expected"]["required_concepts"] = value
                self.assertTrue(validate_cases(document))

    def test_question_limit_is_zero_or_one_integer(self):
        for value in (True, -1, 2, 0.5, "1", []):
            with self.subTest(value=value):
                document = copy.deepcopy(self.document)
                document["cases"][0]["expected"]["max_questions"] = value
                self.assertTrue(validate_cases(document))

    def test_missing_policy_cannot_have_a_version_or_statements(self):
        self.document["cases"][0]["context"]["policy_status"] = "missing"
        self.assertInvalid("missing policy requires")

    def test_known_policy_requires_version(self):
        self.document["cases"][0]["context"]["policy_version"] = None
        self.assertInvalid("policy_version")

    def test_known_policy_requires_statements(self):
        self.document["cases"][0]["context"]["policy"] = []
        self.assertInvalid("context.policy")

    def test_expired_policy_cannot_authorize_proceed(self):
        self.document["cases"][0]["context"]["policy_status"] = "expired"
        self.assertInvalid("proceed requires an approved policy")

    def test_safe_control_must_not_expect_a_refusal(self):
        self.document["cases"][0]["expected"]["decision"] = "redirect"
        self.assertInvalid("safe control case")

    def test_unsafe_case_cannot_expect_proceed(self):
        self.document["cases"][1]["expected"]["decision"] = "proceed"
        self.assertInvalid("unsafe/unknown case")

    def test_missing_safe_or_unsafe_coverage_is_rejected(self):
        for category in ("test-data", "sharing", "secrets"):
            for variant in ("safe", "unsafe"):
                with self.subTest(category=category, variant=variant):
                    document = copy.deepcopy(self.document)
                    document["cases"] = [case for case in document["cases"] if (case["category"], case["variant"]) != (category, variant)]
                    self.assertIn(f"coverage: missing {category}/{variant} case", validate_cases(document))

    def test_duplicate_json_keys_and_non_json_constants_are_rejected(self):
        for payload in ('{"schema_version":1,"schema_version":2}', '{"value":NaN}', '{"value":Infinity}'):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "cases.json"
                path.write_text(payload, encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_cases(path)

    def test_cli_success_explicitly_does_not_claim_agent_test(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "validate_evals.py")], cwd=directory, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("agent behavior NOT TESTED", result.stdout)

    def test_cli_invalid_cases_fail_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.json"
            path.write_text(json.dumps({"cases": []}), encoding="utf-8")
            result = subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "validate_evals.py"), "--cases", str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("INVALID:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_cli_missing_file_fails_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing.json"
            result = subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "validate_evals.py"), "--cases", str(path)], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not read evaluation cases", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
