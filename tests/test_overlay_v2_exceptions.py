"""Expiring exceptions to company enforcement rules (docs/spec/OVERLAY_V2.md §3.1). Offline, synthetic only.

- Validation: accepted and rejected shapes, an unknown rule, values of the wrong kind, an expiry after the file's, the
  shape of `where`, id uniqueness, rule 7 and the secret scan over an exception, and no message repeating a value.
- The JSON Schema agrees with the validator on the same shapes.
- compile and the policy: the exceptions round-trip through compile and the hook's parser, deterministically; a file
  without exceptions compiles as before; the printout names exceptions by id, rule and expiry, never a value; the
  parser refuses malformed exceptions.
- The company-rules hook: active and expired exceptions for both kinds, `where` ignored, a push that rewrites every
  branch never excepted, and a built-in deny never relaxed.
- Evidence: the would_deny line with exception_id, the writer and the schema refusing it elsewhere, and the summary.
- Lint warnings, and verify's probes keeping honest about exceptions.
"""

from __future__ import annotations

import contextlib
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
import os
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
from catpilot_guard import destructive  # noqa: E402
from catpilot_guard import evidence  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402

import evidence_summary  # noqa: E402
import validate_overlay as vo  # noqa: E402

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

SPEC = ROOT / "docs" / "spec"
EXAMPLE_V2 = SPEC / "overlay.v2.example.yaml"
HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-company-rules.py"
ORG = ROOT / "deploy" / "org"
TODAY = dt.date(2026, 11, 17)
TEST_SALT = "5f0c9a1e7d3b4c2a8e6f1d0b9a7c5e3f"
SHA = "e" * 64
# Planted where a value would leak: none may appear in an error, a printout, a reason or an evidence line.
HIDDEN = "zq-hidden"


def example() -> dict:
    data, _ = vo.load_overlay_file(EXAMPLE_V2)
    data["salt"] = TEST_SALT
    return data


def exception(**fields) -> dict:
    entry = {"id": "exception-hotfix", "rule": "protected-branches", "allows": ["hotfix/urgent"],
             "approver_role": "Release manager", "expires_on": dt.date(2027, 1, 1)}
    entry.update(fields)
    return entry


class ExceptionCase(unittest.TestCase):
    def setUp(self):
        self.data = example()

    def mutated(self, mutate) -> dict:
        data = copy.deepcopy(self.data)
        mutate(data)
        return data

    def with_exceptions(self, *entries) -> dict:
        return self.mutated(lambda d: d["enforcement"].update(exceptions=list(entries)))

    def errors(self, data) -> list:
        _, errors = vo.validate_overlay(data, today=TODAY)
        return errors

    def assertRejects(self, data, fragment="") -> str:
        with self.assertRaises(vo.OverlayError) as caught:
            vo.validate_structure(data)
        message = str(caught.exception)
        self.assertIn(fragment, message)
        return message


# ----------------------------------------------------------------- validation


class ValidationTests(ExceptionCase):
    def test_the_example_s_exception_passes(self):
        self.assertEqual(self.errors(self.data), [])
        overlay = vo.validate_structure(self.data)
        self.assertEqual(overlay["enforcement"]["exceptions"], [{
            "id": "exception-analytics-preview", "rule": "deploy-hosts", "allows": ["preview.analytics.example.org"],
            "approver_role": "Platform security lead", "expires_on": dt.date(2027, 2, 1)}])

    def test_accepted_shapes(self):
        cases = {
            "a branch prefix": exception(allows=["hotfix/*", "main"]),
            "a wildcard host": exception(id="exception-hosts", rule="deploy-hosts", allows=["*.preview.example.net"]),
            "where": exception(where={"repositories": ["example-org/web", "Example-Org/api.v2", "o/r_1-x.y"]}),
            "the file's own expiry": exception(expires_on=dt.date(2027, 5, 17)),
            "a date string": exception(expires_on="2027-01-01"),
            "100 values": exception(id="exception-many", rule="deploy-hosts", allows=[f"h{n}.example.net" for n in range(100)]),
            "an 80-character role": exception(approver_role="r" * 80),
        }
        for label, entry in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.errors(self.with_exceptions(entry)), [])
        fifty = [exception(id=f"exception-{n}") for n in range(50)]
        self.assertEqual(self.errors(self.with_exceptions(*fifty)), [])

    def test_rejected_shapes_name_positions_never_values(self):
        hidden_host = HIDDEN + ".example.net"
        cases = {
            "not a list": (lambda d: d["enforcement"].update(exceptions={"id": HIDDEN}), "enforcement.exceptions: expected a list of 1 to 50"),
            "51 exceptions": (lambda d: d["enforcement"].update(exceptions=[exception(id=f"exception-{n}") for n in range(51)]), "1 to 50"),
            "not an object": (lambda d: d["enforcement"].update(exceptions=[HIDDEN]), "enforcement.exceptions[0]: expected an object"),
            "a missing field": (lambda d: d["enforcement"].update(exceptions=[{k: v for k, v in exception().items() if k != "approver_role"}]),
                                "enforcement.exceptions[0]: missing fields ['approver_role']"),
            "an unknown field": (lambda d: d["enforcement"].update(exceptions=[exception(**{hidden_host: 1, "reason": "x"})]),
                                 "enforcement.exceptions[0]: 2 unknown fields; an exception has id, rule, allows"),
            "an unknown rule": (lambda d: d["enforcement"].update(exceptions=[exception(rule=HIDDEN + "-rule")]),
                                "enforcement.exceptions[0].rule: expected the id of a rule in enforcement.rules"),
            "an item id as the rule": (lambda d: d["enforcement"].update(exceptions=[exception(rule="hosting-app-platform")]),
                                       "enforcement.exceptions[0].rule: expected the id of a rule"),
            "a rule that is not a string": (lambda d: d["enforcement"].update(exceptions=[exception(rule=["protected-branches"])]),
                                            "enforcement.exceptions[0].rule: expected the id of a rule"),
            "no values": (lambda d: d["enforcement"].update(exceptions=[exception(allows=[])]), "enforcement.exceptions[0].allows: expected a list of 1 to 100"),
            "101 values": (lambda d: d["enforcement"].update(exceptions=[exception(rule="deploy-hosts", allows=[f"h{n}.example.net" for n in range(101)])]),
                           "1 to 100"),
            "values not a list": (lambda d: d["enforcement"].update(exceptions=[exception(allows=hidden_host)]), "expected a list of 1 to 100"),
            "a value not a string": (lambda d: d["enforcement"].update(exceptions=[exception(allows=[1])]), "allows[0]: expected a quoted string"),
            "a host for a branch rule": (lambda d: d["enforcement"].update(exceptions=[exception(allows=["main", HIDDEN + "..x"])]),
                                         "enforcement.exceptions[0].allows[1]: expected a Git branch name"),
            "a branch for a host rule": (lambda d: d["enforcement"].update(exceptions=[exception(rule="deploy-hosts", allows=[HIDDEN + "-branch"])]),
                                         "enforcement.exceptions[0].allows[0]: expected a lowercase host name"),
            "a URL for a host rule": (lambda d: d["enforcement"].update(exceptions=[exception(rule="deploy-hosts", allows=["https://" + hidden_host])]),
                                      "; an exception allows values of its rule's kind, here deploy_host"),
            "an IP address": (lambda d: d["enforcement"].update(exceptions=[exception(rule="deploy-hosts", allows=["10.20.30.40"])]),
                              "allows[0]: expected a lowercase host name"),
            "a duplicate value": (lambda d: d["enforcement"].update(exceptions=[exception(rule="deploy-hosts", allows=[hidden_host, hidden_host])]),
                                  "allows[1]: duplicates an earlier value of this exception"),
            "a duplicate branch": (lambda d: d["enforcement"].update(exceptions=[exception(allows=[HIDDEN, HIDDEN])]),
                                   "allows[1]: duplicates an earlier value of this exception"),
            # The hook matches branches ignoring case, so these are the same branch (review of #134).
            "a duplicate branch in another case": (lambda d: d["enforcement"].update(exceptions=[exception(allows=["main", "MAIN"])]),
                                                   "allows[1]: duplicates an earlier value of this exception"),
            "an empty role": (lambda d: d["enforcement"].update(exceptions=[exception(approver_role=" ")]), "approver_role: expected a nonempty phrase"),
            "an email as the role": (lambda d: d["enforcement"].update(exceptions=[exception(approver_role=HIDDEN + "@example.org")]),
                                     "approver_role: expected a role, such as a job title, not an email address"),
            "a URL as the role": (lambda d: d["enforcement"].update(exceptions=[exception(approver_role="https://" + hidden_host + "/lead")]),
                                  "approver_role: expected a role, such as a job title, not a URL"),
            "an 81-character role": (lambda d: d["enforcement"].update(exceptions=[exception(approver_role="r" * 81)]), "longer than 80 characters"),
            "a control character in the role": (lambda d: d["enforcement"].update(exceptions=[exception(approver_role="Lead\u2028" + HIDDEN)]),
                                                "control characters are not allowed"),
            "an expiry after the file's": (lambda d: d["enforcement"].update(exceptions=[exception(expires_on=dt.date(2027, 5, 18))]),
                                           "enforcement.exceptions[0].expires_on: after the file's expires_on; an exception never outlives the file"),
            "a datetime": (lambda d: d["enforcement"].update(exceptions=[exception(expires_on=dt.datetime(2027, 1, 1, 9, 0))]), "not a datetime"),
            "not a date": (lambda d: d["enforcement"].update(exceptions=[exception(expires_on="soon")]), "expected a date"),
            "no expiry": (lambda d: d["enforcement"].update(exceptions=[{k: v for k, v in exception().items() if k != "expires_on"}]),
                          "missing fields ['expires_on']"),
            "where not an object": (lambda d: d["enforcement"].update(exceptions=[exception(where=["example-org/web"])]),
                                    "enforcement.exceptions[0].where: expected an object with repositories and nothing else"),
            "where with another key": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": ["o/r"], "branches": ["main"]})]),
                                       "expected an object with repositories and nothing else"),
            "where without repositories": (lambda d: d["enforcement"].update(exceptions=[exception(where={})]), "expected an object with repositories"),
            "no repositories": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": []})]),
                                "where.repositories: expected a list of 1 to 100"),
            "a repository without an owner": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": [HIDDEN]})]),
                                              "where.repositories[0]: expected a repository as owner/name"),
            "a nested path": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": ["o/" + HIDDEN + "/x"]})]),
                              "where.repositories[0]: expected a repository as owner/name"),
            "a URL as a repository": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": ["https://github.com/o/r"]})]),
                                      "expected a repository as owner/name"),
            "a dot as the name": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": ["o/.."]})]),
                                  "expected a repository as owner/name"),
            "a duplicate repository": (lambda d: d["enforcement"].update(exceptions=[exception(where={"repositories": ["o/" + HIDDEN, "O/" + HIDDEN.upper()]})]),
                                       "where.repositories[1]: duplicates an earlier repository (case is ignored)"),
        }
        for label, (mutate, fragment) in cases.items():
            with self.subTest(case=label):
                message = self.assertRejects(self.mutated(mutate), fragment)
                self.assertNotIn(HIDDEN, message.lower())
                self.assertNotIn("10.20.30.40", message)
                self.assertNotIn("hotfix", message)

    def test_ids_are_unique_with_every_other_id(self):
        cases = {
            "a rule id": (exception(id="deploy-hosts"), "already used at enforcement.rules[1].id"),
            "an item id": (exception(id="hosting-app-platform"), "already used at hosting.approved[0].id"),
            "an alias": (exception(id="data-government-identifiers"), "already used at data_classes.never_in_prompts[1].aliases[0]"),
            "another exception": (exception(id="exception-analytics-preview"), "already used at enforcement.exceptions[0].id"),
            "bad grammar": (exception(id="Exception_1"), "expected an id of lowercase letters"),
            "65 characters": (exception(id="e" * 65), "at most 64 characters"),
        }
        for label, (entry, fragment) in cases.items():
            with self.subTest(case=label):
                existing = self.data["enforcement"]["exceptions"][0]
                self.assertRejects(self.with_exceptions(existing, entry), f"enforcement.exceptions[1].id: {fragment}" if "already" in fragment else fragment)
        # A template kind may not reuse an exception id either.
        self.assertRejects(self.mutated(lambda d: d.update(templates=[{"kind": "exception-analytics-preview"}])), "already used at templates[0].kind")

    def test_rule_7_covers_an_exception_s_hosts(self):
        for label, mutate in {
            "phrase": lambda d: d["hosting"]["approved"][1].update(text="Previews on preview.analytics.example.org"),
            "id": lambda d: d["hosting"]["approved"][1].update(id="hosting-preview-analytics-example-org"),
            "owner": lambda d: d.update(owner="ops@preview.analytics.example.org"),
        }.items():
            with self.subTest(case=label):
                errors = [e for e in self.errors(self.mutated(mutate)) if "enforcement exception 'exception-analytics-preview'" in e]
                self.assertTrue(errors, label)
                for error in errors:
                    self.assertNotIn("preview.analytics", error)
        # Enforcement ids too: a rule id is in deny reasons, and both are in evidence (review of #134).
        data = self.mutated(lambda d: d["enforcement"]["exceptions"][0].update(id="exception-preview-analytics-example-org"))
        self.assertIn("enforcement.exceptions[0].id: names a value of enforcement.exceptions[0]; "
                      "enforcement values never appear in model-facing text", self.errors(data))
        for error in self.errors(data):
            self.assertNotIn("example-org", error)  # the id is the offending text: never repeated
        # Nor in an error elsewhere in the file about the same exception's value.
        both = self.mutated(lambda d: (d["enforcement"]["exceptions"][0].update(id="exception-preview-analytics-example-org"),
                                       d.update(owner="ops@preview.analytics.example.org")))
        errors = self.errors(both)
        self.assertIn("overlay.owner: names a value of enforcement.exceptions[0]; enforcement values never appear in model-facing text", errors)
        for error in errors:
            self.assertNotIn("example-org", error)
        # An id holding another source's value is named by position too (review of #134).
        crossed = self.mutated(lambda d: (d["enforcement"]["exceptions"][0].update(id="exception-apps-example-org"),
                                          d.update(owner="ops@preview.analytics.example.org")))
        for error in self.errors(crossed):
            self.assertNotIn("apps-example-org", error)
        rules = self.data["enforcement"]["rules"]
        index = next(i for i, r in enumerate(rules) if r["kind"] == "deploy_host")
        value = next(v for v in rules[index]["values"] if not v.startswith("*."))
        renamed = "deploy-" + value.replace(".", "-")

        def rename(d):
            d["enforcement"]["rules"][index]["id"] = renamed
            for exc in d["enforcement"]["exceptions"]:
                if exc["rule"] == "deploy-hosts":
                    exc["rule"] = renamed
        errors = self.errors(self.mutated(rename))
        self.assertIn("enforcement.rules[%d].id: names a value of enforcement.rules[%d]; enforcement values never appear in "
                      "model-facing text" % (index, index), errors)
        for error in errors:
            self.assertNotIn(renamed, error)
        # A branch exception's values are ordinary words, as a protected_branch rule's are: no rule 7 error.
        data = self.with_exceptions(exception(allows=["external"]))
        self.assertEqual(self.errors(data), [])

    def test_rule_branch_values_are_deduplicated_ignoring_case(self):
        rules = self.data["enforcement"]["rules"]
        index = next(i for i, r in enumerate(rules) if r["kind"] == "protected_branch")
        data = self.mutated(lambda d: d["enforcement"]["rules"][index]["values"].append(d["enforcement"]["rules"][index]["values"][0].upper()))
        self.assertRejects(data, "values[%d]: duplicates an earlier value of this rule" % len(rules[index]["values"]))

    def test_the_secret_scan_covers_exceptions(self):
        data = self.with_exceptions(exception(approver_role="token=abcdef123456"), exception(id="exception-key", allows=["AKIAIOSFODNN7EXAMPLE"]))
        errors = self.errors(data)
        self.assertIn("overlay.enforcement.exceptions[0].approver_role: looks like a secret; overlays never contain credentials", errors)
        self.assertIn("overlay.enforcement.exceptions[1].allows[0]: looks like a secret; overlays never contain credentials", errors)

    def test_no_view_a_model_reads_carries_an_exception(self):
        overlay = vo.validate_structure(self.with_exceptions(exception(id="exception-" + HIDDEN, approver_role=HIDDEN + " lead",
                                                                       where={"repositories": ["o/" + HIDDEN]})))
        for view in (vo.model_facing(overlay), vo.v1_projection(overlay)):
            self.assertNotIn(HIDDEN, repr(view))
            self.assertNotIn("exceptions", repr(view))

    def test_version_1_has_no_exceptions(self):
        v1, _ = vo.load_overlay_file(SPEC / "overlay.example.yaml")
        self.assertRejects(dict(v1, enforcement=self.data["enforcement"]), "unknown fields ['enforcement']")


@unittest.skipUnless(jsonschema, "jsonschema is not installed; pip install --require-hashes -r requirements-dev.txt")
class SchemaTests(ExceptionCase):
    @classmethod
    def setUpClass(cls):
        schema = json.loads((SPEC / "overlay.v2.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        cls.schema = schema
        cls.validator = jsonschema.Draft202012Validator(schema)

    def schema_errors(self, data) -> list:
        return list(self.validator.iter_errors(json.loads(json.dumps(data, default=str))))

    def test_accepted_shapes_agree(self):
        for data in (self.data, self.with_exceptions(exception(where={"repositories": ["example-org/web"]}), exception(id="exception-2", allows=["hotfix/*"]))):
            self.assertEqual(self.schema_errors(data), [])
            vo.validate_structure(data)

    def test_rejected_shapes_agree(self):
        cases = {
            "an empty list": [],
            "not an object": ["x"],
            "a missing role": [{k: v for k, v in exception().items() if k != "approver_role"}],
            "an unknown field": [exception(reason="x")],
            "no values": [exception(allows=[])],
            "an email as the role": [exception(approver_role="lead@example.org")],
            "a URL as the role": [exception(approver_role="see https://wiki.example.org")],
            "an 81-character role": [exception(approver_role="r" * 81)],
            "a bad id": [exception(id="Bad Id")],
            "where with another key": [exception(where={"repositories": ["o/r"], "x": 1})],
            "no repositories": [exception(where={"repositories": []})],
            "a bad repository": [exception(where={"repositories": ["no-owner"]})],
            "a dot as the name": [exception(where={"repositories": ["o/."]})],
        }
        for label, entries in cases.items():
            data = self.mutated(lambda d: d["enforcement"].update(exceptions=entries))
            with self.subTest(case=label):
                self.assertTrue(self.schema_errors(data))
                with self.assertRaises(vo.OverlayError):
                    vo.validate_structure(data)

    def test_the_repository_pattern_agrees_with_the_validator(self):
        import re

        pattern = re.compile(self.schema["$defs"]["repository"]["pattern"])
        for value in ("o/r", "example-org/web.app", "A_b/c-d", "o/...", "o/.", "o/..", "-o/r", "o/r/x", "o", "/r", "o/", "o/r s"):
            with self.subTest(value=value):
                self.assertEqual(bool(pattern.search(value)), bool(vo.REPOSITORY_RE.fullmatch(value)))
        self.assertEqual(self.schema["properties"]["enforcement"]["properties"]["exceptions"]["maxItems"], vo.EXCEPTIONS_MAX)
        self.assertEqual(self.schema["$defs"]["exception"]["properties"]["approver_role"]["maxLength"], vo.APPROVER_ROLE_MAX)
        self.assertEqual(sorted(self.schema["$defs"]["exception"]["properties"]), sorted(vo.EXCEPTION_FIELDS))


# ----------------------------------------------------------------- compile and the policy


class CompileTests(ExceptionCase):
    def compiled(self, data=None) -> tuple:
        raw = b"rules file bytes"
        overlay = vo.validate_structure(data or self.data)
        policy = vo.compile_policy(overlay, raw)
        return policy, vo.policy_text(policy)

    def test_compile_carries_the_exceptions_and_the_hook_reads_them_back(self):
        policy, text = self.compiled()
        self.assertEqual(policy["exceptions"], [{"id": "exception-analytics-preview", "rule": "deploy-hosts",
                                                 "allows": ["preview.analytics.example.org"], "expires_on": "2027-02-01"}])
        self.assertNotIn("Platform security lead", text)  # approver_role stays in the rules file
        vo.check_hook_reads(text)
        parsed = pol.parse(text.encode("utf-8"))
        self.assertEqual(parsed.exceptions, (pol.RuleException("exception-analytics-preview", "deploy-hosts",
                                                               ("preview.analytics.example.org",), dt.date(2027, 2, 1), None),))

    def test_where_is_copied_for_the_pull_request_check(self):
        data = self.with_exceptions(exception(where={"repositories": ["example-org/web", "example-org/api"]}))
        policy, text = self.compiled(data)
        self.assertEqual(policy["exceptions"][0]["where"], {"repositories": ["example-org/web", "example-org/api"]})
        self.assertEqual(pol.parse(text.encode()).exceptions[0].repositories, ("example-org/web", "example-org/api"))

    def test_compile_is_deterministic(self):
        data = self.with_exceptions(exception(), exception(id="exception-b", rule="deploy-hosts", allows=["b.example.net", "a.example.net"]))
        _, first = self.compiled(data)
        _, second = self.compiled(copy.deepcopy(data))
        self.assertEqual(first, second)
        self.assertEqual([e["id"] for e in json.loads(first)["exceptions"]], ["exception-hotfix", "exception-b"])  # file order

    def test_a_file_without_exceptions_compiles_as_before(self):
        policy, _ = self.compiled(self.mutated(lambda d: d["enforcement"].pop("exceptions")))
        self.assertEqual(set(policy), {"format", "format_version", "source_sha256", "expires_on", "rules"})
        self.assertEqual(policy["format_version"], 1)

    def test_the_printout_names_exceptions_never_values(self):
        data = self.with_exceptions(
            exception(id="exception-current", allows=[HIDDEN + "/*"]),
            exception(id="exception-old", allows=["hotfix/old"], expires_on=dt.date(2026, 11, 1)),
            exception(id="exception-scoped", allows=["hotfix/x"], where={"repositories": ["o/" + HIDDEN]}),
        )
        policy, _ = self.compiled(data)
        lines = vo.effective_modes(policy, today=TODAY)
        self.assertIn("exception | rule | expires_on | hooks", lines)
        self.assertIn("exception-current | protected-branches | 2027-01-01 | applied until it expires", lines)
        self.assertIn("exception-old | protected-branches | 2026-11-01 | expired: ignored, the rule applies as written", lines)
        self.assertIn("exception-scoped | protected-branches | 2027-01-01 | not applied: it has where, which only the pull-request check reads", lines)
        self.assertNotIn(HIDDEN, "\n".join(lines))
        no_exceptions, _ = self.compiled(self.mutated(lambda d: d["enforcement"].pop("exceptions")))
        self.assertFalse(any(line.startswith("exception") for line in vo.effective_modes(no_exceptions, today=TODAY)))

    def test_the_cli_prints_exceptions_and_no_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yaml"
            rules.write_text(EXAMPLE_V2.read_text(encoding="utf-8").replace(vo.EXAMPLE_SALT, TEST_SALT), encoding="utf-8")
            out_file = Path(tmp) / "policy.json"
            out, err = io.StringIO(), io.StringIO()
            real = vo.validate_expiry
            with mock.patch.object(vo, "validate_expiry", lambda overlay, today=None: real(overlay, TODAY)), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = vo.main(["compile", str(rules), "--out", str(out_file)])
            self.assertEqual(code, 0, err.getvalue())
            self.assertIn("exception-analytics-preview | deploy-hosts | 2027-02-01 |", out.getvalue())
            self.assertIn("compiled 2 enforcement rules and 1 exception", err.getvalue())
            self.assertEqual(pol.parse(out_file.read_bytes()).exceptions[0].id, "exception-analytics-preview")
            for value in ("preview.analytics", "Platform security lead", "apps.example.org", "hotfix/*"):
                self.assertNotIn(value, out.getvalue() + err.getvalue())


def policy_dict(rules=None, exceptions=None, expires="2099-01-01") -> dict:
    data = {
        "format": "catpilot-company-policy", "format_version": 1, "source_sha256": SHA, "expires_on": expires,
        "rules": rules if rules is not None else [
            {"id": "protected-branches", "kind": "protected_branch", "mode": "block", "values": ["main", "release/*"]},
            {"id": "deploy-hosts", "kind": "deploy_host", "mode": "block", "values": ["apps.example.org", "*.apps.example.org"]},
        ],
    }
    if exceptions is not None:
        data["exceptions"] = exceptions
    return data


def policy_exception(**fields) -> dict:
    entry = {"id": "exception-release", "rule": "protected-branches", "allows": ["release/2026.11"], "expires_on": "2027-01-01"}
    entry.update(fields)
    return entry


def parsed(exceptions=None, rules=None, expires="2099-01-01") -> pol.Policy:
    return pol.parse(json.dumps(policy_dict(rules, exceptions, expires)).encode())


class PolicyParseTests(unittest.TestCase):
    def test_a_policy_with_exceptions_parses(self):
        policy = parsed([policy_exception(), policy_exception(id="exception-web", rule="deploy-hosts", allows=["web.example.net"],
                                                              where={"repositories": ["o/r"]})])
        self.assertEqual([(e.id, e.rule, e.allows, e.expires_on, e.repositories) for e in policy.exceptions], [
            ("exception-release", "protected-branches", ("release/2026.11",), dt.date(2027, 1, 1), None),
            ("exception-web", "deploy-hosts", ("web.example.net",), dt.date(2027, 1, 1), ("o/r",)),
        ])
        self.assertEqual(parsed().exceptions, ())

    def test_malformed_exceptions_are_refused(self):
        cases = {
            "an empty list": [],
            "not a list": {"id": "x"},
            "51 exceptions": [policy_exception(id=f"exception-{n}") for n in range(51)],
            "not an object": ["exception-release"],
            "an unknown key": [policy_exception(approver_role="Release manager")],
            "a missing key": [{k: v for k, v in policy_exception().items() if k != "allows"}],
            "a bad id": [policy_exception(id="Bad_Id")],
            "a rule id as its id": [policy_exception(id="deploy-hosts")],
            "a repeated id": [policy_exception(), policy_exception()],
            "an unknown rule": [policy_exception(rule="other-rule")],
            "no values": [policy_exception(allows=[])],
            "a value with a newline": [policy_exception(allows=["release/\nx"])],
            "a value not a string": [policy_exception(allows=[3])],
            "an expiry after the policy's": [policy_exception(expires_on="2099-01-02")],
            "an impossible date": [policy_exception(expires_on="2027-02-30")],
            "where with another key": [policy_exception(where={"repositories": ["o/r"], "x": 1})],
            "no repositories": [policy_exception(where={"repositories": []})],
            "where not an object": [policy_exception(where=["o/r"])],
        }
        for label, exceptions in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(pol.PolicyError) as caught:
                    pol.parse(json.dumps(policy_dict(exceptions=exceptions)).encode())
                self.assertEqual(caught.exception.args, ("malformed",))

    def test_which_exceptions_a_hook_applies(self):
        policy = parsed([
            policy_exception(id="exception-current", expires_on="2026-11-17"),
            policy_exception(id="exception-old", expires_on="2026-11-16"),
            policy_exception(id="exception-scoped", where={"repositories": ["example-org/web"]}),
            policy_exception(id="exception-other", rule="deploy-hosts", allows=["web.example.net"]),
        ])
        self.assertEqual([e.id for e in policy.active_exceptions("protected-branches", TODAY)], ["exception-current"])  # the expiry day counts
        self.assertEqual([e.id for e in policy.active_exceptions("protected-branches", TODAY + dt.timedelta(days=1))], [])
        self.assertEqual([e.id for e in policy.active_exceptions("deploy-hosts", TODAY)], ["exception-other"])
        # Once the policy itself expires, nothing applies, though compile never writes an exception that outlives it.
        expired = parsed([policy_exception(expires_on="2026-10-01")], expires="2026-11-01")
        self.assertEqual(expired.active_exceptions("protected-branches", dt.date(2026, 9, 1)), expired.exceptions)
        self.assertEqual(expired.active_exceptions("protected-branches", TODAY), ())

    def test_where_is_the_pull_request_check_s_seam(self):
        scoped = parsed([policy_exception(where={"repositories": ["Example-Org/Web"]})]).exceptions[0]
        self.assertFalse(scoped.applies(TODAY))  # the hooks pass no repository
        self.assertTrue(scoped.applies(TODAY, "example-org/web"))
        self.assertFalse(scoped.applies(TODAY, "example-org/api"))
        self.assertFalse(scoped.applies(dt.date(2027, 1, 2), "example-org/web"))

    def test_the_policy_limits_follow_the_validator(self):
        self.assertEqual(pol.EXCEPTIONS_MAX, vo.EXCEPTIONS_MAX)
        self.assertEqual(pol.REPOSITORY_MAX_CHARS, 201)
        self.assertTrue(vo.REPOSITORY_RE.fullmatch("o" * 100 + "/" + "r" * 100))
        self.assertFalse(vo.REPOSITORY_RE.fullmatch("o" * 101 + "/r"))


# ----------------------------------------------------------------- the hook


def bash(command: str, cwd: str | None = None, permission_mode: str = "default") -> dict:
    return {"session_id": "sess-x", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": command},
            "cwd": cwd or tempfile.gettempdir(), "permission_mode": permission_mode}


def effect(result: dict) -> str:
    return result.get("hookSpecificOutput", {}).get("permissionDecision", "none") if result else "none"


class HookDecisionTests(unittest.TestCase):
    def setUp(self):
        self.lines = []
        patcher = mock.patch.object(cr, "record_evidence", lambda event, hook_event=None, host=None, **f: self.lines.append((event, f)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def decide(self, command, exceptions=None, rules=None, host="claude-code", expires="2099-01-01", today=TODAY, ask=False):
        self.lines.clear()
        return effect(cr.decide(bash(command), host, parsed(exceptions, rules, expires), today=today, ask_enabled=ask))

    def events(self):
        return [(e, f["rule_id"], f["mode"], f.get("exception_id")) for e, f in self.lines]

    def test_a_branch_exception_stops_the_rule_protecting_that_branch(self):
        exceptions = [policy_exception()]
        self.assertEqual(self.decide("git push --force origin release/2026.11", exceptions), "none")
        self.assertEqual(self.events(), [("would_deny", "protected-branches", "block", "exception-release")])
        self.assertEqual(self.decide("git push origin --delete release/2026.11", exceptions), "none")
        self.assertEqual(self.decide("git push --force origin release/2026.12", exceptions), "deny")
        self.assertEqual(self.events(), [("deny", "protected-branches", "block", None)])
        self.assertEqual(self.decide("git push --force origin main", exceptions), "deny")

    def test_a_prefix_exception_covers_the_prefix(self):
        exceptions = [policy_exception(allows=["release/*"])]
        for branch in ("release/2026.11", "release/a/b", "RELEASE/x"):
            with self.subTest(branch=branch):
                self.assertEqual(self.decide("git push -f origin %s" % branch, exceptions), "none")
        self.assertEqual(self.decide("git push -f origin main", exceptions), "deny")

    def test_a_bare_force_push_reads_the_checked_out_branch(self):
        with tempfile.TemporaryDirectory() as repo:
            (Path(repo) / ".git").mkdir()
            (Path(repo) / ".git" / "HEAD").write_text("ref: refs/heads/release/2026.11\n")
            result = cr.decide(bash("git push -f", cwd=repo), "claude-code", parsed([policy_exception()]), today=TODAY)
            self.assertEqual(result, {})
            self.assertEqual(self.lines[0][1]["exception_id"], "exception-release")

    def test_every_match_must_be_covered(self):
        self.assertEqual(self.decide("git push --force origin release/2026.11 main", [policy_exception()]), "deny")
        self.assertEqual(self.events(), [("deny", "protected-branches", "block", None)])  # the exception changed nothing
        two = [policy_exception(id="exception-a", allows=["release/a"]), policy_exception(id="exception-b", allows=["release/b"])]
        self.assertEqual(self.decide("git push -f origin release/b release/a", two), "none")
        self.assertEqual(self.events(), [("would_deny", "protected-branches", "block", "exception-a"),
                                         ("would_deny", "protected-branches", "block", "exception-b")])
        # Two exceptions that both cover the one match: the first in policy order is the one recorded.
        both = [policy_exception(id="exception-a", allows=["release/*"]), policy_exception(id="exception-b", allows=["release/b"])]
        self.decide("git push -f origin release/b", both)
        self.assertEqual(self.events(), [("would_deny", "protected-branches", "block", "exception-a")])

    def test_a_push_that_rewrites_every_branch_is_never_excepted(self):
        exceptions = [policy_exception(allows=["main", "release/*"])]
        for command in ("git push --mirror origin", "git push --force --all origin", "git push --force origin 'refs/heads/*:refs/heads/*'"):
            with self.subTest(command=command):
                self.assertEqual(self.decide(command, exceptions), "deny")

    def test_an_expired_exception_is_ignored(self):
        exceptions = [policy_exception(expires_on="2026-11-16")]
        self.assertEqual(self.decide("git push -f origin release/2026.11", exceptions), "deny")
        self.assertEqual(self.decide("git push -f origin release/2026.11", [policy_exception(expires_on="2026-11-17")]), "none")  # its last day

    def test_a_where_exception_is_never_applied_by_the_hook(self):
        exceptions = [policy_exception(where={"repositories": ["example-org/web"]})]
        self.assertEqual(self.decide("git push -f origin release/2026.11", exceptions), "deny")
        self.assertEqual(self.events(), [("deny", "protected-branches", "block", None)])

    def test_an_exception_relaxes_only_its_own_rule(self):
        rules = [{"id": "protected-branches", "kind": "protected_branch", "mode": "block", "values": ["main"]},
                 {"id": "core-branches", "kind": "protected_branch", "mode": "block", "values": ["main"]}]
        result = cr.decide(bash("git push -f origin main"), "claude-code",
                           parsed([policy_exception(allows=["main"])], rules), today=TODAY)
        self.assertEqual(effect(result), "deny")
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("`core-branches`", reason)
        self.assertNotIn("protected-branches", reason)
        self.assertEqual(self.events(), [("would_deny", "protected-branches", "block", "exception-release"),
                                         ("deny", "core-branches", "block", None)])

    def test_an_excepted_rule_decides_nothing_whatever_its_mode(self):
        for mode in ("block", "ask", "monitor"):
            rules = [{"id": "protected-branches", "kind": "protected_branch", "mode": mode, "values": ["main"]}]
            with self.subTest(mode=mode):
                self.assertEqual(self.decide("git push -f origin main", [policy_exception(allows=["main"])], rules, ask=True), "none")
                self.assertEqual(self.events(), [("would_deny", "protected-branches", mode, "exception-release")])

    def test_an_expired_file_applies_no_exception(self):
        self.assertEqual(self.decide("git push -f origin release/2026.11", [policy_exception(expires_on="2026-10-01")], expires="2026-11-01"), "none")
        self.assertEqual(self.events(), [("would_deny", "protected-branches", "monitor", None)])

    def test_a_built_in_deny_is_never_relaxed(self):
        # A company exception allowing main stops the company rule firing on a force push to main; the built-in
        # destructive-operation check is another hook, reads no policy, and still denies it.
        command = "git push --force origin main"
        self.assertEqual(self.decide(command, [policy_exception(allows=["main"])]), "none")
        self.assertEqual(self.events(), [("would_deny", "protected-branches", "block", "exception-release")])
        with mock.patch.object(destructive, "record_evidence", lambda *a, **k: None):
            built_in = destructive.decide(bash(command))
        self.assertEqual(effect(built_in), "deny")

    def test_a_host_exception_adds_approved_hosts(self):
        exceptions = [policy_exception(id="exception-preview", rule="deploy-hosts", allows=["preview.analytics.example.org", "*.vercel.app"])]
        self.assertEqual(self.decide("scp -r dist deploy@preview.analytics.example.org:/srv", exceptions), "none")
        self.assertEqual(self.events(), [("would_deny", "deploy-hosts", "block", "exception-preview")])
        self.assertEqual(self.decide("vercel --prod", exceptions), "none")  # *.vercel.app covers the service's own domain
        self.assertEqual(self.decide("scp -r dist deploy@other.example.net:/srv", exceptions), "deny")
        self.assertEqual(self.decide("rsync -av dist/ $HOST:/srv", exceptions), "deny")  # nothing covers what the hook cannot read
        self.assertEqual(self.decide("scp a preview.analytics.example.org:/srv && netlify deploy --prod", exceptions), "deny")
        self.assertEqual(self.decide("scp a web.apps.example.org:/srv", exceptions), "none")
        self.assertEqual(self.lines, [])  # covered by the rule's own values: no exception was needed

    def test_host_exceptions_expire_and_where_is_ignored(self):
        expired = [policy_exception(id="exception-preview", rule="deploy-hosts", allows=["preview.example.net"], expires_on="2026-11-16")]
        self.assertEqual(self.decide("scp a preview.example.net:/srv", expired), "deny")
        scoped = [policy_exception(id="exception-preview", rule="deploy-hosts", allows=["preview.example.net"], where={"repositories": ["o/r"]})]
        self.assertEqual(self.decide("scp a preview.example.net:/srv", scoped), "deny")

    def test_reasons_and_lines_carry_no_value(self):
        rules = [{"id": "protected-branches", "kind": "protected_branch", "mode": "block", "values": ["main", HIDDEN + "/*"],
                  "use_instead_text": "Internal App Platform (company sign-in)"},
                 {"id": "deploy-hosts", "kind": "deploy_host", "mode": "block", "values": [HIDDEN + "-approved.example.net"]}]
        exceptions = [policy_exception(allows=[HIDDEN + "/fix"]),
                      policy_exception(id="exception-host", rule="deploy-hosts", allows=[HIDDEN + ".example.net"])]
        cases = {"git push -f origin %s/fix && git push -f origin main" % HIDDEN: "deny",
                 "git push -f origin %s/fix" % HIDDEN: "none",
                 "scp a %s.example.net:/srv && vercel" % HIDDEN: "deny",
                 "scp a %s.example.net:/srv" % HIDDEN: "none"}
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.lines.clear()
                result = cr.decide(bash(command), "claude-code", parsed(exceptions, rules), today=TODAY)
                self.assertEqual(effect(result), expected)
                self.assertTrue(self.lines)
                self.assertNotIn(HIDDEN, json.dumps(result) + json.dumps(self.lines))


class HookProcessTests(unittest.TestCase):
    """The shim with the real writer: the line an exception causes is content-free and matches the schema."""

    def test_the_would_deny_line_carries_the_exception_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy_dir = Path(tmp) / "policy"
            policy_dir.mkdir()
            os.chmod(policy_dir, 0o755)
            path = policy_dir / "company-policy.json"
            today = dt.date.today()
            rules = [{"id": "protected-branches", "kind": "protected_branch", "mode": "block", "values": ["main", HIDDEN + "/*"]}]
            path.write_text(json.dumps(policy_dict(rules, [policy_exception(allows=[HIDDEN + "/fix"], expires_on=(today + dt.timedelta(days=5)).isoformat())],
                                                   expires=(today + dt.timedelta(days=30)).isoformat())), encoding="utf-8")
            os.chmod(path, 0o644)
            log = Path(tmp) / "evidence.jsonl"
            env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
            env["CATPILOT_EVIDENCE_LOG"] = str(log)
            proc = subprocess.run([sys.executable, str(HOOK), "--host", "codex", "--policy", str(path)],
                                  input=json.dumps(bash("git push --force origin %s/fix" % HIDDEN)), capture_output=True, text=True,
                                  env=env, timeout=30)
            self.assertEqual((proc.returncode, proc.stdout.strip()), (0, "{}"), proc.stderr)
            (line,) = [json.loads(text) for text in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual({k: line[k] for k in ("event", "hook", "host", "rule_id", "mode", "exception_id", "policy_sha256")},
                             {"event": "would_deny", "hook": "pretooluse-company-rules", "host": "codex", "rule_id": "protected-branches",
                              "mode": "block", "exception_id": "exception-release", "policy_sha256": SHA})
            self.assertNotIn(HIDDEN, log.read_text(encoding="utf-8") + proc.stdout + proc.stderr)
            if jsonschema is not None:
                jsonschema.validate(line, json.loads((SPEC / "evidence-event.schema.json").read_text(encoding="utf-8")))


# ----------------------------------------------------------------- evidence


class EvidenceTests(unittest.TestCase):
    HOOK_FIELDS = {"hook": "pretooluse-company-rules", "tool": "Bash", "rule_id": "deploy-hosts", "mode": "block", "policy_sha256": SHA}

    def test_the_writer_takes_exception_id_only_on_a_hook_s_would_deny_line_with_its_rule(self):
        line = evidence.build_line("would_deny", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="exception-preview"))
        self.assertEqual(line["exception_id"], "exception-preview")
        refused = {
            "on a deny line": ("deny", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="exception-preview")),
            "on an ask line": ("ask", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="exception-preview")),
            "without the rule": ("would_deny", evidence.HOOK_SOURCE, {"hook": "pretooluse-company-rules", "exception_id": "exception-preview"}),
            "from the server": ("would_deny", evidence.SERVER_SOURCE, dict(self.HOOK_FIELDS, exception_id="exception-preview")),
            "free text": ("would_deny", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="preview.analytics.example.org")),
            "capitals": ("would_deny", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="Exception_1")),
            "65 characters": ("would_deny", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="e" * 65)),
        }
        for label, (event, source, fields) in refused.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                evidence.build_line(event, source, fields)

    @unittest.skipUnless(jsonschema, "jsonschema is not installed")
    def test_the_schema_refuses_what_the_writer_refuses(self):
        validator = jsonschema.Draft202012Validator(json.loads((SPEC / "evidence-event.schema.json").read_text(encoding="utf-8")))
        good = evidence.build_line("would_deny", evidence.HOOK_SOURCE, dict(self.HOOK_FIELDS, exception_id="exception-preview"))
        self.assertEqual(list(validator.iter_errors(good)), [])
        for bad in ({"event": "deny"}, {"event": "ask"}, {"rule_id": None}, {"exception_id": "Exception_1"}, {"exception_id": "e" * 65}):
            line = {**good, **bad}
            line = {k: v for k, v in line.items() if v is not None}
            with self.subTest(bad=bad):
                self.assertTrue(list(validator.iter_errors(line)))
        self.assertIn("exception_id", evidence.CHECKED)

    def test_the_summary_counts_exceptions_apart_from_would_deny(self):
        lines = [json.dumps(line) for line in (
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "would_deny", "rule_id": "deploy-hosts", "mode": "monitor", "session_id": "a"},
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "would_deny", "rule_id": "deploy-hosts", "mode": "block",
             "exception_id": "exception-preview", "session_id": "b"},
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "would_deny", "rule_id": "deploy-hosts", "mode": "block",
             "exception_id": "exception-preview", "session_id": "c"},
            {"source": "claude-code-hook", "hook": "pretooluse-company-rules", "event": "deny", "rule_id": "protected-branches", "session_id": "d"},
        )]
        summary = evidence_summary.summarize_lines(lines)
        self.assertEqual(summary["company_rules"]["by_rule"], {
            "deploy-hosts": {"deny": 0, "ask": 0, "would_deny": 1},
            "protected-branches": {"deny": 1, "ask": 0, "would_deny": 0},
        })
        self.assertEqual(summary["company_rules"]["by_exception"], {"exception-preview": {"rule": "deploy-hosts", "count": 2}})
        self.assertEqual(summary["hooks"]["unique_sessions_with_denials"], 1)
        markdown = evidence_summary.render_markdown(summary)
        self.assertIn("| `exception-preview` | `deploy-hosts` | 2 |", markdown)
        self.assertEqual(evidence_summary.summarize_lines([])["company_rules"]["by_exception"], {})


# ----------------------------------------------------------------- lint


class LintTests(ExceptionCase):
    def lint(self, *entries, today=TODAY):
        return vo.lint_overlay(vo.validate_structure(self.with_exceptions(*entries)), today=today)

    def test_an_exception_near_or_past_its_expiry_warns(self):
        expires = dt.date(2027, 1, 1)
        self.assertEqual(self.lint(exception(), today=expires - dt.timedelta(days=15)), [])
        self.assertEqual(self.lint(exception(), today=expires - dt.timedelta(days=14)), [
            "enforcement.exceptions[0] (exception-hotfix): expires on 2027-01-01, within 14 days; after that rule protected-branches applies as written"])
        self.assertEqual(len(self.lint(exception(), today=expires)), 1)  # its last day still applies
        self.assertEqual(self.lint(exception(), today=expires + dt.timedelta(days=1)), [
            "enforcement.exceptions[0] (exception-hotfix): expired on 2027-01-01 and is ignored; rule protected-branches applies as written. "
            "Remove it, or renew it with a reviewer"])

    def test_where_warns_that_no_hook_applies_it(self):
        warnings = self.lint(exception(allows=[HIDDEN + "/*"], where={"repositories": ["o/" + HIDDEN]}))
        self.assertEqual(warnings, ["enforcement.exceptions[0] (exception-hotfix): has where, so no hook applies it; only the pull-request "
                                    "check, which is not built yet, reads where"])
        self.assertNotIn(HIDDEN, "\n".join(warnings))

    def test_the_example_draws_no_exception_warning_on_its_review_date(self):
        self.assertEqual([w for w in vo.lint_overlay(vo.validate_structure(self.data), today=TODAY) if "exceptions" in w], [])

    def test_the_cli_prints_exception_warnings_and_still_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.yaml"
            text = EXAMPLE_V2.read_text(encoding="utf-8").replace(vo.EXAMPLE_SALT, TEST_SALT)
            rules.write_text(text.replace("      expires_on: 2027-02-01", "      expires_on: %s" % (dt.date.today() + dt.timedelta(days=3)).isoformat()),
                             encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            real = vo.validate_expiry
            with mock.patch.object(vo, "validate_expiry", lambda overlay, today=None: real(overlay, TODAY)), \
                    contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = vo.main([str(rules)])
            if dt.date.today() + dt.timedelta(days=3) > dt.date(2027, 5, 17):
                self.skipTest("the example's file expiry has passed; the exception cannot expire after it")
            self.assertEqual(code, 0, err.getvalue())
            self.assertIn("WARNING: enforcement.exceptions[0] (exception-analytics-preview): expires on", err.getvalue())
            self.assertIn("1 expiring exception, which `compile` copies into the policy too.", out.getvalue())
            self.assertNotIn("preview.analytics", out.getvalue() + err.getvalue())


# ----------------------------------------------------------------- verify.sh


def load_helper():
    spec = importlib.util.spec_from_file_location("session_start_files_for_exceptions", ORG / "session_start_files.py")
    helper = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(helper)
    finally:
        sys.dont_write_bytecode = previous
    return helper


class VerifyProbeTests(unittest.TestCase):
    """verify.sh expects exactly the decision the hook gives on its probe, exceptions included."""

    @classmethod
    def setUpClass(cls):
        cls.helper = load_helper()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "company-policy.json"

    def write(self, exceptions=None, rules=None):
        self.path.write_text(json.dumps(policy_dict(rules, exceptions)), encoding="utf-8")
        return parsed(exceptions, rules)

    def assertHonest(self, command, modes, policy):
        expected = self.helper.expected_effect("claude-code", modes, ask_enabled=False)
        with mock.patch.object(cr, "record_evidence", lambda *a, **k: None):
            got = effect(cr.decide(bash(command), "claude-code", policy, today=TODAY))
        self.assertEqual(got, expected, command)
        return expected

    def test_logged_rule_needs_this_rule_policy_and_host(self):
        line = {"event": "would_deny", "hook": "pretooluse-company-rules", "rule_id": "protected-branches", "host": "codex",
                "policy_sha256": "a" * 64}
        check = lambda entries, **kw: self.helper.logged_rule(
            entries, kw.get("rule", "protected-branches"), kw.get("excepted", False), kw.get("expected", "none"),
            kw.get("host", "codex"), kw.get("sha", "a" * 64))
        self.assertTrue(check([line]))
        self.assertTrue(check([dict(line, exception_id="exception-x")], excepted=True))
        self.assertFalse(check([line], excepted=True))  # excepted, but no exception was applied
        self.assertFalse(check([dict(line, exception_id="exception-x")]))  # an exception where none covers
        self.assertFalse(check([line], rule="deploy-hosts"))
        self.assertFalse(check([line], host="claude-code"))
        self.assertFalse(check([line], sha="b" * 64))  # a stale --policy
        self.assertFalse(check([dict(line, hook="pretooluse-destructive-ops")]))
        self.assertFalse(check([dict(line, event="deny")]))  # deciding nothing writes would_deny, never deny
        self.assertTrue(check([dict(line, event="deny")], expected="deny"))
        self.assertTrue(check([line], expected="deny"))  # a monitor rule beside a block rule that denies
        self.assertTrue(self.helper.logged_a_rule([dict(line, event="deny")]))
        self.assertFalse(self.helper.logged_a_rule([{"event": "policy_error", "hook": "pretooluse-company-rules"}]))

    def test_probe_command_points_the_evidence_at_verify_s_log(self):
        log = Path("/tmp/verify log.jsonl")
        hook = 'python3 "/x/pretooluse-company-rules.py" --host codex --policy "/x/p.json"'
        quoted = "CATPILOT_EVIDENCE_LOG='/tmp/verify log.jsonl' "
        cases = {
            'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl" ' + hook: quoted + hook,
            "CATPILOT_EVIDENCE_LOG=/var/log/x.jsonl " + hook: quoted + hook,
            "CATPILOT_EVIDENCE_SYSLOG=1 " + hook: quoted + hook,
            "LANG=C CATPILOT_EVIDENCE_SYSLOG=1 " + hook: quoted + "LANG=C " + hook,
            hook: quoted + hook,
        }
        for command, want in cases.items():
            with self.subTest(command=command):
                self.assertEqual(self.helper.probe_command(command, log), (want, None))
        for command in ("echo '{}' # pretooluse-company-rules.py CATPILOT_EVIDENCE_SYSLOG=1",
                        hook + " CATPILOT_EVIDENCE_LOG=/dev/null", "env CATPILOT_EVIDENCE_LOG=/x " + hook):
            with self.subTest(command=command):
                runnable, problem = self.helper.probe_command(command, log)
                self.assertIsNone(runnable)
                self.assertIn("other than as a leading assignment", problem)

    def test_the_branch_probe_picks_a_branch_no_exception_allows(self):
        cases = {
            "no exceptions": (None, "main", False, "deny"),
            "main excepted": ([policy_exception(allows=["main"])], "release/catpilot-verify", False, "deny"),
            "every branch excepted": ([policy_exception(allows=["main", "release/*"])], "main", True, "none"),
            "a where exception": ([policy_exception(allows=["main"], where={"repositories": ["o/r"]})], "main", False, "deny"),
            "an expired exception": ([policy_exception(allows=["main"], expires_on="2026-11-16")], "main", False, "deny"),
        }
        for label, (exceptions, branch, excepted, expected) in cases.items():
            with self.subTest(case=label):
                policy = self.write(exceptions)
                rule_id, mode, command, expired, modes, was_excepted = self.helper.first_branch_probe(self.path, today=TODAY)
                self.assertEqual((rule_id, mode, expired, was_excepted), ("protected-branches", "block", False, excepted))
                self.assertEqual(command, "git push --force origin %s" % branch)
                self.assertEqual(self.assertHonest(command, modes, policy), expected)

    def test_the_deploy_probe_picks_a_deploy_no_exception_lets_through(self):
        cases = {
            "no exceptions": (None, "netlify deploy --prod"),
            "netlify excepted": ([policy_exception(rule="deploy-hosts", allows=["*.netlify.app"])], "vercel --prod"),
            "a where exception": ([policy_exception(rule="deploy-hosts", allows=["*.netlify.app"], where={"repositories": ["o/r"]})], "netlify deploy --prod"),
        }
        for label, (exceptions, expected_command) in cases.items():
            with self.subTest(case=label):
                policy = self.write(exceptions)
                rule_id, mode, command, expired, modes = self.helper.first_deploy_probe(self.path, today=TODAY)
                self.assertEqual((rule_id, command), ("deploy-hosts", expected_command))
                self.assertEqual(self.assertHonest(command, modes, policy), "deny")
        every = [policy_exception(rule="deploy-hosts", allows=[f"*.{suffix}" for _, suffix in self.helper.DEPLOY_PROBES])]
        self.write(every)
        self.assertIsNone(self.helper.first_deploy_probe(self.path, today=TODAY))


if __name__ == "__main__":
    unittest.main()
