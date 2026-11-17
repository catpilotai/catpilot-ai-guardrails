"""Company rules version 2 (docs/spec/OVERLAY_V2.md): validation, migrate and the JSON Schema. Offline, synthetic only.

One passing and one failing case per rule in the note's §6.3, the §5 examples, and `migrate`.
"""

import contextlib
import copy
import datetime as dt
import io
import json
import re
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from tools import validate_overlay as vo

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "docs" / "spec"
EXAMPLE_V1 = SPEC / "overlay.example.yaml"
EXAMPLE_V2 = SPEC / "overlay.v2.example.yaml"
NOTE = SPEC / "OVERLAY_V2.md"
# The version 2 example's review date, so these tests do not depend on today's date.
TODAY = dt.date(2026, 11, 17)
V1_TODAY = dt.date(2026, 9, 13)


def note_example(heading: str) -> str:
    """The first YAML block after a heading of OVERLAY_V2.md."""
    section = NOTE.read_text(encoding="utf-8").split(heading, 1)[1]
    return re.search(r"```yaml\n(.*?)```", section, re.DOTALL).group(1)


def load(path: Path) -> dict:
    data, _ = vo.load_overlay_file(path)
    return data


def rule(rule_id="extra-rule", kind="deploy_host", values=("deploy.example.net",), **extra) -> dict:
    return {"id": rule_id, "kind": kind, "values": list(values), **extra}


class V2Case(unittest.TestCase):
    def setUp(self):
        self.data = load(EXAMPLE_V2)

    def errors(self, data, hosts=frozenset()):
        _, errors = vo.validate_overlay(data, set(hosts), today=TODAY)
        return errors

    def assertValid(self, data):
        self.assertEqual(self.errors(data), [])

    def assertStructureRejects(self, data, fragment=""):
        with self.assertRaises(vo.OverlayError) as caught:
            vo.validate_structure(data)
        self.assertIn(fragment, str(caught.exception))
        return str(caught.exception)

    def mutated(self, mutate) -> dict:
        data = copy.deepcopy(self.data)
        mutate(data)
        return data


class ExampleTests(V2Case):
    def test_the_v2_example_passes(self):
        self.assertValid(self.data)
        overlay = vo.validate_structure(self.data)
        self.assertEqual(overlay["schema_version"], 2)
        self.assertEqual([r["id"] for r in overlay["enforcement"]["rules"]], ["protected-branches", "deploy-hosts"])

    def test_the_v1_example_still_passes_unchanged(self):
        _, errors = vo.validate_overlay(load(EXAMPLE_V1), today=V1_TODAY)
        self.assertEqual(errors, [])

    def test_the_note_s_complete_example_is_the_shipped_v2_example(self):
        self.assertEqual(yaml.safe_load(note_example("### 5.1")), self.data)

    def test_the_note_s_migrated_example_validates(self):
        data = yaml.safe_load(note_example("### 5.2"))
        _, errors = vo.validate_overlay(data, today=V1_TODAY)
        self.assertEqual(errors, [])

    def test_enforcement_is_optional_and_default_mode_defaults_to_monitor(self):
        self.assertValid(self.mutated(lambda d: d.pop("enforcement")))
        overlay = vo.validate_structure(self.mutated(lambda d: d["enforcement"].pop("default_mode")))
        self.assertEqual(overlay["enforcement"]["default_mode"], "monitor")


class Rule1VersionDispatchTests(V2Case):
    def test_each_version_passes_its_own_rules(self):
        self.assertEqual(vo.validate_structure(self.data)["schema_version"], 2)
        self.assertEqual(vo.validate_structure(load(EXAMPLE_V1))["schema_version"], 1)

    def test_other_versions_and_cross_version_files_are_rejected(self):
        v1 = load(EXAMPLE_V1)
        cases = {
            "version 3": (dict(v1, schema_version=3), "expected 1 or 2"),
            "boolean": (dict(v1, schema_version=True), "expected 1 or 2"),
            "float": (dict(self.data, schema_version=2.0), ""),
            "missing": ({k: v for k, v in v1.items() if k != "schema_version"}, "missing fields ['schema_version']"),
            "v2 content marked 1": (dict(self.data, schema_version=1), "unknown fields ['enforcement']"),
            "v2 items marked 1": (dict(self.mutated(lambda d: d.pop("enforcement")), schema_version=1), "expected a nonempty phrase"),
            "v1 enforcement section": (dict(v1, enforcement=self.data["enforcement"]), "unknown fields ['enforcement']"),
            "v1 content marked 2": (dict(v1, schema_version=2), "plain string is a version 1 item"),
        }
        for label, (data, fragment) in cases.items():
            with self.subTest(case=label):
                self.assertStructureRejects(data, fragment)


class Rule2ItemsTests(V2Case):
    def test_items_are_objects_with_id_and_text_and_optional_aliases(self):
        overlay = vo.validate_structure(self.data)
        self.assertEqual(overlay["identity"]["default"], {"id": "identity-default", "text": "Company sign-in, smallest named group that needs access"})
        self.assertEqual(overlay["hosting"]["approved"][0]["aliases"], ["hosting-internal-app-platform-company-sign-in"])
        self.assertNotIn("aliases", overlay["hosting"]["approved"][1])

    def test_plain_strings_and_malformed_items_are_rejected(self):
        cases = {
            "plain string in a list": lambda d: d["hosting"]["approved"].append("Another platform"),
            "plain identity.default": lambda d: d["identity"].update(default="Company sign-in"),
            "missing text": lambda d: d["services"]["approved"].append({"id": "service-x"}),
            "missing id": lambda d: d["services"]["approved"].append({"text": "Service X"}),
            "extra field": lambda d: d["services"]["approved"][0].update(note="free text"),
            "not an object": lambda d: d["review_triggers"].append(["x"]),
            "empty text": lambda d: d["review_triggers"].append({"id": "trigger-x", "text": " "}),
            "duplicate text": lambda d: d["review_triggers"].append({"id": "trigger-again", "text": "External users"}),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                message = self.assertStructureRejects(self.mutated(mutate))
                if label.startswith("plain"):
                    self.assertIn("plain string is a version 1 item", message)
                    self.assertIn("migrate", message)


class Rule3IdsTests(V2Case):
    def test_ids_and_aliases_pass_at_the_limits(self):
        long_id = "a" * 64
        five = [f"hosting-former-{n}" for n in range(5)]
        self.assertValid(self.mutated(lambda d: d["hosting"]["approved"][1].update(id=long_id, aliases=five)))

    def test_bad_or_repeated_ids_and_aliases_are_rejected(self):
        cases = {
            "uppercase": lambda d: d["hosting"]["approved"][1].update(id="Hosting-power-apps"),
            "double hyphen": lambda d: d["hosting"]["approved"][1].update(id="hosting--power-apps"),
            "trailing hyphen": lambda d: d["hosting"]["approved"][1].update(id="hosting-power-apps-"),
            "65 characters": lambda d: d["hosting"]["approved"][1].update(id="a" * 65),
            "not a string": lambda d: d["hosting"]["approved"][1].update(id=7),
            "same id in two lists": lambda d: d["services"]["approved"][0].update(id="hosting-power-apps"),
            "alias repeats an id": lambda d: d["hosting"]["approved"][1].update(aliases=["data-health-records"]),
            "alias repeats an alias": lambda d: d["hosting"]["approved"][1].update(aliases=["data-government-identifiers"]),
            "alias repeats its own id": lambda d: d["hosting"]["approved"][1].update(aliases=["hosting-power-apps"]),
            "alias grammar": lambda d: d["hosting"]["approved"][1].update(aliases=["Power Apps"]),
            "six aliases": lambda d: d["hosting"]["approved"][1].update(aliases=[f"hosting-old-{n}" for n in range(6)]),
            "rule id repeats an item id": lambda d: d["enforcement"]["rules"].append(rule(rule_id="service-email")),
            "rule id repeats a rule id": lambda d: d["enforcement"]["rules"].append(rule(rule_id="deploy-hosts")),
            "rule id repeats an alias": lambda d: d["enforcement"]["rules"].append(rule(rule_id="data-cardholder-data-and-bank-details")),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                self.assertStructureRejects(self.mutated(mutate))


class Rule4EnforcementTests(V2Case):
    def test_modes_and_rule_counts_pass(self):
        def fifty(d):
            d["enforcement"]["rules"] = [rule(rule_id=f"rule-{n}", mode=vo.MODES[n % 3]) for n in range(50)]
            d["enforcement"]["default_mode"] = "block"
        self.assertValid(self.mutated(fifty))

    def test_bad_modes_counts_and_kinds_are_rejected(self):
        cases = {
            "default_mode": (lambda d: d["enforcement"].update(default_mode="warn"), "monitor, ask, block"),
            "rule mode": (lambda d: d["enforcement"]["rules"][0].update(mode="warn"), "monitor, ask, block"),
            "mode not a string": (lambda d: d["enforcement"]["rules"][0].update(mode=["block"]), "monitor, ask, block"),
            "no rules": (lambda d: d["enforcement"].update(rules=[]), "1 to 50"),
            "51 rules": (lambda d: d["enforcement"].update(rules=[rule(rule_id=f"rule-{n}") for n in range(51)]), "1 to 50"),
            "rules missing": (lambda d: d["enforcement"].pop("rules"), "missing fields ['rules']"),
            "unknown kind": (lambda d: d["enforcement"]["rules"][0].update(kind="open_port"), "expected one of protected_branch, deploy_host"),
            "package_registry before its consumer": (
                lambda d: d["enforcement"]["rules"].append(rule(kind="package_registry", values=["npm.example.org"])), "enters the schema with its first consumer"),
            "cloud_account before its consumer": (
                lambda d: d["enforcement"]["rules"].append(rule(kind="cloud_account", values=["aws:111122223333"])), "enters the schema with its first consumer"),
            "exceptions are the next increment": (lambda d: d["enforcement"].update(exceptions=[]), "unknown fields ['exceptions']"),
            "free text in a rule": (lambda d: d["enforcement"]["rules"][0].update(reason="Because"), "no free text"),
            "not an object": (lambda d: d.update(enforcement=["main"]), "expected an object"),
        }
        for label, (mutate, fragment) in cases.items():
            with self.subTest(case=label):
                self.assertStructureRejects(self.mutated(mutate), fragment)


class Rule5ValuesTests(V2Case):
    GOOD = {
        "protected_branch": ["main", "release/*", "hotfix/*", "feature/x.y", "team/a_b-c"],
        "deploy_host": ["apps.example.org", "*.apps.example.org", "a-b.c-d.example", "xn--bcher-kva.example"],
        "package_registry": ["npm.example.org", "pypi.example.org/simple", "*.registry.example.org/a_b/c-d.e"],
        "cloud_account": ["aws:111122223333", "azure:00000000-0000-0000-0000-000000000000", "gcp:example-org-apps"],
    }
    BAD = {
        "protected_branch": [
            "", "has space", "a..b", "a~1", "a^1", "a:b", "a?", "a[b", "a\\b", "-leading", "*", "rel*",
            "a/*/b", "/*", "/lead", "trail/", "end.", ".hidden", "a/.b", "a.lock", "a.lock/*", "a//b", "a@{b", "@", "HEAD", "tab\tx",
        ],
        "deploy_host": [
            "", "localhost", "*.org", "Apps.example.org", "https://apps.example.org", "apps.example.org:443",
            "apps.example.org/path", "user@apps.example.org", "10.0.0.1", "x.123", "-a.example.org", "a-.example.org",
            "a_b.example.org", "*.*.example.org", "apps..example.org", "apps.example.org.", ("a" * 64) + ".example.org",
        ],
        "package_registry": ["https://npm.example.org", "npm.example.org?x=1", "npm.example.org:443/x", "NPM.example.org", "10.0.0.1/simple", "npm.example.org/a b"],
        "cloud_account": ["aws:1111", "aws:11112222333a", "azure:00000000-0000-0000-0000-00000000000A", "azure:not-a-guid", "gcp:1project", "gcp:short", "gcp:" + "a" * 31, "AWS:111122223333", "oci:abc"],
    }

    def test_each_kind_s_grammar(self):
        # package_registry and cloud_account are checked here too, so the pull request that ships
        # their first consumer only has to accept the kind (§2.2).
        for kind in vo.RULE_KINDS:
            for value in self.GOOD[kind]:
                with self.subTest(kind=kind, value=value):
                    self.assertIsNone(vo.value_problem(kind, value))
            for value in self.BAD[kind]:
                with self.subTest(kind=kind, value=value):
                    problem = vo.value_problem(kind, value)
                    self.assertIsNotNone(problem)
                    if len(value) > 3:  # the message never repeats the value
                        self.assertNotIn(value, problem)

    def test_values_in_a_file_pass(self):
        def add(d):
            d["enforcement"]["rules"].append(rule(rule_id="branches-2", kind="protected_branch", values=self.GOOD["protected_branch"]))
            d["enforcement"]["rules"].append(rule(rule_id="hosts-2", values=self.GOOD["deploy_host"] + [f"h{n}.example.net" for n in range(96)]))
        self.assertValid(self.mutated(add))

    def test_bad_value_lists_are_rejected_without_echoing_the_value(self):
        cases = {
            "bad branch": rule(kind="protected_branch", values=["main", "secret-name..x"]),
            "bad host": rule(values=["https://secret-host.example.net"]),
            "IP address": rule(values=["10.20.30.40"]),
            "no values": rule(values=[]),
            "101 values": rule(values=[f"h{n}.example.net" for n in range(101)]),
            "duplicate": rule(values=["secret-host.example.net", "secret-host.example.net"]),
            "duplicate branch": rule(kind="protected_branch", values=["secret-branch", "secret-branch"]),
            "not a string": rule(kind="protected_branch", values=[1.0]),
            "values not a list": rule(values="secret-host.example.net"),
        }
        for label, bad in cases.items():
            with self.subTest(case=label):
                message = self.assertStructureRejects(self.mutated(lambda d: d["enforcement"]["rules"].append(bad)))
                self.assertNotIn("secret-", message)
                self.assertNotIn("10.20.30.40", message)


class Rule6UseInsteadTests(V2Case):
    def test_an_id_or_alias_of_an_approved_hosting_or_service_item_passes(self):
        for target in ("hosting-app-platform", "hosting-internal-app-platform-company-sign-in", "service-package-mirror"):
            with self.subTest(target=target):
                self.assertValid(self.mutated(lambda d: d["enforcement"]["rules"][1].update(use_instead=target)))

    def test_anything_else_is_rejected(self):
        for target in ("hosting-nowhere", "hosting-personal-cloud", "service-new-software", "data-synthetic", "protected-branches", 3):
            with self.subTest(target=target):
                self.assertStructureRejects(self.mutated(lambda d: d["enforcement"]["rules"][1].update(use_instead=target)), "use_instead")


class Rule7HostsInModelTextTests(V2Case):
    def test_hosts_only_in_enforcement_and_exempt_urls_pass(self):
        def exempt(d):
            d["intake_url"] = "https://apps.example.org/intake"
            d["templates"] = [{"kind": "internal-lookup-tool", "location": "https://apps.example.org/templates/lookup"}]
        _, errors = vo.validate_overlay(self.mutated(exempt), {"apps.example.org"}, today=TODAY)
        self.assertEqual(errors, [])

    def test_a_listed_host_in_any_model_facing_value_is_an_error(self):
        cases = {
            "phrase": lambda d: d["hosting"]["approved"][1].update(text="Power Apps on apps.example.org"),
            "phrase, any case": lambda d: d["services"]["needs_review"][0].update(text="Anything on APPS.Example.ORG"),
            "wildcard host in a phrase": lambda d: d["review_triggers"][0].update(text="External users of x.apps.example.org"),
            "organization": lambda d: d.update(organization="apps.example.org"),
            "owner": lambda d: d.update(owner="ops@apps.example.org"),
            "id": lambda d: d["hosting"]["approved"][1].update(id="hosting-apps-example-org"),
            "alias": lambda d: d["hosting"]["approved"][1].update(aliases=["apps-example-org-old"]),
            "template kind": lambda d: d.update(templates=[{"kind": "apps-example-org"}]),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                errors = self.errors(self.mutated(mutate))
                rule7 = [e for e in errors if "enforcement rule 'deploy-hosts'" in e]
                self.assertTrue(rule7, errors)
                for error in rule7:
                    self.assertNotIn("apps.example.org", error.lower())

    def test_a_branch_name_in_a_phrase_is_not_a_rule_7_error(self):
        # Rule 7 covers the allow-list kinds; protected branch names are ordinary words like "main".
        self.assertValid(self.mutated(lambda d: d["review_triggers"][0].update(text="External users of the main site")))


class Rule8SecretScanTests(V2Case):
    def test_the_example_s_enforcement_passes_the_scan(self):
        self.assertValid(self.data)

    def test_a_secret_in_enforcement_is_an_error(self):
        cases = {
            "AWS key as a branch": rule(kind="protected_branch", values=["AKIAIOSFODNN7EXAMPLE"]),
            "GitHub token as a branch": rule(kind="protected_branch", values=["ghp_" + "a" * 36]),
            "credential assignment as a branch": rule(kind="protected_branch", values=["token=abcdef123456"]),
        }
        for label, bad in cases.items():
            with self.subTest(case=label):
                errors = self.errors(self.mutated(lambda d: d["enforcement"]["rules"].append(bad)))
                self.assertTrue(any(e.startswith("overlay.enforcement.rules[2].values[0]") and "secret" in e for e in errors), errors)


class Rule9LintTests(V2Case):
    def test_monitor_rules_draw_no_warning(self):
        def all_monitor(d):
            d["enforcement"]["rules"][0]["mode"] = "monitor"
        self.assertEqual(vo.lint_overlay(vo.validate_structure(self.mutated(all_monitor))), [])
        self.assertEqual(vo.lint_overlay(vo.validate_structure(load(EXAMPLE_V1))), [])

    def test_ask_and_unverified_block_warn_without_failing_validation(self):
        def modes(d):
            d["enforcement"]["rules"][1]["mode"] = "ask"
        data = self.mutated(modes)
        self.assertValid(data)
        warnings = vo.lint_overlay(vo.validate_structure(data))
        self.assertEqual(len(warnings), 2)
        self.assertIn("(protected-branches): mode block for kind protected_branch", warnings[0])
        self.assertIn("(deploy-hosts): mode ask differs by host", warnings[1])
        self.assertIn("acts as block", warnings[1])
        # default_mode applies to a rule with no mode of its own.
        data = self.mutated(lambda d: d["enforcement"].update(default_mode="ask"))
        self.assertTrue(any("(deploy-hosts): mode ask" in w for w in vo.lint_overlay(vo.validate_structure(data))))

    def test_the_cli_prints_warnings_and_still_passes(self):
        out, err = io.StringIO(), io.StringIO()
        with pin_today(TODAY), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = vo.main([str(EXAMPLE_V2)])
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("WARNING: enforcement.rules[0] (protected-branches)", err.getvalue())
        self.assertIn("OK: overlay for Example Org", out.getvalue())
        self.assertIn("2 enforcement rules: validated only", out.getvalue())
        for value in ("release/*", "hotfix/*", "apps.example.org"):
            self.assertNotIn(value, out.getvalue() + err.getvalue())


class Version1ChecksStillApplyTests(V2Case):
    def test_model_facing_values_get_version_1_s_content_checks(self):
        cases = {
            "url": lambda d: d["hosting"]["approved"][1].update(text="See https://wiki.example.org/hosting"),
            "email": lambda d: d["review_triggers"][0].update(text="Ask alice@example.org"),
            "ip": lambda d: d["hosting"]["approved"][1].update(text="Server 10.1.2.3"),
            "narrative": lambda d: d["review_triggers"][0].update(text="After last year's breach we require review"),
            "secret": lambda d: d["services"]["approved"][0].update(text="api_key=abcdefghijklmnopqrstuvwxyz123456"),
        }
        for label, mutate in cases.items():
            with self.subTest(case=label):
                self.assertTrue(self.errors(self.mutated(mutate)))

    def test_phrase_and_list_limits_and_the_expiry_window(self):
        self.assertStructureRejects(self.mutated(lambda d: d["hosting"]["approved"][1].update(text="x" * 201)), "longer than 200")
        self.assertStructureRejects(
            self.mutated(lambda d: d.update(review_triggers=[{"id": f"trigger-{n}", "text": f"Trigger {n}"} for n in range(31)])), "more than 30")
        _, errors = vo.validate_overlay(self.data, today=dt.date(2027, 6, 1))
        self.assertTrue(any("has passed" in e for e in errors))
        _, errors = vo.validate_overlay(self.data, today=dt.date(2026, 11, 1))
        self.assertTrue(any("in the future" in e for e in errors))

    def test_size_limit_and_symlinks(self):
        with tempfile.TemporaryDirectory() as tmp:
            big = Path(tmp) / "big.yaml"
            big.write_text(EXAMPLE_V2.read_text(encoding="utf-8") + "#" * 131072, encoding="utf-8")
            with self.assertRaises(vo.OverlayError):
                vo.load_overlay_file(big)
            link = Path(tmp) / "link.yaml"
            link.symlink_to(EXAMPLE_V2)
            with self.assertRaises(vo.OverlayError):
                vo.load_overlay_file(link)


def pin_today(day: dt.date):
    real = vo.validate_expiry
    return mock.patch.object(vo, "validate_expiry", lambda overlay, today=None: real(overlay, day))


class DeriveIdTests(unittest.TestCase):
    def test_the_rules_of_section_2_4(self):
        taken = set()
        self.assertEqual(vo.derive_id("hosting", "Internal App Platform (company sign-in)", taken), "hosting-internal-app-platform-company-sign-in")
        self.assertEqual(vo.derive_id("data", "Passwords, keys, tokens, and sign-in codes", taken), "data-passwords-keys-tokens-and-sign-in-codes")
        # Cut at a hyphen to at most 48 characters, the prefix included.
        cut = vo.derive_id("hosting", "The approved cloud subscription managed by IT", taken)
        self.assertEqual(cut, "hosting-the-approved-cloud-subscription-managed")
        self.assertLessEqual(len(cut), 48)
        self.assertEqual(len(vo.derive_id("data", "Customer names and business email addresses", taken)), 48)
        # A repeat gets -2, -3, across lists, and never collides with an id already taken.
        self.assertEqual(vo.derive_id("data", "Health records", taken), "data-health-records")
        self.assertEqual(vo.derive_id("data", "health records!", taken), "data-health-records-2")
        self.assertEqual(vo.derive_id("data", "Health  records", taken), "data-health-records-3")
        taken.add("trigger-x-2")
        self.assertEqual(vo.derive_id("trigger", "X", taken), "trigger-x")
        self.assertEqual(vo.derive_id("trigger", "x", taken), "trigger-x-3")
        # Odd text still gives a valid id.
        self.assertEqual(vo.derive_id("service", "Café ☕ menu", set()), "service-caf-menu")
        self.assertEqual(vo.derive_id("service", "!!!", set()), "service")
        long_word = vo.derive_id("service", "x" * 60, set())
        self.assertEqual(long_word, ("service-" + "x" * 60)[:48])
        for value in taken:
            self.assertTrue(vo.ID_RE.fullmatch(value) and len(value) <= vo.ID_MAX, value)


class MigrateTests(unittest.TestCase):
    def setUp(self):
        self.v1 = load(EXAMPLE_V1)

    def test_the_example_migrates_to_the_note_s_section_5_2_byte_for_byte(self):
        text = vo.migrate_text(self.v1)
        self.assertEqual(text, note_example("### 5.2"))
        migrated = yaml.safe_load(text)
        self.assertEqual(migrated, yaml.safe_load(note_example("### 5.2")))
        # Same content: every phrase, owner, organization and date unchanged; no enforcement.
        self.assertEqual(vo.v1_projection(vo.validate_structure(migrated)), vo.validate_structure(self.v1))
        self.assertNotIn("enforcement", migrated)
        self.assertEqual((migrated["reviewed_on"], migrated["expires_on"]), (self.v1["reviewed_on"], self.v1["expires_on"]))

    def test_round_trip_with_every_optional_field(self):
        v1 = dict(self.v1, intake_url="https://intranet.example.org/intake",
                  templates=[{"kind": "internal-lookup-tool", "location": "https://intranet.example.org/t"}, {"kind": "null"}])
        v1["review_triggers"] = v1["review_triggers"] + ["Writes to a system of record!"]
        text = vo.migrate_text(v1)
        migrated = yaml.safe_load(text)
        overlay, errors = vo.validate_overlay(migrated, {"intranet.example.org"}, today=V1_TODAY)
        self.assertEqual(errors, [])
        self.assertEqual(vo.v1_projection(overlay), vo.validate_structure(v1))
        self.assertEqual(migrated["templates"][1], {"kind": "null"})  # quoted, so it stays a string
        self.assertEqual(migrated["review_triggers"][-1]["id"], "trigger-writes-to-a-system-of-record-2")

    def test_idempotent(self):
        first = vo.migrate_text(self.v1)
        self.assertEqual(vo.migrate_text(copy.deepcopy(self.v1)), first)
        # Migrating what a migrated file projects back to gives the same file again.
        projected = vo.v1_projection(vo.validate_structure(yaml.safe_load(first)))
        self.assertEqual(vo.migrate_text(projected), first)

    def test_a_version_2_file_is_refused_sensibly(self):
        for data in (load(EXAMPLE_V2), yaml.safe_load(vo.migrate_text(self.v1))):
            with self.assertRaises(vo.OverlayError) as caught:
                vo.migrate(data)
            self.assertIn("already version 2", str(caught.exception))
            self.assertIn("nothing to do", str(caught.exception))
        for bad in (dict(self.v1, schema_version=3), ["not", "an", "object"], dict(self.v1, owner="")):
            with self.subTest(bad=type(bad).__name__), self.assertRaises(vo.OverlayError):
                vo.migrate(bad)

    def test_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "rules.v2.yaml"
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                self.assertEqual(vo.main(["migrate", str(EXAMPLE_V1)]), 0)
            self.assertEqual(out.getvalue(), note_example("### 5.2"))
            self.assertIn("no enforcement section was added", err.getvalue())
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(vo.main(["migrate", str(EXAMPLE_V1), "--output", str(target)]), 0)
            self.assertEqual(target.read_text(encoding="utf-8"), note_example("### 5.2"))
            with pin_today(V1_TODAY), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(vo.main([str(target)]), 0)
            # Never overwrites, and a version 2 input is refused with nothing written.
            target.write_text("kept\n", encoding="utf-8")
            for argv in (["migrate", str(EXAMPLE_V1), "--output", str(target)], ["migrate", str(EXAMPLE_V2)]):
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(argv=argv[1:]), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    self.assertEqual(vo.main(argv), 1)
                self.assertEqual(out.getvalue(), "")
                self.assertIn("REFUSED", err.getvalue())
            self.assertEqual(target.read_text(encoding="utf-8"), "kept\n")


try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


def as_json(data: dict) -> dict:
    return json.loads(json.dumps(data, default=str))


@unittest.skipUnless(jsonschema, "jsonschema is not installed; pip install --require-hashes -r requirements-dev.txt")
class JsonSchemaTests(unittest.TestCase):
    """The schema files agree with the validator on these cases. The validator is the reference:
    cross-field rules (uniqueness, use_instead, rule 7, the scans) are the validator's only."""

    @classmethod
    def setUpClass(cls):
        cls.v1 = jsonschema.Draft202012Validator(json.loads((SPEC / "overlay.schema.json").read_text(encoding="utf-8")))
        schema = json.loads((SPEC / "overlay.v2.schema.json").read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        cls.schema = schema
        cls.v2 = jsonschema.Draft202012Validator(schema)

    def test_each_example_matches_its_own_version_s_schema_only(self):
        v1, v2 = as_json(load(EXAMPLE_V1)), as_json(load(EXAMPLE_V2))
        self.assertEqual(list(self.v1.iter_errors(v1)), [])
        self.assertEqual(list(self.v2.iter_errors(v2)), [])
        self.assertEqual(list(self.v2.iter_errors(as_json(yaml.safe_load(note_example("### 5.2"))))), [])
        self.assertTrue(list(self.v2.iter_errors(v1)))
        self.assertTrue(list(self.v1.iter_errors(v2)))

    def test_the_v2_schema_rejects_what_the_validator_rejects_structurally(self):
        base = load(EXAMPLE_V2)
        cases = {
            "plain string": lambda d: d["hosting"]["approved"].append("Another platform"),
            "bad id": lambda d: d["hosting"]["approved"][1].update(id="Bad Id"),
            "six aliases": lambda d: d["hosting"]["approved"][1].update(aliases=[f"a-{n}" for n in range(6)]),
            "bad mode": lambda d: d["enforcement"]["rules"][0].update(mode="warn"),
            "kind not yet accepted": lambda d: d["enforcement"]["rules"].append(rule(kind="cloud_account", values=["aws:111122223333"])),
            "bad branch": lambda d: d["enforcement"]["rules"][0].update(values=["a..b"]),
            "bad host": lambda d: d["enforcement"]["rules"][1].update(values=["https://apps.example.org"]),
            "no rules": lambda d: d["enforcement"].update(rules=[]),
            "free text": lambda d: d["enforcement"]["rules"][0].update(reason="x"),
        }
        for label, mutate in cases.items():
            data = copy.deepcopy(base)
            mutate(data)
            with self.subTest(case=label):
                self.assertTrue(list(self.v2.iter_errors(as_json(data))))
                with self.assertRaises(vo.OverlayError):
                    vo.validate_structure(data)

    def test_value_patterns_agree_with_the_validator(self):
        patterns = {"protected_branch": self.schema["$defs"]["branch"]["pattern"], "deploy_host": self.schema["$defs"]["host"]["pattern"]}
        for kind, pattern in patterns.items():
            compiled = re.compile(pattern)
            for value in Rule5ValuesTests.GOOD[kind] + Rule5ValuesTests.BAD[kind]:
                with self.subTest(kind=kind, value=value):
                    self.assertEqual(bool(compiled.search(value)), vo.value_problem(kind, value) is None)
        self.assertEqual(self.schema["$defs"]["rule"]["properties"]["kind"]["enum"], list(vo.ACCEPTED_KINDS))
        self.assertEqual(self.schema["$defs"]["mode"]["enum"], list(vo.MODES))


if __name__ == "__main__":
    unittest.main()
