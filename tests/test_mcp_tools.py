"""The reference MCP server's tools as pure functions. No SDK, no network, no model."""

import datetime as dt
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

from catpilot_guardrails_mcp import content, policy  # noqa: E402
from catpilot_guardrails_mcp import tools as mcp_tools  # noqa: E402

EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
TODAY = dt.date(2026, 9, 14)


def _load_example_with_template(allowed_hosts: set) -> policy.PolicyState:
    """Load a temporary copy of the shipped example with a template appended.

    The shipped example (EXAMPLE) has no templates entry: a template's host must
    be allowlisted, and the example is meant to load as approved with no extra
    configuration (see test_shipped_example_loads_as_approved_with_no_extra_host_configuration
    below). This helper builds a temporary copy with a template added, for tests
    that need one, such as get_template's approved_starting_point path.
    """
    with tempfile.TemporaryDirectory() as tmp:
        overlay_path = Path(tmp) / "overlay.yaml"
        text = EXAMPLE.read_text() + (
            '\ntemplates:\n  - kind: internal-lookup-tool\n    location: "https://intranet.example.org/templates/lookup"\n'
        )
        overlay_path.write_text(text)
        return policy.load_policy(str(overlay_path), allowed_hosts, now=TODAY)


class Fixtures:
    guidance = content.load_guidance()
    templates = content.load_templates()
    none = policy.load_policy(None)
    approved = policy.load_policy(str(EXAMPLE), {"intranet.example.org"}, now=TODAY)
    approved_with_template = _load_example_with_template({"intranet.example.org"})
    expired = policy.load_policy(str(EXAMPLE), {"intranet.example.org"}, now=dt.date(2027, 6, 1))


class GuidanceTests(unittest.TestCase):
    def test_every_topic_answers_and_unknown_topic_errors(self):
        for topic, component in content.TOPICS.items():
            with self.subTest(topic=topic):
                out = mcp_tools.get_guidance(topic, Fixtures.guidance, Fixtures.none)
                self.assertEqual(out["component"], component)
                self.assertTrue(out["ask"] and out["do"] and out["ask_a_human_if"])
                self.assertTrue(out["unknown_policy"])
                self.assertEqual(out["enforcement"], "none")
        out = mcp_tools.get_guidance("nope", Fixtures.guidance, Fixtures.none)
        self.assertEqual(out["error"], "unknown-topic")

    def test_company_values_come_from_overlay_only_when_approved(self):
        generic = mcp_tools.get_guidance("hosting", Fixtures.guidance, Fixtures.none)
        self.assertIn("generic default", generic["company_values"]["approved"]["source"])
        approved = mcp_tools.get_guidance("hosting", Fixtures.guidance, Fixtures.approved)
        self.assertFalse(approved["unknown_policy"])
        self.assertIn("Internal App Platform (company sign-in)", approved["company_values"]["approved"]["values"])
        self.assertIn("Personal cloud accounts", approved["dont"])
        self.assertEqual(approved["policy_source"]["organization"], "Example Org")
        expired = mcp_tools.get_guidance("hosting", Fixtures.guidance, Fixtures.expired)
        self.assertTrue(expired["unknown_policy"])
        self.assertEqual(expired["policy_status"], "expired")
        self.assertIn("generic default", expired["company_values"]["approved"]["source"])


class CheckPlanTests(unittest.TestCase):
    def test_customer_export_with_card_digits(self):
        out = mcp_tools.check_plan("A tool to look up customers from last month's CRM export with names, emails, and the last four digits of cards.", Fixtures.guidance, Fixtures.none)
        components = [r["component"] for r in out["risks"]]
        self.assertIn("data-in-prompts", components)
        self.assertEqual(out["risks"][0]["severity"], "high")
        self.assertTrue(out["ask_a_human"])
        self.assertTrue(out["unknown_policy"])
        self.assertIn("payment card or bank data", out["labels"]["sensitive_data"])

    def test_clean_plan_has_no_risks_but_is_not_approval(self):
        out = mcp_tools.check_plan("A vacation-request tracker for our team of six, made-up test data, behind company sign-in, on the internal app platform.", Fixtures.guidance, Fixtures.approved, audience="our team", hosting="Internal App Platform")
        self.assertEqual(out["risks"], [])
        self.assertFalse(out["ask_a_human"])
        self.assertIn("not", out["next_step"].lower())
        self.assertFalse(out["unknown_policy"])

    def test_overlay_flags_unapproved_hosting_and_company_triggers(self):
        out = mcp_tools.check_plan("A dashboard for the sales team.", Fixtures.guidance, Fixtures.approved, hosting="my personal Replit account")
        self.assertTrue(out["labels"]["risky_hosting"])
        self.assertTrue(out["labels"]["unapproved_hosting"])
        self.assertIn("hosting-and-where-it-runs", [r["component"] for r in out["risks"]])
        out = mcp_tools.check_plan("Let the app send refunds to customers automatically.", Fixtures.guidance, Fixtures.approved, audience="customers")
        self.assertTrue(out["ask_a_human"])
        self.assertEqual(out["who_to_ask"], "security-review@example.org")

    def test_invalid_description(self):
        self.assertEqual(mcp_tools.check_plan("   ", Fixtures.guidance, Fixtures.none)["error"], "invalid-input")

    def test_hr_lookup_tool_purpose_sets_ask_a_human(self):
        """A plan whose whole purpose is a real employee-records lookup, not a passing mention."""
        out = mcp_tools.check_plan(
            "An internal dashboard for the ops team that pulls the employee roster export, "
            "including salaries and home addresses, into a web app so managers can look people up. "
            "I will paste a sample of the real export into the chat so you can see the columns.",
            Fixtures.guidance, Fixtures.none,
            data_types=["employee names", "salaries", "home addresses"], audience="managers", hosting="unknown",
        )
        self.assertIn("employee or HR records", out["labels"]["sensitive_data"])
        self.assertIn("data-in-prompts", [r["component"] for r in out["risks"]])
        self.assertTrue(out["ask_a_human"])
        human_risk = next(r for r in out["risks"] if r["component"] == "when-to-ask-a-human")
        self.assertIn("employee or HR records", human_risk["why"])

    def test_api_key_mention_is_credentials_only_not_duplicated(self):
        """'API key' should drive keys-and-credentials, not also a duplicate data-in-prompts risk."""
        out = mcp_tools.check_plan(
            "A contact form on our marketing site that emails submissions to the support inbox, "
            "using an API key for the email-sending service.",
            Fixtures.guidance, Fixtures.none,
        )
        components = [r["component"] for r in out["risks"]]
        self.assertIn("keys-and-credentials", components)
        self.assertNotIn("data-in-prompts", components)
        self.assertEqual(components.count("keys-and-credentials"), 1)
        self.assertEqual(out["labels"]["sensitive_data"], [])
        self.assertTrue(out["labels"]["credentials"])
        self.assertTrue(out["ask_a_human"])


class OverlayMatchingTests(unittest.TestCase):
    """Overlay items match structurally: content words in any order, singular or plural, or a category synonym.

    The example overlay is loaded by an absolute path built from the repository root (Fixtures.approved).
    """

    def hosting_risk(self, out):
        return next(r for r in out["risks"] if r["component"] == "hosting-and-where-it-runs")

    def test_unmanaged_virtual_machine_singular_and_plural(self):
        for plan in ("Host a team timer on an unmanaged virtual machine", "Host a team timer on unmanaged virtual machines"):
            with self.subTest(plan=plan):
                out = mcp_tools.check_plan(plan, Fixtures.guidance, Fixtures.approved)
                risk = self.hosting_risk(out)
                self.assertEqual(risk["rule"], "Unmanaged virtual machines")
                self.assertEqual(risk["overlay_list"], "hosting.not_approved")
                self.assertEqual(risk["evidence"], ["unmanaged", "virtual", "machine"])
                self.assertTrue(out["labels"]["unapproved_hosting"])
                self.assertIn("Unmanaged virtual machines", out["labels"]["overlay_rules"])
                self.assertEqual(out["enforcement"], "none")
                self.assertIn("keyword matching", out["method"])

    def test_unapproved_service_matches_through_synonym(self):
        out = mcp_tools.check_plan("Send proprietary source code to an unapproved AI service", Fixtures.guidance, Fixtures.approved)
        risk = next(r for r in out["risks"] if r["component"] == "third-party-services")
        self.assertEqual(risk["rule"], "Any new software service")
        self.assertEqual(risk["overlay_list"], "services.needs_review")
        self.assertEqual(risk["evidence"], ["unapproved", "service"])
        self.assertTrue(out["labels"]["new_service"])
        self.assertFalse(out["unknown_policy"])

    def test_approved_host_and_approved_service_do_not_fire(self):
        out = mcp_tools.check_plan(
            "A vacation-request tracker for our team of six, made-up test data, behind company sign-in, "
            "on the internal app platform, sending reminders through the approved transactional email service.",
            Fixtures.guidance, Fixtures.approved, audience="our team", hosting="Internal App Platform",
        )
        self.assertEqual(out["risks"], [])
        self.assertEqual(out["labels"]["hosting"], "approved")
        self.assertEqual(out["labels"]["audience"], "internal")
        self.assertEqual(out["labels"]["overlay_rules"], [])
        self.assertFalse(out["ask_a_human"])

    def test_missing_hosting_and_audience_are_unknown_not_fine(self):
        out = mcp_tools.check_plan("Host a team timer on an unmanaged virtual machine", Fixtures.guidance, Fixtures.approved)
        self.assertEqual(out["labels"]["hosting"], "unknown")
        self.assertEqual(out["labels"]["audience"], "unknown")
        self.assertIn(Fixtures.guidance["components"]["hosting-and-where-it-runs"]["ask"][0], out["checklist"])
        self.assertIn(Fixtures.guidance["components"]["access-and-identity"]["ask"][0], out["checklist"])
        # The literal word "unknown" counts as not supplied.
        out = mcp_tools.check_plan("A timer.", Fixtures.guidance, Fixtures.none, hosting="unknown")
        self.assertEqual(out["labels"]["hosting"], "unknown")
        # Named hosting with no overlay to check it against is still unknown, not fine: the decision
        # says so and names the generic rule it could not apply.
        out = mcp_tools.check_plan("A timer.", Fixtures.guidance, Fixtures.none, hosting="the team server")
        self.assertEqual(out["labels"]["hosting"], "unknown")
        decision = next(d for d in out["decisions"] if d["field"] == "hosting")
        self.assertEqual((decision["outcome"], decision["source"]), ("unknown", "generic default"))
        self.assertIn("generic defaults cannot approve hosting", decision["note"])

    def test_named_hosting_off_the_approved_list_cites_the_list(self):
        out = mcp_tools.check_plan("A dashboard for the sales team.", Fixtures.guidance, Fixtures.approved, hosting="a shared machine in the lab")
        risk = self.hosting_risk(out)
        self.assertEqual(out["labels"]["hosting"], "unrecognized")
        self.assertEqual(risk["overlay_list"], "hosting.approved")
        self.assertIn("Internal App Platform (company sign-in)", risk["rule"])
        self.assertEqual(risk["evidence"], ["shared", "machine", "lab"])
        # A weak synonym alone does not fire; with one of the item's own words it does and names the item.
        out = mcp_tools.check_plan("A dashboard for the sales team.", Fixtures.guidance, Fixtures.approved, hosting="my personal Replit account")
        self.assertEqual(self.hosting_risk(out)["rule"], "Personal cloud accounts")
        self.assertEqual(len([r for r in out["risks"] if r["component"] == "hosting-and-where-it-runs"]), 1)
        out = mcp_tools.check_plan("A KPI dashboard of key metrics that stores personal data for a new team.", Fixtures.guidance, Fixtures.approved)
        self.assertEqual(out["risks"], [])

    def test_company_data_class_and_review_trigger_carry_rule_and_evidence(self):
        out = mcp_tools.check_plan("Import the employee HR records and issue refunds from the app.", Fixtures.guidance, Fixtures.approved)
        data = next(r for r in out["risks"] if r["component"] == "data-in-prompts")
        self.assertEqual(data["rule"], "Employee HR records")
        self.assertEqual(data["evidence"], ["hr record", "employee", "hr", "record"])  # generic match first, then the overlay words
        human = next(r for r in out["risks"] if r["component"] == "when-to-ask-a-human")
        self.assertEqual(human["rule"], "Payments or refunds")
        self.assertIn("refund", human["evidence"])
        self.assertTrue(out["ask_a_human"])
        # A credential-only data class belongs to the keys-and-credentials risk, not a duplicate data risk.
        out = mcp_tools.check_plan("A form that emails the inbox, using an API key for the email-sending service.", Fixtures.guidance, Fixtures.approved)
        components = [r["component"] for r in out["risks"]]
        self.assertNotIn("data-in-prompts", components)
        keys = next(r for r in out["risks"] if r["component"] == "keys-and-credentials")
        self.assertEqual(keys["rule"], "Passwords, keys, tokens, and sign-in codes")
        self.assertEqual(keys["evidence"], ["api key"])

    def test_generic_risks_have_evidence_and_no_rule(self):
        out = mcp_tools.check_plan("A tool over last month's CRM export.", Fixtures.guidance, Fixtures.none)
        data = next(r for r in out["risks"] if r["component"] == "data-in-prompts")
        self.assertIsNone(data["rule"])
        self.assertEqual(data["evidence"], ["crm export"])


class TemplateAndApprovedTests(unittest.TestCase):
    def test_templates_for_every_kind(self):
        for kind in content.TEMPLATE_KINDS:
            out = mcp_tools.get_template(kind, Fixtures.templates, Fixtures.guidance, Fixtures.none)
            self.assertTrue(out["starting_point"].startswith("## "))
            self.assertTrue(out["constraints"])
            self.assertIsNone(out["approved_starting_point"])
        out = mcp_tools.get_template("internal-lookup-tool", Fixtures.templates, Fixtures.guidance, Fixtures.approved_with_template)
        self.assertEqual(out["approved_starting_point"]["location"], "https://intranet.example.org/templates/lookup")
        self.assertEqual(mcp_tools.get_template("nope", Fixtures.templates, Fixtures.guidance, Fixtures.none)["error"], "unknown-kind")

    def test_list_approved_states(self):
        generic = mcp_tools.list_approved("hosting", Fixtures.guidance, Fixtures.none)
        self.assertTrue(generic["unknown_policy"])
        self.assertIsNone(generic["last_reviewed"])
        approved = mcp_tools.list_approved("services", Fixtures.guidance, Fixtures.approved)
        self.assertFalse(approved["unknown_policy"])
        self.assertIn("The company LLM gateway", approved["items"]["approved"])
        self.assertEqual(approved["last_reviewed"], "2026-09-13")
        self.assertEqual(mcp_tools.list_approved("nope", Fixtures.guidance, Fixtures.none)["error"], "unknown-category")

    def test_expired_overlay_contributes_no_values_anywhere(self):
        """An expired (or not-yet-valid) overlay must behave exactly like no overlay for
        every value a tool returns. Only policy_status and policy_note, both from
        _provenance, may say the overlay expired and name the owner to ask."""
        for category in content.CATEGORIES:
            with self.subTest(category=category):
                none_out = mcp_tools.list_approved(category, Fixtures.guidance, Fixtures.none)
                expired_out = mcp_tools.list_approved(category, Fixtures.guidance, Fixtures.expired)
                self.assertEqual(expired_out["items"], none_out["items"])
                self.assertEqual(expired_out["source"], none_out["source"])
                self.assertEqual(expired_out["last_reviewed"], none_out["last_reviewed"])
                self.assertTrue(expired_out["unknown_policy"])

        for topic in content.TOPICS:
            with self.subTest(topic=topic):
                none_out = mcp_tools.get_guidance(topic, Fixtures.guidance, Fixtures.none)
                expired_out = mcp_tools.get_guidance(topic, Fixtures.guidance, Fixtures.expired)
                self.assertEqual(expired_out["company_values"], none_out["company_values"])
                self.assertEqual(expired_out["dont"], none_out["dont"])

        for kind in content.TEMPLATE_KINDS:
            with self.subTest(kind=kind):
                none_out = mcp_tools.get_template(kind, Fixtures.templates, Fixtures.guidance, Fixtures.none)
                expired_out = mcp_tools.get_template(kind, Fixtures.templates, Fixtures.guidance, Fixtures.expired)
                self.assertEqual(expired_out["approved_starting_point"], none_out["approved_starting_point"])
                self.assertEqual(expired_out["approved_starting_point_note"], none_out["approved_starting_point_note"])

        none_plan = mcp_tools.check_plan("A dashboard for the sales team.", Fixtures.guidance, Fixtures.none, hosting="my personal Replit account")
        expired_plan = mcp_tools.check_plan("A dashboard for the sales team.", Fixtures.guidance, Fixtures.expired, hosting="my personal Replit account")
        self.assertEqual(expired_plan["risks"], none_plan["risks"])
        self.assertEqual(expired_plan["who_to_ask"], none_plan["who_to_ask"])
        self.assertFalse(expired_plan["labels"]["unapproved_hosting"])

        # policy_status and policy_note (the only place expiry may show through) are unaffected.
        expired_guidance = mcp_tools.get_guidance("hosting", Fixtures.guidance, Fixtures.expired)
        self.assertEqual(expired_guidance["policy_status"], "expired")
        self.assertIn("expired on", expired_guidance["policy_note"])
        self.assertIn(Fixtures.expired.source["expires_on"], expired_guidance["policy_note"])
        self.assertIn(Fixtures.expired.overlay["owner"], expired_guidance["policy_note"])


class PolicyStateTests(unittest.TestCase):
    def test_states(self):
        self.assertEqual(policy.load_policy(None).status, "none")
        self.assertEqual(policy.load_policy("relative/overlay.yaml").status, "invalid")
        self.assertEqual(policy.load_policy("/definitely/not/here.yaml").status, "missing")
        self.assertEqual(Fixtures.approved.status, "approved")
        self.assertEqual(Fixtures.expired.status, "expired")
        self.assertEqual(len(Fixtures.approved.source["sha256"]), 64)

    def test_shipped_example_loads_as_approved_with_no_extra_host_configuration(self):
        """The shipped overlay.example.yaml has no templates entry, so it needs no
        allowed_hosts (no CATPILOT_TEMPLATE_HOSTS) to load as approved, as shipped.

        EXAMPLE is an absolute path built from the repository root (ROOT, derived
        from this test file's own location), not a machine-specific path.
        """
        state = policy.load_policy(str(EXAMPLE), set(), now=TODAY)
        self.assertEqual(state.status, "approved")
        self.assertTrue(state.approved)

    def test_template_host_not_allowlisted_is_invalid(self):
        state = _load_example_with_template(set())
        self.assertEqual(state.status, "invalid")


if __name__ == "__main__":
    unittest.main()


class CheckPlanDecisionTests(unittest.TestCase):
    """check_plan decides from the explicit fields and only hints from the description.

    The overlay under test is a copy of the shipped example with its `templates` entry removed,
    written to a temporary directory and loaded by absolute path, so no template host has to be
    allowlisted for these tests.
    """

    @classmethod
    def setUpClass(cls):
        tmp = tempfile.mkdtemp()
        cls.addClassCleanup(shutil.rmtree, tmp, True)
        text = EXAMPLE.read_text(encoding="utf-8").split("\ntemplates:")[0].rstrip() + "\n"
        overlay = Path(tmp) / "overlay.yaml"
        overlay.write_text(text, encoding="utf-8")
        cls.overlay_path = overlay
        cls.approved = policy.load_policy(str(overlay), set(), now=TODAY)
        cls.none = policy.load_policy(None)
        cls.guidance = content.load_guidance()

    def plan(self, description="A small internal tool.", policy_state=None, **fields):
        return mcp_tools.check_plan(description, self.guidance, policy_state or self.none, **fields)

    def decision(self, out, field, value=None):
        for d in out["decisions"]:
            if d["field"] == field and (value is None or d["value"] == value):
                return d
        raise AssertionError(f"no decision for {field} {value!r} in {[(d['field'], d['value']) for d in out['decisions']]}")

    # ---------------------------------------------------------------- shape

    def test_overlay_copy_is_approved_without_a_template_host(self):
        self.assertEqual(self.approved.status, "approved")
        self.assertEqual(self.approved.overlay["templates"], [])

    def test_every_field_gets_a_decision_and_the_keys_are_stable(self):
        out = self.plan("A lookup tool.", data_classes=["made-up records"], audience="our team", hosting="Internal App Platform", services=["the company LLM gateway"], write_access=False)
        self.assertEqual([d["field"] for d in out["decisions"]], ["hosting", "audience", "data_classes", "services", "write_access"])
        for d in out["decisions"]:
            self.assertEqual(set(d), {"field", "value", "outcome", "rule", "source", "evidence", "note"})
            self.assertIn(d["outcome"], ("permitted", "requires_review", "prohibited", "unknown"))
            self.assertIn(d["source"], ("company overlay", "generic default"))
            self.assertTrue(d["rule"])
        # Every key the tool answered with before is still there.
        for key in ("risks", "next_step", "ask_a_human", "who_to_ask", "checklist", "labels", "method", "unknown_policy", "policy_status", "policy_note", "policy_source", "source_version", "enforcement"):
            self.assertIn(key, out)
        self.assertEqual(out["enforcement"], "none")
        self.assertIn("explicit fields decide", out["method"])

    def test_one_decision_per_list_item(self):
        out = self.plan(data_classes=["synthetic names", "salaries"], services=["a new enrichment API", "another new API"])
        self.assertEqual(len([d for d in out["decisions"] if d["field"] == "data_classes"]), 2)
        self.assertEqual(len([d for d in out["decisions"] if d["field"] == "services"]), 2)

    def test_outcome_is_the_worst_across_decisions(self):
        self.assertEqual(self.plan().get("outcome"), "unknown")
        self.assertEqual(self.plan(audience="our team", hosting="Internal App Platform", data_classes=["made-up records"], services=[], write_access=False, policy_state=self.approved)["outcome"], "permitted")
        self.assertEqual(self.plan(audience="customers", hosting="Internal App Platform", write_access=False, policy_state=self.approved)["outcome"], "requires_review")
        self.assertEqual(self.plan(audience="our team", hosting="Internal App Platform", data_classes=["cardholder data"], write_access=False, policy_state=self.approved)["outcome"], "prohibited")
        permitted = self.plan(audience="our team", hosting="Internal App Platform", data_classes=["made-up records with example.com addresses"], services=["the company LLM gateway"], write_access=False, policy_state=self.approved)
        self.assertEqual(permitted["outcome"], "permitted")
        self.assertFalse(permitted["ask_a_human"])
        self.assertEqual(permitted["risks"], [])

    # ---------------------------------------------------------------- hosting

    def test_hosting_missing_is_unknown_and_asks_where_it_runs(self):
        out = self.plan()
        d = self.decision(out, "hosting")
        self.assertEqual((d["value"], d["outcome"]), ("unknown", "unknown"))
        self.assertIn(self.guidance["components"]["hosting-and-where-it-runs"]["ask"][0], out["checklist"])
        self.assertEqual(out["labels"]["hosting"], "unknown")
        self.assertEqual(self.decision(self.plan(hosting="unknown"), "hosting")["outcome"], "unknown")

    def test_hosting_approved_by_equality_and_by_content_words(self):
        for value in ("Internal App Platform (company sign-in)", "the internal app platform", "Power Apps in the company tenant"):
            with self.subTest(value=value):
                out = self.plan(hosting=value, policy_state=self.approved)
                d = self.decision(out, "hosting")
                self.assertEqual(d["outcome"], "permitted")
                self.assertEqual(d["source"], "company overlay")
                self.assertIn(d["rule"], self.approved.overlay["hosting"]["approved"])
                self.assertEqual(out["labels"]["hosting"], "approved")
                self.assertEqual(out["risks"], [])

    def test_hosting_negation_never_reads_as_approval(self):
        for value in ("Not Internal App Platform", "a custom build instead of the Internal App Platform", "no internal app platform, a box under my desk"):
            with self.subTest(value=value):
                out = self.plan(hosting=value, policy_state=self.approved)
                d = self.decision(out, "hosting")
                self.assertNotEqual(d["outcome"], "permitted")
                self.assertNotEqual(out["labels"]["hosting"], "approved")

    def test_hosting_on_the_not_approved_list_is_prohibited(self):
        out = self.plan(hosting="a personal cloud account", policy_state=self.approved)
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("prohibited", "Personal cloud accounts", "company overlay"))
        self.assertEqual(out["labels"]["hosting"], "not_approved")
        self.assertTrue(out["labels"]["unapproved_hosting"])
        risk = next(r for r in out["risks"] if r["component"] == "hosting-and-where-it-runs")
        self.assertEqual((risk["basis"], risk["severity"], risk["overlay_list"]), ("decision", "high", "hosting.not_approved"))

    def test_hosting_off_both_lists_needs_review_and_notes_the_approved_list(self):
        out = self.plan(hosting="a shared machine in the lab", policy_state=self.approved)
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["rule"]), ("requires_review", "hosting must be on the company's approved list"))
        self.assertIn("Internal App Platform (company sign-in)", d["note"])
        self.assertEqual(out["labels"]["hosting"], "unrecognized")

    def test_hosting_without_an_overlay(self):
        out = self.plan(hosting="my personal Replit account")
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["source"]), ("requires_review", "generic default"))
        self.assertTrue(out["labels"]["risky_hosting"])
        out = self.plan(hosting="the team server")
        d = self.decision(out, "hosting")
        self.assertEqual(d["outcome"], "unknown")
        self.assertEqual(d["note"], "no company overlay; generic defaults cannot approve hosting")

    def test_mixed_or_negated_mention_of_an_approved_item_is_requires_review(self):
        """Naming an approved item together with something else, or negating it, is not a plain approval."""
        d = self.decision(self.plan(services=["A new model endpoint instead of the company LLM gateway"], policy_state=self.approved), "services")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("requires_review", "negated mention of an approved item", "company overlay"))
        self.assertEqual(d["evidence"], ["new", "model", "endpoint", "instead"])
        d = self.decision(self.plan(services=["Company LLM gateway and a new model endpoint"], policy_state=self.approved), "services")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("requires_review", "mixed mention: an approved item is named together with something else", "company overlay"))
        self.assertEqual(d["evidence"], ["new", "model", "endpoint"])
        out = self.plan(hosting="Internal App Platform and a personal VPS", policy_state=self.approved)
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("requires_review", "mixed mention: an approved item is named together with something else", "company overlay"))
        self.assertEqual(d["evidence"], ["personal", "vps"])
        self.assertEqual(out["labels"]["hosting"], "unrecognized")
        self.assertTrue(out["labels"]["unapproved_hosting"])
        # An exact match, including one that drops the optional leading "The", still permits.
        for value in ("Company LLM gateway", "The company LLM gateway", "Internal object storage"):
            with self.subTest(value=value):
                d = self.decision(self.plan(services=[value], policy_state=self.approved), "services")
                self.assertEqual(d["outcome"], "permitted")

    # ---------------------------------------------------------------- hosting: not deployed

    def test_not_deployed_hosting_is_permitted_with_an_internal_audience(self):
        """A hosting value that says the thing is never deployed anywhere is permitted, not
        `requires_review` for missing the approved list -- there is nothing to approve."""
        for value in (
            "local existing workspace; no deployment",
            "not deployed",
            "developer-controlled local execution; no new hosting",
        ):
            with self.subTest(value=value):
                out = self.plan(hosting=value, audience="internal staff", policy_state=self.approved)
                d = self.decision(out, "hosting")
                self.assertEqual((d["outcome"], d["rule"], d["source"]),
                                  ("permitted", "not deployed; hosting is reviewed when the thing is published for others", "generic default"))
                self.assertEqual(out["labels"]["hosting"], "not_deployed")
                self.assertEqual(out["risks"], [])

    def test_laptop_only_hosting_is_requires_review_with_an_internal_audience(self):
        """Unlike the plain not-deployed cues, a machine-only cue ("my laptop") is a machine
        other people depend on once the audience is not the builder alone -- not the old
        `prohibited` from matching "laptop" against the whole not-approved list."""
        out = self.plan(hosting="runs on my laptop only", audience="internal staff", policy_state=self.approved)
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["rule"], d["source"]),
                          ("requires_review", "a machine other people depend on is not managed hosting", "generic default"))
        self.assertEqual(out["labels"]["hosting"], "not_deployed")
        risk = next(r for r in out["risks"] if r["component"] == "hosting-and-where-it-runs")
        self.assertEqual(risk["basis"], "decision")

    def test_laptop_only_hosting_depends_on_who_else_is_the_audience(self):
        out = self.plan(hosting="runs on my laptop only", audience="just me", policy_state=self.approved)
        self.assertEqual(self.decision(out, "hosting")["outcome"], "permitted")
        self.assertEqual(out["labels"]["hosting"], "not_deployed")
        out = self.plan(hosting="runs on my laptop only", audience="the whole company", policy_state=self.approved)
        self.assertEqual(self.decision(out, "hosting")["outcome"], "requires_review")

    def test_not_deployed_hosting_stays_permitted_for_an_external_audience_but_the_plan_does_not(self):
        """A script that never leaves the builder's machine is not hosting even when its output
        is for others; the audience decision, not the hosting decision, is what needs review."""
        out = self.plan(hosting="not deployed", audience="customers", policy_state=self.approved)
        d = self.decision(out, "hosting")
        self.assertEqual(d["outcome"], "permitted")
        self.assertEqual(out["labels"]["hosting"], "not_deployed")
        self.assertEqual(out["outcome"], "requires_review")
        self.assertTrue(out["ask_a_human"])

    def test_not_deployed_shortcut_skipped_when_an_approved_entry_is_also_named(self):
        out = self.plan(hosting="local Internal App Platform", policy_state=self.approved)
        self.assertNotEqual(out["labels"]["hosting"], "not_deployed")
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["rule"]), ("requires_review", "mixed mention: an approved item is named together with something else"))

    def test_not_deployed_shortcut_skipped_for_a_free_tier_on_a_laptop(self):
        out = self.plan(hosting="free tier on my laptop", policy_state=self.approved)
        self.assertNotEqual(out["labels"]["hosting"], "not_deployed")
        d = self.decision(out, "hosting")
        self.assertEqual((d["outcome"], d["rule"]), ("prohibited", "Free-tier hosting"))

    # ---------------------------------------------------------------- audience

    def test_audience_normalizes_and_decides(self):
        cases = {
            "the ops team": ("internal", "permitted"),
            "colleagues in finance": ("internal", "permitted"),
            "our customers": ("external", "requires_review"),
            "a partner agency": ("external", "requires_review"),
            "anyone with the link": ("public", "requires_review"),
            "the general public": ("public", "requires_review"),
            "whoever needs it": ("unknown", "unknown"),
        }
        for value, (category, outcome) in cases.items():
            with self.subTest(value=value):
                out = self.plan(audience=value)
                d = self.decision(out, "audience")
                self.assertEqual((d["value"], d["outcome"]), (category, outcome))
                self.assertEqual(out["labels"]["audience"], category)
        out = self.plan(audience="whoever needs it")
        self.assertIn(self.guidance["components"]["access-and-identity"]["ask"][0], out["checklist"])

    def test_external_audience_cites_the_overlay_review_trigger(self):
        out = self.plan(audience="our customers", policy_state=self.approved)
        d = self.decision(out, "audience")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("requires_review", "External users", "company overlay"))
        self.assertTrue(out["ask_a_human"])
        self.assertIn("sharing-and-publishing", [r["component"] for r in out["risks"]])
        generic = self.decision(self.plan(audience="our customers"), "audience")
        self.assertEqual(generic["source"], "generic default")
        self.assertIn("outside the company", generic["rule"])

    def test_internal_audience_cites_the_overlay_default(self):
        d = self.decision(self.plan(audience="the ops team", policy_state=self.approved), "audience")
        self.assertEqual((d["outcome"], d["rule"]), ("permitted", "Company sign-in, smallest named group that needs access"))

    def test_local_only_external_connection_phrase_is_not_an_external_audience_hint(self):
        """Regression for the exact route transcript wording: a negated network connection is not a person."""
        out = self.plan(
            "Create a local Python script for a single internal builder. It reads the existing local "
            "route_points.json, sums distance_km values, rounds to one decimal, and prints exactly one "
            "JSON object. It does not deploy, share output, use credentials, contact any service, or make "
            "any external connection.",
            data_classes=["non-personal local operational route distance measurements"],
            data_provenance="real",
            audience="one internal company builder",
            hosting="not deployed; runs locally",
            services=[],
            credential_references=[],
            write_access=False,
            policy_state=self.approved,
        )
        self.assertEqual(self.decision(out, "audience")["outcome"], "permitted")
        self.assertEqual(self.decision(out, "data_classes")["outcome"], "unknown")
        self.assertFalse(out["labels"]["external_audience"])
        self.assertFalse(out["labels"]["review_trigger"])
        self.assertFalse(out["ask_a_human"])
        self.assertNotIn("access-and-identity", [risk["component"] for risk in out["risks"]])

    def test_real_external_audience_phrase_still_sets_review(self):
        out = self.plan(
            "Share the local report with external partners.",
            audience="one internal company builder",
            data_classes=["made-up records"],
            data_provenance="synthetic",
            hosting="not deployed",
            services=[],
            write_access=False,
            policy_state=self.approved,
        )
        self.assertTrue(out["labels"]["external_audience"])
        self.assertTrue(out["labels"]["review_trigger"])
        self.assertTrue(out["ask_a_human"])
        self.assertIn("access-and-identity", [risk["component"] for risk in out["risks"]])

    def test_external_network_product_people_remain_an_audience_hint(self):
        for phrase in ("external API developers", "external service users", "external service providers"):
            with self.subTest(phrase=phrase):
                out = self.plan(
                    f"Share the report with {phrase}.",
                    audience="one internal company builder",
                    data_classes=["made-up records"],
                    data_provenance="synthetic",
                    hosting="not deployed",
                    services=[],
                    write_access=False,
                    policy_state=self.approved,
                )
                self.assertTrue(out["labels"]["external_audience"])
                self.assertTrue(out["ask_a_human"])
                self.assertIn("access-and-identity", [risk["component"] for risk in out["risks"]])

    # ---------------------------------------------------------------- data classes

    def test_data_classes_against_the_overlay(self):
        cases = {
            "cardholder data": ("prohibited", "Cardholder data and bank details"),
            "government identifiers": ("prohibited", "Government identifiers"),
            "customer names and business email addresses": ("requires_review", "Customer names and business email addresses"),
            "published product information": ("permitted", "Published product information"),
        }
        for value, (outcome, rule) in cases.items():
            with self.subTest(value=value):
                d = self.decision(self.plan(data_classes=[value], policy_state=self.approved), "data_classes", value)
                self.assertEqual((d["outcome"], d["rule"], d["source"]), (outcome, rule, "company overlay"))
        unmatched = self.decision(self.plan(data_classes=["seating-chart preferences"], policy_state=self.approved), "data_classes")
        self.assertEqual(unmatched["outcome"], "unknown")
        self.assertEqual(unmatched["rule"], "this data class is not covered by the available policy; ask the data owner")
        self.assertEqual(unmatched["note"], "not in the company's data classes; ask the owner")

    def test_unmatched_supplied_class_is_not_described_as_missing(self):
        """A supplied but unlisted class stays conservatively unknown with an accurate explanation."""
        unmatched = self.decision(
            self.plan(data_classes=["local route distance values"], data_provenance="real", policy_state=self.approved),
            "data_classes",
        )
        self.assertEqual(unmatched["outcome"], "unknown")
        self.assertEqual(unmatched["rule"], "this data class is not covered by the available policy; ask the data owner")
        self.assertNotIn("no data classes were named", unmatched["rule"])

    def test_credential_data_class_belongs_to_keys_and_credentials(self):
        out = self.plan(data_classes=["an API key for the email service"], policy_state=self.approved)
        d = self.decision(out, "data_classes")
        self.assertEqual(d["outcome"], "prohibited")
        self.assertIn("keys-and-credentials", [r["component"] for r in out["risks"]])
        self.assertNotIn("data-in-prompts", [r["component"] for r in out["risks"]])
        self.assertTrue(out["labels"]["credentials"])

    def test_data_classes_without_an_overlay(self):
        cases = {
            "card numbers from the payments system": "prohibited",
            "passport numbers": "prohibited",
            "patient health information": "prohibited",
            "an smtp password": "prohibited",
            "the employee records export": "requires_review",
            "last month's customer export": "requires_review",
            "synthetic patient records": "permitted",
            "made-up rows with example.com addresses": "permitted",
            "seating-chart preferences": "unknown",
        }
        for value, outcome in cases.items():
            with self.subTest(value=value):
                d = self.decision(self.plan(data_classes=[value]), "data_classes", value)
                self.assertEqual(d["outcome"], outcome, d)
                self.assertEqual(d["source"], "generic default")
        self.assertIn("employee or HR records", self.plan(data_classes=["the employee records export"])["labels"]["sensitive_data"])

    def test_synthetic_data_class_is_permitted_under_the_overlay_too(self):
        d = self.decision(self.plan(data_classes=["synthetic patient records"], policy_state=self.approved), "data_classes")
        self.assertEqual(d["outcome"], "permitted")
        d = self.decision(self.plan(data_classes=["made-up records with example.com addresses"], policy_state=self.approved), "data_classes")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("permitted", "Made-up records with example.com addresses", "company overlay"))

    def test_data_types_is_a_deprecated_alias_for_data_classes(self):
        out = self.plan(data_types=["cardholder data"], policy_state=self.approved)
        self.assertEqual(self.decision(out, "data_classes", "cardholder data")["outcome"], "prohibited")
        both = self.plan(data_classes=["published product information"], data_types=["cardholder data"], policy_state=self.approved)
        self.assertEqual([d["value"] for d in both["decisions"] if d["field"] == "data_classes"], ["published product information", "cardholder data"])
        self.assertEqual(both["outcome"], "prohibited")

    def test_health_records_not_synthetic_is_prohibited_with_and_without_the_overlay(self):
        """The word "synthetic" must not take the safe branch before its own negation is checked."""
        for policy_state in (self.approved, self.none):
            with self.subTest(overlay=policy_state.status):
                d = self.decision(self.plan(data_classes=["Health records, not synthetic"], policy_state=policy_state), "data_classes")
                self.assertEqual(d["outcome"], "prohibited")
                self.assertEqual(d["note"], "mixed or negated cue; treated as real")

    def test_synthetic_negation_variants_are_read_correctly(self):
        for value in ("non-synthetic health records", "health records rather than sample data", "Health records, isn't synthetic"):
            with self.subTest(value=value):
                d = self.decision(self.plan(data_classes=[value], policy_state=self.approved), "data_classes")
                self.assertEqual((d["outcome"], d["rule"], d["source"]), ("prohibited", "Health records", "company overlay"))
                self.assertEqual(d["note"], "mixed or negated cue; treated as real")

    def test_mixed_synthetic_and_real_cue_is_treated_as_real(self):
        """A cue like "real" or "customer records" outweighs a synthetic-looking word in the same item."""
        d = self.decision(self.plan(data_classes=["sample rows and real customer records"]), "data_classes")
        self.assertEqual(d["outcome"], "requires_review")
        self.assertEqual(d["note"], "mixed or negated cue; treated as real")
        self.assertIn("sample", d["evidence"])
        self.assertIn("real", d["evidence"])

    def test_data_provenance_overrides_the_text_inference(self):
        # "synthetic" forces the made-up-data branch even with no synthetic-sounding word at all.
        d = self.decision(self.plan(data_classes=["health records"], data_provenance="synthetic", policy_state=self.approved), "data_classes")
        self.assertEqual(d["outcome"], "permitted")
        # "real" forces the real-data rules even with a synthetic-sounding word right there.
        d = self.decision(self.plan(data_classes=["sample health records"], data_provenance="real", policy_state=self.approved), "data_classes")
        self.assertEqual((d["outcome"], d["rule"]), ("prohibited", "Health records"))

    def test_data_provenance_unknown_is_treated_as_real_with_a_note(self):
        out = self.plan(data_classes=["sample health records"], data_provenance="unknown", policy_state=self.approved)
        d = self.decision(out, "data_classes")
        self.assertEqual(d["outcome"], "prohibited")
        self.assertEqual(d["note"], "provenance unknown; treated as real")
        self.assertEqual(out["labels"]["data_provenance"], "unknown")

    def test_identifier_only_credential_reference_is_safe_but_unknown_credential_material_is_not(self):
        safe = self.plan(
            data_classes=["made-up records"], data_provenance="synthetic", audience="our team", hosting="not deployed", services=["none"],
            write_access=False,
            credential_references=[{"name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": False, "value_in_generated_artifacts": False}],
            policy_state=self.approved,
        )
        reference = self.decision(safe, "credential_references", "CHECKIN_RELAY_TOKEN")
        self.assertEqual(reference["outcome"], "permitted")
        self.assertEqual(self.decision(safe, "services")["outcome"], "permitted")
        self.assertEqual(safe["outcome"], "permitted")
        real = self.plan(
            data_classes=["an unknown access token value"], data_provenance="unknown",
            policy_state=self.approved,
        )
        self.assertEqual(self.decision(real, "data_classes")["outcome"], "prohibited")
        self.assertIn("keys-and-credentials", [risk["component"] for risk in real["risks"]])

    def test_credential_references_reject_values_and_non_identifier_metadata(self):
        for references in (
            [{"name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": False}],
            [{"name": "CHECKIN_RELAY_TOKEN", "value": "not-allowed"}],
            [{"name": "checkin_relay_token"}],
            [{"name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": "false", "value_in_generated_artifacts": False}],
        ):
            with self.subTest(references=references):
                self.assertEqual(self.plan(credential_references=references)["error"], "invalid-input")
        exposed = self.plan(credential_references=[{
            "name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": True,
            "value_in_generated_artifacts": False,
        }])
        self.assertEqual(self.decision(exposed, "credential_references")["outcome"], "prohibited")

    def test_invalid_data_provenance_is_an_error_not_a_crash(self):
        out = self.plan(data_classes=["health records"], data_provenance="maybe", policy_state=self.approved)
        self.assertEqual(out["error"], "invalid-input")
        self.assertNotIn("outcome", out)
        self.assertNotIn("decisions", out)

    def test_data_provenance_label_reports_what_was_given(self):
        self.assertIsNone(self.plan(data_classes=["health records"])["labels"]["data_provenance"])
        self.assertEqual(self.plan(data_classes=["health records"], data_provenance="synthetic")["labels"]["data_provenance"], "synthetic")

    # ---------------------------------------------------------------- services

    def test_services_against_the_overlay(self):
        d = self.decision(self.plan(services=["the approved transactional email service"], policy_state=self.approved), "services")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("permitted", "The approved transactional email service", "company overlay"))
        d = self.decision(self.plan(services=["a browser extension"], policy_state=self.approved), "services")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("requires_review", "Browser extensions", "company overlay"))
        d = self.decision(self.plan(services=["Widgetron"], policy_state=self.approved), "services")
        self.assertEqual((d["outcome"], d["rule"], d["source"]), ("requires_review", "any new software service needs review", "generic default"))

    def test_explicit_empty_services_are_permitted_without_matching_service_names(self):
        for services in ([], ["none"], [" No Services "], ["n/a"]):
            with self.subTest(services=services):
                d = self.decision(self.plan(services=services, policy_state=self.approved), "services")
                self.assertEqual((d["value"], d["outcome"]), ([], "permitted"))
        d = self.decision(self.plan(services=["NoneCloud"], policy_state=self.approved), "services")
        self.assertEqual((d["value"], d["outcome"]), ("NoneCloud", "requires_review"))

    def test_every_named_service_needs_review_without_an_overlay(self):
        out = self.plan(services=["the approved transactional email service", "Widgetron"])
        for d in [d for d in out["decisions"] if d["field"] == "services"]:
            self.assertEqual((d["outcome"], d["rule"]), ("requires_review", "any new software service needs review"))
        self.assertTrue(out["labels"]["new_service"])

    def test_an_approved_service_suppresses_the_new_service_hint(self):
        out = self.plan("Use the approved transactional email service integration.", policy_state=self.approved)
        self.assertEqual(out["risks"], [])
        self.assertEqual(out["hints"], [])
        self.assertFalse(out["labels"]["new_service"])
        # Even with no overlay, "approved" directly before a service noun is a negation for the generic rule.
        self.assertEqual(self.plan("Use the approved transactional email service integration.")["hints"], [])
        # Naming it in `services` suppresses the hint for that name as well.
        out = self.plan("We will add the enrichment connector.", services=["approved enrichment connector"])
        self.assertEqual([h["component"] for h in out["hints"]], [])
        # An unapproved connector still hints.
        self.assertTrue(self.plan("We will add a new enrichment connector.")["hints"])

    # ---------------------------------------------------------------- write access

    def test_write_access(self):
        out = self.plan(write_access=True, policy_state=self.approved)
        d = self.decision(out, "write_access")
        self.assertEqual((d["value"], d["outcome"], d["rule"], d["source"]), (True, "requires_review", "Writes to a system of record", "company overlay"))
        self.assertTrue(out["ask_a_human"])
        d = self.decision(self.plan(write_access=True), "write_access")
        self.assertEqual((d["outcome"], d["source"]), ("requires_review", "generic default"))
        self.assertEqual(self.decision(self.plan(write_access=False), "write_access")["outcome"], "permitted")
        out = self.plan()
        self.assertEqual(self.decision(out, "write_access")["outcome"], "unknown")
        self.assertTrue(any("system of record" in q for q in out["checklist"]))

    # ---------------------------------------------------------------- hints and negation

    def test_mention_is_not_choice(self):
        for description in (
            "An internal dashboard. No external users or public links.",
            "Use synthetic patient records only; no actual health information.",
            "Made-up rows only, never real customer data.",
            "A sample file instead of the real customer export.",
        ):
            for state in (self.none, self.approved):
                with self.subTest(description=description, overlay=state.status):
                    out = mcp_tools.check_plan(description, self.guidance, state)
                    self.assertEqual(out["risks"], [], out["risks"])
                    self.assertEqual(out["hints"], [], out["hints"])
                    self.assertFalse(out["ask_a_human"])
                    self.assertEqual(out["outcome"], "unknown")
                    self.assertEqual(out["labels"]["sensitive_data"], [])

    def test_the_same_words_without_the_negation_still_hint(self):
        for description, component in (
            ("External users will use it", "access-and-identity"),
            ("Real patient records will be searchable", "data-in-prompts"),
            ("We will paste the smtp password into the code", "keys-and-credentials"),
        ):
            with self.subTest(description=description):
                out = self.plan(description)
                self.assertIn(component, [h["component"] for h in out["hints"]])
                self.assertTrue(out["ask_a_human"])
                self.assertEqual(out["outcome"], "unknown")
                self.assertTrue(all("hint" in h["note"] for h in out["hints"]))

    def test_a_hint_never_sets_the_outcome_and_a_field_overrides_it(self):
        out = self.plan("Real patient records will be searchable", data_classes=["synthetic patient records"], audience="the ops team")
        self.assertEqual(out["outcome"], "unknown")  # write_access and hosting are still unanswered
        self.assertEqual(self.decision(out, "data_classes")["outcome"], "permitted")
        self.assertIn("data-in-prompts", [h["component"] for h in out["hints"]])
        self.assertTrue(out["ask_a_human"])  # the hint alone still asks a human to look

    def test_overlay_hints_are_negated_too(self):
        out = mcp_tools.check_plan("An internal timer. Not on an unmanaged virtual machine, and no external users.", self.guidance, self.approved)
        self.assertEqual(out["risks"], [])
        self.assertEqual(out["labels"]["overlay_rules"], [])
        self.assertFalse(out["labels"]["unapproved_hosting"])

    def test_risks_say_whether_a_decision_or_a_hint_raised_them(self):
        out = self.plan("Customers will search the CRM export.", hosting="a personal cloud account", policy_state=self.approved)
        basis = {r["component"]: r["basis"] for r in out["risks"]}
        self.assertEqual(basis["hosting-and-where-it-runs"], "decision")
        self.assertEqual(basis["data-in-prompts"], "hint")
        self.assertTrue(all(r["basis"] in ("decision", "hint") for r in out["risks"]))

    def test_next_step_comes_from_the_worst_decision(self):
        out = self.plan("A small tool.", hosting="a personal cloud account", audience="our customers", policy_state=self.approved)
        self.assertEqual(out["next_step"], self.guidance["components"]["hosting-and-where-it-runs"]["do"][0])
        out = self.plan("A small tool.", audience="our customers", hosting="Internal App Platform", policy_state=self.approved)
        self.assertEqual(out["next_step"], self.guidance["components"]["access-and-identity"]["do"][0])
        out = self.plan("Real patient records will be searchable")
        self.assertEqual(out["next_step"], out["risks"][0]["safer_alternative"])
        self.assertIn("not approval", self.plan("A timer for the team.")["next_step"])

    def test_fully_benign_plan_is_permitted_overall(self):
        """Internal audience, synthetic data, approved hosting, approved service, no write access: a clean pass."""
        out = self.plan(
            "A small internal tool for the ops team.",
            audience="our ops team",
            data_classes=["synthetic patient records"],
            hosting="Internal App Platform",
            services=["the company LLM gateway"],
            write_access=False,
            policy_state=self.approved,
        )
        self.assertEqual(out["outcome"], "permitted")
        self.assertFalse(out["ask_a_human"])
        self.assertEqual(out["risks"], [])
        self.assertTrue(all(d["outcome"] == "permitted" for d in out["decisions"]))

    def test_fully_benign_local_plan_is_permitted_with_no_hosting_question(self):
        """A never-deployed local tool for an internal audience: permitted overall, and the
        hosting question is not left in the checklist since hosting has already been answered."""
        out = self.plan(
            "A small internal tool for the ops team that never leaves my machine.",
            audience="our ops team",
            data_classes=["synthetic patient records"],
            hosting="not deployed",
            services=["the company LLM gateway"],
            write_access=False,
            policy_state=self.approved,
        )
        self.assertEqual(out["outcome"], "permitted")
        self.assertFalse(out["ask_a_human"])
        self.assertEqual(out["risks"], [])
        self.assertEqual(out["labels"]["hosting"], "not_deployed")
        self.assertNotIn(self.guidance["components"]["hosting-and-where-it-runs"]["ask"][0], out["checklist"])
