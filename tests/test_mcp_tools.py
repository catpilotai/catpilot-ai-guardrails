"""The reference MCP server's tools as pure functions. No SDK, no network, no model."""

import copy
import datetime as dt
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

from catpilot_guardrails_mcp import content, policy  # noqa: E402
from catpilot_guardrails_mcp import tools as mcp_tools  # noqa: E402

EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
TODAY = dt.date(2026, 9, 14)


class Fixtures:
    guidance = content.load_guidance()
    templates = content.load_templates()
    none = policy.load_policy(None)
    approved = policy.load_policy(str(EXAMPLE), {"intranet.example.org"}, now=TODAY)
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
        self.assertEqual(out["labels"]["audience"], "named")
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
        out = mcp_tools.check_plan("A timer.", Fixtures.guidance, Fixtures.none, hosting="the team server")
        self.assertEqual(out["labels"]["hosting"], "unchecked")

    def test_named_hosting_off_the_approved_list_cites_the_list(self):
        out = mcp_tools.check_plan("A dashboard for the sales team.", Fixtures.guidance, Fixtures.approved, hosting="a shared workstation in the lab")
        risk = self.hosting_risk(out)
        self.assertEqual(out["labels"]["hosting"], "not approved")
        self.assertEqual(risk["overlay_list"], "hosting.approved")
        self.assertIn("Internal App Platform (company sign-in)", risk["rule"])
        self.assertEqual(risk["evidence"], ["shared", "workstation", "lab"])
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
        out = mcp_tools.get_template("internal-lookup-tool", Fixtures.templates, Fixtures.guidance, Fixtures.approved)
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
        self.assertEqual(policy.load_policy(str(EXAMPLE), set(), now=TODAY).status, "invalid")  # template host not allowlisted
        self.assertEqual(len(Fixtures.approved.source["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
