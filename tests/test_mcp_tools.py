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
        expired = mcp_tools.list_approved("contacts", Fixtures.guidance, Fixtures.expired)
        self.assertTrue(expired["unknown_policy"])
        self.assertIn("EXPIRED", expired["source"])
        self.assertEqual(mcp_tools.list_approved("nope", Fixtures.guidance, Fixtures.none)["error"], "unknown-category")


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
