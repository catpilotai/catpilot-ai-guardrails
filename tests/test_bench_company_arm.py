"""Information-equivalent static company-policy arm. Synthetic, offline only."""

import datetime as dt
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

from tools import validate_overlay
from tools.bench import sandbox


def company_overlay() -> dict:
    today = dt.date.today()
    return {
        "schema_version": 1,
        "organization": "Sample Company",
        "owner": "security@example.org",
        "reviewed_on": today - dt.timedelta(days=1),
        "expires_on": today + dt.timedelta(days=30),
        "data_classes": {
            "never_in_prompts": ["Payment card details"],
            "ok_with_approval": ["Customer names"],
            "ok": ["Synthetic records"],
        },
        "hosting": {"approved": ["Company App Platform"], "not_approved": ["Personal accounts"]},
        "services": {"approved": ["Company LLM Gateway"], "needs_review": ["New model endpoints"]},
        "identity": {"default": "Company sign-in", "never": ["Public links"]},
        "review_triggers": ["Writes to a system of record"],
        "templates": [{"kind": "dashboard", "location": "https://intranet.example.org/templates/dashboard"}],
    }


class CompanyChecklistArmTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.overlay = self.root / "overlay.yaml"
        self.data = company_overlay()
        self.write_overlay()
        self.env = mock.patch.dict(os.environ, {"CATPILOT_TEMPLATE_HOSTS": " intranet.example.org, "})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.skill_source = self.root / "skill-source"
        self.skill_source.mkdir()
        (self.skill_source / "SKILL.md").write_text("Synthetic skill.\n", encoding="utf-8")

    def write_overlay(self):
        self.overlay.write_text(yaml.safe_dump(self.data, sort_keys=False), encoding="utf-8")

    def build(self, host="claude-code", arm="F", planted=None):
        return sandbox.build_sandbox(
            {"id": "synthetic-company-policy", "sandbox": planted or []},
            arm,
            self.root / f"{host}-{arm}",
            host=host,
            skill_source=self.skill_source,
            server_script=self.root / "unused-server.py",
            python="unused-python",
            overlay_file=self.overlay,
        )

    def policy_from_instruction(self, text):
        return yaml.safe_load(text.split("```yaml\n", 1)[1].split("\n```", 1)[0])

    def test_f_has_company_values_but_no_mcp_transport(self):
        self.assertIn("F", sandbox.ARMS)
        self.assertIn("F", sandbox.VALUE_ARMS)
        self.assertNotIn("F", sandbox.MCP_ARMS)
        self.assertEqual(sandbox.MCP_ARMS, ("C", "D"))
        self.assertIn("complete validated company overlay", sandbox.ARM_NOTES["F"])

    def test_f_plants_the_same_checklist_and_every_company_fact_for_both_hosts(self):
        for host, filename in (("claude-code", "CLAUDE.md"), ("codex", "AGENTS.md")):
            with self.subTest(host=host):
                box = self.build(host)
                text = (box.project / filename).read_text(encoding="utf-8")
                self.assertTrue(text.startswith(sandbox.CHECKLIST_INSTRUCTION + "\n\n"))
                self.assertEqual(self.policy_from_instruction(text), self.data)
                self.assertIn(hashlib.sha256(self.overlay.read_bytes()).hexdigest(), text)
                self.assertNotIn(str(self.overlay), text)
                self.assertIsNone(box.skill_installed_at)
                self.assertFalse((box.project / ".claude").exists())
                self.assertFalse((box.project / ".agents").exists())
                self.assertEqual(box.mcp_config, {"mcpServers": {}})
                self.assertEqual(box.overlay_file, self.overlay)
                self.assertIn(filename, box.planted)

    def test_d_and_f_reference_the_exact_same_overlay_input(self):
        dynamic = self.build(arm="D")
        static = self.build(arm="F")
        server_overlay = dynamic.mcp_config["mcpServers"][sandbox.MCP_SERVER_NAME]["env"]["CATPILOT_OVERLAY_FILE"]
        self.assertEqual(Path(server_overlay), static.overlay_file.resolve())
        self.assertEqual(
            dynamic.mcp_config["mcpServers"][sandbox.MCP_SERVER_NAME]["env"]["CATPILOT_TEMPLATE_HOSTS"],
            os.environ["CATPILOT_TEMPLATE_HOSTS"],
        )
        self.assertEqual(sandbox.load_overlay(dynamic.overlay_file), sandbox.load_overlay(static.overlay_file))
        text = (static.project / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertEqual(self.policy_from_instruction(text), validate_overlay.validate_structure(sandbox.load_overlay(dynamic.overlay_file)))

    def test_existing_instructions_survive_and_policy_counts_as_planted(self):
        box = self.build(
            planted=[{"path": "CLAUDE.md", "content": "# Existing project\n\nKeep the sample fixture.\n"}]
        )
        text = (box.project / "CLAUDE.md").read_text(encoding="utf-8")
        self.assertTrue(text.startswith("# Existing project\n\nKeep the sample fixture.\n\n"))
        self.assertEqual(box.planted.count("CLAUDE.md"), 1)
        before = sandbox.snapshot(box.project)
        (box.project / "app.py").write_text("print('sample')\n", encoding="utf-8")
        self.assertEqual(sandbox.diff(before, sandbox.snapshot(box.project)), {"created": ["app.py"], "changed": [], "deleted": []})

    def test_templates_are_preserved_including_entries_without_locations(self):
        self.data["templates"].append({"kind": "local-report"})
        self.write_overlay()
        text = sandbox.company_checklist_instruction(self.overlay)
        self.assertEqual(self.policy_from_instruction(text)["templates"], self.data["templates"])

    def test_absent_optional_templates_normalize_to_empty_list(self):
        self.data.pop("templates")
        self.write_overlay()
        self.assertEqual(self.policy_from_instruction(sandbox.company_checklist_instruction(self.overlay))["templates"], [])

    def test_overlay_requires_all_policy_fields(self):
        self.data.pop("identity")
        self.write_overlay()
        with self.assertRaisesRegex(ValueError, "missing fields"):
            self.build()

    def test_expired_and_future_overlays_are_rejected_before_the_run(self):
        today = dt.date.today()
        cases = (
            (today - dt.timedelta(days=30), today - dt.timedelta(days=1), "has passed"),
            (today + dt.timedelta(days=1), today + dt.timedelta(days=30), "in the future"),
        )
        for reviewed, expires, error in cases:
            with self.subTest(error=error):
                self.data["reviewed_on"] = reviewed
                self.data["expires_on"] = expires
                self.write_overlay()
                with self.assertRaisesRegex(ValueError, error):
                    sandbox.company_checklist_instruction(self.overlay)

    def test_template_allowlist_matches_server_environment(self):
        with mock.patch.dict(os.environ, {"CATPILOT_TEMPLATE_HOSTS": ""}):
            with self.assertRaisesRegex(ValueError, "not on the allowlist"):
                self.build()

    def test_content_rejection_does_not_silently_remove_policy_fields(self):
        self.data["services"]["approved"].append("api_key=abcdefghijklmnopqrstuvwxyz123456")
        self.write_overlay()
        with self.assertRaisesRegex(ValueError, "looks like a secret"):
            sandbox.company_checklist_instruction(self.overlay)

    def test_missing_relative_and_symlink_inputs_are_rejected(self):
        with self.assertRaises(FileNotFoundError):
            sandbox.company_checklist_instruction(self.root / "missing.yaml")
        with self.assertRaisesRegex(ValueError, "absolute path"):
            sandbox.company_checklist_instruction(Path("overlay.yaml"))
        link = self.root / "linked.yaml"
        link.symlink_to(self.overlay)
        with self.assertRaisesRegex(ValueError, "symlinks are not allowed"):
            sandbox.company_checklist_instruction(link)

    def test_static_rendering_does_not_mutate_the_overlay_source(self):
        raw = self.overlay.read_bytes()
        sandbox.company_checklist_instruction(self.overlay)
        self.assertEqual(self.overlay.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
