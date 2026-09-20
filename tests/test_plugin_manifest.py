"""The plugin manifest and one-entry marketplace stay a skills-only package that names the shipped skills."""

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PluginManifestTests(unittest.TestCase):
    def test_manifest_names_and_layout(self):
        manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(manifest["name"], "catpilot-guardrails")
        self.assertEqual(manifest["license"], "MIT")
        for key in ("skills", "hooks", "mcpServers", "commands", "agents"):
            self.assertNotIn(key, manifest, f"{key} would change what the plugin carries; the README and DEPLOY_ORG say skills only")
        # Skills are auto-discovered from skills/: every shipped skill has a SKILL.md whose name matches its directory.
        shipped = sorted(p.name for p in (ROOT / "skills").iterdir() if p.is_dir())
        self.assertEqual(shipped, ["catpilot-safe-building", "catpilot-security-core"])
        for name in shipped:
            text = (ROOT / "skills" / name / "SKILL.md").read_text()
            self.assertIn(f"name: {name}\n", text)

    def test_plugin_stays_skills_only(self):
        # A hooks/hooks.json or a root .mcp.json would be auto-loaded by the plugin and turn it into something
        # the docs do not describe (and would earn the "Desktop only" label on a ChatGPT workspace import).
        self.assertFalse((ROOT / "hooks" / "hooks.json").exists())
        self.assertFalse((ROOT / ".mcp.json").exists())

    def test_marketplace_points_at_the_repository_root(self):
        marketplace = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text())
        self.assertEqual(marketplace["name"], "catpilot")
        self.assertTrue(marketplace["description"])
        self.assertEqual(marketplace["owner"]["name"], "Catpilot")
        self.assertEqual([p["name"] for p in marketplace["plugins"]], ["catpilot-guardrails"])
        self.assertEqual(marketplace["plugins"][0]["source"], "./")
        manifest = json.loads((ROOT / ".claude-plugin" / "plugin.json").read_text())
        self.assertEqual(marketplace["plugins"][0]["version"], manifest["version"])


if __name__ == "__main__":
    unittest.main()
