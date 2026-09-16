"""Per-host artifact rendering: determinism, layout, size budgets, stamps. Offline."""

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools import bundle, targets

ROOT = Path(__file__).resolve().parents[1]
TIER = ROOT / "src" / "skills" / "safe-building"
EXPECTED_FILES = {
    "README.md",
    "catpilot-safe-building.zip",
    "chatgpt-project-instructions.md",
    "copilot-agent-instructions.md",
    "copilot-declarative-agent.stub.json",
    "AGENTS.md",
    "copilot-instructions.md",
    "lovable-knowledge.md",
    "bolt-prompt.txt",
    "replit-instructions.md",
    "v0-instructions.md",
    "web/safe-ai-building.html",
}


class TargetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        base = Path(cls.tmp.name)
        cls.cfg = bundle.load_bundle_cfg(TIER)
        bundle.build_tier(TIER, base / "skills", with_targets=True, targets_root=base / "dist")
        cls.release_dir = base / "dist" / cls.cfg["version"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_expected_files_and_determinism(self):
        files = {str(p.relative_to(self.release_dir)) for p in self.release_dir.rglob("*") if p.is_file()}
        self.assertEqual(files, EXPECTED_FILES)
        with tempfile.TemporaryDirectory() as tmp:
            bundle.build_tier(TIER, Path(tmp) / "skills", with_targets=True, targets_root=Path(tmp) / "dist")
            self.assertEqual(bundle._hash_tree(Path(tmp) / "dist"), bundle._hash_tree(self.release_dir.parent))

    def test_committed_dist_matches_sources(self):
        self.assertEqual(bundle._hash_tree(self.release_dir.parent), bundle._hash_tree(bundle.TARGETS_ROOT))

    def test_zip_has_single_top_level_folder_with_skill_and_manifest(self):
        with zipfile.ZipFile(self.release_dir / "catpilot-safe-building.zip") as zf:
            names = zf.namelist()
            self.assertEqual(names, ["catpilot-safe-building/", "catpilot-safe-building/SKILL.md", "catpilot-safe-building/catpilot.json"])
            for member in ("SKILL.md", "catpilot.json"):
                shipped = zf.read(f"catpilot-safe-building/{member}").decode("utf-8")
                self.assertEqual(shipped, (bundle.DIST_ROOT / "catpilot-safe-building" / member).read_text(), member)
            for info in zf.infolist():
                self.assertEqual(info.date_time[:3], tuple(int(part) for part in self.cfg["version"].split(".")))

    def test_paste_targets_fit_instruction_limits_and_carry_release(self):
        release = self.cfg["version"]
        for name in ("chatgpt-project-instructions.md", "copilot-agent-instructions.md", "lovable-knowledge.md", "bolt-prompt.txt", "replit-instructions.md", "v0-instructions.md", "AGENTS.md", "copilot-instructions.md"):
            text = (self.release_dir / name).read_text()
            self.assertIn(release, text.splitlines()[0], name)
            self.assertLessEqual(len(text), targets.PASTE_LIMIT, name)
            self.assertNotIn("{{", text)
            for title in ("Data in prompts", "Access and identity", "Hosting and where it runs", "Sharing and publishing", "Keys and credentials", "Third-party services", "Untrusted input", "When to ask a human"):
                self.assertIn(title, text, name)
        stub = json.loads((self.release_dir / "copilot-declarative-agent.stub.json").read_text())
        self.assertLessEqual(len(stub["instructions"]), targets.PASTE_LIMIT)
        self.assertIn(release, stub["description"])

    def test_web_page_lists_checkpoints_and_tabs(self):
        page = (self.release_dir / "web" / "safe-ai-building.html").read_text()
        for tab in ("claude", "chatgpt", "copilot", "lovable", "bolt", "replit", "v0", "agents"):
            self.assertIn(f'id="panel-{tab}"', page)
        self.assertEqual(page.count("<li><h3>"), 8)
        self.assertIn("npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-safe-building", page)
        self.assertIn("not monitoring, not enforcement", page)
        self.assertNotIn("{{", page)
        self.assertNotIn("<script src=", page)

    def test_condensed_rejects_oversized_output(self):
        skills = bundle.load_tier_skills(TIER)
        rendered = {s.id: bundle.render_slots(s.body, self.cfg["slots"], s.id) for s in skills}
        digests = [targets.digest(s, rendered[s.id]) for s in sorted(skills, key=lambda s: s.id)]
        digests[0]["do"] = ["x" * 9000]
        with self.assertRaisesRegex(ValueError, "paste limit"):
            targets.condensed(self.cfg, digests, self.cfg["preamble"], self.cfg["version"])


if __name__ == "__main__":
    unittest.main()
