"""Per-host artifact rendering: determinism, layout, size budgets, stamps. Offline."""

import datetime as dt
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools import bundle, targets, validate_overlay

ROOT = Path(__file__).resolve().parents[1]
TIER = ROOT / "src" / "skills" / "safe-building"
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
EXPECTED_FILES = {
    "README.md",
    "catpilot-safe-building.zip",
    "chatgpt-project-instructions.md",
    "copilot-agent-instructions.md",
    "copilot-declarative-agent.stub.json",
    "AGENTS.md",
    "CLAUDE.md",
    "copilot-instructions.md",
    "lovable-knowledge.md",
    "bolt-prompt.txt",
    "replit-instructions.md",
    "v0-instructions.md",
    "web/safe-ai-building.html",
}
PASTE_FILES = (
    "chatgpt-project-instructions.md", "copilot-agent-instructions.md", "copilot-instructions.md", "AGENTS.md", "CLAUDE.md",
    "lovable-knowledge.md", "bolt-prompt.txt", "replit-instructions.md", "v0-instructions.md",
)
# The rules every paste block must keep, public or private.
PASTE_RULES = (
    "never both",
    "stands in for the real file",
    "stub that sends nothing",
    "APP_API_TOKEN names a setting",
    "Build without reading its value; let code read it at runtime.",
    "replace (rotate) it",
)
CHECKPOINT_TITLES = (
    "Data in prompts", "Access and identity", "Hosting and where it runs", "Sharing and publishing",
    "Keys and credentials", "Third-party services", "Untrusted input", "When to ask a human",
)


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
                stamped = bundle.calver_date(self.cfg["version"])
                self.assertEqual(info.date_time[:3], (stamped.year, stamped.month, stamped.day))

    def test_paste_targets_keep_the_critical_rules(self):
        """The condensed renderer keeps the first three safe alternatives per checkpoint, so the rules that matter most must sit there."""
        for name in PASTE_FILES:
            text = (self.release_dir / name).read_text()
            for phrase in PASTE_RULES:
                self.assertIn(phrase, text, f"{name} lost the rule: {phrase}")

    def test_paste_targets_fit_instruction_limits_and_carry_release(self):
        release = self.cfg["version"]
        for name in ("chatgpt-project-instructions.md", "copilot-agent-instructions.md", "lovable-knowledge.md", "bolt-prompt.txt", "replit-instructions.md", "v0-instructions.md", "AGENTS.md", "CLAUDE.md", "copilot-instructions.md"):
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
        with self.assertRaisesRegex(ValueError, "paste limit.*Tighten the component bullets"):
            targets.condensed(self.cfg, digests, self.cfg["preamble"], self.cfg["version"])


class PrivatePasteTests(unittest.TestCase):
    """Private builds add the company values, so the paste text leaves out
    items to fit, and never the rules every paste block must keep."""

    @classmethod
    def setUpClass(cls):
        cls.cfg = bundle.load_bundle_cfg(TIER)
        skills = bundle.load_tier_skills(TIER)
        rendered = {s.id: bundle.render_slots(s.body, cls.cfg["slots"], s.id) for s in skills}
        cls.digests = [targets.digest(s, rendered[s.id]) for s in sorted(skills, key=lambda s: s.id)]
        cls.full = targets.condensed(cls.cfg, cls.digests, cls.cfg["preamble"], cls.cfg["version"])

    def paste(self, values_block: str) -> str:
        return targets.condensed(self.cfg, self.digests, self.cfg["preamble"], self.cfg["version"], values_block=values_block)

    def stop_counts(self, text: str) -> list[int]:
        return [line.count("; ") + 1 for line in text.splitlines() if line.startswith("Stop and ask a human if: ")]

    def test_short_company_values_leave_everything_in(self):
        text = self.paste("Company values: short.")
        self.assertEqual(text.count("Company values: short."), 1)
        self.assertEqual(self.stop_counts(text), self.stop_counts(self.full))
        for phrase in PASTE_RULES:
            self.assertIn(phrase, text)

    def test_stop_triggers_go_before_safe_alternatives_and_one_of_each_stays(self):
        budget = targets.PASTE_LIMIT - targets.PASTE_HEADROOM
        self.assertEqual(self.stop_counts(self.full), [3] * 8)
        full_do = [line for line in self.full.splitlines() if line.startswith("Do: ")]
        previous = [3] * 8
        trimmed_do = False
        for size in range(250, 3750, 250):
            with self.subTest(values=size):
                text = self.paste("v" * size)
                self.assertLessEqual(len(text), budget)
                for title in CHECKPOINT_TITLES:
                    self.assertIn(title, text)
                counts = self.stop_counts(text)
                self.assertEqual(len(counts), 8)
                self.assertTrue(all(1 <= c <= p for c, p in zip(counts, previous)), counts)
                do = [line for line in text.splitlines() if line.startswith("Do: ")]
                self.assertEqual(len(do), 8)
                if do != full_do:
                    trimmed_do = True
                    self.assertEqual(counts, [1] * 8, "a safe alternative went while a checkpoint still had a second stop trigger")
                    self.assertTrue(all(line.startswith(first.split(". ")[0]) for line, first in zip(do, full_do)))
                else:
                    for phrase in PASTE_RULES:
                        self.assertIn(phrase, text)
                previous = counts
        self.assertTrue(trimmed_do, "the sizes tried never reached the safe alternatives")

    def test_company_values_too_long_to_fit_name_the_overlay(self):
        with self.assertRaisesRegex(ValueError, r"company values take 7000\. Shorten the overlay's lists by at least \d+ characters"):
            self.paste("v" * 7000)

    def test_private_paste_blocks_keep_the_rules_with_longer_company_values(self):
        data, raw = validate_overlay.load_overlay_file(EXAMPLE)
        data["owner"] = "kestrel-rules-test-with-a-longer-address@example.org"
        data["hosting"]["approved"] = [h.replace("Internal App Platform", "Kestrel Test Platform") for h in data["hosting"]["approved"]]
        data["services"]["needs_review"] = data["services"]["needs_review"] + ["Any automation that posts to a shared channel"]
        overlay, errors = validate_overlay.validate_overlay(data, {"intranet.example.org"}, today=dt.date(2026, 9, 13))
        self.assertEqual(errors, [])
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(TIER, Path(tmp), overlay=overlay, overlay_bytes=raw, with_targets=True)
            hosts = Path(tmp) / f"{out.name}-hosts"
            for name in PASTE_FILES:
                text = (hosts / name).read_text()
                self.assertLessEqual(len(text), targets.PASTE_LIMIT, name)
                for expected in PASTE_RULES + ("Kestrel Test Platform", "kestrel-rules-test-with-a-longer-address@example.org"):
                    self.assertIn(expected, text, f"{name} lost: {expected}")


if __name__ == "__main__":
    unittest.main()
