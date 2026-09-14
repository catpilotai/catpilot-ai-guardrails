"""Skill directory validator over the repository and over broken synthetic skills."""

import shutil
import tempfile
import unittest
from pathlib import Path

from tools import bundle, validate_skill

ROOT = Path(__file__).resolve().parents[1]


class ValidateSkillTests(unittest.TestCase):
    def test_repository_skills_validate(self):
        for path in validate_skill.default_paths():
            errors, _ = validate_skill.validate_skill_dir(path)
            self.assertEqual(errors, [], path)
        self.assertGreaterEqual(len(validate_skill.default_paths()), 19)

    def test_broken_source_skill_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "data-in-prompts"
            shutil.copytree(ROOT / "src" / "skills" / "safe-building" / "data-in-prompts", src)
            text = (src / "SKILL.md").read_text()
            (src / "SKILL.md").write_text(text.replace("license: MIT\n", ""))
            errors, _ = validate_skill.validate_skill_dir(src)
            self.assertTrue(any("license" in e for e in errors))
            renamed = Path(tmp) / "renamed"
            src.rename(renamed)
            errors, _ = validate_skill.validate_skill_dir(renamed)
            self.assertTrue(any("directory name" in e for e in errors))

    def test_bundle_with_unresolved_slot_or_broken_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(ROOT / "src" / "skills" / "safe-building", Path(tmp))
            skill = out / "SKILL.md"
            skill.write_text(skill.read_text() + "\nLeftover {{owner}} and a [link](references/missing.md).\n")
            errors, _ = validate_skill.validate_skill_dir(out)
            self.assertTrue(any("unresolved" in e for e in errors))
            self.assertTrue(any("broken local link" in e for e in errors))

    def test_cli(self):
        self.assertEqual(validate_skill.main([]), 0)


if __name__ == "__main__":
    unittest.main()
