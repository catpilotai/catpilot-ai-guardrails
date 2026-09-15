"""Skill directory validator over the repository and over broken synthetic skills."""

import json
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

    def test_built_bundle_with_a_non_string_metadata_value_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(ROOT / "src" / "skills" / "safe-building", Path(tmp))
            skill = out / "SKILL.md"
            fm, body = bundle.split_frontmatter(skill.read_text())
            fm["metadata"]["catpilot-components"] = [
                {"id": "data-in-prompts", "version": "1.0.0"}
            ]
            skill.write_text(bundle.render_skill_md(fm, body))
            errors, _ = validate_skill.validate_skill_dir(out)
            self.assertTrue(any("only string values under metadata" in e for e in errors), errors)

    def test_built_bundle_whose_manifest_components_disagree_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(ROOT / "src" / "skills" / "safe-building", Path(tmp))
            manifest_path = out / bundle.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text())
            manifest["bundle"]["components"][0]["version"] = "9.9.9"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            errors, _ = validate_skill.validate_skill_dir(out)
            self.assertTrue(any("does not match" in e for e in errors), errors)

    def test_built_bundle_with_a_missing_or_unparseable_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(ROOT / "src" / "skills" / "core", Path(tmp))
            manifest_path = out / bundle.MANIFEST_NAME
            manifest = json.loads(manifest_path.read_text())
            manifest["bundle"]["components"][0]["reference"] = "references/gone.md"
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
            errors, _ = validate_skill.validate_skill_dir(out)
            self.assertTrue(any("missing reference" in e for e in errors), errors)

            manifest_path.write_text("{not json")
            errors, _ = validate_skill.validate_skill_dir(out)
            self.assertTrue(any("does not parse" in e for e in errors), errors)

            manifest_path.unlink()
            errors, _ = validate_skill.validate_skill_dir(out)
            self.assertTrue(any("not a file in the skill directory" in e for e in errors), errors)

    def test_cli(self):
        self.assertEqual(validate_skill.main([]), 0)


if __name__ == "__main__":
    unittest.main()
