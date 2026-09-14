"""Bundler safety: adversarial filesystem and YAML cases, run only in disposable temporary directories."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from tools import bundle

FRONTMATTER = {
    "name": "demo-safety",
    "description": "A demo safety rule.",
    "license": "MIT",
    "metadata": {"catpilot": {"id": "demo-safety", "version": "1.0.0", "severity": "high", "category": "demo"}},
}
CONFIG = {"name": "demo-core", "tier": "core", "version": "2026.09.14", "description": "A demo.", "preamble": "# Demo\n\nRead the rules."}


class BundleSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tier = self.root / "source" / "core"
        self.skill_dir = self.tier / "demo-safety"
        self.skill_dir.mkdir(parents=True)
        self.dist = self.root / "dist"
        self.config = dict(CONFIG)
        self.write_config()
        self.write_skill()

    def write_config(self):
        self.tier.joinpath("bundle.toml").write_text("[bundle]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in self.config.items()), encoding="utf-8")

    def write_skill(self, body="## Rules\n\nHelp safe work proceed.\n"):
        self.skill_dir.joinpath("SKILL.md").write_text(bundle.render_skill_md(FRONTMATTER, body), encoding="utf-8")

    def test_repository_sources_pass_the_checks(self):
        for tier in bundle.discover_tiers():
            bundle.load_bundle_cfg(tier)
            bundle.load_tier_skills(tier)

    def test_duplicate_yaml_keys_and_non_mapping_frontmatter_rejected(self):
        for content in ("name: a\nname: b", "[a, b]", "metadata:\n  x: 1\n  x: 2", "? [1, 2]\n: x"):
            with self.subTest(content=content), self.assertRaises(ValueError):
                bundle.split_frontmatter("---\n" + content + "\n---\nbody")
        fm, body = bundle.split_frontmatter("---\nname: a\n---\nbody")
        self.assertEqual((fm, body), ({"name": "a"}, "body"))

    def test_source_symlink_rejected_without_following(self):
        outside = self.root / "outside.txt"
        outside.write_text("private synthetic sentinel")
        scripts = self.skill_dir / "scripts"
        scripts.mkdir()
        (scripts / "linked.txt").symlink_to(outside)
        with self.assertRaisesRegex(ValueError, "regular files"):
            bundle.build_tier(self.tier, self.dist)
        self.assertEqual(outside.read_text(), "private synthetic sentinel")
        self.assertFalse(self.dist.exists())

    def test_output_root_symlink_rejected(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        self.dist.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            bundle.build_tier(self.tier, self.dist)
        self.assertEqual(list(elsewhere.iterdir()), [])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO test")
    def test_special_file_in_source_rejected(self):
        scripts = self.skill_dir / "scripts"
        scripts.mkdir()
        os.mkfifo(scripts / "pipe")
        with self.assertRaisesRegex(ValueError, "regular files"):
            bundle.load_source_skill(self.skill_dir)

    def test_malicious_names_are_rejected_before_any_deletion(self):
        victim = self.root / "outside"
        victim.mkdir()
        sentinel = victim / "keep.txt"
        sentinel.write_text("preserve me")
        for field, value in (("name", "../outside"), ("name", str(victim)), ("name", "."), ("name", ".."), ("name", "x/y"), ("name", "a" * 65), ("tier", "../bad"), ("tier", "x/y")):
            with self.subTest(field=field, value=value):
                self.config = dict(CONFIG, **{field: value})
                self.write_config()
                with self.assertRaises(ValueError):
                    bundle.build_tier(self.tier, self.dist)
                self.assertEqual(sentinel.read_text(), "preserve me")
                self.assertFalse(self.dist.exists())

    def test_invalid_config_does_not_replace_previous_output(self):
        output = bundle.build_tier(self.tier, self.dist)
        before = bundle._hash_tree(output)
        self.assertTrue(before)
        for field, value in (("version", "2026.02.30"), ("version", "not-calver"), ("description", "x" * 1025), ("preamble", " ")):
            with self.subTest(field=field, value=value):
                self.config = dict(CONFIG, **{field: value})
                self.write_config()
                with self.assertRaises(ValueError):
                    bundle.build_tier(self.tier, self.dist)
                self.assertEqual(before, bundle._hash_tree(output))

    def test_build_is_deterministic(self):
        first = bundle._hash_tree(bundle.build_tier(self.tier, self.dist))
        second = bundle._hash_tree(bundle.build_tier(self.tier, self.dist))
        self.assertEqual(first, second)
        self.assertIn("SKILL.md", first)
