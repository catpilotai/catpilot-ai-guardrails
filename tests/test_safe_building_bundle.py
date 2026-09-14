"""Bundler behavior for the safe-building tier: slots, overlays, guards. Offline."""

import copy
import datetime as dt
import shutil
import tempfile
import unittest
from pathlib import Path

import yaml

from tools import bundle, validate_overlay

ROOT = Path(__file__).resolve().parents[1]
TIER = ROOT / "src" / "skills" / "safe-building"
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"


def load_example():
    data, raw = validate_overlay.load_overlay_file(EXAMPLE)
    overlay, errors = validate_overlay.validate_overlay(data, {"intranet.example.org"}, today=dt.date(2026, 9, 13))
    assert not errors, errors
    return overlay, raw


class PublicBuildTests(unittest.TestCase):
    def test_public_build_is_deterministic_and_slot_free(self):
        with tempfile.TemporaryDirectory() as a, tempfile.TemporaryDirectory() as b:
            out_a = bundle.build_tier(TIER, Path(a))
            out_b = bundle.build_tier(TIER, Path(b))
            self.assertEqual(bundle._hash_tree(out_a), bundle._hash_tree(out_b))
            text = (out_a / "SKILL.md").read_text()
            self.assertNotIn("{{", text)
            fm, body = bundle.split_frontmatter(text)
            cp = fm["metadata"]["catpilot"]
            self.assertEqual(cp["mode"], "advisory")
            self.assertEqual(cp["training_module"], "399")
            self.assertEqual(cp["applies_to"]["surfaces"], ["app-builder", "chat", "coding-agent"])
            self.assertEqual(cp["severity"], "high")
            self.assertEqual([c["id"] for c in cp["bundle"]["components"]], sorted(d.name for d in TIER.iterdir() if d.is_dir()))
            self.assertIn("## Data in prompts", body)
            self.assertIn("Component: `data-in-prompts` · Course checkpoints: 3.1, 3.2", body)
            self.assertIn("This copy contains no company-specific values", body)

    def test_committed_bundles_match_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            for tier in bundle.discover_tiers():
                bundle.build_tier(tier, Path(tmp))
            self.assertEqual(bundle._hash_tree(Path(tmp)), bundle._hash_tree(bundle.DIST_ROOT))

    def test_slot_without_default_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "safe-building"
            shutil.copytree(TIER, src)
            skill = src / "untrusted-input" / "SKILL.md"
            skill.write_text(skill.read_text() + "\n{{no_such_slot}}\n")
            with self.assertRaisesRegex(ValueError, "no_such_slot"):
                bundle.build_tier(src, Path(tmp) / "out")

    def test_core_bundle_has_no_title_metadata_lines(self):
        text = (bundle.DIST_ROOT / "catpilot-security-core" / "SKILL.md").read_text()
        self.assertIn("## secret-blocking", text)
        self.assertNotIn("Component: `", text)
        self.assertNotIn("always-on guardrails", bundle.split_frontmatter(text)[0]["description"].lower())


class OverlayGuardTests(unittest.TestCase):
    def test_overlay_in_public_tree_refuses_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            shutil.copytree(ROOT / "src" / "skills", src)
            shutil.copyfile(EXAMPLE, src / "safe-building" / "overlay.yaml")
            with self.assertRaisesRegex(ValueError, "overlay-shaped"):
                bundle.guard_no_overlay_in_public_tree([src])
            # Content-shaped detection does not depend on the file name.
            (src / "safe-building" / "overlay.yaml").rename(src / "safe-building" / "values.yaml")
            with self.assertRaises(ValueError):
                bundle.guard_no_overlay_in_public_tree([src])

    def test_clean_tree_passes_guard(self):
        bundle.guard_no_overlay_in_public_tree()


class PrivateBuildTests(unittest.TestCase):
    def test_private_bundle_renders_overlay_values_and_provenance(self):
        overlay, raw = load_example()
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(TIER, Path(tmp), overlay=overlay, overlay_bytes=raw)
            self.assertEqual(out.name, "catpilot-safe-building-example-org")
            text = (out / "SKILL.md").read_text()
            self.assertNotIn("{{", text)
            for expected in ("Example Org", "security-review@example.org", "Internal App Platform (company sign-in)", "internal-lookup-tool: https://intranet.example.org/templates/lookup", "reviewed for Example Org on 2026-09-13 and expire on 2027-03-13"):
                self.assertIn(expected, text)
            fm, body = bundle.split_frontmatter(text)
            meta = fm["metadata"]["catpilot"]["overlay"]
            self.assertEqual(meta["organization"], "Example Org")
            self.assertEqual(meta["reviewed_on"], "2026-09-13")
            self.assertEqual(len(meta["overlay_sha256"]), 64)
            self.assertEqual(len(meta["content_sha256"]), 64)
            self.assertEqual(fm["name"], "catpilot-safe-building-example-org")
            # Baseline text survives; the overlay only fills slots.
            self.assertIn("Never suggest that deleting names", body)

    def test_private_out_inside_repository_is_refused(self):
        code = bundle.cmd_private(EXAMPLE, ROOT / "private-skills", ["intranet.example.org"], None)
        self.assertEqual(code, 2)
        self.assertFalse((ROOT / "private-skills").exists())

    def test_expired_overlay_is_refused(self):
        data, _ = validate_overlay.load_overlay_file(EXAMPLE)
        data = copy.deepcopy(data)
        data["expires_on"] = dt.date(2026, 1, 1)
        with self.assertRaises(validate_overlay.OverlayError):
            validate_overlay.validate_overlay(data, {"intranet.example.org"})
        data["expires_on"] = dt.date(2026, 9, 20)
        _, errors = validate_overlay.validate_overlay(data, {"intranet.example.org"}, today=dt.date(2026, 10, 1))
        self.assertTrue(any("has passed" in e for e in errors))

    def test_core_tier_has_no_slots_so_overlay_is_rejected(self):
        overlay, raw = load_example()
        with tempfile.TemporaryDirectory() as tmp, self.assertRaisesRegex(ValueError, "no slots"):
            bundle.build_tier(ROOT / "src" / "skills" / "core", Path(tmp), overlay=overlay, overlay_bytes=raw)


if __name__ == "__main__":
    unittest.main()
