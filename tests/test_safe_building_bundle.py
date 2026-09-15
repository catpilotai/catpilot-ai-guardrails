"""Bundler behavior for the safe-building tier: slots, overlays, guards. Offline."""

import copy
import datetime as dt
import json
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
            meta = fm["metadata"]
            manifest = json.loads((out_a / bundle.MANIFEST_NAME).read_text())
            self.assertEqual(meta["catpilot-mode"], "advisory")
            self.assertEqual(manifest["training_module"], "399")
            self.assertEqual(manifest["applies_to"]["surfaces"], ["app-builder", "chat", "coding-agent"])
            self.assertEqual(meta["catpilot-severity"], "high")
            self.assertEqual([c["id"] for c in manifest["bundle"]["components"]], sorted(d.name for d in TIER.iterdir() if d.is_dir()))
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


class ShippedMetadataTests(unittest.TestCase):
    """Shipped frontmatter is string-only, as the Agent Skills specification
    requires, and catpilot.json carries every field the nested block used to."""

    def bundles(self):
        return sorted(d for d in bundle.DIST_ROOT.iterdir() if d.is_dir())

    def test_every_metadata_value_in_a_shipped_bundle_is_a_string(self):
        for bundle_dir in self.bundles():
            with self.subTest(bundle=bundle_dir.name):
                fm, _ = bundle.split_frontmatter((bundle_dir / "SKILL.md").read_text())
                meta = fm["metadata"]
                self.assertTrue(meta)
                for key, value in meta.items():
                    self.assertIsInstance(key, str, key)
                    self.assertIsInstance(value, str, key)
                self.assertEqual(meta["catpilot-manifest"], bundle.MANIFEST_NAME)
                self.assertEqual(list(meta), [k for k in bundle.METADATA_KEY_ORDER if k in meta])

    def test_components_field_matches_the_manifest(self):
        for bundle_dir in self.bundles():
            with self.subTest(bundle=bundle_dir.name):
                fm, _ = bundle.split_frontmatter((bundle_dir / "SKILL.md").read_text())
                manifest = json.loads((bundle_dir / bundle.MANIFEST_NAME).read_text())
                self.assertEqual(
                    bundle.parse_components_field(fm["metadata"]["catpilot-components"]),
                    [(c["id"], c["version"]) for c in manifest["bundle"]["components"]],
                )

    def test_manifest_is_sorted_json_with_a_trailing_newline(self):
        for bundle_dir in self.bundles():
            with self.subTest(bundle=bundle_dir.name):
                text = (bundle_dir / bundle.MANIFEST_NAME).read_text()
                self.assertTrue(text.endswith("}\n"))
                self.assertEqual(text, json.dumps(json.loads(text), indent=2, sort_keys=True, ensure_ascii=False) + "\n")

    def test_manifest_round_trips_every_field_the_frontmatter_used_to_carry(self):
        for tier in bundle.discover_tiers():
            cfg = bundle.load_bundle_cfg(tier)
            skills = bundle.load_tier_skills(tier)
            out = bundle.DIST_ROOT / cfg["name"]
            with self.subTest(tier=tier.name):
                manifest = json.loads((out / bundle.MANIFEST_NAME).read_text())
                self.assertEqual(manifest["schema_version"], 1)
                self.assertEqual(manifest["bundle"]["name"], cfg["name"])
                self.assertEqual(manifest["bundle"]["version"], cfg["version"])
                self.assertEqual(manifest["bundle"]["tier"], cfg["tier"])
                self.assertEqual(manifest["bundle"]["layout"], bundle.layout_kind(cfg))
                self.assertEqual(manifest["severity"], bundle.max_severity([s.severity for s in skills]))
                self.assertEqual(manifest["category"], cfg.get("category", "security"))
                self.assertEqual(manifest["applies_to"], bundle.aggregate_applies_to(skills))
                self.assertEqual(manifest["control_mappings"], bundle.aggregate_control_mappings(skills))
                self.assertEqual(manifest["maintainers"], [{"team": "catpilot-security"}])
                self.assertEqual(manifest["provenance"]["origin"], "catpilot")
                self.assertEqual(
                    manifest["provenance"]["incident_derived"],
                    any(s.cp.get("provenance", {}).get("incident_derived") for s in skills),
                )
                self.assertEqual(manifest.get("mode"), cfg.get("mode"))
                self.assertEqual(manifest.get("training_module"), bundle.aggregate_training_module(cfg, skills))
                by_id = {c["id"]: c for c in manifest["bundle"]["components"]}
                self.assertEqual(list(by_id), sorted(s.id for s in skills))
                for s in skills:
                    entry = by_id[s.id]
                    self.assertEqual(entry["version"], s.version)
                    self.assertEqual(entry["severity"], s.severity)
                    self.assertEqual(entry["category"], s.cp["category"])
                    self.assertEqual(entry.get("title"), s.title)
                    if bundle.layout_kind(cfg) == "baseline-references":
                        self.assertTrue((out / entry["reference"]).is_file())
                    else:
                        self.assertNotIn("reference", entry)

    def test_source_components_keep_the_nested_authoring_form(self):
        for tier in bundle.discover_tiers():
            for skill in bundle.load_tier_skills(tier):
                with self.subTest(skill=skill.id):
                    self.assertEqual(skill.frontmatter["metadata"]["catpilot"]["id"], skill.id)
                    self.assertFalse((skill.path / bundle.MANIFEST_NAME).exists())


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
            overlay_meta = json.loads((out / bundle.MANIFEST_NAME).read_text())["overlay"]
            self.assertEqual(overlay_meta["organization"], "Example Org")
            self.assertEqual(overlay_meta["reviewed_on"], "2026-09-13")
            self.assertEqual(overlay_meta["expires_on"], "2027-03-13")
            self.assertEqual(len(overlay_meta["overlay_sha256"]), 64)
            self.assertEqual(len(overlay_meta["content_sha256"]), 64)
            # The frontmatter carries the same facts as one string, and the full content digest.
            self.assertEqual(
                fm["metadata"]["catpilot-overlay"],
                f"Example Org, reviewed 2026-09-13, expires 2027-03-13, overlay sha256 {overlay_meta['overlay_sha256'][:12]}",
            )
            self.assertEqual(fm["metadata"]["catpilot-content-sha256"], overlay_meta["content_sha256"])
            self.assertTrue(all(isinstance(v, str) for v in fm["metadata"].values()))
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


class PrivateHostBlockTests(unittest.TestCase):
    def test_private_build_renders_host_blocks_with_company_values(self):
        overlay, raw = load_example()
        with tempfile.TemporaryDirectory() as tmp:
            out = bundle.build_tier(TIER, Path(tmp), overlay=overlay, overlay_bytes=raw, with_targets=True, install_source="acme/ai-guidance")
            hosts = Path(tmp) / f"{out.name}-hosts"
            names = {p.name for p in hosts.iterdir()}
            self.assertIn("chatgpt-project-instructions.md", names)
            self.assertIn(f"{out.name}.zip", names)
            self.assertNotIn("web", names)
            block = (hosts / "chatgpt-project-instructions.md").read_text()
            self.assertLessEqual(len(block), 8000)
            for expected in ("Company values for Example Org", "Internal App Platform", "security-review@example.org", out.name):
                self.assertIn(expected, block)
            self.assertNotIn("{{", block)
            readme = (hosts / "README.md").read_text()
            self.assertIn("PRIVATE", readme)
            self.assertIn("npx skills add acme/ai-guidance --skill " + out.name, readme)
            import zipfile
            with zipfile.ZipFile(hosts / f"{out.name}.zip") as zf:
                self.assertEqual(zf.namelist(), [f"{out.name}/", f"{out.name}/SKILL.md", f"{out.name}/catpilot.json"])
                self.assertEqual(
                    json.loads(zf.read(f"{out.name}/catpilot.json"))["overlay"]["organization"], "Example Org"
                )
