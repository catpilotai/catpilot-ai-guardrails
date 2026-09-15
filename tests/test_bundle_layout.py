"""The baseline-references layout: a short SKILL.md the host always reads plus one reference file per component."""

import json
import tempfile
import unittest
from pathlib import Path

from tools import bundle

FRONTMATTER = {
    "name": "demo-safety",
    "description": "A demo safety rule.",
    "license": "MIT",
    "metadata": {"catpilot": {"id": "demo-safety", "title": "Demo safety", "version": "1.0.0", "severity": "high", "category": "demo"}},
}
BODY = """## Baseline

**Applies when:** any demo command runs.

**Always:**
- Ask before the irreversible step.

Open the full component before acting.

## Why

Because demos break.

```bash
## not a heading: inside a fence
```

## Rules

- Long rule one.
- Long rule two.
"""


class BaselineReferencesTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.tier = root / "source" / "core"
        self.skill_dir = self.tier / "demo-safety"
        self.skill_dir.mkdir(parents=True)
        self.dist = root / "dist"
        self.config = {"name": "demo-core", "tier": "core", "version": "2026.09.15", "description": "A demo.", "preamble": "# Demo\n\nRead the baseline."}
        self.layout = {"kind": "baseline-references", "max_lines": 60}
        self.write_config()
        self.write_skill(BODY)

    def write_config(self):
        text = "[bundle]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in self.config.items())
        if self.layout is not None:
            text += "\n[bundle.layout]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in self.layout.items())
        self.tier.joinpath("bundle.toml").write_text(text, encoding="utf-8")

    def write_skill(self, body):
        self.skill_dir.joinpath("SKILL.md").write_text(bundle.render_skill_md(FRONTMATTER, body), encoding="utf-8")

    def test_baseline_and_reference_are_written(self):
        out = bundle.build_tier(self.tier, self.dist)
        skill = (out / "SKILL.md").read_text()
        self.assertIn("Ask before the irreversible step.", skill)
        self.assertNotIn("Long rule one.", skill)
        self.assertIn("[references/demo-safety.md](references/demo-safety.md)", skill)
        fm, _ = bundle.split_frontmatter(skill)
        self.assertEqual(fm["metadata"]["catpilot"]["bundle"]["layout"], "baseline-references")
        ref = (out / "references" / "demo-safety.md").read_text()
        self.assertTrue(ref.startswith("# Demo safety\n"))
        self.assertIn("Long rule one.", ref)
        self.assertIn("## Baseline", ref)
        self.assertIn("## not a heading: inside a fence", ref)

    def test_single_layout_is_unchanged(self):
        self.layout = None
        self.write_config()
        out = bundle.build_tier(self.tier, self.dist)
        skill = (out / "SKILL.md").read_text()
        self.assertIn("Long rule one.", skill)
        self.assertFalse((out / "references").exists())
        fm, _ = bundle.split_frontmatter(skill)
        self.assertNotIn("layout", fm["metadata"]["catpilot"]["bundle"])

    def test_missing_baseline_section_fails_before_writing(self):
        self.write_skill("## Why\n\nNo baseline here.\n")
        with self.assertRaisesRegex(ValueError, "Baseline"):
            bundle.build_tier(self.tier, self.dist)
        self.assertFalse(self.dist.exists())

    def test_line_cap_is_enforced(self):
        self.layout["max_lines"] = 50
        self.write_config()
        long_baseline = "## Baseline\n\n" + "\n".join(f"- rule {i}" for i in range(60)) + "\n\n## Why\n\nx\n"
        self.write_skill(long_baseline)
        with self.assertRaisesRegex(ValueError, "max_lines"):
            bundle.build_tier(self.tier, self.dist)

    def test_layout_config_is_validated(self):
        for layout in ({"kind": "router"}, {"kind": "baseline-references", "max_lines": 10}, {"kind": "baseline-references", "extra": 1}, {"kind": "baseline-references", "baseline_section": ""}):
            with self.subTest(layout=layout):
                self.layout = layout
                self.write_config()
                with self.assertRaises(ValueError):
                    bundle.load_bundle_cfg(self.tier)

    def test_extract_section_is_fence_aware(self):
        body = "## Baseline\n\ntext\n\n```\n## fake\n```\n\nmore\n\n## Next\n\nno\n"
        self.assertEqual(bundle.extract_section(body, "Baseline"), "text\n\n```\n## fake\n```\n\nmore")
