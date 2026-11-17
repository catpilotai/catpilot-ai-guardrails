"""One renderer for benchmark condition F and the shipped company-checklist target. Offline."""

import contextlib
import datetime as dt
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import bundle, company_checklist, targets, validate_overlay
from tools.bench import sandbox

ROOT = Path(__file__).resolve().parents[1]
TIER = ROOT / "src" / "skills" / "safe-building"
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
# The example overlay's review date. The expiry check runs as of this day, so
# the tests do not start failing when the example's expires_on passes.
REVIEW_DAY = dt.date(2026, 9, 13)
# The line budget from Claude Code's guidance for CLAUDE.md files.
LINE_BUDGET = 200


def as_of_review_day():
    real = validate_overlay.validate_expiry
    return mock.patch.object(validate_overlay, "validate_expiry", lambda overlay, today=None: real(overlay, REVIEW_DAY))


def block_size(text: str) -> tuple[int, int]:
    """Lines, and approximate tokens at four characters per token."""
    return len(text.splitlines()), round(len(text) / 4)


class SharedRendererTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        pinned = as_of_review_day()
        pinned.start()
        self.addCleanup(pinned.stop)

    def shipped_checklist(self) -> bytes:
        """company-checklist.md from the private build an administrator runs."""
        with contextlib.redirect_stdout(io.StringIO()):
            code = bundle.cmd_private(EXAMPLE, self.root / "private", [], None)
        self.assertEqual(code, 0)
        (hosts,) = (self.root / "private").glob("*-hosts")
        return (hosts / targets.COMPANY_CHECKLIST_NAME).read_bytes()

    def condition_f_file(self, host: str) -> bytes:
        """The instruction file benchmark condition F plants in a fresh project."""
        skill_source = self.root / "skill-source"
        skill_source.mkdir(exist_ok=True)
        box = sandbox.build_sandbox(
            {"id": "synthetic", "sandbox": []},
            "F",
            self.root / f"project-{host}",
            host=host,
            skill_source=skill_source,
            server_script=self.root / "unused-server.py",
            python="unused-python",
            overlay_file=EXAMPLE,
        )
        return (box.project / sandbox.ARM_D_INSTRUCTION_FILE[host]).read_bytes()

    def test_condition_f_text_equals_the_shipped_target_for_the_example_overlay(self):
        shipped = self.shipped_checklist()
        for host in ("claude-code", "codex"):
            with self.subTest(host=host):
                self.assertEqual(self.condition_f_file(host), shipped)
        text = company_checklist.company_checklist_instruction(EXAMPLE)
        self.assertEqual(shipped.decode("utf-8"), text + "\n")
        self.assertTrue(text.startswith(sandbox.CHECKLIST_INSTRUCTION + "\n\n## Company policy\n\n"))

    def test_sandbox_re_exports_the_shared_names(self):
        self.assertIs(sandbox.CHECKLIST_INSTRUCTION, company_checklist.CHECKLIST_INSTRUCTION)
        self.assertIs(sandbox.company_checklist_instruction, company_checklist.company_checklist_instruction)
        self.assertIs(sandbox.validated_company_overlay, company_checklist.validated_company_overlay)

    def test_example_block_fits_the_claude_md_line_budget(self):
        text = company_checklist.company_checklist_instruction(EXAMPLE)
        lines, tokens = block_size(text)
        self.assertLessEqual(
            lines,
            LINE_BUDGET,
            f"the company checklist for the example overlay is {lines} lines, about {tokens} tokens; "
            f"the budget from Claude Code's guidance for CLAUDE.md files is {LINE_BUDGET} lines",
        )

    def test_the_target_lists_itself_in_the_private_readme(self):
        self.shipped_checklist()
        (hosts,) = (self.root / "private").glob("*-hosts")
        readme = (hosts / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"| `{targets.COMPANY_CHECKLIST_NAME}` | Claude Code, Codex |", readme)


class PublicBuildTests(unittest.TestCase):
    def test_the_tier_enables_the_target_but_the_public_build_writes_no_file(self):
        cfg = bundle.load_bundle_cfg(TIER)
        self.assertIn("company-checklist", cfg["targets"]["enabled"])
        self.assertIn("company-checklist", targets.TARGET_NAMES)
        with tempfile.TemporaryDirectory() as tmp:
            bundle.build_tier(TIER, Path(tmp) / "skills", with_targets=True, targets_root=Path(tmp) / "dist")
            written = [p for p in Path(tmp).rglob("*") if p.is_file()]
            self.assertTrue(written)
            self.assertFalse([p for p in written if p.name == targets.COMPANY_CHECKLIST_NAME])
            readme = (Path(tmp) / "dist" / cfg["version"] / "README.md").read_text(encoding="utf-8")
            self.assertNotIn(targets.COMPANY_CHECKLIST_NAME, readme)
        self.assertFalse(list(bundle.TARGETS_ROOT.rglob(targets.COMPANY_CHECKLIST_NAME)))

    def test_public_build_of_only_this_target_is_refused_before_anything_is_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            dist = Path(tmp) / "dist"
            sentinel = dist / "2026.01.01" / "README.md"
            sentinel.parent.mkdir(parents=True)
            sentinel.write_text("kept\n", encoding="utf-8")
            with (
                mock.patch.object(bundle, "TARGETS_ROOT", dist),
                mock.patch.object(bundle, "DIST_ROOT", Path(tmp) / "skills"),
                contextlib.redirect_stderr(io.StringIO()) as err,
            ):
                code = bundle.main(["--target", "company-checklist"])
            self.assertEqual(code, 2)
            self.assertIn("--overlay", err.getvalue())
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "kept\n")
            self.assertFalse((Path(tmp) / "skills").exists())


if __name__ == "__main__":
    unittest.main()
