"""Workflows parse, run with read-only permissions, and pin third-party actions to commit SHAs."""

import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_workflows_are_pinned_and_read_only(self):
        paths = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertGreaterEqual(len(paths), 3)
        for path in paths:
            with self.subTest(workflow=path.name):
                workflow = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
                self.assertIn("on", workflow)
                self.assertEqual(workflow["permissions"], {"contents": "read"})
                for job in workflow["jobs"].values():
                    for step in job["steps"]:
                        if "uses" in step:
                            self.assertRegex(step["uses"], re.compile(r"^[\w.-]+/[\w./-]+@[a-f0-9]{40}$"))


if __name__ == "__main__":
    unittest.main()
