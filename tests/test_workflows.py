"""Workflows parse, run with read-only permissions, and pin third-party actions to commit SHAs.

One exception, held exactly: release-attestations.yml signs published releases, so its single job may write
release assets and attestations and request an OIDC token, and it runs only on a published release or by hand.
"""

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
                    if path.name == "release-attestations.yml":
                        self.assertEqual(set(workflow["on"]), {"release", "workflow_dispatch"})
                        self.assertEqual(workflow["on"]["release"], {"types": ["published"]})
                        self.assertEqual(job["permissions"], {"contents": "write", "id-token": "write", "attestations": "write"})
                    else:
                        self.assertNotIn("permissions", job, "only release-attestations.yml may raise a job's permissions")
                    for step in job["steps"]:
                        if "uses" in step:
                            self.assertRegex(step["uses"], re.compile(r"^[\w.-]+/[\w./-]+@[a-f0-9]{40}$"))

    def test_attestation_workflow_never_interpolates_the_tag_into_a_script(self):
        # The tag reaches shell steps only through $TAG, so a crafted dispatch input cannot inject commands.
        text = (ROOT / ".github" / "workflows" / "release-attestations.yml").read_text(encoding="utf-8")
        workflow = yaml.load(text, Loader=yaml.BaseLoader)
        for step in workflow["jobs"]["attest"]["steps"]:
            self.assertNotIn("${{", step.get("run", ""))


if __name__ == "__main__":
    unittest.main()
