"""Catch YAML parser errors before GitHub rejects the entire workflow."""
from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_workflows_parse_and_action_references_are_pinned(self):
        for path in sorted((ROOT / '.github/workflows').glob('*.yml')):
            with self.subTest(workflow=path.name):
                # BaseLoader preserves GitHub's `on` key as text, not YAML 1.1 bool.
                workflow = yaml.load(path.read_text(encoding='utf-8'), Loader=yaml.BaseLoader)
                self.assertIn('on', workflow)
                self.assertIn('jobs', workflow)
                self.assertEqual(workflow['permissions'], {'contents': 'read'})
                for job in workflow['jobs'].values():
                    for step in job['steps']:
                        if 'uses' in step:
                            self.assertRegex(step['uses'], re.compile(r'^[\w.-]+/[\w./-]+@[a-f0-9]{40}$'))
                        if 'run' in step:
                            self.assertIsInstance(step['run'], str)
                            self.assertTrue(step['run'].strip())
