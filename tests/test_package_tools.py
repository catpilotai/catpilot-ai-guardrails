from pathlib import Path
import tempfile
import unittest
from tools.bundle import render_skill_md
from tools.validate_skill import validate_package
from tools.recommend import recommend


class PackageToolsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'demo-skill'
        self.root.mkdir()
        self.metadata = {'name': 'demo-skill', 'description': 'A synthetic test.', 'metadata': {'version': '1'}}

    def write(self, body='Plain instructions.'):
        (self.root / 'SKILL.md').write_text(render_skill_md(self.metadata, body))

    def test_portable_string_metadata_and_missing_local_links(self):
        self.write()
        self.assertEqual(validate_package(self.root), [])
        self.write('See [missing](references/missing.md).')
        self.assertTrue(validate_package(self.root))
        self.metadata['metadata'] = {'catpilot': {'nested': True}}
        self.write()
        self.assertTrue(validate_package(self.root))

    def test_path_escape_symlink_and_size_budget(self):
        outside = self.root.parent / 'outside.md'
        outside.write_text('synthetic')
        for body in ['[outside](../outside.md)', '\n'.join(['content'] * 501)]:
            self.write(body)
            self.assertTrue(validate_package(self.root))
        self.write()
        (self.root / 'linked.md').symlink_to(outside)
        self.assertTrue(validate_package(self.root))

    def test_recommendation_is_read_only_and_labels_legacy_references(self):
        (self.root / 'package.json').write_text('{"dependencies":{"next":"pinned","typescript":"pinned"}}')
        before = list(self.root.iterdir())
        result = recommend(self.root)
        self.assertEqual(result['framework_hints'], ['nextjs', 'typescript'])
        self.assertEqual(result['mutations'], 'none')
        self.assertIn('legacy', result['framework_bundles'])
        self.assertEqual(before, list(self.root.iterdir()))

    def test_recommender_ignores_symlinked_manifests(self):
        outside = self.root.parent / 'private.txt'
        outside.write_text('django')
        (self.root / 'requirements.txt').symlink_to(outside)
        self.assertEqual(recommend(self.root)['framework_hints'], [])
