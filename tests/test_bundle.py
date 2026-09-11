"""Filesystem adversarial cases run only in disposable synthetic directories."""

from copy import deepcopy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import bundle


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.tier = self.root / 'source' / 'core'
        self.skill_dir = self.tier / 'demo-safety'
        self.skill_dir.mkdir(parents=True)
        self.dist = self.root / 'dist'
        self.config = {'name': 'demo-core', 'tier': 'core', 'version': '2026.09.11', 'description': 'A demo.', 'preamble': '# Demo\n\nRead relevant references.'}
        self.frontmatter = {'name': 'demo-safety', 'description': 'A demo safety rule.', 'license': 'MIT', 'metadata': {'catpilot': {'id': 'demo-safety', 'version': '1.0.0', 'severity': 'high', 'category': 'demo'}}}
        self.write_config()
        self.write_skill()

    def write_config(self):
        import json
        (self.tier / 'bundle.toml').write_text('[bundle]\n' + '\n'.join(f'{k} = {json.dumps(v)}' for k, v in self.config.items()), encoding='utf-8')

    def write_skill(self, body='## Rules\n\nHelp safe work proceed.\n'):
        (self.skill_dir / 'SKILL.md').write_text(bundle.render_skill_md(self.frontmatter, body), encoding='utf-8')

    def test_repository_sources_validate(self):
        for tier in bundle.discover_tiers():
            bundle.load_bundle_cfg(tier)
            for source in tier.iterdir():
                if source.is_dir():
                    bundle.load_source_skill(source)

    def test_malicious_names_never_delete_external_directory(self):
        victim = self.root / 'outside'
        victim.mkdir()
        sentinel = victim / 'keep.txt'
        sentinel.write_text('preserve me')
        for name in ('../outside', str(victim), '.', '..', 'x/y', 'x\\y', 'a' * 65):
            with self.subTest(name=name):
                self.config['name'] = name
                self.write_config()
                with self.assertRaises(ValueError):
                    bundle.build_tier(self.tier, self.dist)
                self.assertEqual(sentinel.read_text(), 'preserve me')
                self.assertFalse(self.dist.exists())

    def test_invalid_config_cannot_replace_previous_output(self):
        output = bundle.build_tier(self.tier, self.dist)
        before = bundle._hash_tree(output)
        for field, value in (('version', '2026.02.30'), ('version', 1), ('description', 'x' * 1025), ('description', []), ('preamble', ' '), ('tier', '../bad')):
            original = deepcopy(self.config)
            with self.subTest(field=field, value=value):
                self.config[field] = value
                self.write_config()
                with self.assertRaises(ValueError):
                    bundle.build_tier(self.tier, self.dist)
                self.assertEqual(before, bundle._hash_tree(output))
            self.config = original

    def test_source_and_output_symlinks_rejected_without_following(self):
        outside = self.root / 'outside.txt'
        outside.write_text('private synthetic sentinel')
        scripts = self.skill_dir / 'scripts'
        scripts.mkdir()
        link = scripts / 'linked.txt'
        link.symlink_to(outside)
        with self.assertRaises(ValueError):
            bundle.build_tier(self.tier, self.dist)
        link.unlink()
        self.dist.symlink_to(self.root / 'elsewhere', target_is_directory=True)
        with self.assertRaises(ValueError):
            bundle.build_tier(self.tier, self.dist)
        self.assertEqual(outside.read_text(), 'private synthetic sentinel')

    def test_copy_failure_preserves_previous_output(self):
        output = bundle.build_tier(self.tier, self.dist)
        before = bundle._hash_tree(output)
        self.write_skill('A changed rule.')
        with patch.object(bundle, 'copy_companions', side_effect=OSError('synthetic copy failure')):
            with self.assertRaises(OSError):
                bundle.build_tier(self.tier, self.dist)
        self.assertEqual(before, bundle._hash_tree(output))

    def test_build_is_deterministic_and_progressive(self):
        output = bundle.build_tier(self.tier, self.dist)
        before = bundle._hash_tree(output)
        bundle.build_tier(self.tier, self.dist)
        self.assertEqual(before, bundle._hash_tree(output))
        entry = (output / 'SKILL.md').read_text()
        self.assertIn('references/demo-safety/REFERENCE.md', entry)
        self.assertNotIn('Help safe work proceed.', entry)
        fm, _ = bundle.split_frontmatter(entry)
        self.assertTrue(all(isinstance(value, str) for value in fm['metadata'].values()))
        self.assertTrue((output / fm['metadata']['catpilot-manifest']).is_file())

    def test_companion_links_relocated_and_scripts_preserve_executable_bit(self):
        for directory in ('references', 'scripts'):
            (self.skill_dir / directory).mkdir()
        (self.skill_dir / 'references' / 'DETAILS.md').write_text('Extra details.')
        script = self.skill_dir / 'scripts' / 'check.py'
        script.write_text('print("synthetic")\n')
        script.chmod(0o755)
        self.write_skill('See [details](references/DETAILS.md). Run `scripts/check.py`.\n')
        output = bundle.build_tier(self.tier, self.dist)
        body = (output / 'references/demo-safety/REFERENCE.md').read_text()
        self.assertIn('[details](DETAILS.md)', body)
        self.assertIn('`../../scripts/demo-safety/check.py`', body)
        self.assertEqual((output / 'scripts/demo-safety/check.py').stat().st_mode & 0o111, 0o111)

    def test_duplicate_yaml_and_non_object_frontmatter_rejected(self):
        for content in ('name: a\nname: b', '[a, b]', 'metadata:\n  x: 1\n  x: 2'):
            with self.subTest(content=content), self.assertRaises(ValueError):
                bundle.split_frontmatter('---\n' + content + '\n---\nbody')

    def test_name_and_nested_types_are_validated(self):
        for field, value in (('name', 'x' * 65), ('description', ['x']), ('metadata', []), ('compatibility', 'x' * 501)):
            fm = deepcopy(self.frontmatter)
            fm[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bundle.validate_source_skill(bundle.SourceSkill(self.skill_dir, fm, 'Body'))
        fm = deepcopy(self.frontmatter)
        fm['metadata']['catpilot']['applies_to'] = {'runtimes': 'codex'}
        with self.assertRaises(ValueError):
            bundle.validate_source_skill(bundle.SourceSkill(self.skill_dir, fm, 'Body'))

    def test_empty_body_rejected(self):
        self.write_skill(' \n')
        with self.assertRaises(ValueError):
            bundle.load_source_skill(self.skill_dir)

    def test_fence_demoting_preserves_nested_and_indented_code(self):
        body = '## Heading\n````md\n```\n# example\n```\n````\n   ~~~py\n# comment\n   ~~~\n## After'
        actual = bundle._demote_headings(body)
        self.assertIn('### Heading', actual)
        self.assertIn('\n# example\n', actual)
        self.assertIn('\n# comment\n', actual)
        self.assertTrue(actual.endswith('### After'))

    def test_nested_companion_links_and_anchors_are_relocated(self):
        (self.skill_dir / 'references/nested').mkdir(parents=True)
        (self.skill_dir / 'scripts').mkdir()
        (self.skill_dir / 'scripts/check.py').write_text('pass\n')
        (self.skill_dir / 'references/nested/DETAIL.md').write_text('[run](../../scripts/check.py#usage)')
        output = bundle.build_tier(self.tier, self.dist)
        self.assertEqual((output / 'references/demo-safety/nested/DETAIL.md').read_text(), '[run](../../../scripts/demo-safety/check.py#usage)')

    def test_generated_bytecode_is_not_packaged(self):
        (self.skill_dir / 'scripts/__pycache__').mkdir(parents=True)
        (self.skill_dir / 'scripts/__pycache__/check.cpython-313.pyc').write_bytes(b'not source')
        output = bundle.build_tier(self.tier, self.dist)
        self.assertFalse(any(output.rglob('*.pyc')))

    def test_executable_mode_drift_is_detected(self):
        file = self.root / 'mode-test'
        file.write_text('unchanged content')
        file.chmod(0o644)
        before = bundle._hash_tree(self.root)
        file.chmod(0o755)
        self.assertNotEqual(before, bundle._hash_tree(self.root))

    def test_duplicate_tier_names_fail_before_building(self):
        other = self.root / 'source/other'
        other.mkdir()
        (other / 'bundle.toml').write_bytes((self.tier / 'bundle.toml').read_bytes())
        with patch.object(bundle, 'SRC_ROOT', self.root / 'source'), self.assertRaises(ValueError):
            bundle.discover_tiers()

    def test_rename_failure_restores_previous_package(self):
        output = bundle.build_tier(self.tier, self.dist)
        before = bundle._hash_tree(output)
        self.write_skill('Changed content')
        original = Path.rename
        def fail_stage(path, destination):
            if path.parent.name.startswith('.bundle-') and path.name == 'demo-core':
                raise OSError('synthetic publish failure')
            return original(path, destination)
        with patch.object(Path, 'rename', fail_stage), self.assertRaises(OSError):
            bundle.build_tier(self.tier, self.dist)
        self.assertEqual(before, bundle._hash_tree(output))

    def test_failed_restore_keeps_recoverable_previous_copy(self):
        output = bundle.build_tier(self.tier, self.dist)
        before = bundle._hash_tree(output)
        self.write_skill('Changed content')
        original = Path.rename
        def fail_publish_and_restore(path, destination):
            if path.name == 'package' or (path.parent.name.startswith('.bundle-') and path.name == 'demo-core'):
                raise OSError('synthetic filesystem unavailable')
            return original(path, destination)
        with patch.object(Path, 'rename', fail_publish_and_restore), self.assertRaisesRegex(OSError, 'retained at'):
            bundle.build_tier(self.tier, self.dist)
        retained = list(self.dist.glob('.previous-*/package'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(before, bundle._hash_tree(retained[0]))


if __name__ == '__main__':
    unittest.main()
