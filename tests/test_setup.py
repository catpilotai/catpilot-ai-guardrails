"""Exercise only disposable legacy-install targets, never personal config."""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SetupTests(unittest.TestCase):
    def run_setup(self, root, *args):
        return subprocess.run(['bash', str(ROOT / 'setup.sh'), *args], cwd=root, capture_output=True, text=True, timeout=20)

    def test_invalid_argument_and_missing_install_fail_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            for args in [('--verify',), ('--framework',), ('--framework', '../escape')]:
                self.assertNotEqual(self.run_setup(temp, *args).returncode, 0)
                self.assertEqual(list(Path(temp).iterdir()), [])

    def test_fresh_verify_and_preserve_unrelated_configuration(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'CLAUDE.md').symlink_to('unrelated.md')
            (root / '.aider.conf.yml').write_text('read: existing.md\n')
            result = self.run_setup(root, '--no-framework')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / 'CLAUDE.md').readlink(), Path('unrelated.md'))
            self.assertEqual((root / '.aider.conf.yml').read_text(), 'read: existing.md\n')
            self.assertEqual(self.run_setup(root, '--verify').returncode, 0)
            (root / '.github/copilot-instructions.md').write_text('AI Guardrails\nVersion: 0.0.0\n')
            self.assertNotEqual(self.run_setup(root, '--verify').returncode, 0)

    def test_symlinked_output_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / 'outside'
            outside.mkdir()
            (root / '.github').symlink_to(outside, target_is_directory=True)
            self.assertNotEqual(self.run_setup(root, '--no-framework').returncode, 0)
            self.assertEqual(list(outside.iterdir()), [])

    def test_force_keeps_each_backup_and_custom_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / '.github').mkdir()
            (root / '.github/copilot-instructions.md').write_text('Custom user rule\n')
            for _ in range(2):
                result = self.run_setup(root, '--force', '--no-framework')
                self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(list((root / '.github').glob('*.backup.*'))), 2)
            self.assertIn('Custom user rule', (root / '.github/copilot-instructions.md').read_text())

    def test_framework_installs_preserve_unrelated_temp_and_verify(self):
        for framework in ('nextjs', 'django', 'rails', 'express', 'fastapi', 'springboot', 'python', 'typescript', 'openclaw', 'agentic', 'docker'):
            with self.subTest(framework=framework), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                (root / '.github').mkdir()
                sentinel = root / '.github/copilot-instructions.md.tmp'
                sentinel.write_text('unrelated user file')
                result = self.run_setup(root, '--framework', framework)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.run_setup(root, '--verify').returncode, 0)
                self.assertEqual(sentinel.read_text(), 'unrelated user file')

    @unittest.skipUnless(hasattr(os, 'mkfifo'), 'POSIX FIFO test')
    def test_nonregular_output_is_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / '.github').mkdir()
            os.mkfifo(root / '.github/copilot-instructions.md')
            self.assertNotEqual(self.run_setup(root, '--no-framework').returncode, 0)
