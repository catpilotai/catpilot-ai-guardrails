"""tools/build_zipapp.py: the hooks as one deterministic zipapp (issue #97, option 2, first step)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "tools" / "build_zipapp.py"


class ZipappTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def build(self, name: str, **env: str) -> Path:
        out = self.dir / name
        proc = subprocess.run([sys.executable, str(BUILD), "--out", str(out)], capture_output=True, text=True, timeout=60,
                              env=dict(os.environ, **env))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.split()[0], hashlib.sha256(out.read_bytes()).hexdigest())
        return out

    def test_two_builds_give_the_same_bytes(self):
        first = self.build("a.pyz", PYTHONHASHSEED="1")
        os.utime(ROOT / "catpilot_guard" / "__init__.py")  # a newer mtime on a source changes nothing
        second = self.build("b.pyz", PYTHONHASHSEED="2")
        self.assertEqual(first.read_bytes(), second.read_bytes())

    def test_entries_are_sorted_with_fixed_time_and_mode(self):
        out = self.build("a.pyz")
        self.assertTrue(out.read_bytes().startswith(b"#!/usr/bin/env python3\n"))
        with zipfile.ZipFile(out) as archive:
            infos = archive.infolist()
        names = [i.filename for i in infos]
        self.assertEqual(names, sorted(names))
        self.assertIn("__main__.py", names)
        self.assertIn("catpilot_guard/destructive.py", names)
        self.assertFalse([n for n in names if n.endswith(".pyc") or "__pycache__" in n])
        for info in infos:
            self.assertEqual(info.date_time, (1980, 1, 1, 0, 0, 0))
            self.assertEqual(info.external_attr >> 16, 0o100644)
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED)

    def test_it_runs_a_check_by_name_and_fails_closed_on_an_unknown_one(self):
        out = self.build("a.pyz")
        event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                            "tool_input": {"command": "git push --force origin main"}, "cwd": self.tmp.name})
        env = dict(os.environ, CATPILOT_EVIDENCE_LOG=str(self.dir / "evidence.jsonl"))
        proc = subprocess.run([sys.executable, str(out), "destructive"], input=event, capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        unknown = subprocess.run([sys.executable, str(out), "no-such-check"], input=event, capture_output=True, text=True, timeout=30)
        self.assertEqual(unknown.returncode, 2)
        self.assertIn("nothing was allowed", unknown.stderr)


if __name__ == "__main__":
    unittest.main()
