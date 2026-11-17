"""A hook that cannot deliver its decision must still block.

Claude Code treats only exit code 2 as a block. Before this test existed, a hook
whose stdout pipe had been closed raised on print() and exited 1, or 120 when
the interpreter's own flush at exit failed, and the host would have run the
call. Each case below runs a hook script as a subprocess with a broken stdout
or stderr and expects exit code 2.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "hooks" / "claude-code"

# Assembled from parts so this file is not itself a literal credential or key block.
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
KEY_BLOCK = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD9\n-----END " + "RSA PRIVATE KEY-----\n"

WRITE_DENY = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/x/key.pem", "content": KEY_BLOCK}}
WRITE_NONE = {"tool_name": "Write", "tool_input": {"file_path": "/tmp/x/a.txt", "content": "hello"}}
DENY = {
    "pretooluse-destructive-ops.py": {"tool_name": "Bash", "tool_input": {"command": "git push --force origin main"}},
    "pretooluse-secrets.py": {"tool_name": "Bash", "tool_input": {"command": "export AWS_ACCESS_KEY_ID=" + AWS_EXAMPLE_KEY}},
    "pretooluse-write-secrets.py": WRITE_DENY,
    "pretooluse-write-private-key.py": WRITE_DENY,
}
NO_DECISION = {
    "pretooluse-destructive-ops.py": {"tool_name": "Bash", "tool_input": {"command": "ls"}},
    "pretooluse-secrets.py": {"tool_name": "Bash", "tool_input": {"command": "ls"}},
    "pretooluse-write-secrets.py": WRITE_NONE,
    "pretooluse-write-private-key.py": WRITE_NONE,
}


def run(script: Path, stdin: bytes, *, close_stdout: bool = False, close_stderr: bool = False) -> subprocess.CompletedProcess:
    """Run a hook with stdout and/or stderr writing into a pipe whose reader is already gone."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_")}
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    if close_stdout:
        os.close(out_r)
    if close_stderr:
        os.close(err_r)
    try:
        proc = subprocess.run([sys.executable, str(script)], input=stdin, stdout=out_w, stderr=err_w, env=env, timeout=30)
    finally:
        os.close(out_w)
        os.close(err_w)
        if not close_stdout:
            os.close(out_r)
        if not close_stderr:
            os.close(err_r)
    return proc


class BrokenStdoutBlocks(unittest.TestCase):
    def test_a_deny_that_cannot_be_written_still_blocks(self):
        for name, event in DENY.items():
            with self.subTest(hook=name):
                self.assertEqual(run(HOOKS / name, json.dumps(event).encode(), close_stdout=True).returncode, 2)

    def test_no_decision_that_cannot_be_written_blocks(self):
        # Fail closed: the host received nothing, so the hook does not let the call through.
        for name, event in NO_DECISION.items():
            with self.subTest(hook=name):
                self.assertEqual(run(HOOKS / name, json.dumps(event).encode(), close_stdout=True).returncode, 2)

    def test_unreadable_input_blocks_with_stderr_closed(self):
        for name in DENY:
            with self.subTest(hook=name):
                self.assertEqual(run(HOOKS / name, b"not json", close_stderr=True).returncode, 2)

    def test_a_deny_still_exits_0_when_both_streams_work(self):
        for name, event in DENY.items():
            with self.subTest(hook=name):
                proc = subprocess.run([sys.executable, str(HOOKS / name)], input=json.dumps(event).encode(), capture_output=True, timeout=30)
                self.assertEqual(proc.returncode, 0)
                self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")


class MissingPackageBlocksWithStderrClosed(unittest.TestCase):
    def test_a_shim_without_its_package_blocks_even_if_the_message_cannot_be_shown(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in DENY:
                shutil.copy(HOOKS / name, Path(tmp) / name)
            # Two levels up from a temporary directory is not the repository, so no package is found.
            for name, event in DENY.items():
                with self.subTest(hook=name):
                    self.assertEqual(run(Path(tmp) / name, json.dumps(event).encode(), close_stderr=True).returncode, 2)


if __name__ == "__main__":
    unittest.main()
