"""The unit tests that apply on Windows: the windows-latest job in .github/workflows/baseline.yml runs this file.

`python tests/windows_suite.py` runs every test in MODULES except those SKIPPED names, each for a stated reason. The
rest of the suite drives bash scripts (install.sh, verify.sh), sudo-style installs or POSIX permissions, and runs on
Linux and macOS only. On Python before 3.10 only the modules written for 3.8 run (MODULES_3_8): the others use
annotations such as `dict | None`, which 3.8 evaluates. The file name does not match test_*.py, so
`python -m unittest discover -s tests` does not run it twice.

This verifies the hooks' Python on Windows. It runs no tool: not Claude Code, Codex or Copilot CLI (WINDOWS.md §3.1).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULES_3_8 = ("test_powershell", "test_windows")
MODULES = MODULES_3_8 + (
    "test_hook",
    "test_write_hook",
    "test_destructive_hook",
    "test_hook_output",
    "test_harness_gates",
    "test_deploy_targets",
    "test_registry_targets",
    "test_cloud_targets",
)
# Test ids (module.Class.method) that read POSIX-only behaviour, with the reason.
SKIPPED = {
    "test_destructive_hook.DestructiveHookTests.test_running_users_home_by_absolute_path":
        "sets HOME; Windows's os.path.expanduser reads USERPROFILE (test_powershell covers the Windows home)",
    "test_registry_targets.HookProcessTests.test_denies_and_logs_content_free":
        "places the policy with POSIX permissions; on Windows its access list is checked (test_windows covers that)",
    "test_cloud_targets.HookProcessTests.test_denies_and_logs_content_free":
        "places the policy with POSIX permissions; on Windows its access list is checked (test_windows covers that)",
}


def _tests(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _tests(item)
        else:
            yield item


def suite() -> unittest.TestSuite:
    sys.path.insert(0, str(HERE))
    sys.path.insert(0, str(HERE.parent))
    names = MODULES if sys.version_info >= (3, 10) else MODULES_3_8
    out = unittest.TestSuite()
    for test in _tests(unittest.defaultTestLoader.loadTestsFromNames(names)):
        if test.id() in SKIPPED:
            continue
        out.addTest(test)
    return out


if __name__ == "__main__":
    result = unittest.TextTestRunner(verbosity=2).run(suite())
    sys.exit(0 if result.wasSuccessful() else 1)
