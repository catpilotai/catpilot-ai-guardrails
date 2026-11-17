#!/usr/bin/env python3
"""SessionStart hook for Claude Code and Codex: the company rules at session start. Advice, not enforcement.

  python3 catpilot-company-rules.py --host claude-code|codex [--dir /absolute/path/to/instructions]

The code is catpilot_guard/session_start.py. This file is a shim at the path a hook configuration
names. It looks for the catpilot_guard/ package next to itself (the deployed layout), then at the
repository root two levels up (a checkout), puts that directory first on sys.path, and runs the
module's main(). Without --dir, the rules are read from instructions/ beside the directory holding
this file: <managed dir>/catpilot-guardrails/instructions/ when it sits in
<managed dir>/catpilot-guardrails/hooks/.

If the package is missing or cannot be imported, it prints that company rules could not be loaded
and are unknown, in the SessionStart output both hosts document, and exits 0. SessionStart cannot
block on either host, so this is a notice, not a control. Standard library only. Python 3.8+.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# The same text as catpilot_guard.session_start.UNAVAILABLE; tests/test_session_start.py checks it.
UNAVAILABLE = "Company rules could not be loaded and are unknown. Ask your IT or security owner."


def package_parent() -> Path | None:
    """The directory that holds catpilot_guard/: this file's own directory, else the repository root."""
    here = Path(__file__).resolve().parent
    for parent in (here, here.parent.parent):
        if (parent / "catpilot_guard").is_dir():
            return parent
    return None


def default_dir() -> Path:
    """instructions/ beside the directory that holds this file."""
    return Path(__file__).resolve().parent.parent / "instructions"


if __name__ == "__main__":
    sys.dont_write_bytecode = True  # a hook run leaves no __pycache__ beside a managed copy

try:
    _parent = package_parent()
    if _parent is None:
        raise ImportError("catpilot_guard not found")
    sys.path.insert(0, str(_parent))
    # The module's names, so code that loads this file as a module still finds them.
    from catpilot_guard.session_start import *  # noqa: F403
    from catpilot_guard.session_start import main
except Exception:
    if __name__ != "__main__":
        raise
    output = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": UNAVAILABLE}, "systemMessage": UNAVAILABLE}
    try:
        sys.stdout.write(json.dumps(output) + "\n")
        sys.stdout.flush()
    except Exception:
        # The notice could not be shown. Point stdout at os.devnull so the interpreter's flush at exit
        # cannot replace 0 with 120.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), 1)
        except Exception:
            pass
    sys.exit(0)

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:], default_dir=default_dir()))
