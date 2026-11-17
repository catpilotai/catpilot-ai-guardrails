#!/usr/bin/env python3
"""Claude Code PreToolUse hook on the Bash tool: deny a shell command that carries a literal credential.

The check is catpilot_guard/secrets.py. This file is a shim at the path settings name. It looks
for the catpilot_guard/ package next to itself (the layout deploy/org/install.sh places), then at
the repository root two levels up (a checkout), puts that directory first on sys.path, and runs
the module's main(). If the package is missing or cannot be imported, it prints a short message
and exits 2, which the host treats as a block. Standard library only. Python 3.8+.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

UNAVAILABLE = (
    "Catpilot secret check unavailable: the catpilot_guard package was not found beside this hook "
    "or could not be loaded, so the command was not allowed. Reinstall the hooks with the package beside them."
)


def package_parent() -> Path | None:
    """The directory that holds catpilot_guard/: this file's own directory, else the repository root."""
    here = Path(__file__).resolve().parent
    for parent in (here, here.parent.parent):
        if (parent / "catpilot_guard").is_dir():
            return parent
    return None


if __name__ == "__main__":
    sys.dont_write_bytecode = True  # a hook run leaves no __pycache__ beside a managed copy

try:
    _parent = package_parent()
    if _parent is None:
        raise ImportError("catpilot_guard not found")
    sys.path.insert(0, str(_parent))
    # The check's names, so code that loads this file as a module still finds them.
    from catpilot_guard.secrets import *  # noqa: F403
    from catpilot_guard.secrets import main
except Exception:
    if __name__ != "__main__":
        raise
    try:
        print(UNAVAILABLE, file=sys.stderr)
        sys.stderr.flush()
    except Exception:
        # The exit code blocks whether or not the message was shown. Point stderr at
        # os.devnull so the interpreter's flush at exit cannot replace 2 with 120.
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), 2)
        except Exception:
            pass
    sys.exit(2)

if __name__ == "__main__":
    sys.exit(main())
