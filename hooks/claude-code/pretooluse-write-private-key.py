#!/usr/bin/env python3
"""Compatibility entry point: runs pretooluse-write-secrets.py.

This hook was renamed when it grew from private-key blocks to every literal
credential pattern. Settings that still point at this file keep working and get
exactly the same decisions. New settings should reference
pretooluse-write-secrets.py. If that file is missing, this exits 2 (a block).
"""

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    try:
        runpy.run_path(str(Path(__file__).resolve().parent / "pretooluse-write-secrets.py"), run_name="__main__")
    except SystemExit:
        raise
    except Exception:
        print("Catpilot write check unavailable: pretooluse-write-secrets.py could not run. Review the write before retrying.", file=sys.stderr)
        sys.exit(2)
