#!/usr/bin/env python3
"""Benchmark runner for the held-out safe-building scenarios.

Runs each scenario in three arms on one host, scans what the run did and what
it left behind, scores the text criteria with a judge model, and writes a
Markdown report. The design is `evals/BENCHMARK.md`; the scenario format is the
private scenario directory's own README.

  bench.py --scenarios <dir> --host claude-code|codex --arms A,B,C --runs 3 \
           --model sonnet --out <dir> [--overlay <file>] [--max-turns 12] \
           [--judge-model haiku] [--dry-run] [--report <path>]

Start with --dry-run: it validates the scenarios, builds one sandbox per
scenario and arm, prints the exact host command for each, and calls no model.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.bench import cli  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(cli.main())
