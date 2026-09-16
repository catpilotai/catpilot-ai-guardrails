"""Benchmark runner for the held-out safe-building scenarios.

The design this implements is `evals/BENCHMARK.md`. The scenario format and the
scanner vocabulary are the private scenario directory's own README; the runner
is pointed at that directory with `--scenarios` and never copies it anywhere.

Modules:
  scenarios   load, validate, and hash the scenario files
  sandbox     build one temporary project per run, snapshot it, diff it
  hosts       build and run the host command, normalize the transcript
  scanners    deterministic checks, one function per vocabulary primitive
  judge       the text criteria, scored by a model against a fixed rubric
  aggregate   counts per scenario, arm, and host, with the within-arm spread
  report      the Markdown report, with the configuration block
  cli         argument parsing and the run loop
"""

from __future__ import annotations

__all__ = [
    "aggregate",
    "cli",
    "hosts",
    "judge",
    "report",
    "sandbox",
    "scanners",
    "scenarios",
]
