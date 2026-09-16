# Evaluation reports

Reports produced by `tools/eval.py` land here, one per release, named
`<release>.md` (or `<release>-<host>.md` when more than one host is run).

Reports produced by `tools/bench.py`, the with/without benchmark described in
`../BENCHMARK.md`, are named `<release>-benchmark-<host>.md`: one file per host
per release, so a Claude Code pass and a Codex pass over the same scenario set
sit beside each other instead of overwriting each other, and the word
`benchmark` separates an actions-and-artifacts measurement over held-out
scenarios from the heuristic scorer's report on the development set. The runner
writes that file under its own `--out` directory, never into this repository; a
benchmark report arrives here only when a person copies it in, with the
`Reviewed by:` line filled in.

What exists so far is verification notes and smoke observations, not a
report: `2026.09.13-claude-code-verification.md`, `2026.09.14-codex-verification.md`,
`2026.09.14-codex-smoke.md` (two scenarios, one run each, heuristic scores),
`2026.09.14-mcp-verification.md`, `2026.09.14-write-hook-verification.md`,
and `2026.09.15-core-layout-verification.md` (whether Claude Code and Codex
open a reference file of the split core skill before acting).
The first full with/without report is the open item in `../../docs/ROADMAP.md`:
it needs held-out scenarios, repeated runs, a clean test identity, and a
named reviewer. Until then, the safe-building scenarios in `../scenarios/`
are a development set: visible to authors, never a held-out benchmark.

A report is only as honest as its configuration block. Every report must
state the host and version, the model, the injection method (installed skill
or appended text), the run count, the fixture and skill hashes, the date, and
who reviewed the heuristic scores. Unknown stays unknown.
