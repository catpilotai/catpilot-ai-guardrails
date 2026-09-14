# Evaluation reports

Reports produced by `tools/eval.py` land here, one per release, named
`<release>.md` (or `<release>-<host>.md` when more than one host is run).

What exists so far is verification notes and smoke observations, not a
report: `2026.09.13-claude-code-verification.md`, `2026.09.14-codex-verification.md`,
and `2026.09.14-codex-smoke.md` (two scenarios, one run each, heuristic scores).
The first full with/without report is scheduled with the MCP release, after
held-out scenarios exist and a clean test identity is available. Until then, the safe-building scenarios in
`../scenarios/` are a development set: visible to authors, never a held-out
benchmark.

A report is only as honest as its configuration block. Every report must
state the host and version, the model, the injection method (installed skill
or appended text), the run count, the fixture and skill hashes, the date, and
who reviewed the heuristic scores. Unknown stays unknown.
