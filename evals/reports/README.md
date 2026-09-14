# Evaluation reports

Reports produced by `tools/eval.py` land here, one per release, named
`<release>.md` (or `<release>-<host>.md` when more than one host is run).

None is published yet. The first with/without report is scheduled with the
MCP release in the direction document, after held-out scenarios exist and a
clean test identity is available. Until then, the safe-building scenarios in
`../scenarios/` are a development set: visible to authors, never a held-out
benchmark.

A report is only as honest as its configuration block. Every report must
state the host and version, the model, the injection method (installed skill
or appended text), the run count, the fixture and skill hashes, the date, and
who reviewed the heuristic scores. Unknown stays unknown.
