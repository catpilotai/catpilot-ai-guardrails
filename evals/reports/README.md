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

Verification notes and smoke observations are distinct from benchmark reports: `2026.09.13-claude-code-verification.md`, `2026.09.14-codex-verification.md`,
`2026.09.14-codex-smoke.md` (two scenarios, one run each, heuristic scores),
`2026.09.14-mcp-verification.md`, `2026.09.14-write-hook-verification.md`,
and `2026.09.15-core-layout-verification.md` (whether Claude Code and Codex
open a reference file of the split core skill before acting).
Four historical benchmark reports are published, each opening with the dated completion note while preserving its previously published text: `2026.09.15-benchmark-claude-code.md` and `2026.09.15-benchmark-codex.md`
(ten held-out scenarios; A, no guidance; B, skill installed; C, skill plus company server without an instruction; single turn, with historical rescoring corrections),
and `2026.09.16-1-benchmark-claude-code.md` and `2026.09.16-1-benchmark-codex.md`
(a fresh set of ten; A, no guidance; B, skill installed; D, skill plus company rules through the server; E, generic checklist; two turns per run, Sonnet judge). The scenario
files behind each pair are published in `../scenarios-retired/` once retired. The safe-building scenarios in `../scenarios/` are a development
set: visible to authors, never a held-out benchmark.

**Historical completion limitation.** All completion counts in these four reports, including the correction tables, use file-presence/content checks as a textual proxy. They do not verify functional completion of the generated app or script. Current scorer fixes, executable completion checks, and reference-gate improvements do not automatically validate or rescore archived results. Original tables are retained for audit history; withdrawn within-arm-spread verdicts do not establish a difference or equivalence. See the [current evaluation contract](../../docs/EVALUATION_CONTRACT.md).

A report is only as honest as its configuration block. Every report must
state the host and version, the model, the injection method (installed skill
or appended text), the run count, the fixture and skill hashes, the date, and
who reviewed the heuristic scores. Unknown stays unknown.
