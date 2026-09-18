# Quick guide

This is an illustrative public fixture, not a benchmark result. A support
coordinator might say: “I need a short count of our made-up ticket statuses for
tomorrow's practice session.” The functional demo turns that request into a
small local `digest.py` deliverable and checks several fabricated inputs.

```bash
.venv/bin/python tools/bench.py --scenarios evals/scenarios-functional-demo \
  --examples evals/reference-examples/functional-demo --host codex --arms A \
  --runs 1 --out .bench-runs/demo --dry-run
```

The command uses **A, no guidance**, which is a valid standalone baseline.

The blank `voice_reviewed_by` in this demo permits a non-model dry-run only. A
live benchmark needs a real named human reviewer.

For any candidate experiment, stop here and complete the human review,
freezing, and preregistration gates in [the experiment plan](EXPERIMENT_PLAN.md).
