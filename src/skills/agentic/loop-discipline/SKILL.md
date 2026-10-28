---
name: loop-discipline
description: Bound agent tool loops with hard retry caps, external-state verifiers, shared workflow retry budgets, mandatory state invalidation after mutating calls, exponential-backoff tool health probes, and pass@1 evaluation.
license: MIT
metadata:
  catpilot:
    id: loop-discipline
    version: 1.0.0
    severity: high
    category: agentic-security
    applies_to:
      languages:
      - any
      frameworks:
      - any
      runtimes:
      - claude-code
      - cursor
      - openclaw
      - cline
      - aider
      - copilot
      - codex-cli
    control_mappings:
      soc2:
      - CC7.1
      - CC7.2
      - A1.1
      pci_dss:
      - '6.4'
      - '10.2'
      iso_27001:
      - A.12.1.3
      - A.14.2.8
      nist_csf:
      - DE.CM-7
      - RS.MI-2
      owasp_top_10:
      - A04:2021
    provenance:
      origin: catpilot
      incident_derived: true
    maintainers:
    - team: catpilot-security
    references:
    - https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/
---

## Baseline

**Applies when:** Building, debugging, or evaluating agent tool-calling loops, retry wrappers, state/context managers, tool-health circuit breakers, or agent benchmark suites.

**Always:**
- Cap per-tool retries (`max_attempts = 3`) and require an external-state verifier (checking file diff hash, schema version, ticket state, or DOM snapshot—never the model's self-report) to prove the world changed before granting another retry.
- Enforce a shared, workflow-scoped retry budget across nested sub-agents, crons, and step wrappers, plus jittered exponential backoff (`max_calls`, `max_cost_usd`, `max_duration_sec`).
- Invalidate cached context and force a fresh state re-read after every state-changing tool call (`file_write`, `git_commit`, `package_install`, `db_migrate`, `browser_click`).
- Probe failing tools with capped exponential backoff (`min(2 ** failures, 3600)`) and reset failure counts on recovery rather than permanently blacklisting a tool for the life of the process.
- Evaluate and report agent loop quality using `pass@1` alongside verifier evidence traces; reserve `pass@k` (`k > 1`) strictly for research diagnostics.

**Never:**
- Retry a tool call up to an arbitrary loop limit based solely on the model claiming `"trying again"` without verifying external state progress.
- Continue executing subsequent steps of a plan against a pre-mutation context snapshot after a mutating tool call has run.
- Permanently cache a `"tool is broken"` verdict with no re-probe mechanism, or headline `pass@100` as evidence of production reliability.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

Uncapped retries launder one bug into seven partial writes and orphaned resources. Meanwhile, nested retry layers (cron retry × sub-agent retry × tool retry) multiply into retry storms unless governed by a single workflow-wide budget. Finally, acting on stale context after a file write or migration is the single most common cause of cascading edits in long-horizon coding and ops loops.

## When to apply

Apply this component whenever implementing an agent execution loop, retry policy, context cache, circuit breaker, or evaluation harness.

## Rules

### Rule 1 — Verifier-backed retry caps and shared workflow budgets

Default `max_attempts = 3`. A retry is granted only if an external verifier confirms the previous attempt produced a new state transition, and all layers draw from a single workflow retry/cost/time budget.

### Rule 2 — Invalidate context after every mutating action

Treat agent context as a cache with explicit invalidation rules: every mutating tool call invalidates its affected scope so the next step re-reads ground truth.

### Rule 3 — Probe with capped exponential backoff, never permanent blacklists

Track `last_failure` and `consecutive_failures`; skip during the backoff window and probe once the window elapses so recovery is detected automatically.

## Negative examples

```python
# ❌ Unbounded retry on model self-report and stale state across steps
for attempt in range(20):
    res = tool(args)
    if res.get("ok"):
        break
    args = model.revise(args, res.get("error"))
```

## Remediation

```python
from dataclasses import dataclass

@dataclass
class VerifierResult:
    state_changed: bool
    evidence: str

def run_tool_bounded(tool, args, verifier, max_attempts: int = 3):
    last_evidence = None
    for attempt in range(1, max_attempts + 1):
        result = tool(args)
        verdict = verifier()
        if verdict.state_changed and verdict.evidence != last_evidence:
            if result.get("ok"):
                return result
            last_evidence = verdict.evidence
        else:
            raise RuntimeError(f"{tool.__name__} attempt {attempt} produced no verifiable state change")
    raise RuntimeError(f"{tool.__name__}: exhausted {max_attempts} verified attempts")
```

## References

- Timeouts, retries, and backoff with jitter — https://aws.amazon.com/builders-library/timeouts-retries-and-backoff-with-jitter/
