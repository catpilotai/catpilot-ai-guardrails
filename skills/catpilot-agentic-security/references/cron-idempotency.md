# cron-idempotency

Component `cron-idempotency` · version 1.0.0 · severity high · category agentic-security.
Full text of one component of the `catpilot-agentic-security` bundle. The baseline rules are in `../SKILL.md`; this file has the rest: examples, remediation, and detection patterns.
## Baseline

**Applies when:** Configuring, writing, or reviewing scheduled agent tasks (cron jobs, heartbeat loops, background workers, or recurring workflows).

**Always:**
- Set an explicit `timeoutSeconds` and token/cost budget on every scheduled agent job, and use deterministic scripts or lightweight models for routine polling.
- Separate read-only monitoring crons from write actions; scheduled jobs must not have `shell`, `write`, `deploy`, or outbound `message` tools unless human digest approval is in the loop.
- Enforce an atomic, durable work-claim and completion marker (`store.claim(item.id, run_id, ttl_seconds)` / `store.mark_done(...)`) before acting on any item so overlapping or retried runs are proven no-ops.
- Pass a deterministic `idempotency_key` to every external side effect (payments, emails, ticket creation, webhook posts, deployments).
- Release claims cleanly on failure (`store.release(item.id)`) only when the side effect did not commit, and log per-run token spend and claimed item IDs.

**Never:**
- Run a scheduled agent with `timeoutSeconds: null`, unrestricted `"tools": "all"`, or permission to edit its own schedule, prompt, or toolset (`cron_edit`).
- Assume wall-clock schedule spacing (`"*/15 * * * *"`) prevents overlapping runs or duplicate side effects.
- Trigger external side effects (charging cards, sending customer emails, deploying) inside a scheduled loop without both a durable work claim and a provider-side idempotency key.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

Scheduled tasks are unsupervised agent sessions: when a cron job misfires, loops, or overlaps with a slow prior run, no human is watching the terminal. Treating `"every 15 minutes"` as a state boundary rather than a trigger causes duplicate invoices, repeated customer emails, and runaway token bills whenever a run overlaps, restarts, or retries.

## When to apply

Apply this component whenever creating or reviewing cron schedules, background agent workers, heartbeat checks, or queue consumers.

## Rules

### Rule 1 — Bound runtime, tools, and self-modification

Every cron job requires a hard `timeoutSeconds`, an explicit read-only tool allowlist by default, and zero access to schedule/prompt self-modification tools.

### Rule 2 — Atomic work claims before acting

Before acting on any work item, acquire an atomic lease (`claim(item_id, run_id, ttl)`) in durable storage and mark it completed upon success so concurrent or subsequent ticks skip already-claimed work.

### Rule 3 — Idempotency keys on all external side effects

Every external API call that mutates state must carry a deterministic `idempotency_key` derived from the logical unit of work.

## Negative examples

```python
# ❌ Unbounded cron that replays side effects on overlap or retry
def scheduled_run():
    for item in fetch_pending_items():
        send_invoice(item)
        deploy(item)
```

## Remediation

```python
def scheduled_run(store, run_id: str):
    for item in fetch_pending_items():
        if not store.claim(item.id, run_id=run_id, ttl_seconds=300):
            continue
        try:
            send_invoice(item, idempotency_key=f"invoice:{item.id}")
            store.mark_done(item.id, run_id=run_id)
        except Exception:
            store.release(item.id)
            raise
```

## References

- Designing robust and predictable APIs with idempotency — https://stripe.com/docs/api/idempotent_requests
