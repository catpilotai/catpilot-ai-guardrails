# Live response smoke tests

`tools/run_live_evals.py` compares baseline responses with explicitly injected
CATpilot guidance using the synthetic corpus. It supplies relevant component
references, excludes the answer key, and records host/model/effort, hashes,
latency, reported usage/cost, raw outputs, and failures. It never assigns an
automatic pass based on keywords.

This is **prompt-only**, not an installation, activation, scanner, or mandatory
enforcement benchmark. Injecting full relevant references does not measure
how well a host discovers or selectively loads them in normal use. Baseline
and advisory see identical fictional policy context.

```bash
# Plan only; no host/model call or output directory is created.
python tools/run_live_evals.py --host codex --binary /absolute/path/to/codex --model gpt-5.5

# Explicitly opt into four model calls (two cases, two conditions).
python tools/run_live_evals.py --host claude --binary /absolute/path/to/claude --model claude-sonnet-4-6 --execute
```

Use repeated `--case <id>` values and raise `--max-calls` explicitly to expand
the matrix. Each call has a timeout; Claude also receives a per-call budget
(default $0.50). Codex provides no dollar cap here: the runner limits calls
and duration, not token spend. Existing CLI subscription/usage limits apply.
Reported Claude model usage may include auxiliary models as well as the
requested main model. Unknown prices/costs remain unknown.

The runner requests restrictions on ordinary personal/project customization,
plugins, hooks, and shell tools or all built-in tools, and uses temporary working directories.
It retains existing login/home access. This is **not** a VM, separate identity,
or a general sandbox for adversarial executable tasks. Use only this reviewed
synthetic corpus; do not add customer secrets, private code, or live actions.
Host-managed policy can still affect responses. **Codex still emitted local
skill-discovery warnings despite `skip_host_skill_discovery` in this trial.**
Do not claim a clean skills-free baseline or compare absolute host token counts
as equivalent contexts. The runner flags observed discovery warnings; absence
of a warning is not proof of isolation. A truly controlled benchmark needs
a separately provisioned clean test identity/environment.

Artifacts are placed in a new owner-only `.eval-runs/<run-id>/` directory,
ignored by Git. Raw host logs can contain machine paths and account context:
review/redact before sharing. No results are uploaded automatically.

Review responses against each case's required concepts and forbidden actions.
Separately score response density, one clear next action, false blocks, and
successful safe completion. Record observations and failures; do not derive a
security-effectiveness percentage from a tiny public smoke sample. Held-out,
repeated tests and real artifact/action checks remain required.
