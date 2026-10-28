# Using the checks inside an agent harness

A harness is the loop you build around a model for a specific job: plan, call
a tool, check the result, repeat. Finance close-out agents, support triage
loops, data-pipeline fixers, internal builders on the Claude Agent SDK, the
OpenAI Agents SDK, LangGraph, CrewAI, or plain Python. The loop owns the tool
boundary. That is the one place in this repository's three modes where
enforcement is possible, because the loop, not the model, decides whether a
tool call runs.

Three things from this repository fit a harness:

1. **Standing guidance for the loop.** Load `skills/catpilot-security-core/SKILL.md`
   (engineering work), `skills/catpilot-agentic-security/SKILL.md` (autonomous
   and multi-agent loops), or `skills/catpilot-safe-building/SKILL.md` (a loop
   that serves non-engineers) as system-level instructions, or through the SDK's
   skills support where it has one. This is advice; it shapes what the model
   proposes.
2. **Tool gates.**
   - `secret_gate.py` exposes the Claude Code hooks' credential and file-write
     checks as functions (`gate_shell_command`, `gate_tool_call`,
     `gate_file_write`, `gate_write_tool_call`).
   - `destructive_gate.py` exposes the destructive-operation check
     (`gate_destructive_command`, `gate_destructive_tool_call`).
   - `network_gate.py` exposes outbound URL / SSRF protection
     (`gate_url_fetch`, `gate_url_tool_call`), blocking non-HTTP(S) schemes,
     cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`),
     `localhost`, and hostnames resolving to private, loopback, link-local, or
     reserved IP ranges.
   - `path_gate.py` exposes workspace path confinement (`gate_file_path`,
     `gate_path_tool_call`), resolving symlinks and `~`, blocking credential
     directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`)
     and `/etc/passwd` / `/etc/shadow`, and requiring targets to resolve inside
     `allowed_dirs`.
   Call them before executing a shell command, file read/write, or outbound HTTP
   fetch. This is enforcement on the paths you route through them.
3. **Loop guardrails as reference text and skill bundle.**
   `skills/catpilot-agentic-security/` (and `frameworks/agentic/FULL_AGENTIC.md`)
   covers tool-execution sandboxing, human-in-the-loop for destructive
   operations, memory and context isolation, cron and scheduled-task
   idempotency, agent identity integrity, and tool-loop discipline: retry caps,
   state invalidation after every state-changing call, verifier-backed
   progress, delegation-depth caps.

## The gates

```python
from pathlib import Path
from hooks.harness.secret_gate import gate_shell_command, gate_file_write
from hooks.harness.destructive_gate import gate_destructive_command
from hooks.harness.network_gate import gate_url_fetch
from hooks.harness.path_gate import gate_file_path

WORKSPACE = Path("/app/workspace").resolve()

def run_shell(command: str) -> str:
    for gate in (gate_shell_command, gate_destructive_command):
        reason = gate(command)
        if reason:
            return f"Refused: {reason}"  # the model sees why; nothing ran
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def write_file(path: str, content: str) -> str:
    for reason in (
        gate_file_path(path, allowed_dirs=[WORKSPACE]),
        gate_file_write(content),
    ):
        if reason:
            return f"Refused: {reason}"
    target = (WORKSPACE / path).resolve()
    target.write_text(content, encoding="utf-8")
    return "Written"

def fetch_url(url: str) -> str:
    reason = gate_url_fetch(url)
    if reason:
        return f"Refused: {reason}"
    # Disable redirects so a public URL cannot 302 into an internal address
    return requests.get(url, timeout=10, allow_redirects=False).text
```

Or from the command line, to try them:

```bash
python hooks/harness/secret_gate.py 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
python hooks/harness/destructive_gate.py 'az containerapp update --name app --resource-group rg --yaml partial.yaml'
python hooks/harness/network_gate.py 'http://169.254.169.254/latest/meta-data/'
python hooks/harness/path_gate.py '~/.ssh/id_rsa' '/tmp/workspace'
# gate_destructive_command(command, cwd=...) reads the checked-out branch from cwd for a bare `git push --force`.
```

The secret and destructive checks are the same files the Claude Code hooks run,
loaded in place, so the two cannot drift. None of the gates ever return
"allow"; an input without a match returns `None` and your loop's own rules
apply. A non-string input raises, so a broken caller fails closed.

If your tool's argument uses a custom field name, use
`gate_tool_call(tool_name, tool_input, field="cmd")`,
`gate_write_tool_call(tool_name, tool_input, field="body")`,
`gate_destructive_tool_call(tool_name, tool_input, field="cmd")`,
`gate_url_tool_call(tool_name, tool_input, field="endpoint")`, or
`gate_path_tool_call(tool_name, tool_input, allowed_dirs=[WORKSPACE], field="target")`
rather than pulling the value out yourself: each reads `tool_input[field]` and
fails closed the same way. A missing, null, or non-string value for that field
returns a deny reason that names the field, instead of silently treating it as
an empty, always-allowed input.

## What you can and cannot claim afterwards

- You can say: shell commands, file paths, file writes, and URL fetches that
  pass through your gated functions are refused when they carry a literal
  credential, match a destructive operation pattern, escape `allowed_dirs`, or
  target an internal/metadata address, verified on the date you tested them.
- You cannot say: the harness is protected. Any tool call that does not pass
  through the gate, any prompt, and any path added later is uncovered until you
  route it through a check and test it.

Record both in your harness's own README, the way this repository's
tested-runtimes table in `docs/REFERENCE.md` does. A gate nobody can point to in the code is not a
control.

## Retries, crons, and the loop itself

The tool gates are narrow checks. The larger risks in a harness are
loop behaviors: a retry storm that repeats a side effect, a scheduled run that
replays yesterday's action, a sub-agent that inherits more authority than the
task needs, a memory file that quietly rewrites the agent's constraints. Those
have no one-line gate. The agentic guidance in `skills/catpilot-agentic-security/`
(and `frameworks/agentic/`) sets out the rules: idempotency keys on every
external side effect, a durable work claim per scheduled run, retry budgets
shared across the whole workflow, a verifier that proves the last attempt
changed the world before the next one runs, and hash checks on behavioral files
at session start. Implement them in the loop, test them with a failing tool,
and write down what you tested.
