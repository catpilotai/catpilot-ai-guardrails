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
   (engineering work) or `skills/catpilot-safe-building/SKILL.md` (a loop that
   serves non-engineers) as system-level instructions, or through the SDK's
   skills support where it has one. This is advice; it shapes what the model
   proposes.
2. **Tool gates.** `secret_gate.py` exposes the Claude Code hooks' credential
   and file-write checks as functions (`gate_shell_command`, `gate_tool_call`,
   `gate_file_write`, `gate_write_tool_call`), and `destructive_gate.py`
   exposes the destructive-operation check (`gate_destructive_command`,
   `gate_destructive_tool_call`). Call them before executing a shell command or
   file write. This is enforcement on the paths you route through them.
3. **Loop guardrails as reference text.** `frameworks/agentic/FULL_AGENTIC.md`
   covers tool-execution sandboxing, human-in-the-loop for destructive
   operations, memory and context isolation, cron and scheduled-task
   idempotency, agent identity integrity, and tool-loop discipline: retry caps,
   state invalidation after every state-changing call, verifier-backed
   progress, delegation-depth caps. It is guidance you implement in the loop,
   not a package the loop installs.

## The gates

```python
from hooks.harness.secret_gate import gate_shell_command, gate_file_write
from hooks.harness.destructive_gate import gate_destructive_command

def run_shell(command: str) -> str:
    for gate in (gate_shell_command, gate_destructive_command):
        reason = gate(command)
        if reason:
            return f"Refused: {reason}"  # the model sees why; nothing ran
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def write_file(path: Path, content: str) -> str:
    reason = gate_file_write(content)
    if reason:
        return f"Refused: {reason}"
    path.write_text(content, encoding="utf-8")
    return "Written"
```

Or from the command line, to try them:

```bash
python hooks/harness/secret_gate.py 'export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE'
python hooks/harness/destructive_gate.py 'az containerapp update --name app --resource-group rg --yaml partial.yaml'
```

The checks are the same files the Claude Code hooks run, loaded in place, so the
two cannot drift. Neither ever returns "allow"; an input without a match returns
`None` and your loop's own rules apply. A non-string input raises, so a
broken caller fails closed.

If your tool's argument is not named `command` or `content`, use
`gate_tool_call(tool_name, tool_input, field="cmd")`,
`gate_write_tool_call(tool_name, tool_input, field="body")`, or
`gate_destructive_tool_call(tool_name, tool_input, field="cmd")` rather than
pulling the value out yourself: each reads `tool_input[field]` and fails closed
the same way. A missing, null, or non-string value for that field returns a
deny reason that names the field, instead of silently treating it as an empty,
always-allowed input.

## What you can and cannot claim afterwards

- You can say: shell commands and file writes that pass through your gated
  functions are refused when they carry a literal credential or match a
  destructive operation pattern, verified on the date you tested them.
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
have no one-line gate. The agentic guidance in `frameworks/agentic/` sets out
the rules: idempotency keys on every external side effect, a durable work
claim per scheduled run, retry budgets shared across the whole workflow, a
verifier that proves the last attempt changed the world before the next one
runs, and hash checks on behavioral files at session start. Implement them in
the loop, test them with a failing tool, and write down what you tested.
