"""Use the Claude Code hook's credential check as a tool gate inside any Python agent harness.

A harness is a loop you wrote around a model: plan, call a tool, check, repeat.
The loop owns the tool boundary, so the loop can enforce what a skill can only
advise. This module exposes the same check the Claude Code hook uses, as a
plain function, so a harness can refuse a shell command that carries a literal
credential before the command runs.

    from hooks.harness.secret_gate import gate_shell_command

    reason = gate_shell_command(proposed_command)
    if reason:
        # return the reason to the model as the tool result; do not execute
        ...

What this is: enforcement on the one path you route through it, in a harness
you control. What it is not: a secret scanner for prompts, files, or other
tools, and not a claim about any path that bypasses your gate. Test it in your
loop with a documentation-only key such as AKIAIOSFODNN7EXAMPLE, and write down
which tool calls go through the gate and which do not.

Standard library only. The check itself lives in ../claude-code/pretooluse-secrets.py
so the hook and the harness gate cannot drift apart.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_HOOK = Path(__file__).resolve().parent.parent / "claude-code" / "pretooluse-secrets.py"


def _load_hook():
    spec = importlib.util.spec_from_file_location("catpilot_pretooluse_secrets", _HOOK)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_hook = _load_hook()


def gate_shell_command(command: str) -> str | None:
    """Return a plain-language refusal reason if the command carries a literal credential, else None.

    Raises ValueError on a non-string command, so a broken caller fails closed
    rather than silently allowing.
    """
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    verdict = _hook.decide({"tool_name": "Bash", "tool_input": {"command": command}})
    if not verdict:
        return None
    return verdict["hookSpecificOutput"]["permissionDecisionReason"]


def gate_tool_call(tool_name: str, tool_input: dict, field: str = "command") -> str | None:
    """Same check for a harness whose shell tool has another name.

    The command text is read from `tool_input[field]` (default "command"); pass
    `field` when an adapter's tool uses a different key. Fails closed: a missing,
    null, or non-string value for that field returns a deny reason naming the
    field, instead of silently treating it as an empty (so always-allowed) command.
    """
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be a mapping")
    if field not in tool_input:
        return f"Catpilot secret check: the tool call has no '{field}' field, so it was not allowed."
    command = tool_input[field]
    if not isinstance(command, str):
        return f"Catpilot secret check: the '{field}' field must be a string, so the tool call was not allowed."
    verdict = _hook.decide({"tool_name": "Bash", "tool_input": {"command": command}})
    return verdict["hookSpecificOutput"]["permissionDecisionReason"] if verdict else None


if __name__ == "__main__":
    import sys

    reason = gate_shell_command(" ".join(sys.argv[1:]))
    print(reason or "allowed: no literal credential found")
    sys.exit(2 if reason else 0)
