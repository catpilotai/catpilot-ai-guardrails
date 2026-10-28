"""Use the Claude Code hooks' credential and file-write checks as tool gates inside any Python agent harness.

A harness is a loop you wrote around a model: plan, call a tool, check, repeat.
The loop owns the tool boundary, so the loop can enforce what a skill can only
advise. This module exposes the same checks the Claude Code hooks use, as
plain functions, so a harness can refuse a shell command or file write that
carries a literal credential before the tool runs.

    from hooks.harness.secret_gate import gate_shell_command, gate_file_write

    reason = gate_shell_command(proposed_command)
    if reason:
        # return the reason to the model as the tool result; do not execute
        ...

What this is: enforcement on the paths you route through it, in a harness
you control. What it is not: a secret scanner for prompts, file reads, or other
tools, and not a claim about any path that bypasses your gate. Test it in your
loop with a documentation-only key such as AKIAIOSFODNN7EXAMPLE, and write down
which tool calls go through the gate and which do not.

Standard library only. The checks themselves live in ../claude-code/ so the
hooks and the harness gates cannot drift apart.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

_HOOK_DIR = Path(__file__).resolve().parent.parent / "claude-code"
_HOOK = _HOOK_DIR / "pretooluse-secrets.py"
_WRITE_HOOK = _HOOK_DIR / "pretooluse-write-secrets.py"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_hook = _load_module("catpilot_pretooluse_secrets", _HOOK)
_write_hook = _load_module("catpilot_pretooluse_write_secrets", _WRITE_HOOK)


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


def gate_file_write(content: str) -> str | None:
    """Return a plain-language refusal reason if content to be written carries a literal credential or private key, else None.

    Raises ValueError on non-string content, failing closed.
    """
    if not isinstance(content, str):
        raise ValueError("content must be a string")
    verdict = _write_hook.inspect_event({"tool_name": "Write", "tool_input": {"content": content}})
    if not verdict:
        return None
    return verdict["hookSpecificOutput"]["permissionDecisionReason"]


def gate_write_tool_call(tool_name: str, tool_input: dict, field: str = "content") -> str | None:
    """Same write check for a harness whose file-writing tool uses a custom name or field. Fails closed."""
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be a mapping")
    if tool_name in ("Write", "Edit", "MultiEdit", "NotebookEdit") and field == "content":
        try:
            verdict = _write_hook.inspect_event({"tool_name": tool_name, "tool_input": tool_input})
        except ValueError:
            return f"Catpilot write check: invalid input for '{tool_name}', so the write was not allowed."
        return verdict["hookSpecificOutput"]["permissionDecisionReason"] if verdict else None
    if field not in tool_input:
        return f"Catpilot write check: the tool call has no '{field}' field, so it was not allowed."
    content = tool_input[field]
    if not isinstance(content, str):
        return f"Catpilot write check: the '{field}' field must be a string, so the tool call was not allowed."
    verdict = _write_hook.inspect_event({"tool_name": "Write", "tool_input": {"content": content}})
    return verdict["hookSpecificOutput"]["permissionDecisionReason"] if verdict else None


if __name__ == "__main__":
    import sys

    reason = gate_shell_command(" ".join(sys.argv[1:]))
    print(reason or "allowed: no literal credential found")
    sys.exit(2 if reason else 0)
