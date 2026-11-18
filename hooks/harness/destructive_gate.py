"""Use the Claude Code hook's destructive-operation check as a tool gate inside any Python agent harness.

Exposes the check in catpilot_guard/destructive.py (the module the Claude Code
hook pretooluse-destructive-ops.py runs) as plain functions so an agent loop can
refuse high-blast-radius shell commands (partial cloud-CLI replacements,
auto-approved Terraform applies/destroys, unguarded rm -rf, force-pushes to
protected branches, and credential exfiltration pipes) before the command runs.

Standard library only.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

try:
    from catpilot_guard import destructive as _hook
except ImportError:
    # Run as a script (python hooks/harness/destructive_gate.py), the repository root is not on the path.
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from catpilot_guard import destructive as _hook


def gate_destructive_command(command: str, cwd: str | None = None) -> str | None:
    """Return a plain-language refusal reason if the command matches a destructive pattern, else None.

    cwd is the directory the command will run in (default: the current one); it is
    used only to read the checked-out branch for a bare `git push --force`.
    Raises ValueError on a non-string command, on a command with a NUL character,
    on a command longer than 200,000 characters (no timer runs here to bound
    reading it), and on a command that takes longer than six seconds to read
    (catpilot_guard.destructive.ReadTimeout), so a broken caller fails closed
    rather than silently allowing.
    """
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    verdict = _hook.decide({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd or os.getcwd()})
    if not verdict:
        return None
    return verdict["hookSpecificOutput"]["permissionDecisionReason"]


def gate_destructive_tool_call(tool_name: str, tool_input: dict, field: str = "command", cwd: str | None = None) -> str | None:
    """Same check for a harness whose shell tool has another name. Fails closed."""
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be a mapping")
    if field not in tool_input:
        return f"Catpilot destructive-operation check: the tool call has no '{field}' field, so it was not allowed."
    command = tool_input[field]
    if not isinstance(command, str):
        return f"Catpilot destructive-operation check: the '{field}' field must be a string, so the tool call was not allowed."
    verdict = _hook.decide({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": cwd or os.getcwd()})
    return verdict["hookSpecificOutput"]["permissionDecisionReason"] if verdict else None


if __name__ == "__main__":
    reason = gate_destructive_command(" ".join(sys.argv[1:]))
    print(reason or "allowed: no destructive operation pattern matched")
    sys.exit(2 if reason else 0)
