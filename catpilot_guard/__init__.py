"""Catpilot's tool-call checks, one module per check, standard library only. Python 3.8+.

  secrets        a literal credential in a shell command
  write_secrets  a literal credential or private-key block in a file write or edit
  destructive    a high-blast-radius shell command
  company_rules  the company's own enforcement rules, from the compiled policy that policy.py reads
                 (tools/validate_overlay.py compile), in monitor, ask or block

Each module reads one Claude Code PreToolUse event on stdin in main() and prints a deny
decision or nothing. The files in hooks/claude-code/ are thin shims that run main(), and
hooks/harness/ calls the same functions. Importing the package imports no check.

  copilot        GitHub Copilot CLI's PreToolUse event read in the Claude Code shape the checks take, and
                 its decision written with the fields Copilot reads (--host copilot-cli)
  evidence       the content-free evidence writer the checks and the reference MCP server
                 share (docs/spec/EVIDENCE.md); a check imports it only to write a line
  session_start  not a check: the SessionStart hook for Claude Code and Codex that puts the
                 company rules in front of the model, or says they expired or could not be
                 loaded (hooks/session-start/). Advice, not enforcement

write_decision() and write_reason() are how every main() talks to the host, so that a
failure to write never ends in an exit code the host treats as non-blocking. session_start
writes through them too but always exits 0: SessionStart cannot block on either host.
"""
from __future__ import annotations

import json
import os
import sys


def write_decision(result: dict) -> int:
    """Print the decision as one JSON line and return the hook's exit code.

    0 once the line is written and flushed. 2, which blocks, when stdout cannot take it
    (the host closed the pipe, or there is no stdout): the host did not receive the
    decision, and any other non-zero exit would let the call run. stdout is then pointed
    at os.devnull, so the interpreter's own flush at exit cannot fail again and replace
    the exit code with 120.
    """
    try:
        sys.stdout.write(json.dumps(result) + "\n")
        sys.stdout.flush()
        return 0
    except Exception:
        _discard(sys.stdout)
        return 2


def write_reason(message: str) -> None:
    """Print a message for the person on stderr. Never raises: the exit code decides.

    If stderr cannot take it, stderr is pointed at os.devnull too: the interpreter also
    replaces the exit code with 120 when its flush of stderr at exit fails.
    """
    try:
        sys.stderr.write(message + "\n")
        sys.stderr.flush()
    except Exception:
        _discard(sys.stderr)


def _discard(stream) -> None:
    """Point a standard stream's file descriptor at os.devnull, so later flushes succeed."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, stream.fileno())
        finally:
            os.close(devnull)
    except Exception:
        pass


# The tools a PreToolUse check can say it ran on, in its evidence lines. Claude Code and Codex send the same
# PreToolUse event shape for Bash (tool_input.command). Copilot CLI's is read through catpilot_guard/copilot.py
# (event_for_host, decision_for_host), so the checks decide the same way on every tool.
HOOK_HOSTS = ("claude-code", "codex", "copilot-cli")
DEFAULT_HOOK_HOST = "claude-code"
COPILOT_CLI = "copilot-cli"


def event_for_host(event: object, host: str | None) -> object:
    """The hook event in the Claude Code shape every check reads. Only Copilot CLI's differs.
    Raises ValueError for a Copilot file write of a shape it does not know, so the hook fails closed."""
    if host == COPILOT_CLI:
        from .copilot import to_claude

        return to_claude(event)
    return event


def decision_for_host(result: dict, host: str | None) -> dict:
    """The decision with the fields the host reads. Copilot CLI also gets top-level permissionDecision fields."""
    if host == COPILOT_CLI:
        from .copilot import with_copilot_fields

        return with_copilot_fields(result)
    return result


EVIDENCE_DEFAULT_FLAG = "--evidence-default"
EVIDENCE_ENV = "CATPILOT_EVIDENCE_LOG"
# Where --evidence-default sends evidence: under the home directory of whoever runs the hook. os.path.expanduser
# reads HOME on macOS and Linux and USERPROFILE on Windows, so a hook command needs no shell to name it
# (docs/spec/WINDOWS.md §3.1).
EVIDENCE_DEFAULT_PATH = os.path.join("~", ".catpilot-guardrails", "evidence.jsonl")


def take_evidence_default(argv: list | None = None) -> list:
    """The hook's arguments without one --evidence-default, applying it. Never raises.

    With the flag, and CATPILOT_EVIDENCE_LOG unset or empty, evidence goes to ~/.catpilot-guardrails/evidence.jsonl,
    the file the managed commands' `CATPILOT_EVIDENCE_LOG="$HOME/..."` prefix names, without a shell to expand it. A
    variable already set wins. A home that does not expand to an absolute path sets nothing, so evidence never lands
    in the session's working directory. The flag changes where evidence is written, never a decision.
    """
    try:
        args = sys.argv[1:] if argv is None else list(argv)
        if EVIDENCE_DEFAULT_FLAG not in args:
            return args
        args.remove(EVIDENCE_DEFAULT_FLAG)
        if not os.environ.get(EVIDENCE_ENV, "").strip():
            path = os.path.expanduser(EVIDENCE_DEFAULT_PATH)
            if os.path.isabs(path):
                os.environ[EVIDENCE_ENV] = path
        return args
    except Exception:
        return list(sys.argv[1:] if argv is None else argv)


def hook_host(argv: list | None = None) -> str | None:
    """The tool a PreToolUse check runs on, from `--host claude-code|codex|copilot-cli`.

    No arguments: claude-code, the tool every configuration written before this option names.
    `--host codex` or `--host=codex` (or another of HOOK_HOSTS): that tool. Anything else: None,
    so the line leaves host out rather than name the wrong tool. It labels evidence lines, and for
    copilot-cli it also selects how the event is read and the decision written (event_for_host,
    decision_for_host); what a check decides never depends on it. It never raises.
    """
    try:
        args = sys.argv[1:] if argv is None else list(argv)
        if not args:
            return DEFAULT_HOOK_HOST
        if len(args) == 2 and args[0] == "--host":
            value = args[1]
        elif len(args) == 1 and isinstance(args[0], str) and args[0].startswith("--host="):
            value = args[0][len("--host="):]
        else:
            return None
        return value if value in HOOK_HOSTS else None
    except Exception:
        return None
