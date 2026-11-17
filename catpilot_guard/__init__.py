"""Catpilot's tool-call checks, one module per check, standard library only. Python 3.8+.

  secrets        a literal credential in a shell command
  write_secrets  a literal credential or private-key block in a file write or edit
  destructive    a high-blast-radius shell command

Each module reads one Claude Code PreToolUse event on stdin in main() and prints a deny
decision or nothing. The files in hooks/claude-code/ are thin shims that run main(), and
hooks/harness/ calls the same functions. Importing the package imports no check.

  evidence       the content-free evidence writer the checks and the reference MCP server
                 share (docs/spec/EVIDENCE.md); a check imports it only to write a line

write_decision() and write_reason() are how every main() talks to the host, so that a
failure to write never ends in an exit code the host treats as non-blocking.
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
