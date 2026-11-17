"""Catpilot's tool-call checks, one module per check, standard library only. Python 3.8+.

  secrets        a literal credential in a shell command
  write_secrets  a literal credential or private-key block in a file write or edit
  destructive    a high-blast-radius shell command

Each module reads one Claude Code PreToolUse event on stdin in main() and prints a deny
decision or nothing. The files in hooks/claude-code/ are thin shims that run main(), and
hooks/harness/ calls the same functions. Importing the package imports no check.
"""
from __future__ import annotations
