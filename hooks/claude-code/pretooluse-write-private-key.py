#!/usr/bin/env python3
"""Claude Code PreToolUse hook: deny a file write or edit that adds a literal private-key block.

Covers the Write, Edit, MultiEdit, and NotebookEdit tools only. It looks for a
PEM private-key header in the content being added and returns a deny decision
with a plain-language reason that never echoes the content. It never returns
allow, so every other host rule still applies. Malformed or oversized input
exits 2, which the host treats as a block.

Not a general secret scanner: it does not inspect shell commands (see
pretooluse-secrets.py), file reads, prompts, or other tools. Standard library
only; no network, no logging.
"""

from __future__ import annotations

import json
import re
import sys

PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
MAX_INPUT = 1_048_576

REASON = (
    "A literal private-key block was found in the content being written. Keep key "
    "material out of files the agent writes: reference it from a secret store or use an "
    "unmistakable placeholder such as SAMPLE-KEY. No key material is included in this message."
)


def added_text(tool_name: str, tool_input: object) -> list[str] | None:
    """The strings a supported tool would add to a file, or None for tools this hook does not cover."""
    if not isinstance(tool_input, dict):
        raise ValueError("invalid tool input")
    if tool_name == "Write":
        parts = [tool_input.get("content")]
    elif tool_name == "Edit":
        parts = [tool_input.get("new_string")]
    elif tool_name == "MultiEdit":
        edits = tool_input.get("edits")
        if not isinstance(edits, list) or not all(isinstance(e, dict) for e in edits):
            raise ValueError("invalid edits")
        parts = [e.get("new_string") for e in edits]
    elif tool_name == "NotebookEdit":
        parts = [tool_input.get("new_source")]
    else:
        return None
    if not all(isinstance(p, str) for p in parts):
        raise ValueError("missing write content")
    return parts


def inspect_event(event: object) -> dict:
    if not isinstance(event, dict):
        raise ValueError("invalid hook event")
    parts = added_text(str(event.get("tool_name")), event.get("tool_input"))
    if parts is None:
        return {}
    if any(PRIVATE_KEY.search(p) for p in parts):
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": REASON,
            }
        }
    return {}


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ValueError("hook input too large")
        result = inspect_event(json.loads(payload))
    except (ValueError, TypeError, RecursionError):
        print("Catpilot write check unavailable: invalid or oversized hook input. Review the write before retrying.", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
