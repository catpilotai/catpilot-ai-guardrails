#!/usr/bin/env python3
"""Claude Code PreToolUse hook: deny a file write or edit that adds a literal credential or private-key block.

Covers the Write, Edit, MultiEdit, and NotebookEdit tools only. It checks the
content being added against the literal credential patterns documented in the
secret-blocking component of catpilot-security-core (including PEM private-key
headers, API keys, tokens, database URLs with embedded passwords, and literal
password/secret/token assignments) and returns a deny decision with a
plain-language reason that never echoes the content. It never returns allow, so
every other host rule still applies. Malformed or oversized input exits 2,
which the host treats as a block.

Not a general secret scanner: it does not inspect shell commands (see
pretooluse-secrets.py), file reads, prompts, or other tools. Standard library
only; no network, no logging unless CATPILOT_EVIDENCE_LOG or
CATPILOT_EVIDENCE_SYSLOG is set.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
MAX_INPUT = 1_048_576

PRIVATE_KEY_REASON = (
    "A literal private-key block was found in the content being written. Keep key "
    "material out of files the agent writes: reference it from a secret store or use an "
    "unmistakable placeholder such as SAMPLE-KEY. No key material is included in this message."
)


def _load_secrets_hook():
    hook_path = Path(__file__).resolve().parent / "pretooluse-secrets.py"
    spec = importlib.util.spec_from_file_location("catpilot_pretooluse_secrets", hook_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_secrets = _load_secrets_hook()


# Optional evidence log. When CATPILOT_EVIDENCE_LOG names a file, each deny appends one JSON
# line: the time, the hook, the decision, and the credential type. When CATPILOT_EVIDENCE_SYSLOG
# is set, the same content-free JSON line is emitted to syslog. Never the command, never
# the matched text. Off unless set; a logging failure never changes the decision, because
# this function swallows every error.
EVIDENCE_ENV = "CATPILOT_EVIDENCE_LOG"
SYSLOG_ENV = "CATPILOT_EVIDENCE_SYSLOG"
HOOK_NAME = "pretooluse-write-private-key"


def record_evidence(event: str, **fields) -> None:
    path = os.environ.get(EVIDENCE_ENV, "").strip()
    syslog_spec = os.environ.get(SYSLOG_ENV, "").strip()
    if not path and not syslog_spec:
        return
    line = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source": "claude-code-hook", "hook": HOOK_NAME, "event": event}
    line.update({k: v for k, v in fields.items() if v is not None})
    serialized = json.dumps(line, sort_keys=True)
    if path:
        try:
            target = Path(os.path.expanduser(path))
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(serialized + "\n")
        except Exception:
            pass
    if syslog_spec:
        try:
            _secrets.emit_syslog(serialized, syslog_spec)
        except Exception:
            pass


def session_id_of(event: object) -> str | None:
    sid = event.get("session_id") if isinstance(event, dict) else None
    return sid if isinstance(sid, str) and 0 < len(sid) <= 128 else None


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


def find_write_credential(parts: list[str]) -> tuple[str, str] | None:
    """Return (evidence_label, reason) for the first literal credential in parts, or None."""
    for part in parts:
        if PRIVATE_KEY.search(part):
            return "private-key-block", PRIVATE_KEY_REASON
        label = _secrets.find_credential(part)
        if label is not None:
            if label == "private key block":
                return "private-key-block", PRIVATE_KEY_REASON
            reason = (
                f"Catpilot secret check: the content being written appears to contain a literal credential ({label}). "
                "Keep secret values out of files the agent writes: read them from an environment variable or secret "
                "store at runtime (for example process.env.STRIPE_API_KEY or os.environ['STRIPE_API_KEY']), or use "
                "an unmistakable placeholder such as REPLACE_ME. The matched text is not included in this message."
            )
            return label, reason
    return None


def inspect_event(event: object) -> dict:
    if not isinstance(event, dict):
        raise ValueError("invalid hook event")
    parts = added_text(str(event.get("tool_name")), event.get("tool_input"))
    if parts is None:
        return {}
    found = find_write_credential(parts)
    if found is not None:
        label, reason = found
        record_evidence("deny", tool=str(event.get("tool_name")), label=label, session_id=session_id_of(event))
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
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
        record_evidence("input_error")
        print("Catpilot write check unavailable: invalid or oversized hook input. Review the write before retrying.", file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
