"""Content-free evidence lines, schema version 1: the one writer for the hooks, the session-start script and the reference MCP server.

The schema is docs/spec/evidence-event.schema.json, described in docs/spec/EVIDENCE.md. When
CATPILOT_EVIDENCE_LOG names a file, each event appends one JSON line to it. When
CATPILOT_EVIDENCE_SYSLOG is set ("1", "true", "yes", a host:port, or a socket path), the same
line goes to syslog. Off unless one is set.

What a line carries: the schema version, a random event id, the time, the source, the event,
and the enumerated fields its caller passes (a hook name, a label, a tool name, a session id, a
company rule or exception id, a policy hash, a size). Never a command, a file path, file content,
a prompt, a plan description, or a value from the company rules file.

Several hooks and sessions may append to one file at once. Each line is one write to a file
opened for append, under an exclusive fcntl lock where the platform has one. The writer waits at
most LOCK_WAIT_SECONDS for the lock and then writes without it, so a stuck lock cannot hold up a
decision. Nothing here raises: record() swallows every error, so a logging failure never changes
a decision or an answer.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
except ImportError:  # Windows has no fcntl: each line is still one write, without a lock
    fcntl = None

SCHEMA_VERSION = 1
# The closed list. Written today: deny and input_error (hooks), ask, would_deny and policy_error (the
# company-rules hook), lookup (server), and rules_delivered, rules_expired and policy_error (the session-start
# script); see docs/spec/EVIDENCE.md. A company rule an expiring exception relaxed writes would_deny with
# exception_id: adding an event would change this list, which needs a new schema version (EVIDENCE.md §6).
EVENTS = ("rules_delivered", "rules_expired", "deny", "ask", "would_deny", "policy_error", "input_error", "lookup")
MODES = ("monitor", "ask", "block")

EVIDENCE_ENV = "CATPILOT_EVIDENCE_LOG"
SYSLOG_ENV = "CATPILOT_EVIDENCE_SYSLOG"
HOOK_SOURCE = "claude-code-hook"
SERVER_SOURCE = "mcp-server"
SESSION_START_SOURCE = "session-start"
CLAUDE_CODE = "claude-code"
CODEX = "codex"
COPILOT_CLI = "copilot-cli"

LOCK_WAIT_SECONDS = 0.5

# An opaque identifier, never free text. A session id outside this shape is left out of the line.
SESSION_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")
# Fields the writer refuses to write in any other shape: (pattern, longest length). Rule and exception ids follow
# docs/spec/OVERLAY_V2.md §2.1: lowercase letters, digits and single hyphens, at most 64 characters.
RULE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
CHECKED = {
    "session_id": (SESSION_ID, 128),
    "rule_id": (RULE_ID, 64),
    "exception_id": (RULE_ID, 64),
    "policy_sha256": (re.compile(r"[0-9a-f]{64}"), 64),
}
ENVELOPE = ("schema_version", "event_id", "ts", "source", "event")


def session_id_of(hook_event: object) -> str | None:
    """The host's session id from a hook event, or None when it is missing or not an opaque identifier."""
    sid = hook_event.get("session_id") if isinstance(hook_event, dict) else None
    return sid if isinstance(sid, str) and SESSION_ID.fullmatch(sid) else None


def build_line(event: str, source: str, fields: dict | None = None) -> dict:
    """One event as a dict: the envelope, then the caller's fields as given. Raises ValueError on a malformed value."""
    if event not in EVENTS:
        raise ValueError("unknown evidence event")
    line = {
        "schema_version": SCHEMA_VERSION,
        "event_id": str(uuid.uuid4()),
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
        "event": event,
    }
    for key, value in (fields or {}).items():
        if key in ENVELOPE:
            raise ValueError("the envelope is the writer's")
        if value is not None and key in CHECKED:
            pattern, longest = CHECKED[key]
            if not (isinstance(value, str) and len(value) <= longest and pattern.fullmatch(value)):
                raise ValueError("malformed evidence field")
        if key == "mode" and value is not None and value not in MODES:
            raise ValueError("unknown mode")
        line[key] = value
    # An exception id says which exception relaxed the rule a company-rules hook's would_deny line names
    # (OVERLAY_V2.md §3.1); on any other line, or without the rule, it would say nothing true. The schema refuses the same.
    if line.get("exception_id") is not None and (event != "would_deny" or source != HOOK_SOURCE or line.get("rule_id") is None):
        raise ValueError("exception_id belongs on a hook's would_deny line with its rule_id")
    return line


def emit_syslog(payload_json: str, spec: str) -> None:
    """Send one line to syslog: the local socket for "1", "true" or "yes", else a host:port (UDP) or a socket path."""
    import logging
    import logging.handlers

    address: str | tuple[str, int] = ("localhost", 514)
    if spec not in ("1", "true", "yes"):
        if ":" in spec and not spec.startswith("/"):
            host, port_s = spec.rsplit(":", 1)
            address = (host, int(port_s))
        else:
            address = spec
    elif sys.platform == "darwin" and Path("/var/run/syslog").exists():
        address = "/var/run/syslog"
    elif Path("/dev/log").exists():
        address = "/dev/log"
    handler = logging.handlers.SysLogHandler(address=address)
    # A failed send is dropped. Left to the logging module, it prints a traceback with this line to
    # stderr (Python 3.11 and later connect a socket path lazily, inside emit).
    handler.handleError = lambda record: None
    try:
        record = logging.LogRecord(
            name="catpilot-guardrails", level=logging.INFO, pathname="", lineno=0,
            msg=f"catpilot-guardrails: {payload_json}", args=(), exc_info=None,
        )
        handler.emit(record)
    finally:
        handler.close()


def _lock(fd: int) -> None:
    """Take an exclusive advisory lock on fd, waiting at most LOCK_WAIT_SECONDS; carry on without it otherwise."""
    if fcntl is None:
        return
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:  # another writer holds it
            if time.monotonic() >= deadline:
                return
            time.sleep(0.005)
        except OSError:  # a filesystem without locks
            return


def append_line(path: str, serialized: str) -> None:
    """Append serialized and a newline to the file at path, creating its directory, as one write."""
    target = Path(os.path.expanduser(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    data = memoryview((serialized + "\n").encode("utf-8"))
    # Unbuffered append: each write() is one write(2) at the end of the file. The lock is released on close.
    with open(target, "ab", buffering=0) as fh:
        _lock(fh.fileno())
        while data:
            written = fh.write(data)
            if not written:
                raise OSError("evidence write made no progress")
            data = data[written:]


def record(event: str, source: str, fields: dict | None = None) -> None:
    """Write one line to the configured sinks. Returns at once when none is set. Never raises."""
    try:
        path = os.environ.get(EVIDENCE_ENV, "").strip()
        syslog_spec = os.environ.get(SYSLOG_ENV, "").strip()
        if not path and not syslog_spec:
            return
        serialized = json.dumps(build_line(event, source, fields), sort_keys=True)
    except Exception:
        return
    if path:
        try:
            append_line(path, serialized)
        except Exception:
            pass
    if syslog_spec:
        try:
            emit_syslog(serialized, syslog_spec)
        except Exception:
            pass


def record_hook_event(hook: str, event: str, hook_event: object = None, host: str | None = None, **fields) -> None:
    """A hook's line: its name, the host when the caller knows it, the session id read from the hook event,
    and the given fields. A value that is None is left out, as the hooks did before. Never raises."""
    try:
        values = {"hook": hook, "host": host, "session_id": session_id_of(hook_event)}
        values.update(fields)
        record(event, HOOK_SOURCE, {key: value for key, value in values.items() if value is not None})
    except Exception:
        pass
