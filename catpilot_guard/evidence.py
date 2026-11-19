"""Content-free evidence lines, schema version 1: the one writer for the hooks, the session-start script and the reference MCP server.

The schema is docs/spec/evidence-event.schema.json, described in docs/spec/EVIDENCE.md. When
CATPILOT_EVIDENCE_LOG names a file, each event appends one JSON line to it. When
CATPILOT_EVIDENCE_SYSLOG is set ("1", "true", "yes", a host:port, or a socket path), the same
line goes to syslog. When CATPILOT_EVIDENCE_HTTPS names an https URL, deny, ask, would_deny and input_error
lines are also POSTed there, each send bounded by a short timeout. Off unless one is set. With
CATPILOT_EVIDENCE_CHAIN=1, each line written to the file carries prev_sha256, the SHA-256 of the file's previous
line, so tools/evidence_verify.py can find an edit, a deletion or a reordering (docs/spec/EVIDENCE.md §8).

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

import hashlib
import json
import os
import re
import sys
import threading
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
# script); see docs/spec/EVIDENCE.md. A company rule whose matches expiring exceptions all covered writes
# would_deny with exception_id: adding an event would change this list, which needs a new schema version (EVIDENCE.md §6).
EVENTS = ("rules_delivered", "rules_expired", "deny", "ask", "would_deny", "policy_error", "input_error", "lookup")
MODES = ("monitor", "ask", "block")

EVIDENCE_ENV = "CATPILOT_EVIDENCE_LOG"
SYSLOG_ENV = "CATPILOT_EVIDENCE_SYSLOG"
CHAIN_ENV = "CATPILOT_EVIDENCE_CHAIN"
HTTPS_ENV = "CATPILOT_EVIDENCE_HTTPS"
HTTPS_TOKEN_FILE_ENV = "CATPILOT_EVIDENCE_HTTPS_TOKEN_FILE"
HTTPS_TIMEOUT_ENV = "CATPILOT_EVIDENCE_HTTPS_TIMEOUT"
HOOK_SOURCE = "claude-code-hook"
SERVER_SOURCE = "mcp-server"
SESSION_START_SOURCE = "session-start"
CLAUDE_CODE = "claude-code"
CODEX = "codex"
COPILOT_CLI = "copilot-cli"

LOCK_WAIT_SECONDS = 0.5

# The hash chain (docs/spec/EVIDENCE.md §8). The first chained line of an empty file points at GENESIS. The writer
# looks back at most CHAIN_TAIL_LIMIT bytes for the start of the previous line.
GENESIS = "0" * 64
CHAIN_TAIL_LIMIT = 1 << 20
TRUE_VALUES = ("1", "true", "yes")

# Forwarding (docs/spec/EVIDENCE.md §9): only the events where a check blocked or would have blocked, only the
# schema's fields, and the whole send bounded by the timeout, DNS included, so a dead endpoint costs at most that.
FORWARD_EVENTS = ("deny", "ask", "would_deny", "input_error")
FORWARD_TIMEOUT_DEFAULT = 1.0
FORWARD_TIMEOUT_MAX = 3.0
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")
SCHEMA_FIELDS = (
    "schema_version", "event_id", "ts", "source", "host", "event", "rule_id", "exception_id", "mode", "policy_sha256",
    "release", "session_id", "session_source", "block_chars", "block_lines", "hook", "tool", "label", "error",
    "policy_status", "unknown_policy", "topic", "category", "kind", "outcome", "ask_a_human", "fields", "prev_sha256",
)

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
# Fields only the writer sets: the envelope, and the chain's link.
WRITER_FIELDS = ENVELOPE + ("prev_sha256",)


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
        if key in WRITER_FIELDS:
            raise ValueError("the envelope is the writer's")
        if value is not None and key in CHECKED:
            pattern, longest = CHECKED[key]
            if not (isinstance(value, str) and len(value) <= longest and pattern.fullmatch(value)):
                raise ValueError("malformed evidence field")
        if key == "mode" and value is not None and value not in MODES:
            raise ValueError("unknown mode")
        line[key] = value
    # An exception id says which exception covered matches of the rule a company-rules hook's would_deny line names
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


def _lock(fd: int) -> bool:
    """Take an exclusive advisory lock on fd, waiting at most LOCK_WAIT_SECONDS; carry on without it otherwise.
    True when the lock is held."""
    if fcntl is None:
        return False
    deadline = time.monotonic() + LOCK_WAIT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:  # another writer holds it
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.005)
        except OSError:  # a filesystem without locks
            return False


def line_sha256(raw: bytes) -> str:
    """The chain's hash of one line: SHA-256 of its bytes, without the newline that ends it."""
    return hashlib.sha256(raw).hexdigest()


def _tail(fh) -> tuple:
    """(the file's last line as bytes, or None when the file is empty; whether the file ends with a newline).
    Raises OSError when the line's start is not within CHAIN_TAIL_LIMIT bytes of the end."""
    end = fh.seek(0, os.SEEK_END)
    if end == 0:
        return None, True
    fh.seek(end - 1)
    ends_with_newline = fh.read(1) == b"\n"
    pos = end - 1 if ends_with_newline else end
    buf = b""
    while pos > 0:
        step = min(4096, pos)
        pos -= step
        fh.seek(pos)
        buf = fh.read(step) + buf
        cut = buf.rfind(b"\n")
        if cut != -1:
            return buf[cut + 1:], ends_with_newline
        if len(buf) > CHAIN_TAIL_LIMIT:
            raise OSError("evidence line too long to chain")
    return buf, ends_with_newline


def _write_all(fh, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = fh.write(view)
        if not written:
            raise OSError("evidence write made no progress")
        view = view[written:]


def append_line(path: str, serialized: str) -> None:
    """Append serialized and a newline to the file at path, creating its directory, as one write."""
    target = Path(os.path.expanduser(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    # Unbuffered append: each write() is one write(2) at the end of the file. The lock is released on close.
    with open(target, "ab", buffering=0) as fh:
        _lock(fh.fileno())
        _write_all(fh, (serialized + "\n").encode("utf-8"))


def append_chained(path: str, line: dict) -> str:
    """Append line to the file at path with prev_sha256, the hash of the file's last line (GENESIS for an empty
    file), read and written under one lock. Returns the line as written. When the last line cannot be read, the
    line is written without prev_sha256 and the verifier reports the gap. Without the lock (Windows, a lock held
    past LOCK_WAIT_SECONDS, a file system without locks) two writers can link to the same line; the verifier
    reports that as a break too."""
    target = Path(os.path.expanduser(path))
    target.parent.mkdir(parents=True, exist_ok=True)
    # a+b: reads anywhere, and every write goes to the end of the file.
    with open(target, "a+b", buffering=0) as fh:
        _lock(fh.fileno())
        prefix = b""
        try:
            last, ends_with_newline = _tail(fh)
            line = dict(line, prev_sha256=GENESIS if last is None else line_sha256(last))
            if not ends_with_newline:  # a torn last line stays a line of its own, and the chain covers it
                prefix = b"\n"
        except OSError:
            pass
        serialized = json.dumps(line, sort_keys=True)
        _write_all(fh, prefix + (serialized + "\n").encode("utf-8"))
    return serialized


def forward_target(spec: str) -> str | None:
    """The URL to POST forwarded lines to: an https URL, or http to a loopback address (a collector on this
    machine). None for anything else, including a URL with a user name, a password or a fragment in it."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(spec)
        host = parts.hostname
        if parts.username is not None or parts.password is not None or not host or parts.fragment:
            return None
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        return None
    if parts.scheme == "https" or (parts.scheme == "http" and host in LOOPBACK_HOSTS):
        return spec
    return None


def forward_timeout() -> float:
    """Seconds one forward may take, from CATPILOT_EVIDENCE_HTTPS_TIMEOUT, within (0, FORWARD_TIMEOUT_MAX]."""
    try:
        value = float(os.environ.get(HTTPS_TIMEOUT_ENV, "").strip() or FORWARD_TIMEOUT_DEFAULT)
    except ValueError:
        return FORWARD_TIMEOUT_DEFAULT
    if not value > 0:  # also refuses NaN
        return FORWARD_TIMEOUT_DEFAULT
    return min(value, FORWARD_TIMEOUT_MAX)


def _bearer_token(token_file: str) -> str | None:
    """The token in token_file, stripped, when it is one run of printable ASCII; None otherwise."""
    with open(os.path.expanduser(token_file), "rb") as fh:
        raw = fh.read(4097)
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError:
        return None
    if not token or len(token) > 4096 or any(not (33 <= ord(c) <= 126) for c in token):
        return None
    return token


def forward_https(line: dict, url: str, timeout: float, token_file: str = "") -> None:
    """POST line, cut to the schema's fields, to url as JSON, from a daemon thread the caller waits on for at
    most timeout seconds. Never follows a redirect. A failure, a refusal or a timeout drops the line."""
    import urllib.request

    body = json.dumps({key: line[key] for key in SCHEMA_FIELDS if key in line}, sort_keys=True).encode("utf-8")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    def send() -> None:
        try:
            headers = {"Content-Type": "application/json", "User-Agent": "catpilot-guardrails-evidence/1"}
            if token_file:
                token = _bearer_token(token_file)
                if token is None:
                    return  # set but unusable: send nothing rather than send without it
                headers["Authorization"] = "Bearer " + token
            request = urllib.request.Request(url, data=body, headers=headers, method="POST")
            with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
                response.read(1024)
        except Exception:
            pass

    worker = threading.Thread(target=send, name="catpilot-evidence-forward", daemon=True)
    worker.start()
    worker.join(timeout)


def record(event: str, source: str, fields: dict | None = None) -> None:
    """Write one line to the configured sinks. Returns at once when none is set. Never raises."""
    try:
        path = os.environ.get(EVIDENCE_ENV, "").strip()
        syslog_spec = os.environ.get(SYSLOG_ENV, "").strip()
        https_spec = os.environ.get(HTTPS_ENV, "").strip()
        if not path and not syslog_spec and not https_spec:
            return
        line = build_line(event, source, fields)
        serialized = json.dumps(line, sort_keys=True)
        chain = os.environ.get(CHAIN_ENV, "").strip().lower() in TRUE_VALUES
    except Exception:
        return
    if path:
        try:
            if chain:
                # The other sinks get the line as the file has it, link included, so an off-box copy anchors the chain.
                serialized = append_chained(path, line)
                line = json.loads(serialized)
            else:
                append_line(path, serialized)
        except Exception:
            pass
    if syslog_spec:
        try:
            emit_syslog(serialized, syslog_spec)
        except Exception:
            pass
    if https_spec and event in FORWARD_EVENTS:
        try:
            url = forward_target(https_spec)
            if url:
                forward_https(line, url, forward_timeout(), os.environ.get(HTTPS_TOKEN_FILE_ENV, "").strip())
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
