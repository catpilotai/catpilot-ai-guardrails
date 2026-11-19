"""Company rules at session start, on Claude Code and Codex. Advice, not enforcement.

hooks/session-start/catpilot-company-rules.py runs this module's main() as a SessionStart command hook.

A private build (tools/bundle.py --overlay) writes two files side by side:

  company-checklist.md    the checklist and the company rules: the text benchmark condition F plants
  company-checklist.json  the sidecar: the rules' owner, reviewed_on and expires_on, the SHA-256 of the
                          rules file and of company-checklist.md, and the release the build came from

main() reads the SessionStart event on stdin for the session id and how the session started. It checks
the two files against each other, compares expires_on with today's local date, prints one JSON object
in the SessionStart output shape both hosts document, writes one evidence line, and exits 0:

  current   Codex: the block as additionalContext, which Codex adds as developer context.
            Claude Code: a one-line status; a managed CLAUDE.md carries the block itself.
            Evidence: rules_delivered, with the rules hash, the release and the block's size.
  expired   a short notice naming the expiry date and the owner, never the rules, as additionalContext
            and as systemMessage, the warning the person sees. Evidence: rules_expired.
  error     files missing, unreadable or malformed, or a sidecar that does not match the block: a
            notice that the company rules could not be loaded and are unknown, the same two ways.
            Evidence: policy_error with a fixed label (ERROR_LABELS) and nothing else.

The expiry day itself is current, and "today" is the machine's local date, as in
tools/validate_overlay.py and the reference server: the date in the rules file is a calendar date, and
the person reads it against their own calendar.

SessionStart cannot block on either host, so this is a notice, not a control. Every path exits 0,
including a stdout the host closed: on these hosts a non-zero exit only adds a hook-error notice.
Nothing read from stdin or the command line is printed, and the evidence line carries no rule text,
no value from the rules, and no path.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from . import take_evidence_default, write_decision, write_reason

CLAUDE_CODE = "claude-code"
CODEX = "codex"
HOSTS = (CLAUDE_CODE, CODEX)
# The two files a private build writes into its hosts directory (tools/targets.py names them too).
BLOCK_NAME = "company-checklist.md"
SIDECAR_NAME = "company-checklist.json"
SIDECAR_SCHEMA_VERSION = 1
# How the session started: the hook event's `source`, as both hosts document it.
START_SOURCES = ("startup", "resume", "clear", "compact", "fork")
# Why the rules could not be loaded: the only values a policy_error line carries in `label`.
ERROR_LABELS = ("bad-arguments", "missing", "unreadable", "malformed", "hash-mismatch", "internal-error")

# Codex gives the model only a preview of a hook's additionalContext above about 2,500 tokens, unless
# the hook's additionalContextLimit is raised. Estimated at four characters per token.
CODEX_TOKEN_BUDGET = 2500
CHARS_PER_TOKEN = 4
# Claude Code's guidance for a CLAUDE.md file: under 200 lines.
CLAUDE_MD_LINE_BUDGET = 200

MAX_EVENT_BYTES = 1_048_576
MAX_BLOCK_BYTES = 1_048_576
MAX_SIDECAR_BYTES = 65_536

SHA256 = re.compile(r"[0-9a-f]{64}")
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
RELEASE = re.compile(r"[0-9A-Za-z.+-]{1,64}")
# The release shape the evidence schema accepts. Any other release is left out of the line.
EVIDENCE_RELEASE = re.compile(r"[0-9]{4}\.[0-9]{2}(?:\.[0-9]{2})?(?:-[0-9]+)?")
# The line tools/company_checklist.py writes into the block.
BLOCK_POLICY_HASH = re.compile(r"^Overlay SHA-256: ([0-9a-f]{64})$", re.MULTILINE)
LINE_BREAKS_AND_CONTROLS = re.compile("[\x00-\x1f\x7f\x85\u2028\u2029]")

UNAVAILABLE = "Company rules could not be loaded and are unknown. Ask your IT or security owner."
USAGE = (
    "usage: catpilot-company-rules.py --host claude-code|codex [--dir /absolute/path/to/instructions]\n"
    "Runs as a SessionStart hook: reads the hook event on stdin and prints the host's JSON output.\n"
)


class RulesError(Exception):
    """The rules could not be loaded. Its one argument is a label from ERROR_LABELS, never content."""


@dataclass(frozen=True)
class Rules:
    block: str
    owner: str
    reviewed_on: dt.date
    expires_on: dt.date
    policy_sha256: str
    release: str | None


def parse_args(argv: list) -> tuple:
    """(host or None, directory or None, ok). ok is False for an argument that is unknown, repeated or
    missing its value, a host other than HOSTS, or a relative --dir: a relative path would resolve
    against the session's working directory, which the user controls. Argument values are never printed."""
    values: dict = {}
    ok = True
    i = 0
    while i < len(argv):
        name, sep, value = str(argv[i]).partition("=")
        i += 1
        if not sep:
            if i >= len(argv):
                ok = False
                break
            value = str(argv[i])
            i += 1
        if name not in ("--host", "--dir") or name in values:
            ok = False
            continue
        values[name] = value
    host = values.get("--host")
    if host not in HOSTS:
        host, ok = None, False
    directory = None
    if "--dir" in values:
        directory = Path(values["--dir"])
        if not directory.is_absolute():
            directory, ok = None, False
    return host, directory, ok


def read_event(stream) -> dict:
    """The SessionStart event, or {} when stdin is a terminal, empty, too large, or not a JSON object."""
    try:
        if stream is None or stream.isatty():
            return {}
        raw = getattr(stream, "buffer", stream).read(MAX_EVENT_BYTES + 1)
        if not raw or len(raw) > MAX_EVENT_BYTES:
            return {}
        event = json.loads(raw)
    except Exception:
        return {}
    return event if isinstance(event, dict) else {}


def start_source(hook_event: dict) -> str | None:
    """How the session started (startup, resume, clear, compact or fork), or None when absent or unknown."""
    value = hook_event.get("source")
    return value if isinstance(value, str) and value in START_SOURCES else None


def _read(path: Path, limit: int) -> bytes:
    try:
        with open(path, "rb") as fh:
            data = fh.read(limit + 1)
    except FileNotFoundError:
        raise RulesError("missing") from None
    except OSError:
        raise RulesError("unreadable") from None
    if len(data) > limit:
        raise RulesError("malformed")
    return data


def _date(value: object) -> dt.date:
    if not (isinstance(value, str) and ISO_DATE.fullmatch(value)):
        raise RulesError("malformed")
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        raise RulesError("malformed") from None


def load(directory: Path) -> Rules:
    """The block and its sidecar from directory, checked against each other. Raises RulesError."""
    block_bytes = _read(directory / BLOCK_NAME, MAX_BLOCK_BYTES)
    sidecar_bytes = _read(directory / SIDECAR_NAME, MAX_SIDECAR_BYTES)
    try:
        block = block_bytes.decode("utf-8")
        sidecar = json.loads(sidecar_bytes.decode("utf-8"))
    except ValueError:  # UnicodeDecodeError and json.JSONDecodeError are both ValueErrors
        raise RulesError("malformed") from None
    if not isinstance(sidecar, dict):
        raise RulesError("malformed")
    version = sidecar.get("schema_version")
    if type(version) is not int or version != SIDECAR_SCHEMA_VERSION:
        raise RulesError("malformed")
    owner = sidecar.get("owner")
    if not (isinstance(owner, str) and 3 <= len(owner) <= 160 and owner == owner.strip()
            and not LINE_BREAKS_AND_CONTROLS.search(owner)):
        raise RulesError("malformed")
    reviewed_on = _date(sidecar.get("reviewed_on"))
    expires_on = _date(sidecar.get("expires_on"))
    if expires_on <= reviewed_on:
        raise RulesError("malformed")
    policy_sha256 = sidecar.get("policy_sha256")
    block_sha256 = sidecar.get("block_sha256")
    for value in (policy_sha256, block_sha256):
        if not (isinstance(value, str) and SHA256.fullmatch(value)):
            raise RulesError("malformed")
    release = sidecar.get("release")
    if release is not None and not (isinstance(release, str) and RELEASE.fullmatch(release)):
        raise RulesError("malformed")
    stated = BLOCK_POLICY_HASH.search(block)
    if stated is None:
        raise RulesError("malformed")
    if hashlib.sha256(block_bytes).hexdigest() != block_sha256 or stated.group(1) != policy_sha256:
        raise RulesError("hash-mismatch")
    return Rules(block, owner, reviewed_on, expires_on, policy_sha256, release)


def host_output(context: str, notice: str | None = None) -> dict:
    """The SessionStart output both hosts document: additionalContext for the model, and, when the person
    should know too, systemMessage, which both hosts show as a warning."""
    output: dict = {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}}
    if notice is not None:
        output["systemMessage"] = notice
    return output


def current_output(host: str, rules: Rules) -> dict:
    if host == CODEX:
        return host_output(rules.block)
    return host_output(
        f"Company rules from {rules.owner}, reviewed {rules.reviewed_on.isoformat()}, "
        f"valid until {rules.expires_on.isoformat()}, are current."
    )


def expired_notice(host: str, rules: Rules) -> str:
    parts = [f"The company rules expired on {rules.expires_on.isoformat()} and are not in force."]
    if host == CLAUDE_CODE:
        parts.append("The company rules in the instruction file are out of date and must not be relied on.")
    parts.append(f"Ask {rules.owner} for current rules.")
    return " ".join(parts)


def error_output() -> dict:
    return host_output(UNAVAILABLE, UNAVAILABLE)


def block_size(block: str) -> tuple:
    """(characters, lines, estimated tokens) of the block."""
    chars = len(block)
    return chars, len(block.splitlines()), math.ceil(chars / CHARS_PER_TOKEN)


def size_note(host: str, block: str) -> str | None:
    """A line for stderr when the block is over the host's budget, or None. Sizes only, never content."""
    chars, lines, tokens = block_size(block)
    if host == CODEX and tokens > CODEX_TOKEN_BUDGET:
        return (
            f"Catpilot company rules: the block is {chars} characters, about {tokens} tokens. Codex gives the "
            f"model only a preview of hook context above about {CODEX_TOKEN_BUDGET:,} tokens unless the hook's "
            "additionalContextLimit is raised."
        )
    if host == CLAUDE_CODE and lines > CLAUDE_MD_LINE_BUDGET:
        return (
            f"Catpilot company rules: the block is {lines} lines. Claude Code's guidance for a CLAUDE.md file "
            f"is under {CLAUDE_MD_LINE_BUDGET} lines."
        )
    return None


def record_evidence(event: str, host: str | None, hook_event: dict, **fields) -> None:
    """One evidence line through the shared writer, imported here so that a missing or broken writer is a
    logging failure: it changes no output, and nothing here raises."""
    try:
        from . import evidence

        values = {"host": host, "session_id": evidence.session_id_of(hook_event), "session_source": start_source(hook_event)}
        values.update(fields)
        evidence.record(event, evidence.SESSION_START_SOURCE, {key: value for key, value in values.items() if value is not None})
    except Exception:
        pass


def main(argv: list | None = None, default_dir: Path | None = None, today: dt.date | None = None) -> int:
    """Run as a SessionStart hook. Always returns 0.

    argv defaults to sys.argv[1:]. default_dir is the directory used without --dir; the entry script
    passes the deployed layout's instructions/ directory. today is for tests; the hook uses the local date.
    """
    argv = take_evidence_default(sys.argv[1:] if argv is None else list(argv))
    if any(arg in ("-h", "--help") for arg in argv):
        try:
            sys.stdout.write(USAGE)
            sys.stdout.flush()
        except Exception:
            pass
        return 0
    hook_event = read_event(sys.stdin)
    host, directory, ok = parse_args(argv)
    note = None
    try:
        if not ok:
            raise RulesError("bad-arguments")
        directory = directory or default_dir
        if directory is None:
            raise RulesError("missing")
        rules = load(Path(directory))
        release = rules.release if rules.release and EVIDENCE_RELEASE.fullmatch(rules.release) else None
        if (today or dt.date.today()) > rules.expires_on:
            notice = expired_notice(host, rules)
            output = host_output(notice, notice)
            record_evidence("rules_expired", host, hook_event, policy_sha256=rules.policy_sha256, release=release)
        else:
            output = current_output(host, rules)
            chars, lines, _ = block_size(rules.block)
            note = size_note(host, rules.block)
            record_evidence("rules_delivered", host, hook_event, policy_sha256=rules.policy_sha256, release=release,
                            block_chars=chars, block_lines=lines)
    except Exception as exc:
        label = exc.args[0] if isinstance(exc, RulesError) and exc.args and exc.args[0] in ERROR_LABELS else "internal-error"
        output = error_output()
        record_evidence("policy_error", host, hook_event, label=label)
    # On a stdout the host closed, write_decision points stdout at os.devnull and returns 2. SessionStart
    # cannot block, so the exit code stays 0.
    write_decision(output)
    if note is not None:
        write_reason(note)
    return 0


if __name__ == "__main__":
    sys.exit(main())
