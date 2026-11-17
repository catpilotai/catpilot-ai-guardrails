#!/usr/bin/env python3
"""The files that put the company rules in front of the model at session start, for deploy/org/install.sh,
verify.sh and uninstall.sh. Advice, not enforcement: SessionStart cannot block on either host, and a
CLAUDE.md shapes what the model does without enforcing anything.

  settings --cc-dir DIR            read managed-settings.json on stdin, print it with the SessionStart hook added
  requirements --codex-dir DIR     print the requirements.toml that declares the Codex SessionStart hook
  claude-md-place --block FILE --target FILE
                                   put the block in the managed CLAUDE.md between the marker comments: create the
                                   file, or replace only the marked section; a file without the markers is left
                                   alone and the section is printed to merge
  claude-md-remove --target FILE   remove the marked section; delete the file only when nothing else is in it
  verify --cc-dir DIR --codex-dir DIR --home DIR [--timeout SECONDS]
                                   verify.sh's checks of the above, one report line each

What each host reads, from the vendors' documentation (read on 2026-11-16):
  Claude Code  the managed CLAUDE.md in the managed directory, /Library/Application Support/ClaudeCode/CLAUDE.md
               on macOS and /etc/claude-code/CLAUDE.md on Linux and WSL; block-level HTML comments in a CLAUDE.md
               are stripped before the content reaches the model (https://code.claude.com/docs/en/memory). The
               SessionStart hook comes from managed-settings.json (https://code.claude.com/docs/en/hooks).
  Codex        managed hooks under [hooks] in /etc/codex/requirements.toml, with an absolute managed_dir that must
               exist and commands that use absolute script paths under it
               (https://learn.chatgpt.com/docs/hooks, "Managed hooks in local Codex").

Standard library only. Python 3.8+: verify.sh may run on 3.8, which has no tomllib, so requirements.toml is
read with tomllib where there is one and otherwise with a reader for the few shapes verify.sh looks at.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

BEGIN = "<!-- catpilot-company-rules:begin -->"
END = "<!-- catpilot-company-rules:end -->"
SCRIPT = "catpilot-company-rules.py"
BLOCK_NAME = "company-checklist.md"
SIDECAR_NAME = "company-checklist.json"
# How a session started, the SessionStart matcher's subject on both hosts. The rules come back after each.
START_SOURCES = ("startup", "resume", "clear", "compact", "fork")
MATCHER = "|".join(START_SOURCES)
# The prefix the managed PreToolUse hook commands carry, so each person's evidence lands in their own home.
EVIDENCE_PREFIX = 'CATPILOT_EVIDENCE_LOG="$HOME/.catpilot-guardrails/evidence.jsonl"'
TIMEOUT_SECONDS = 10  # the timeout the managed PreToolUse hooks have
# A managed directory is written into a double-quoted shell word and a TOML literal string, so it may hold none
# of the characters either would read specially.
UNSAFE_PATH = re.compile("[\"'\\\\$`\x00-\x1f\x7f]")
# The texts catpilot_guard/session_start.py prints; verify reads its output against them.
UNAVAILABLE = "Company rules could not be loaded and are unknown. Ask your IT or security owner."
POLICY_HASH_LINE = re.compile(r"^Overlay SHA-256: ([0-9a-f]{64})$", re.MULTILINE)
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

CLAUDE_CODE = "claude-code"
CODEX = "codex"


class UsageError(Exception):
    """A value install.sh passed cannot be written safely. Its message is printed and the script exits 2."""


def checked_dir(value: str) -> str:
    if not value.startswith("/") or UNSAFE_PATH.search(value):
        raise UsageError(
            "managed directory %r must be an absolute path without quotes, backslashes, $, ` or control characters" % value
        )
    return value.rstrip("/") or "/"


def tree(managed_dir: str) -> str:
    """Where install.sh places the hooks and the rules under a tool's managed directory."""
    return managed_dir.rstrip("/") + "/catpilot-guardrails"


def hook_command(managed_dir: str, host: str) -> str:
    script = "%s/hooks/%s" % (tree(checked_dir(managed_dir)), SCRIPT)
    return '%s python3 "%s" --host %s' % (EVIDENCE_PREFIX, script, host)


def session_start_group(cc_dir: str) -> dict:
    return {
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": hook_command(cc_dir, CLAUDE_CODE), "timeout": TIMEOUT_SECONDS}],
    }


def settings_with_session_start(base: str, cc_dir: str) -> str:
    """managed-settings.json with the SessionStart group appended to hooks, in the template's own layout."""
    data = json.loads(base)
    if not isinstance(data, dict) or not isinstance(data.setdefault("hooks", {}), dict):
        raise UsageError("managed-settings.json must be a JSON object whose hooks key is an object")
    groups = data["hooks"].setdefault("SessionStart", [])
    if not isinstance(groups, list):
        raise UsageError("hooks.SessionStart in managed-settings.json must be a list")
    groups.append(session_start_group(cc_dir))
    return json.dumps(data, indent=2)


def requirements_toml(codex_dir: str) -> str:
    managed_dir = tree(checked_dir(codex_dir)) + "/hooks"
    return "\n".join(
        [
            "# Catpilot Guardrails: the company rules at session start, written by deploy/org/install.sh --overlay.",
            "# A managed SessionStart hook: Codex adds what it prints as developer context. Advice, not enforcement:",
            "# SessionStart cannot block. It leaves allow_managed_hooks_only and [features].hooks unset, so people's own",
            "# hooks keep running; docs/DEPLOY_ORG.md says what each would change.",
            "",
            "[hooks]",
            'managed_dir = "%s"' % managed_dir,
            "",
            "[[hooks.SessionStart]]",
            'matcher = "%s"' % MATCHER,
            "",
            "[[hooks.SessionStart.hooks]]",
            'type = "command"',
            "command = '%s'" % hook_command(codex_dir, CODEX),
            "timeout = %d" % TIMEOUT_SECONDS,
        ]
    )


# --- the managed CLAUDE.md -------------------------------------------------------------------------------------


def section(block: str) -> str:
    """The block between the two marker lines. The markers are block-level HTML comments, which Claude Code strips
    before the file reaches the model."""
    return "%s\n%s%s%s\n" % (BEGIN, block, "" if block.endswith("\n") else "\n", END)


def find_section(text: str):
    """(lines, begin index, end index) when the text holds exactly one begin line followed by one end line;
    (lines, None, None) when it holds neither marker; None when the markers are anything else."""
    lines = text.splitlines(True)
    begins = [i for i, line in enumerate(lines) if line.strip() == BEGIN]
    ends = [i for i, line in enumerate(lines) if line.strip() == END]
    if not begins and not ends:
        return lines, None, None
    if len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0]:
        return lines, begins[0], ends[0]
    return None


def section_body(text: str):
    """The text between the markers, or None when there is no single marked section."""
    found = find_section(text)
    if found is None or found[1] is None:
        return None
    lines, begin, end = found
    return "".join(lines[begin + 1 : end])


def write_replacing(target: Path, text: str, mode: int, owner=None) -> None:
    """Write text to target through a temporary file in the same directory, so a reader sees the old file or the
    new one and never part of either."""
    fd, tmp = tempfile.mkstemp(prefix=".%s." % target.name, dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fchmod(fh.fileno(), mode)
            if owner is not None:
                try:
                    os.fchown(fh.fileno(), owner[0], owner[1])
                except OSError:
                    pass
        os.replace(tmp, str(target))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_existing(target: Path):
    """(text, mode, (uid, gid)) of an existing regular file, or None when it cannot be read as UTF-8 text."""
    st = os.lstat(str(target))
    try:
        text = target.read_bytes().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    return text, stat.S_IMODE(st.st_mode), (st.st_uid, st.st_gid)


def place_claude_md(block_path: Path, target: Path) -> int:
    block = block_path.read_bytes().decode("utf-8")
    wanted = section(block)
    merge = wanted.rstrip("\n")
    if not os.path.lexists(str(target)):
        write_replacing(target, wanted, 0o644)
        print("rules   %s (created, holding only the marked company rules section)" % target)
        return 0
    why = None
    existing = None
    if target.is_symlink() or not target.is_file():
        why = "it is not a regular file"
    else:
        existing = read_existing(target)
        if existing is None:
            why = "it could not be read as UTF-8 text"
    found = find_section(existing[0]) if existing else None
    if why is None and found is None:
        why = "its catpilot-company-rules markers are not one begin line followed by one end line"
    if why is None and found[1] is None:
        print("exists  %s (not modified: it has no catpilot-company-rules markers); add this section to it, both marker lines included:" % target)
        print(merge)
        return 0
    if why is not None:
        print("exists  %s (not modified: %s); put this section in it by hand, both marker lines included:" % (target, why))
        print(merge)
        return 0
    text, mode, owner = existing
    lines, begin, end = found
    updated = "".join(lines[:begin]) + wanted + "".join(lines[end + 1 :])
    if updated == text:
        print("rules   %s (marked section unchanged)" % target)
        return 0
    write_replacing(target, updated, mode, owner)
    print("rules   %s (marked section replaced; the rest of the file is unchanged)" % target)
    return 0


def remove_claude_md(target: Path) -> int:
    if not os.path.lexists(str(target)):
        return 0
    if target.is_symlink() or not target.is_file():
        print("kept    %s (not a regular file; remove the catpilot-company-rules section from it by hand)" % target)
        return 0
    existing = read_existing(target)
    if existing is None:
        print("kept    %s (not UTF-8 text; remove the catpilot-company-rules section from it by hand)" % target)
        return 0
    text, mode, owner = existing
    found = find_section(text)
    if found is None:
        print("kept    %s (its catpilot-company-rules markers are unbalanced; remove the section between them by hand)" % target)
        return 0
    lines, begin, end = found
    if begin is None:
        return 0  # no section of ours: nothing to remove, nothing to say
    rest = "".join(lines[:begin]) + "".join(lines[end + 1 :])
    if not rest.strip():
        os.unlink(str(target))
        print("removed %s" % target)
        return 0
    write_replacing(target, rest, mode, owner)
    print("removed the company rules section from %s (the rest of the file is kept)" % target)
    return 0


# --- reading requirements.toml without tomllib ------------------------------------------------------------------

_ARRAY_TABLE = re.compile(r"^\[\[\s*([A-Za-z0-9_.-]+)\s*\]\]\s*(?:#.*)?$")
_TABLE = re.compile(r"^\[\s*([A-Za-z0-9_.-]+)\s*\]\s*(?:#.*)?$")
_KEY_VALUE = re.compile(r"^([A-Za-z0-9_-]+)\s*=\s*(.*)$")
_BASIC = re.compile(r'^"((?:[^"\\\x00-\x1f]|\\.)*)"\s*(?:#.*)?$')
_LITERAL = re.compile(r"^'([^'\x00-\x08\x0a-\x1f]*)'\s*(?:#.*)?$")
_INTEGER = re.compile(r"^([+-]?[0-9][0-9_]*)\s*(?:#.*)?$")
_BOOLEAN = re.compile(r"^(true|false)\s*(?:#.*)?$")
_ESCAPE = re.compile(r"\\(U[0-9A-Fa-f]{8}|.)")


def _unescape(body: str) -> str:
    """A TOML basic string's body as text. JSON reads every TOML 1.0 escape but the eight-digit \\U form."""

    def one(m) -> str:
        escape = m.group(1)
        if escape[0] == "U":
            return json.dumps(chr(int(escape[1:], 16)))[1:-1]  # ValueError beyond U+10FFFF
        return m.group(0)

    return json.loads('"%s"' % _ESCAPE.sub(one, body))


def _toml_value(raw: str):
    """A single-line string, integer or boolean, or None for anything else."""
    raw = raw.strip()
    if raw.startswith('"""') or raw.startswith("'''"):
        return None
    m = _BASIC.match(raw)
    if m:
        try:
            return _unescape(m.group(1))
        except ValueError:
            return None
    m = _LITERAL.match(raw)
    if m:
        return m.group(1)
    m = _BOOLEAN.match(raw)
    if m:
        return m.group(1) == "true"
    m = _INTEGER.match(raw)
    if m:
        return int(m.group(1).replace("_", ""))
    return None


def minimal_toml(text: str) -> dict:
    """The parts of a requirements.toml that verify.sh reads, for an interpreter without tomllib: the [hooks] table
    and its [[hooks.<Event>]] and [[hooks.<Event>.hooks]] tables, with bare keys and single-line string, integer
    and boolean values, plus top-level keys of those kinds and [features]. Everything else is skipped, so a hook
    written in another TOML form (inline tables, dotted keys) is not seen."""
    root: dict = {}
    current = root
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ARRAY_TABLE.match(line)
        if m:
            parts = m.group(1).split(".")
            current = None
            if len(parts) == 2 and parts[0] == "hooks":
                group: dict = {}
                hooks = root.setdefault("hooks", {})
                if isinstance(hooks.setdefault(parts[1], []), list):
                    hooks[parts[1]].append(group)
                    current = group
            elif len(parts) == 3 and parts[0] == "hooks" and parts[2] == "hooks":
                groups = root.get("hooks", {}).get(parts[1])
                if isinstance(groups, list) and groups:
                    handler: dict = {}
                    groups[-1].setdefault("hooks", []).append(handler)
                    current = handler
            continue
        m = _TABLE.match(line)
        if m:
            current = root.setdefault(m.group(1), {}) if m.group(1) in ("hooks", "features") else None
            if current is not None and not isinstance(current, dict):
                current = None
            continue
        m = _KEY_VALUE.match(line)
        if m and current is not None:
            value = _toml_value(m.group(2))
            if value is not None:
                current[m.group(1)] = value
    return root


def read_toml(path: Path, prefer_tomllib: bool = True):
    """(data, reader name). Raises ValueError when the file is not valid TOML (tomllib only) or not UTF-8."""
    text = path.read_bytes().decode("utf-8")
    if prefer_tomllib:
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            pass
        else:
            return tomllib.loads(text), "tomllib"
    return minimal_toml(text), "a minimal reader; this Python has no tomllib"


# --- verify -----------------------------------------------------------------------------------------------------


class Report:
    """Lines in verify.sh's format. verify.sh counts "present" as present, MISSING and INVALID as missing, and FAIL
    as failed; every other line is information."""

    def line(self, word: str, text: str) -> None:
        print("%-8s %s" % (word, text))
        sys.stdout.flush()

    def present(self, path: Path) -> bool:
        if path.exists():
            self.line("present", str(path))
            return True
        self.line("MISSING", str(path))
        return False


def load_copy(report: Report, root: Path):
    """Check one tool's copy of the block and its sidecar. Returns the sidecar (a dict) with the block's text under
    "_block" when the two match, else None."""
    block_path = root / "instructions" / BLOCK_NAME
    sidecar_path = root / "instructions" / SIDECAR_NAME
    have_block = report.present(block_path)
    have_sidecar = report.present(sidecar_path)
    if not (have_block and have_sidecar):
        return None
    try:
        block_bytes = block_path.read_bytes()
        block = block_bytes.decode("utf-8")
        sidecar = json.loads(sidecar_path.read_bytes().decode("utf-8"))
    except (OSError, ValueError):
        report.line("FAIL", "%s or %s could not be read as UTF-8 JSON and text" % (sidecar_path.name, block_path.name))
        return None
    fields = ("owner", "reviewed_on", "expires_on", "policy_sha256", "block_sha256")
    if not isinstance(sidecar, dict) or not all(isinstance(sidecar.get(k), str) for k in fields) or not all(
        ISO_DATE.fullmatch(sidecar[k]) for k in ("reviewed_on", "expires_on")
    ):
        report.line("FAIL", "%s is not the sidecar a private build writes" % sidecar_path)
        return None
    digest = hashlib.sha256(block_bytes).hexdigest()
    stated = POLICY_HASH_LINE.search(block)
    if digest != sidecar["block_sha256"]:
        report.line(
            "FAIL",
            "%s has SHA-256 %s..., not the %s... in %s: the two files come from different builds, or one was edited; "
            "the hook prints that the rules could not be loaded" % (block_path, digest[:12], sidecar["block_sha256"][:12], SIDECAR_NAME),
        )
        return None
    if stated is None or stated.group(1) != sidecar["policy_sha256"]:
        report.line("FAIL", "%s does not state the rules file's SHA-256 that %s records" % (block_path, SIDECAR_NAME))
        return None
    report.line("matches", "%s has the SHA-256 in %s (%s...)" % (BLOCK_NAME, SIDECAR_NAME, digest[:12]))
    sidecar = dict(sidecar)
    sidecar["_block"] = block
    return sidecar


def expected_state(rules, today: dt.date) -> str:
    if rules is None:
        return "error"
    try:
        expires = dt.date(*(int(part) for part in rules["expires_on"].split("-")))
    except ValueError:
        return "error"
    return "expired" if today > expires else "current"


def status_line(rules: dict) -> str:
    return "Company rules from %s, reviewed %s, valid until %s, are current." % (
        rules["owner"], rules["reviewed_on"], rules["expires_on"])


def judge(report: Report, label: str, host: str, state: str, rules, result, success: str = "runs") -> None:
    """Report what one run of the session-start script printed against what the rules on disk call for."""
    if isinstance(result, str):
        report.line("FAIL", "%s %s" % (label, result))
        return
    try:
        output = json.loads(result.stdout)
        specific = output["hookSpecificOutput"]
        context = specific["additionalContext"]
        ok_shape = specific.get("hookEventName") == "SessionStart" and isinstance(context, str)
    except (ValueError, TypeError, KeyError):
        ok_shape = False
    if result.returncode != 0 or not ok_shape:
        report.line("FAIL", "%s exited %d without the SessionStart JSON both hosts read" % (label, result.returncode))
        return
    notice = output.get("systemMessage")
    if state == "error":
        if context == UNAVAILABLE:
            report.line("notice", "%s prints that the company rules could not be loaded (see above)" % label)
        else:
            report.line("FAIL", "%s does not print that the company rules could not be loaded" % label)
        return
    if state == "expired":
        expected = "expired on %s" % rules["expires_on"]
        if notice and notice == context and expected in context and rules["_block"] not in context:
            report.line("notice", "%s prints the expired notice, as a warning and to the model, and no rules" % label)
        else:
            report.line("FAIL", "%s does not print the expired notice for rules that expired on %s" % (label, rules["expires_on"]))
        return
    if notice is not None:
        if context == UNAVAILABLE:
            report.line("FAIL", "%s prints that the company rules could not be loaded" % label)
        else:
            report.line("FAIL", "%s prints a warning for rules that are current" % label)
        return
    if host == CODEX and context == rules["_block"]:
        report.line(success, "%s gives the model the whole block as additionalContext" % label)
    elif host == CLAUDE_CODE and context == status_line(rules):
        report.line(success, "%s gives the model the one-line status; the managed CLAUDE.md carries the block" % label)
    else:
        what = "the whole block" if host == CODEX else "the one-line status"
        report.line("FAIL", "%s does not give the model %s" % (label, what))


def clean_env(home: Path) -> dict:
    """This environment without the evidence variables, with HOME at verify.sh's temporary directory, so neither a
    variable from the environment nor a command's own CATPILOT_EVIDENCE_LOG="$HOME/..." writes anywhere real."""
    env = {k: v for k, v in os.environ.items() if k not in ("CATPILOT_EVIDENCE_LOG", "CATPILOT_EVIDENCE_SYSLOG")}
    env["HOME"] = str(home)
    return env


def run(argv: list, home: Path, timeout: int):
    """A CompletedProcess, or a sentence saying why there is none."""
    event = json.dumps({"session_id": "catpilot-verify", "hook_event_name": "SessionStart", "source": "startup",
                        "cwd": str(home)})
    try:
        return subprocess.run(argv, input=event, capture_output=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=clean_env(home), cwd=str(home))
    except subprocess.TimeoutExpired:
        return "did not finish within the %ds hook timeout" % timeout
    except OSError as exc:
        return "could not start (%s)" % exc.__class__.__name__


def covers(matcher, source: str, anchored: bool) -> bool:
    if matcher in (None, "", "*"):
        return True
    if not isinstance(matcher, str):
        return False
    try:
        found = re.fullmatch(matcher, source) if anchored else re.search(matcher, source)
    except re.error:
        return False
    return found is not None


def registered(groups, anchored: bool):
    """(group matcher, command) for each command hook that runs the session-start script."""
    found = []
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        for handler in group.get("hooks") or []:
            command = handler.get("command") if isinstance(handler, dict) else None
            if isinstance(command, str) and SCRIPT in command:
                found.append((group.get("matcher"), command))
    return found


def check_registration(report: Report, what: str, entries, anchored: bool, label_host: str, state: str, rules,
                       home: Path, timeout: int, merge_hint: str) -> None:
    if not entries:
        report.line("FAIL", "%s does not run %s at SessionStart (%s)" % (what, SCRIPT, merge_hint))
        return
    for matcher, command in entries:
        missed = [s for s in START_SOURCES if not covers(matcher, s, anchored)]
        if missed:
            report.line("FAIL", "%s runs %s under a matcher that does not cover %s, so the rules do not come back "
                        "after those" % (what, SCRIPT, ",".join(missed)))
        if "CATPILOT_EVIDENCE_SYSLOG" in command:
            report.line("skipped", "%s command for %s (it forwards evidence to syslog; check it in a session)" % (what, SCRIPT))
            continue
        judge(report, "%s runs it at SessionStart, and its command, run through a shell," % what, label_host, state, rules,
              run(["bash", "-c", command], home, timeout), success="wired")


def verify(cc_dir: Path, codex_dir: Path, home: Path, timeout: int, today=None, prefer_tomllib: bool = True) -> int:
    report = Report()
    today = today or dt.date.today()
    cc_root = Path(tree(str(cc_dir)))
    codex_root = Path(tree(str(codex_dir)))
    claude_md = cc_dir / "CLAUDE.md"
    settings_path = cc_dir / "managed-settings.json"
    requirements_path = codex_dir / "requirements.toml"

    settings = None
    if settings_path.exists():
        try:
            settings = json.loads(settings_path.read_bytes().decode("utf-8"))
        except (OSError, ValueError):
            settings = None
    hooks = settings.get("hooks") if isinstance(settings, dict) else None
    cc_entries = registered(hooks.get("SessionStart") if isinstance(hooks, dict) else None, anchored=True)

    requirements = None
    reader = None
    requirements_error = None
    if requirements_path.exists():
        try:
            requirements, reader = read_toml(requirements_path, prefer_tomllib)
        except (OSError, ValueError) as exc:
            requirements_error = exc.__class__.__name__
    req_hooks = requirements.get("hooks") if isinstance(requirements, dict) else None
    codex_entries = registered(req_hooks.get("SessionStart") if isinstance(req_hooks, dict) else None, anchored=False)

    claude_md_text = None
    if claude_md.is_file():
        try:
            claude_md_text = claude_md.read_bytes().decode("utf-8")
        except (OSError, UnicodeDecodeError):
            claude_md_text = None

    placed = (
        any((root / sub).exists() for root in (cc_root, codex_root)
            for sub in ("hooks/" + SCRIPT, "instructions/" + BLOCK_NAME, "instructions/" + SIDECAR_NAME))
        or cc_entries or codex_entries
        or (claude_md_text is not None and BEGIN in claude_md_text)
        or (requirements_error is None and requirements_path.exists() and SCRIPT in requirements_path.read_bytes().decode("utf-8", "replace"))
    )
    if not placed:
        report.line("absent", "company rules at session start (install.sh places them only with --overlay)")
        return 0

    # Claude Code: the rules in the managed CLAUDE.md, a status at session start.
    print("Claude Code")
    report.present(cc_root / "hooks" / SCRIPT)
    cc_rules = load_copy(report, cc_root)
    if report.present(claude_md):
        body = section_body(claude_md_text) if claude_md_text is not None else None
        if body is None:
            report.line("FAIL", "%s has no single catpilot-company-rules section (install.sh prints the section to "
                        "merge when the file already existed)" % claude_md)
        elif cc_rules is not None:
            if hashlib.sha256(body.encode("utf-8")).hexdigest() == cc_rules["block_sha256"]:
                report.line("matches", "the marked section in %s is %s (same SHA-256)" % (claude_md.name, BLOCK_NAME))
            else:
                report.line("FAIL", "the marked section in %s is not %s: the model reads other rules than the ones the "
                            "status hook reports on; run install.sh --overlay again" % (claude_md, BLOCK_NAME))
    state = expected_state(cc_rules, today)
    if cc_rules is not None:
        if state == "expired":
            report.line("FAIL", "company rules from %s expired on %s (today is %s on this machine): both hooks print "
                        "the expired notice instead; renew the review and install again"
                        % (cc_rules["owner"], cc_rules["expires_on"], today.isoformat()))
        else:
            report.line("valid", "company rules from %s, reviewed %s, valid until %s (today is %s on this machine)"
                        % (cc_rules["owner"], cc_rules["reviewed_on"], cc_rules["expires_on"], today.isoformat()))
    script = cc_root / "hooks" / SCRIPT
    if script.exists():
        judge(report, "%s --host %s, run directly," % (SCRIPT, CLAUDE_CODE), CLAUDE_CODE, state, cc_rules,
              run([sys.executable, str(script), "--host", CLAUDE_CODE], home, timeout))
    if settings is None:
        report.line("FAIL", "%s is missing or does not parse, so no SessionStart hook runs" % settings_path)
    else:
        check_registration(report, "managed-settings.json", cc_entries, True, CLAUDE_CODE, state, cc_rules, home,
                           timeout, "install.sh prints the JSON to merge when the file already existed")

    # Codex: the rules as developer context from a managed SessionStart hook.
    print("Codex CLI")
    report.present(codex_root / "hooks" / SCRIPT)
    for module in ("__init__", "session_start", "evidence"):
        report.present(codex_root / "hooks" / "catpilot_guard" / (module + ".py"))
    codex_rules = load_copy(report, codex_root)
    codex_state = expected_state(codex_rules, today)
    if cc_rules is not None and codex_rules is not None:
        if (cc_rules["block_sha256"], cc_rules["expires_on"]) == (codex_rules["block_sha256"], codex_rules["expires_on"]):
            report.line("matches", "the Codex copy of the rules is the Claude Code copy")
        else:
            report.line("FAIL", "the Codex and Claude Code copies differ: run install.sh --overlay again")
    if codex_rules is not None and codex_state == "expired" and state != "expired":
        report.line("FAIL", "the Codex copy of the company rules expired on %s" % codex_rules["expires_on"])
    script = codex_root / "hooks" / SCRIPT
    if script.exists():
        judge(report, "%s --host %s, run directly," % (SCRIPT, CODEX), CODEX, codex_state, codex_rules,
              run([sys.executable, str(script), "--host", CODEX], home, timeout))
    if report.present(requirements_path):
        if requirements_error is not None:
            report.line("INVALID", "%s does not parse as TOML" % requirements_path)
            return 0
        print("         (read with %s)" % reader)
        features = requirements.get("features") if isinstance(requirements, dict) else None
        if isinstance(features, dict) and features.get("hooks") is False:
            report.line("FAIL", "%s sets [features].hooks = false, which turns every hook off" % requirements_path)
        managed_dir = req_hooks.get("managed_dir") if isinstance(req_hooks, dict) else None
        if not isinstance(managed_dir, str) or not os.path.isabs(managed_dir):
            report.line("FAIL", "%s sets no absolute [hooks] managed_dir; Codex loads managed hooks only with one" % requirements_path)
        elif not Path(managed_dir).is_dir():
            report.line("FAIL", "[hooks] managed_dir %s does not exist; Codex loads managed hooks only when it does" % managed_dir)
        else:
            report.line("present", "%s ([hooks] managed_dir)" % managed_dir)
            for _, command in codex_entries:
                paths = [token for token in _split(command) if token.endswith(SCRIPT)]
                if paths and not paths[0].startswith(managed_dir.rstrip("/") + "/"):
                    report.line("note", "the command runs %s, outside managed_dir; Codex's documentation says managed "
                                "hook commands should use absolute script paths under it" % paths[0])
        hint = "install.sh prints the TOML to merge when the file already existed"
        if reader != "tomllib":
            hint += "; this reader follows only [[hooks.SessionStart]] tables, so if the file declares it another way, "
            hint += "run verify.sh with PYTHON_BIN set to Python 3.11 or later"
        check_registration(report, "requirements.toml", codex_entries, False, CODEX, codex_state, codex_rules, home,
                           timeout, hint)
    return 0


def _split(command: str) -> list:
    try:
        return shlex.split(command)
    except ValueError:
        return []


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="action")
    p = sub.add_parser("settings")
    p.add_argument("--cc-dir", required=True)
    p = sub.add_parser("requirements")
    p.add_argument("--codex-dir", required=True)
    p = sub.add_parser("claude-md-place")
    p.add_argument("--block", required=True, type=Path)
    p.add_argument("--target", required=True, type=Path)
    p = sub.add_parser("claude-md-remove")
    p.add_argument("--target", required=True, type=Path)
    p = sub.add_parser("verify")
    p.add_argument("--cc-dir", required=True, type=Path)
    p.add_argument("--codex-dir", required=True, type=Path)
    p.add_argument("--home", required=True, type=Path)
    p.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        if args.action == "settings":
            print(settings_with_session_start(sys.stdin.read(), args.cc_dir))
        elif args.action == "requirements":
            print(requirements_toml(args.codex_dir))
        elif args.action == "claude-md-place":
            return place_claude_md(args.block, args.target)
        elif args.action == "claude-md-remove":
            return remove_claude_md(args.target)
        elif args.action == "verify":
            return verify(args.cc_dir, args.codex_dir, args.home, args.timeout)
        else:
            parser.print_usage(sys.stderr)
            return 2
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
