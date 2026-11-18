#!/usr/bin/env python3
"""The files that put the company rules in front of the model at session start, for deploy/org/install.sh,
verify.sh and uninstall.sh. Advice, not enforcement: SessionStart cannot block on either host, and a
CLAUDE.md shapes what the model does without enforcing anything.

  settings --cc-dir DIR [--enforce]
                                   read managed-settings.json on stdin, print it with the SessionStart hook added,
                                   and with --enforce the company-rules PreToolUse hook too
  requirements --codex-dir DIR [--no-rules] [--enforce]
                                   print the requirements.toml that declares the managed Codex hooks: the
                                   PreToolUse checks always, the SessionStart hook unless --no-rules, and the
                                   company-rules PreToolUse hook with --enforce
  claude-md-place --block FILE --target FILE
                                   put the block in the managed CLAUDE.md between the marker comments: create the
                                   file, or replace only the marked section; a file without the markers is left
                                   alone and the section is printed to merge
  claude-md-remove --target FILE   remove the marked section; delete the file only when nothing else is in it
  verify --cc-dir DIR --codex-dir DIR --home DIR [--timeout SECONDS]
                                   verify.sh's checks of the above, one report line each
  verify-codex-hooks --codex-dir DIR --home DIR [--timeout SECONDS]
                                   verify.sh's checks of the managed Codex PreToolUse hooks: the files, each hook run
                                   directly on harmless probes, and each requirements.toml command run through a shell
  copilot-policy --copilot-dir DIR [--enforce]
                                   print the Copilot CLI policy hook file install.sh writes to <DIR>/policy.d/: the
                                   three checks as PreToolUse hooks, and the company-rules hook with --enforce
  verify-copilot-hooks --copilot-dir DIR --home DIR [--timeout SECONDS]
                                   verify.sh's checks of the Copilot CLI policy hooks: the files, the policy file's
                                   owner and mode, each hook run directly on harmless probes in Copilot's event shape,
                                   and each command the policy file declares run through a shell
  verify-company-rules --cc-dir DIR --codex-dir DIR --home DIR [--copilot-dir DIR] [--timeout SECONDS]
                                   verify.sh's checks of the company-rules hook on each tool with a compiled policy:
                                   the files and their ownership, the policy loading, a probe for its first
                                   protected_branch rule, and the hook as the managed file registers it

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
# The blocking hooks install.sh registers for Codex in requirements.toml: (matcher, tool the matcher must cover,
# hook files). Codex reports every file edit as apply_patch, whichever of apply_patch, Edit or Write the matcher
# names; Bash commands as Bash. Each command passes --host codex so its evidence lines name the tool.
CODEX_PRETOOLUSE = (
    ("^Bash$", "Bash", ("pretooluse-secrets.py", "pretooluse-destructive-ops.py")),
    ("^apply_patch$", "apply_patch", ("pretooluse-write-secrets.py",)),
)
# Names a matcher may use for a tool: for file edits, Codex also matches Edit and Write and still reports apply_patch.
CODEX_MATCHER_NAMES = {"Bash": ("Bash",), "apply_patch": ("apply_patch", "Edit", "Write")}
# [features] written as a dotted key or an inline table, which the minimal reader does not read.
_FEATURES_ELSEWHERE = re.compile(r"^\s*([\"']?)features\1\s*(?:\.|=)", re.MULTILINE)
CODEX_HOOK_FILES = tuple(name for _, _, names in CODEX_PRETOOLUSE for name in names)
CODEX_HOOK_MODULES = ("__init__", "secrets", "write_secrets", "destructive", "evidence", "policy", "company_rules", "deploy_targets")
# The company-rules hook and the compiled policy it reads (install.sh --overlay, when the rules file has enforcement
# rules). The policy sits under the tool's tree, root-owned like the hooks; the hook takes its path on its command line.
COMPANY_HOOK = "pretooluse-company-rules.py"
POLICY_NAME = "company-policy.json"
# A managed directory is written into a double-quoted shell word and a TOML literal string, so it may hold none
# of the characters either would read specially.
UNSAFE_PATH = re.compile("[\"'\\\\$`\x00-\x1f\x7f]")
# The texts catpilot_guard/session_start.py prints; verify reads its output against them.
UNAVAILABLE = "Company rules could not be loaded and are unknown. Ask your IT or security owner."
POLICY_HASH_LINE = re.compile(r"^Overlay SHA-256: ([0-9a-f]{64})$", re.MULTILINE)
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")

CLAUDE_CODE = "claude-code"
CODEX = "codex"
COPILOT = "copilot-cli"

# GitHub Copilot CLI policy hooks (docs.github.com/en/copilot/reference/hooks-reference, read on 2026-11-17): JSON
# files in /etc/github-copilot/policy.d/, owned by root and writable by no one else, loaded before user and project
# hooks; people cannot turn them off with disableAllHooks, and they run whatever the folder's trust state. Under the
# Claude-style event name PreToolUse, Copilot sends the Claude Code event shape with Claude tool names (bash and
# powershell as Bash, create as Write, edit, str_replace_editor and apply_patch as Edit) and matches a |-separated
# matcher against those names or the runtime name; write_bash and write_powershell, input to a running shell, keep
# their runtime names. A hook that times out lets the call run, so the timeout is Copilot's default of 30 seconds.
COPILOT_POLICY_NAME = "catpilot-guardrails.json"
COPILOT_SHELL_MATCHER = "Bash|write_bash|write_powershell"
COPILOT_PRETOOLUSE = (
    (COPILOT_SHELL_MATCHER, ("Bash", "write_bash"), ("pretooluse-secrets.py", "pretooluse-destructive-ops.py")),
    ("Write|Edit", ("Write", "Edit"), ("pretooluse-write-secrets.py",)),
)
COPILOT_HOOK_FILES = tuple(name for _, _, names in COPILOT_PRETOOLUSE for name in names)
COPILOT_TIMEOUT_SECONDS = 30


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


def policy_path(managed_dir: str) -> str:
    return "%s/policy/%s" % (tree(checked_dir(managed_dir)), POLICY_NAME)


def company_hook_command(managed_dir: str, host: str) -> str:
    script = "%s/hooks/%s" % (tree(checked_dir(managed_dir)), COMPANY_HOOK)
    return '%s python3 "%s" --host %s --policy "%s"' % (EVIDENCE_PREFIX, script, host, policy_path(managed_dir))


def copilot_command(copilot_dir: str, filename: str, enforce_policy: bool = False) -> str:
    script = "%s/hooks/%s" % (tree(checked_dir(copilot_dir)), filename)
    command = '%s python3 "%s" --host %s' % (EVIDENCE_PREFIX, script, COPILOT)
    if enforce_policy:
        command += ' --policy "%s"' % policy_path(copilot_dir)
    return command


def copilot_policy_json(copilot_dir: str, enforce: bool = False) -> str:
    """The policy hook file install.sh writes to <copilot dir>/policy.d/: the three checks, and with enforce the
    company-rules hook with the compiled policy."""
    entries = []
    for matcher, _, names in COPILOT_PRETOOLUSE:
        for name in names:
            entries.append({"type": "command", "matcher": matcher, "bash": copilot_command(copilot_dir, name),
                            "timeoutSec": COPILOT_TIMEOUT_SECONDS})
    if enforce:
        entries.append({"type": "command", "matcher": COPILOT_SHELL_MATCHER,
                        "bash": copilot_command(copilot_dir, COMPANY_HOOK, enforce_policy=True),
                        "timeoutSec": COPILOT_TIMEOUT_SECONDS})
    return json.dumps({"version": 1, "hooks": {"PreToolUse": entries}}, indent=2)


def session_start_group(cc_dir: str) -> dict:
    return {
        "matcher": MATCHER,
        "hooks": [{"type": "command", "command": hook_command(cc_dir, CLAUDE_CODE), "timeout": TIMEOUT_SECONDS}],
    }


def settings_with_session_start(base: str, cc_dir: str, enforce: bool = False) -> str:
    """managed-settings.json with the SessionStart group appended to hooks, in the template's own layout, and with
    enforce, a PreToolUse group on Bash that runs the company-rules hook with the compiled policy."""
    data = json.loads(base)
    if not isinstance(data, dict) or not isinstance(data.setdefault("hooks", {}), dict):
        raise UsageError("managed-settings.json must be a JSON object whose hooks key is an object")
    if enforce:
        pretooluse = data["hooks"].setdefault("PreToolUse", [])
        if not isinstance(pretooluse, list):
            raise UsageError("hooks.PreToolUse in managed-settings.json must be a list")
        pretooluse.append({
            "matcher": "Bash",
            "hooks": [{"type": "command", "command": company_hook_command(cc_dir, CLAUDE_CODE), "timeout": TIMEOUT_SECONDS}],
        })
    groups = data["hooks"].setdefault("SessionStart", [])
    if not isinstance(groups, list):
        raise UsageError("hooks.SessionStart in managed-settings.json must be a list")
    groups.append(session_start_group(cc_dir))
    return json.dumps(data, indent=2)


def codex_pretooluse_command(codex_dir: str, filename: str) -> str:
    script = "%s/hooks/%s" % (tree(checked_dir(codex_dir)), filename)
    return '%s python3 "%s" --host %s' % (EVIDENCE_PREFIX, script, CODEX)


def requirements_toml(codex_dir: str, rules: bool = True, enforce: bool = False) -> str:
    """The requirements.toml install.sh writes: the blocking PreToolUse hooks always, the session-start hook with
    the company rules (install.sh --overlay) only, and the company-rules hook when the rules file has enforcement
    rules (enforce)."""
    managed_dir = tree(checked_dir(codex_dir)) + "/hooks"
    lines = [
        "# Catpilot Guardrails, written by deploy/org/install.sh: managed Codex hooks.",
        "# PreToolUse: the credential and destructive-operation checks on Bash and the credential check on file edits",
        "# (apply_patch); each denies what it matches and never allows anything. Pinning the hooks feature on keeps",
        "# them on for people who turned hooks off in their own config. allow_managed_hooks_only stays unset, so",
        "# people's own hooks keep running; docs/DEPLOY_ORG.md says what it would change.",
    ]
    if rules:
        lines += [
            "# SessionStart (install.sh --overlay): the company rules as developer context. Advice, not enforcement:",
            "# SessionStart cannot block.",
        ]
    if enforce:
        lines += [
            "# PreToolUse company rules (install.sh --overlay, when the rules file has enforcement rules): the company's",
            "# own rules from the compiled policy, in monitor, ask or block. Codex cannot ask, so ask acts as block.",
        ]
    lines += ["", "[features]", "hooks = true", "", "[hooks]", 'managed_dir = "%s"' % managed_dir]
    for matcher, _, names in CODEX_PRETOOLUSE:
        lines += ["", "[[hooks.PreToolUse]]", 'matcher = "%s"' % matcher]
        for name in names:
            lines += [
                "",
                "[[hooks.PreToolUse.hooks]]",
                'type = "command"',
                "command = '%s'" % codex_pretooluse_command(codex_dir, name),
                "timeout = %d" % TIMEOUT_SECONDS,
            ]
    if enforce:
        lines += [
            "",
            "[[hooks.PreToolUse]]",
            'matcher = "^Bash$"',
            "",
            "[[hooks.PreToolUse.hooks]]",
            'type = "command"',
            "command = '%s'" % company_hook_command(codex_dir, CODEX),
            "timeout = %d" % TIMEOUT_SECONDS,
        ]
    if rules:
        lines += [
            "",
            "[[hooks.SessionStart]]",
            'matcher = "%s"' % MATCHER,
            "",
            "[[hooks.SessionStart.hooks]]",
            'type = "command"',
            "command = '%s'" % hook_command(codex_dir, CODEX),
            "timeout = %d" % TIMEOUT_SECONDS,
        ]
    return "\n".join(lines)


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
        if reader != "tomllib" and _FEATURES_ELSEWHERE.search(requirements_path.read_bytes().decode("utf-8", "replace")):
            report.line("FAIL", "%s sets features as a dotted key or an inline table, which this reader cannot read; run "
                        "verify.sh with PYTHON_BIN set to Python 3.11 or later" % requirements_path)
        elif isinstance(features, dict) and features.get("hooks") is False:
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


# --- verify the managed Codex PreToolUse hooks ------------------------------------------------------------------

# Harmless probes. The key is AWS's documentation-only example; nothing here is a real credential or target.
_DOC_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
_PATCH_WITH_KEY = "*** Begin Patch\n*** Add File: probe.env\n+AWS_ACCESS_KEY_ID=%s\n*** End Patch\n" % _DOC_KEY
_PATCH_HARMLESS = "*** Begin Patch\n*** Add File: notes.md\n+# Notes\n*** End Patch\n"
CODEX_PROBES = {
    "pretooluse-secrets.py": (("Bash", "export AWS_ACCESS_KEY_ID=%s && echo ok" % _DOC_KEY, "a command carrying AWS's documentation example key"),
                              ("Bash", "ls", "ls")),
    "pretooluse-destructive-ops.py": (("Bash", "git push --force origin main", "git push --force origin main"),
                                      ("Bash", "ls", "ls")),
    "pretooluse-write-secrets.py": (("apply_patch", _PATCH_WITH_KEY, "a patch adding AWS's documentation example key"),
                                    ("apply_patch", _PATCH_HARMLESS, "a patch adding a harmless file")),
}


def codex_event(tool: str, command: str, cwd: Path) -> str:
    """A PreToolUse event in Codex's shape: Bash and apply_patch both carry tool_input.command."""
    return json.dumps({"session_id": "catpilot-verify", "turn_id": "catpilot-verify", "hook_event_name": "PreToolUse",
                       "tool_name": tool, "tool_input": {"command": command}, "cwd": str(cwd)})


def run_hook(argv: list, event: str, home: Path, timeout: int):
    """A CompletedProcess, or a sentence saying why there is none."""
    try:
        return subprocess.run(argv, input=event, capture_output=True, encoding="utf-8", errors="replace",
                              timeout=timeout, env=clean_env(home), cwd=str(home))
    except subprocess.TimeoutExpired:
        return "did not finish within the %ds hook timeout" % timeout
    except OSError as exc:
        return "could not start (%s)" % exc.__class__.__name__


def decision(result) -> str:
    """"deny", "none" (the empty decision) or a sentence saying what went wrong."""
    if isinstance(result, str):
        return result
    if result.returncode != 0:
        return "exited %d instead of returning a decision (2 means it could not read the event or load the catpilot_guard package)" % result.returncode
    try:
        output = json.loads(result.stdout)
    except ValueError:
        return "printed no JSON decision"
    if output == {}:
        return "none"
    try:
        if output["hookSpecificOutput"]["permissionDecision"] == "deny":
            return "deny"
    except (TypeError, KeyError):
        pass
    return "printed something other than a deny or the empty decision"


def codex_registrations(groups) -> list:
    """(matcher, hook file, command) for each command hook that runs one of the Catpilot PreToolUse checks."""
    found = []
    for group in groups if isinstance(groups, list) else []:
        if not isinstance(group, dict):
            continue
        for handler in group.get("hooks") or []:
            command = handler.get("command") if isinstance(handler, dict) else None
            if not isinstance(command, str):
                continue
            for name in CODEX_HOOK_FILES:
                if name in command:
                    found.append((group.get("matcher"), name, command))
    return found


def verify_codex_hooks(codex_dir: Path, home: Path, timeout: int, prefer_tomllib: bool = True) -> int:
    report = Report()
    hooks_dir = Path(tree(str(codex_dir))) / "hooks"
    for name in CODEX_HOOK_FILES:
        report.present(hooks_dir / name)
    for module in CODEX_HOOK_MODULES:
        report.present(hooks_dir / "catpilot_guard" / (module + ".py"))
    tool_of = {name: tool for _, tool, names in CODEX_PRETOOLUSE for name in names}
    for name in CODEX_HOOK_FILES:
        script = hooks_dir / name
        if not script.exists():
            continue
        for (tool, command, what), expected in zip(CODEX_PROBES[name], ("deny", "none")):
            got = decision(run_hook([sys.executable, str(script), "--host", CODEX], codex_event(tool, command, home), home, timeout))
            if got == expected:
                report.line("denies" if expected == "deny" else "passes", "%s --host codex: %s" % (name, what))
            elif got in ("deny", "none"):
                report.line("FAIL", "%s --host codex %s %s" % (name, "did not deny" if expected == "deny" else "denied", what))
            else:
                report.line("FAIL", "%s --host codex %s on %s" % (name, got, what))
    requirements_path = codex_dir / "requirements.toml"
    if not report.present(requirements_path):
        return 0
    try:
        requirements, reader = read_toml(requirements_path, prefer_tomllib)
    except (OSError, ValueError):
        report.line("INVALID", "%s does not parse as TOML" % requirements_path)
        return 0
    print("         (read with %s)" % reader)
    features = requirements.get("features") if isinstance(requirements, dict) else None
    if reader != "tomllib" and _FEATURES_ELSEWHERE.search(requirements_path.read_bytes().decode("utf-8", "replace")):
        report.line("FAIL", "%s sets features as a dotted key or an inline table, which this reader cannot read, so it "
                    "cannot tell whether hooks are turned off; run verify.sh with PYTHON_BIN set to Python 3.11 or later"
                    % requirements_path)
    elif isinstance(features, dict) and features.get("hooks") is False:
        report.line("FAIL", "%s sets [features].hooks = false, which turns every hook off" % requirements_path)
    elif not (isinstance(features, dict) and features.get("hooks") is True):
        report.line("note", "%s does not pin [features].hooks = true, so a person who turns hooks off in their own "
                    "config turns these off too" % requirements_path)
    req_hooks = requirements.get("hooks") if isinstance(requirements, dict) else None
    managed_dir = req_hooks.get("managed_dir") if isinstance(req_hooks, dict) else None
    if not isinstance(managed_dir, str) or not os.path.isabs(managed_dir):
        report.line("FAIL", "%s sets no absolute [hooks] managed_dir; Codex loads managed hooks only with one" % requirements_path)
    elif not Path(managed_dir).is_dir():
        report.line("FAIL", "[hooks] managed_dir %s does not exist; Codex loads managed hooks only when it does" % managed_dir)
    entries = codex_registrations(req_hooks.get("PreToolUse") if isinstance(req_hooks, dict) else None)
    hint = "install.sh prints the TOML to merge when the file already existed"
    if reader != "tomllib":
        hint += "; this reader follows only [[hooks.PreToolUse]] tables, so if the file declares them another way, "
        hint += "run verify.sh with PYTHON_BIN set to Python 3.11 or later"
    for name in CODEX_HOOK_FILES:
        mine = [(matcher, command) for matcher, hook, command in entries if hook == name]
        if not mine:
            report.line("FAIL", "requirements.toml does not run %s at PreToolUse (%s)" % (name, hint))
            continue
        tool = tool_of[name]
        tool_probe, command_probe, what = CODEX_PROBES[name][0]
        harmless_tool, harmless_command, harmless_what = CODEX_PROBES[name][1]
        for matcher, command in mine:
            if not any(covers(matcher, alias, anchored=False) for alias in CODEX_MATCHER_NAMES[tool]):
                report.line("FAIL", "requirements.toml runs %s under a matcher that does not cover %s" % (name, tool))
            if "--host codex" not in command and "--host=codex" not in command:
                report.line("note", "requirements.toml runs %s without --host codex, so its evidence lines say claude-code" % name)
            if isinstance(managed_dir, str):
                paths = [token for token in _split(command) if token.endswith(name)]
                if paths and not paths[0].startswith(managed_dir.rstrip("/") + "/"):
                    report.line("note", "the command runs %s, outside managed_dir; Codex's documentation says managed "
                                "hook commands should use absolute script paths under it" % paths[0])
            if "CATPILOT_EVIDENCE_SYSLOG" in command:
                report.line("skipped", "requirements.toml command for %s (it forwards evidence to syslog; check it in a session)" % name)
                continue
            got = decision(run_hook(["bash", "-c", command], codex_event(tool_probe, command_probe, home), home, timeout))
            passed = decision(run_hook(["bash", "-c", command], codex_event(harmless_tool, harmless_command, home), home, timeout))
            if got == "deny" and passed == "none":
                report.line("wired", "requirements.toml runs %s at PreToolUse and it denies its probe" % name)
            elif got == "deny":
                if passed == "deny":
                    report.line("FAIL", "requirements.toml command for %s denied %s, which it must let through" % (name, harmless_what))
                else:
                    report.line("FAIL", "requirements.toml command for %s %s on %s" % (name, passed, harmless_what))
            elif got == "none":
                report.line("FAIL", "requirements.toml command for %s did not deny %s" % (name, what))
            else:
                report.line("FAIL", "requirements.toml command for %s %s on %s" % (name, got, what))
    return 0


# --- verify the company-rules hook ------------------------------------------------------------------------------

# What a compiled rule's mode does on each tool (catpilot_guard/company_rules.py): ask acts as block unless the hook's
# command line has --ask; with it, Claude Code asks in its default permission mode, which the probe event sets, and the
# hook returns ask on Copilot CLI for Copilot to settle. Codex cannot ask, so ask denies there either way.
ASKING_HOSTS = (CLAUDE_CODE, COPILOT)


def expected_effect(host: str, modes: list, ask_enabled: bool) -> str:
    """The decision the hook gives when rules in these modes all match: the strictest wins."""
    effects = {"deny" if m == "block" or (m == "ask" and not (ask_enabled and host in ASKING_HOSTS)) else "ask" if m == "ask"
               else "none" for m in modes}
    return "deny" if "deny" in effects else "ask" if "ask" in effects else "none"


def has_ask_flag(command: str) -> bool:
    return "--ask" in _split(command)
EFFECT_WORDS = {"deny": "denies", "ask": "asks the person about", "none": "logs, without blocking,"}
COMPANY_LOG = ".catpilot-guardrails/evidence.jsonl"  # where the registered command's own prefix sends evidence


def company_event(host: str, command: str, cwd: Path) -> str:
    event = {"session_id": "catpilot-verify", "hook_event_name": "PreToolUse", "tool_name": "Bash",
             "tool_input": {"command": command}, "cwd": str(cwd)}
    if host == COPILOT:
        event["timestamp"] = dt.datetime.now(dt.timezone.utc).isoformat()
    if host == CLAUDE_CODE:
        event["permission_mode"] = "default"
    return json.dumps(event)


def company_decision(result, copilot: bool = False) -> str:
    """"deny", "ask", "none" (the empty decision) or a sentence saying what went wrong. For Copilot CLI a deny or an
    ask must also carry the top-level permissionDecision, the field Copilot's documentation lists."""
    if isinstance(result, str):
        return result
    if result.returncode != 0:
        return "exited %d instead of returning a decision (2 means it could not read the event or load the catpilot_guard package)" % result.returncode
    try:
        output = json.loads(result.stdout)
    except ValueError:
        return "printed no JSON decision"
    if output == {}:
        return "none"
    try:
        found = output["hookSpecificOutput"]["permissionDecision"]
    except (TypeError, KeyError):
        found = None
    if found in ("deny", "ask") and copilot and output.get("permissionDecision") != found:
        return "decided without the top-level permissionDecision Copilot CLI reads (is --host copilot-cli missing?)"
    return found if found in ("deny", "ask") else "printed something other than a deny, an ask or the empty decision"


def policy_errors(log: Path) -> list:
    """The labels of the policy_error lines in an evidence log verify itself pointed the hook at."""
    try:
        lines = log.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    labels = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("event") == "policy_error" and entry.get("hook") == "pretooluse-company-rules":
            labels.append(str(entry.get("label")))
    return labels


def branch_matches(value: str, branch: str) -> bool:
    """catpilot_guard/policy.py's branch_matches, repeated so this helper imports only the standard library (a test
    checks the two agree)."""
    if not branch:
        return False
    if value.startswith("refs/heads/"):
        value = value[len("refs/heads/"):]
    if value.endswith("/*"):
        prefix = value[:-1].casefold()
        name = branch.casefold()
        return name.startswith(prefix) and len(name) > len(prefix)
    return value.casefold() == branch.casefold()


def first_branch_probe(policy_file: Path):
    """(rule id, mode, command, expired, modes) for a force push to a branch the policy's first protected_branch rule
    covers, or None. modes are the effective modes of every rule that covers that branch, the probed one included, so
    the expected decision is the strictest of them, as the hook decides. The caller never prints the command."""
    try:
        data = json.loads(policy_file.read_text(encoding="utf-8"))
        expired = dt.date.fromisoformat(data["expires_on"]) < dt.date.today()
        branch_rules = [rule for rule in data["rules"] if rule["kind"] == "protected_branch"]
        if not branch_rules:
            return None
        first = branch_rules[0]
        value = first["values"][0]
        branch = value[:-1] + "catpilot-verify" if value.endswith("/*") else value
        modes = ["monitor" if expired else rule["mode"] for rule in branch_rules
                 if any(branch_matches(v, branch) for v in rule["values"])]
        return first["id"], first["mode"], "git push --force origin %s" % shlex.quote(branch), expired, modes
    except (OSError, ValueError, KeyError, TypeError, IndexError, AttributeError):
        return None


# Deploys the probe can name, each with the hosting service's own domain (catpilot_guard/deploy_targets.py).
DEPLOY_PROBES = (("netlify deploy --prod", "netlify.app"), ("vercel --prod", "vercel.app"), ("surge dist", "surge.sh"),
                 ("firebase deploy", "web.app"), ("wrangler deploy", "workers.dev"))


def suffix_covered(value: str, suffix: str) -> bool:
    """catpilot_guard/deploy_targets.py's host_covered for a service's own domain, repeated so this helper imports only
    the standard library (a test checks the two agree): only `*.D` with the suffix under or equal to D covers it."""
    value = value.lower()
    return value.startswith("*.") and (suffix == value[2:] or suffix.endswith("." + value[2:]))


def first_deploy_probe(policy_file: Path):
    """(rule id, mode, command, expired, modes) for a deploy the policy's first deploy_host rule does not allow, or None.
    modes are the effective modes of every deploy_host rule that does not allow it either: each is its own allow-list."""
    try:
        data = json.loads(policy_file.read_text(encoding="utf-8"))
        expired = dt.date.fromisoformat(data["expires_on"]) < dt.date.today()
        rules = [rule for rule in data["rules"] if rule["kind"] == "deploy_host"]
        if not rules:
            return None
        first = rules[0]
        for command, suffix in DEPLOY_PROBES:
            if not any(suffix_covered(v, suffix) for v in first["values"]):
                modes = ["monitor" if expired else rule["mode"] for rule in rules
                         if not any(suffix_covered(v, suffix) for v in rule["values"])]
                return first["id"], first["mode"], command, expired, modes
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    return None


def company_commands(host: str, managed: Path, prefer_tomllib: bool):
    """(matcher, command) for each registration of the company-rules hook in the tool's managed file, the file, and
    a sentence when the file cannot be read."""
    if host == COPILOT:
        path = managed / "policy.d" / COPILOT_POLICY_NAME
        try:
            entries = (json.loads(path.read_text(encoding="utf-8")).get("hooks") or {}).get("PreToolUse")
        except (OSError, ValueError, AttributeError):
            return [], path, "%s cannot be read as JSON" % path
        found = [(entry.get("matcher"), entry.get("bash")) for entry in (entries if isinstance(entries, list) else [])
                 if isinstance(entry, dict) and isinstance(entry.get("bash"), str) and COMPANY_HOOK in entry["bash"]]
        return found, path, None
    if host == CLAUDE_CODE:
        path = managed / "managed-settings.json"
        try:
            groups = (json.loads(path.read_text(encoding="utf-8")).get("hooks") or {}).get("PreToolUse")
        except (OSError, ValueError, AttributeError):
            return [], path, "%s cannot be read as JSON" % path
    else:
        path = managed / "requirements.toml"
        try:
            requirements, _ = read_toml(path, prefer_tomllib)
            groups = (requirements.get("hooks") or {}).get("PreToolUse")
        except (OSError, ValueError, AttributeError):
            return [], path, "%s cannot be read as TOML" % path
    found = []
    for group in groups if isinstance(groups, list) else []:
        for handler in (group.get("hooks") or []) if isinstance(group, dict) else []:
            command = handler.get("command") if isinstance(handler, dict) else None
            if isinstance(command, str) and COMPANY_HOOK in command:
                found.append((group.get("matcher"), command))
    return found, path, None


def verify_company_rules(cc_dir: Path, codex_dir: Path, home: Path, timeout: int, prefer_tomllib: bool = True,
                         copilot_dir: Path | None = None) -> int:
    """For each tool with a compiled policy: the files, the hook run directly on a harmless command and on a probe
    for the first protected_branch rule, and the hook as the tool's managed file registers it. A policy the hook
    refuses (wrong owner, writable by others, malformed) shows as a policy_error line, which is a FAIL here."""
    report = Report()
    tools = [(CLAUDE_CODE, cc_dir), (CODEX, codex_dir)] + ([(COPILOT, copilot_dir)] if copilot_dir is not None else [])
    for host, managed in tools:
        root = Path(tree(str(managed)))
        policy_file = root / "policy" / POLICY_NAME
        if not policy_file.exists():
            managed_file = (managed / "policy.d" / COPILOT_POLICY_NAME if host == COPILOT
                            else managed / ("managed-settings.json" if host == CLAUDE_CODE else "requirements.toml"))
            try:
                registered = COMPANY_HOOK in managed_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                registered = False
            if registered:
                report.line("FAIL", "%s runs %s, and there is no compiled policy at %s: every command logs policy_error and "
                            "no company rule applies; reinstall with a rules file that has enforcement rules, or remove "
                            "that hook entry" % (managed_file, COMPANY_HOOK, policy_file))
            else:
                report.line("skipped", "company-rules hook for %s: no compiled policy at %s" % (host, policy_file))
            continue
        report.present(policy_file)
        hook = root / "hooks" / COMPANY_HOOK
        if not report.present(hook):
            continue
        probe = first_branch_probe(policy_file)
        runs = [("ls", [], "a harmless command")]
        if probe is not None:
            rule_id, mode, command, expired, modes = probe
            runs.append((command, modes,
                         "a force push to a branch rule %s protects (%s%s)" % (rule_id, mode, ", expired: monitor" if expired else "")))
        deploy = first_deploy_probe(policy_file)
        if deploy is not None:
            rule_id, mode, command, expired, modes = deploy
            runs.append((command, modes,
                         "a deploy to a host rule %s does not allow (%s%s)" % (rule_id, mode, ", expired: monitor" if expired else "")))
        if probe is None and deploy is None:
            report.line("note", "the %s policy has no protected_branch or deploy_host rule, so only a harmless command is probed" % host)
        log = home / ("verify-company-%s.jsonl" % host)
        for command, modes, what in runs:
            expected = expected_effect(host, modes, ask_enabled=False)  # run directly, without --ask
            verb = "lets through" if command == "ls" else EFFECT_WORDS[expected]
            env = clean_env(home)
            env["CATPILOT_EVIDENCE_LOG"] = str(log)
            try:
                result = subprocess.run([sys.executable, str(hook), "--host", host, "--policy", str(policy_file)],
                                        input=company_event(host, command, home), capture_output=True, encoding="utf-8",
                                        errors="replace", timeout=timeout, env=env, cwd=str(home))
            except subprocess.TimeoutExpired:
                result = "did not finish within the %ds hook timeout" % timeout
            except OSError as exc:
                result = "could not start (%s)" % exc.__class__.__name__
            got = company_decision(result, copilot=(host == COPILOT))
            if got == expected:
                word = "passes" if command == "ls" else {"deny": "denies", "ask": "asks", "none": "logs"}[expected]
                report.line(word, "%s --host %s %s %s" % (COMPANY_HOOK, host, verb, what))
            else:
                report.line("FAIL", "%s --host %s: expected it to %s %s, got %s" % (COMPANY_HOOK, host, expected, what, got))
        for label in sorted(set(policy_errors(log))):
            report.line("FAIL", "the company-rules hook for %s could not use its policy (%s); it applies no company rule "
                        "until this is fixed: the policy and its directory must be owned like the hooks and writable only "
                        "by their owner" % (host, label))
        entries, managed_file, problem = company_commands(host, managed, prefer_tomllib)
        if problem:
            report.line("INVALID", problem)
            continue
        if not entries:
            report.line("FAIL", "%s does not run %s, so the company rules are compiled but not enforced on %s" % (managed_file, COMPANY_HOOK, host))
            continue
        registered_log = home / COMPANY_LOG
        try:
            registered_log.unlink()  # this tool's runs only: the other tool's lines must not count against it
        except OSError:
            pass
        for matcher, command in entries:
            if not (copilot_covers(matcher, "Bash") if host == COPILOT else covers(matcher, "Bash", anchored=(host == CLAUDE_CODE))):
                report.line("FAIL", "%s runs %s under a matcher that does not cover Bash" % (managed_file, COMPANY_HOOK))
            if host == COPILOT and "--host copilot-cli" not in command and "--host=copilot-cli" not in command:
                report.line("FAIL", "%s runs %s without --host copilot-cli, so its decisions lack the fields Copilot CLI reads" % (managed_file, COMPANY_HOOK))
            if "CATPILOT_EVIDENCE_SYSLOG" in command:
                report.line("skipped", "%s command for %s (it forwards evidence to syslog; check it in a session)" % (managed_file, COMPANY_HOOK))
                continue
            for probe_command, modes, what in runs:
                expected = expected_effect(host, modes, has_ask_flag(command))
                verb = "lets through" if probe_command == "ls" else EFFECT_WORDS[expected]
                got = company_decision(run_hook(["bash", "-c", command], company_event(host, probe_command, home), home, timeout),
                                       copilot=(host == COPILOT))
                if got == expected:
                    report.line("wired", "%s runs %s, which %s %s" % (managed_file, COMPANY_HOOK, verb, what))
                else:
                    report.line("FAIL", "%s command for %s: expected it to %s %s, got %s" % (managed_file, COMPANY_HOOK, expected, what, got))
            for label in sorted(set(policy_errors(registered_log))):
                report.line("FAIL", "%s runs %s with a policy it could not use (%s)" % (managed_file, COMPANY_HOOK, label))
    return 0

# --- verify the Copilot CLI policy hooks --------------------------------------------------------------------------

COPILOT_PROBES = {
    "pretooluse-secrets.py": (("Bash", {"command": "export AWS_ACCESS_KEY_ID=%s && echo ok" % _DOC_KEY}, "a command carrying AWS's documentation example key"),
                              ("Bash", {"command": "ls"}, "ls")),
    "pretooluse-destructive-ops.py": (("Bash", {"command": "git push --force origin main"}, "git push --force origin main"),
                                      ("Bash", {"command": "ls"}, "ls")),
    "pretooluse-write-secrets.py": (("Write", {"path": "probe.env", "file_text": "AWS_ACCESS_KEY_ID=%s\n" % _DOC_KEY}, "a new file holding AWS's documentation example key"),
                                    ("Write", {"path": "notes.md", "file_text": "# Notes\n"}, "a harmless new file")),
}


def copilot_event(tool: str, tool_input: dict, cwd: Path) -> str:
    """A PreToolUse event in the shape Copilot CLI sends for the PascalCase event name."""
    return json.dumps({"hook_event_name": "PreToolUse", "session_id": "catpilot-verify",
                       "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(), "cwd": str(cwd),
                       "tool_name": tool, "tool_input": tool_input})


def copilot_decision(result) -> str:
    """Like decision(), and a deny must also carry the top-level permissionDecision Copilot documents."""
    got = decision(result)
    if got == "deny":
        try:
            if json.loads(result.stdout).get("permissionDecision") != "deny":
                return "denied without the top-level permissionDecision Copilot CLI reads"
        except (ValueError, AttributeError):
            return "printed no JSON decision"
    return got


def copilot_covers(matcher, tool: str) -> bool:
    """Copilot's Claude-format matcher for PascalCase PreToolUse: empty, * or ** match every tool; a name or
    |-separated names match by equality; anything else is a regex anchored at both ends."""
    if matcher in (None, "", "*", "**"):
        return True
    if not isinstance(matcher, str):
        return False
    tokens = matcher.split("|")
    if all(re.fullmatch(r"[A-Za-z0-9_]+", token) for token in tokens):
        return tool in tokens
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return False


def verify_copilot_hooks(copilot_dir: Path, home: Path, timeout: int) -> int:
    report = Report()
    hooks_dir = Path(tree(str(copilot_dir))) / "hooks"
    for name in COPILOT_HOOK_FILES:
        report.present(hooks_dir / name)
    for module in CODEX_HOOK_MODULES + ("copilot",):
        report.present(hooks_dir / "catpilot_guard" / (module + ".py"))
    tools_of = {name: tools for _, tools, names in COPILOT_PRETOOLUSE for name in names}
    for name in COPILOT_HOOK_FILES:
        script = hooks_dir / name
        if not script.exists():
            continue
        for (tool, tool_input, what), expected in zip(COPILOT_PROBES[name], ("deny", "none")):
            got = copilot_decision(run_hook([sys.executable, str(script), "--host", COPILOT], copilot_event(tool, tool_input, home), home, timeout))
            if got == expected:
                report.line("denies" if expected == "deny" else "passes", "%s --host copilot-cli: %s" % (name, what))
            elif got in ("deny", "none"):
                report.line("FAIL", "%s --host copilot-cli %s %s" % (name, "did not deny" if expected == "deny" else "denied", what))
            else:
                report.line("FAIL", "%s --host copilot-cli %s on %s" % (name, got, what))
    policy_file = Path(str(copilot_dir)) / "policy.d" / COPILOT_POLICY_NAME
    if not report.present(policy_file):
        return 0
    info = policy_file.stat()
    if info.st_uid != 0 or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        message = "%s must be owned by root and writable by no one else; Copilot CLI does not load a policy file otherwise" % policy_file
        report.line("note" if os.environ.get("CATPILOT_ALLOW_NONROOT") == "1" else "FAIL", message)
    try:
        data = json.loads(policy_file.read_text(encoding="utf-8"))
        entries = data["hooks"]["PreToolUse"]
        if data.get("version") != 1 or not isinstance(entries, list):
            raise ValueError
    except (OSError, ValueError, KeyError, TypeError):
        report.line("INVALID", "%s is not a version 1 hook file with a PreToolUse list" % policy_file)
        return 0
    camel = (data.get("hooks") or {}).get("preToolUse")
    if isinstance(camel, list) and any(isinstance(e, dict) and "catpilot-guardrails" in str(e.get("bash", "")) for e in camel):
        report.line("FAIL", "%s registers Catpilot hooks under preToolUse; they read the PreToolUse event shape" % policy_file)
    for name in COPILOT_HOOK_FILES:
        mine = [entry for entry in entries if isinstance(entry, dict) and name in str(entry.get("bash", ""))]
        if not mine:
            report.line("FAIL", "%s does not run %s at PreToolUse" % (policy_file, name))
            continue
        (probe_tool, probe_input, what), (harmless_tool, harmless_input, harmless_what) = COPILOT_PROBES[name]
        for entry in mine:
            command = entry["bash"]
            for tool in tools_of[name]:
                if not copilot_covers(entry.get("matcher"), tool):
                    report.line("FAIL", "%s runs %s under a matcher that does not cover %s" % (policy_file, name, tool))
            if "--host copilot-cli" not in command and "--host=copilot-cli" not in command:
                report.line("FAIL", "%s runs %s without --host copilot-cli, so it cannot read Copilot's file edits" % (policy_file, name))
            seconds = entry.get("timeoutSec", entry.get("timeout", COPILOT_TIMEOUT_SECONDS))
            if not isinstance(seconds, (int, float)) or seconds < TIMEOUT_SECONDS:
                report.line("note", "%s gives %s a timeout under %ds; Copilot CLI lets a call run when a hook times out" % (policy_file, name, TIMEOUT_SECONDS))
            if "CATPILOT_EVIDENCE_SYSLOG" in command:
                report.line("skipped", "%s command for %s (it forwards evidence to syslog; check it in a session)" % (policy_file, name))
                continue
            got = copilot_decision(run_hook(["bash", "-c", command], copilot_event(probe_tool, probe_input, home), home, timeout))
            passed = copilot_decision(run_hook(["bash", "-c", command], copilot_event(harmless_tool, harmless_input, home), home, timeout))
            if got == "deny" and passed == "none":
                report.line("wired", "%s runs %s at PreToolUse and it denies its probe" % (policy_file, name))
            elif got == "deny":
                report.line("FAIL", "%s command for %s %s on %s" % (policy_file, name, "denied" if passed == "deny" else passed, harmless_what))
            else:
                report.line("FAIL", "%s command for %s %s on %s" % (policy_file, name, "did not deny" if got == "none" else got, what))
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
    p.add_argument("--enforce", action="store_true", help="also the company-rules hook (a compiled policy)")
    p = sub.add_parser("requirements")
    p.add_argument("--codex-dir", required=True)
    p.add_argument("--no-rules", action="store_true", help="without the session-start hook (no --overlay)")
    p.add_argument("--enforce", action="store_true", help="also the company-rules hook (a compiled policy)")
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
    p = sub.add_parser("verify-codex-hooks")
    p.add_argument("--codex-dir", required=True, type=Path)
    p.add_argument("--home", required=True, type=Path)
    p.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS)
    p = sub.add_parser("verify-company-rules")
    p.add_argument("--cc-dir", required=True, type=Path)
    p.add_argument("--codex-dir", required=True, type=Path)
    p.add_argument("--copilot-dir", type=Path)
    p.add_argument("--home", required=True, type=Path)
    p.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS)
    p = sub.add_parser("copilot-policy")
    p.add_argument("--copilot-dir", required=True)
    p.add_argument("--enforce", action="store_true", help="also the company-rules hook (a compiled policy)")
    p = sub.add_parser("verify-copilot-hooks")
    p.add_argument("--copilot-dir", required=True, type=Path)
    p.add_argument("--home", required=True, type=Path)
    p.add_argument("--timeout", type=int, default=TIMEOUT_SECONDS)
    args = parser.parse_args(argv)
    try:
        if args.action == "settings":
            print(settings_with_session_start(sys.stdin.read(), args.cc_dir, enforce=args.enforce))
        elif args.action == "requirements":
            if args.no_rules and args.enforce:
                raise UsageError("--enforce comes with the company rules: it cannot be combined with --no-rules")
            print(requirements_toml(args.codex_dir, rules=not args.no_rules, enforce=args.enforce))
        elif args.action == "claude-md-place":
            return place_claude_md(args.block, args.target)
        elif args.action == "claude-md-remove":
            return remove_claude_md(args.target)
        elif args.action == "verify":
            return verify(args.cc_dir, args.codex_dir, args.home, args.timeout)
        elif args.action == "verify-codex-hooks":
            return verify_codex_hooks(args.codex_dir, args.home, args.timeout)
        elif args.action == "verify-company-rules":
            return verify_company_rules(args.cc_dir, args.codex_dir, args.home, args.timeout, copilot_dir=args.copilot_dir)
        elif args.action == "copilot-policy":
            print(copilot_policy_json(args.copilot_dir, enforce=args.enforce))
        elif args.action == "verify-copilot-hooks":
            return verify_copilot_hooks(args.copilot_dir, args.home, args.timeout)
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
