#!/usr/bin/env python3
"""The managed files deploy/org/install.ps1 places on Windows, and the checks verify.ps1 runs (docs/spec/WINDOWS.md §3.3).

install.ps1 handles what is Windows-specific (elevation, paths, access lists, the interpreter); this file writes the
JSON and TOML and runs the probes, as session_start_files.py does for install.sh. Every hook command names the
interpreter by absolute path and runs without a shell:

  Claude Code  exec form: "command" is python.exe, "args" the hook path and its options, "onFailure": "block"
  Codex CLI    requirements.toml with [hooks] windows_managed_dir and each command as command_windows
  Copilot CLI  a policy.d file whose entries use "exec" and "args"

  python windows_files.py place  --python EXE --server-url URL --cc-dir DIR --codex-dir DIR --copilot-dir DIR
  python windows_files.py remove --python EXE --server-url URL --cc-dir DIR --codex-dir DIR --copilot-dir DIR
  python windows_files.py verify --cc-dir DIR --codex-dir DIR --copilot-dir DIR

place writes each managed file only when it is absent (an identical file is reported current; any other is kept
and the content printed for a merge); remove deletes a managed file only when it is byte for byte what place
writes. Standard library only, Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
sys.path.insert(0, str(HERE))
import session_start_files as ssf  # noqa: E402

TEMPLATE = HERE / "claude-code" / "managed-settings.json"
EXAMPLE_URL = "https://mcp.example.com/mcp"
# An absolute Windows path a JSON string, a TOML literal string and a double-quoted command word all carry as written.
WINDOWS_PATH = re.compile(r"^[A-Za-z]:\\[^\"'$`%<>|*?\x00-\x1f\x7f]*$")
SETTINGS_NAME = "managed-settings.json"
REQUIREMENTS_NAME = "requirements.toml"
COPILOT_POLICY = Path("policy.d", ssf.COPILOT_POLICY_NAME)
TIMEOUT = ssf.TIMEOUT_SECONDS
VERSION_CHECK = "import sys; print('%d.%d.%d' % sys.version_info[:3]); sys.exit(0 if sys.version_info >= (3, 8) else 3)"
# A PowerShell spelling of a destructive command, for the destructive check on Claude Code's PowerShell tool.
POWERSHELL_PROBE = "Remove-Item -Recurse -Force C:\\Windows"


class UsageError(Exception):
    pass


def checked(value: str, what: str = "path") -> str:
    if not WINDOWS_PATH.match(value or ""):
        raise UsageError("%s %r must be an absolute Windows path (C:\\...) without quotes, $, `, %%, <, >, |, * or ?" % (what, value))
    return value.rstrip("\\")


def hooks_dir(managed_dir: str) -> str:
    return checked(managed_dir) + "\\catpilot-guardrails\\hooks"


def cc_settings(cc_dir: str, python: str, server_url: str) -> str:
    """deploy/org/claude-code/managed-settings.json with the server URL, each hook in exec form."""
    if any(c in server_url for c in "\"\\\x00\n\r") or not server_url.startswith(("https://", "http://")):
        raise UsageError("server URL %r must be an http(s) URL without quotes or backslashes" % server_url)
    data = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    data["managedMcpServers"]["catpilot-guardrails"]["url"] = server_url
    for group in data["hooks"]["PreToolUse"]:
        for entry in group["hooks"]:
            name = re.search(r"/hooks/([A-Za-z0-9_.-]+\.py)", entry["command"]).group(1)
            entry["command"] = checked(python, "interpreter")
            entry["args"] = ["%s\\%s" % (hooks_dir(cc_dir), name), ssf.EVIDENCE_DEFAULT]
    return json.dumps(data, indent=2)


# How Codex runs command_windows (openai/codex, read 2026-11-19): codex-rs/hooks/src/engine/command_runner.rs runs the
# line through the session's shell, which on Windows is PowerShell (shell_detect.rs default_user_shell: get_shell
# (PowerShell), with cmd.exe only as the last fallback), as `<powershell> -NoProfile -Command <line>`
# (core/src/shell.rs derive_exec_args). In PowerShell a quoted path is a string, not a command, so the line starts
# with the call operator. Under the cmd.exe fallback this line does not run, and Codex may then let the tool run.
CODEX_SHELL = ("powershell.exe", "-NoProfile", "-Command")


def command_line(python: str, script: str, host: str) -> str:
    return '& "%s" "%s" %s --host %s' % (checked(python, "interpreter"), script, ssf.EVIDENCE_DEFAULT, host)


def codex_requirements(codex_dir: str, python: str) -> str:
    managed = hooks_dir(codex_dir)
    lines = [
        "# Catpilot Guardrails, written by deploy/org/install.ps1: managed Codex hooks on Windows.",
        "# PreToolUse: the credential and destructive-operation checks on Bash and the credential check on file edits",
        "# (apply_patch). Each command names the interpreter by absolute path; command_windows is what Codex runs on",
        "# Windows, through the session's PowerShell (hence the & call operator), and command carries the same line.",
        "", "[features]", "hooks = true", "", "[hooks]", "windows_managed_dir = '%s'" % managed,
    ]
    for matcher, _, names in ssf.CODEX_PRETOOLUSE:
        lines += ["", "[[hooks.PreToolUse]]", 'matcher = "%s"' % matcher]
        for name in names:
            line = command_line(python, "%s\\%s" % (managed, name), ssf.CODEX)
            lines += ["", "[[hooks.PreToolUse.hooks]]", 'type = "command"', "command = '%s'" % line,
                      "command_windows = '%s'" % line, "timeout = %d" % TIMEOUT]
    return "\n".join(lines)


def copilot_policy(copilot_dir: str, python: str) -> str:
    entries = []
    for matcher, _, names in ssf.COPILOT_PRETOOLUSE:
        for name in names:
            entries.append({"type": "command", "matcher": matcher, "exec": checked(python, "interpreter"),
                            "args": ["%s\\%s" % (hooks_dir(copilot_dir), name), ssf.EVIDENCE_DEFAULT, "--host", ssf.COPILOT],
                            "timeoutSec": ssf.COPILOT_TIMEOUT_SECONDS})
    return json.dumps({"version": 1, "hooks": {"PreToolUse": entries}}, indent=2)


def managed_files(args, python: str = None) -> list:
    """(path, content) for each managed file install.ps1 writes, naming PYTHON (default: args.python)."""
    python = python or args.python
    return [
        (Path(checked(args.cc_dir)) / SETTINGS_NAME, cc_settings(args.cc_dir, python, args.server_url)),
        (Path(checked(args.codex_dir)) / REQUIREMENTS_NAME, codex_requirements(args.codex_dir, python)),
        (Path(checked(args.copilot_dir)) / COPILOT_POLICY, copilot_policy(args.copilot_dir, python)),
    ]


def place(args) -> int:
    previous = []
    if args.previous_python and args.previous_python != args.python:
        previous = [content for _, content in managed_files(args, python=args.previous_python)]
    for index, (path, content) in enumerate(managed_files(args)):
        data = (content + "\n").encode("utf-8")
        if path.exists() or path.is_symlink():
            if path.is_file() and not path.is_symlink() and path.read_bytes() == data:
                print("current %s" % path)
            elif previous and path.is_file() and not path.is_symlink() and path.read_bytes() == (previous[index] + "\n").encode("utf-8"):
                # What install.ps1 wrote with the interpreter it named before: ours, so it is replaced.
                path.write_bytes(data)
                print("updated %s (now names %s)" % (path, args.python))
            else:
                print("exists  %s (not overwritten); merge this into it:" % path)
                print(content)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        print("policy  %s" % path)
    return 0


def remove(args) -> int:
    for path, content in managed_files(args):
        if not path.is_file():
            continue
        if path.read_bytes() == (content + "\n").encode("utf-8"):
            path.unlink()
            print("removed %s" % path)
        elif b"catpilot" in path.read_bytes():
            print("kept    %s (edited since install; remove the entries that run catpilot-guardrails\\hooks\\ by hand)" % path)
    return 0


# verify ------------------------------------------------------------------------------------------------------------

class Report:
    def __init__(self):
        self.failed = 0
        self.missing = 0

    def line(self, word: str, text: str) -> None:
        if word == "FAIL":
            self.failed += 1
        elif word == "MISSING":
            self.missing += 1
        print("%-8s %s" % (word, text))


def run(argv: list, event: str, home: Path, timeout: int):
    return ssf.run_hook(argv, event, home, timeout, extra_env={"USERPROFILE": str(home)})


def claude_event(tool: str, tool_input: dict, cwd: Path) -> str:
    return json.dumps({"session_id": "catpilot-verify", "hook_event_name": "PreToolUse", "tool_name": tool,
                       "tool_input": tool_input, "cwd": str(cwd)})


def claude_probes(name: str, home: Path) -> list:
    """(tool, input, what, expected) for one Claude Code hook."""
    key = "AWS_ACCESS_KEY_ID=%s" % ssf._DOC_KEY
    if name == "pretooluse-secrets.py":
        return [("Bash", {"command": "export %s && echo ok" % key}, "a command carrying AWS's documentation example key", "deny"),
                ("PowerShell", {"command": "$env:AWS_ACCESS_KEY_ID = '%s'" % ssf._DOC_KEY}, "a PowerShell command carrying the same key", "deny"),
                ("Bash", {"command": "ls"}, "ls", "none")]
    if name == "pretooluse-destructive-ops.py":
        return [("Bash", {"command": "git push --force origin main"}, "git push --force origin main", "deny"),
                ("PowerShell", {"command": POWERSHELL_PROBE}, POWERSHELL_PROBE, "deny"),
                ("PowerShell", {"command": "Get-ChildItem"}, "Get-ChildItem", "none")]
    return [("Write", {"file_path": str(home / "probe.env"), "content": key + "\n"}, "a file write carrying AWS's documentation example key", "deny"),
            ("Write", {"file_path": str(home / "notes.md"), "content": "# Notes\n"}, "a harmless file write", "none")]


def judge(report: Report, label: str, what: str, expected: str, got: str) -> None:
    if got == expected:
        report.line("denies" if expected == "deny" else "passes", "%s: %s" % (label, what))
    elif got in ("deny", "none"):
        report.line("FAIL", "%s %s %s" % (label, "denied" if got == "deny" else "did not deny", what))
    else:
        report.line("FAIL", "%s %s on %s" % (label, got, what))


def check_interpreter(report: Report, python: str, seen: dict, home: Path, timeout: int) -> bool:
    if python in seen:
        return seen[python]
    ok = False
    if not WINDOWS_PATH.match(python) and not (os.name != "nt" and python.startswith("/")):
        report.line("FAIL", "the hook commands name %r, not an absolute path; reinstall with install.ps1" % python)
    else:
        try:
            proc = subprocess.run([python, "-c", VERSION_CHECK], capture_output=True, text=True, timeout=timeout, cwd=str(home))
            if proc.returncode == 0:
                report.line("runs", "%s, Python %s" % (python, proc.stdout.strip()))
                ok = True
            elif proc.returncode == 3:
                report.line("FAIL", "%s is Python %s; the hooks need 3.8 or later" % (python, proc.stdout.strip()))
            else:
                report.line("FAIL", "%s exited %d instead of starting" % (python, proc.returncode))
        except subprocess.TimeoutExpired:
            report.line("FAIL", "%s did not start within %ds" % (python, timeout))
        except OSError as exc:
            report.line("FAIL", "%s could not start (%s). Claude Code (onFailure block) then blocks every command and "
                        "write the hooks cover" % (python, exc.__class__.__name__))
    seen[python] = ok
    return ok


def check_acl(report: Report, path: Path) -> None:
    """On Windows: the owner and access list leave the path changeable only by Administrators, SYSTEM or
    TrustedInstaller, the rule the company-policy check applies (catpilot_guard/policy.py)."""
    if os.name != "nt":
        report.line("skipped", "access list of %s (not Windows)" % path)
        return
    if not path.exists():
        return
    sys.path.insert(0, str(REPO))
    from catpilot_guard import policy
    try:
        owner, aces = policy._windows_security(name=str(path))
    except OSError as exc:
        report.line("FAIL", "could not read the access list of %s (%s)" % (path, exc))
        return
    if policy.acl_trusted(owner, aces):
        report.line("locked", "%s: only Administrators, SYSTEM or TrustedInstaller can change it" % path)
    else:
        report.line("FAIL", "%s can be changed by an account other than Administrators, SYSTEM or TrustedInstaller; "
                    "run install.ps1 again" % path)


def split_windows(command: str) -> list:
    return [a if a else b for a, b in re.findall(r'"([^"]*)"|(\S+)', command)]


def verify(args) -> int:
    report = Report()
    seen: dict = {}
    timeout = args.timeout
    with tempfile.TemporaryDirectory(prefix="catpilot-verify-") as tmp:
        home = Path(tmp)

        print("Claude Code (managed dir: %s)" % args.cc_dir)
        settings_path = Path(args.cc_dir) / SETTINGS_NAME
        names_seen = set()
        if not settings_path.is_file():
            report.line("MISSING", str(settings_path))
        else:
            try:
                settings = json.loads(settings_path.read_text(encoding="utf-8"))
                groups = settings["hooks"]["PreToolUse"]
            except (ValueError, KeyError, TypeError):
                report.line("FAIL", "%s does not parse as JSON with hooks.PreToolUse" % settings_path)
                groups = []
            for group in groups:
                matcher = group.get("matcher", "")
                for entry in group.get("hooks") or []:
                    hook_args = entry.get("args")
                    if not isinstance(hook_args, list) or not hook_args or not str(hook_args[0]).endswith(".py"):
                        continue
                    name = Path(str(hook_args[0]).replace("\\", "/")).name
                    names_seen.add(name)
                    if entry.get("onFailure") != "block":
                        report.line("note", "%s runs %s without \"onFailure\": \"block\" (Claude Code 2.1.295+)" % (SETTINGS_NAME, name))
                    if not check_interpreter(report, entry.get("command", ""), seen, home, timeout):
                        continue
                    for tool, tool_input, what, expected in claude_probes(name, home):
                        if not ssf.covers(matcher, tool, anchored=True):
                            if expected == "deny":
                                report.line("FAIL", "%s runs %s under matcher %r, which does not cover %s" % (SETTINGS_NAME, name, matcher, tool))
                            continue
                        got = ssf.decision(run([entry["command"]] + [str(a) for a in hook_args], claude_event(tool, tool_input, home), home, timeout))
                        judge(report, "%s (exec form)" % name, what, expected, got)
            for name in ("pretooluse-secrets.py", "pretooluse-destructive-ops.py", "pretooluse-write-secrets.py"):
                if name not in names_seen:
                    report.line("FAIL", "%s does not run %s in exec form (install.ps1 prints the JSON to merge when the file existed)" % (SETTINGS_NAME, name))
        check_acl(report, Path(args.cc_dir) / "catpilot-guardrails")
        print()

        print("Codex CLI (managed dir: %s)" % args.codex_dir)
        req = Path(args.codex_dir) / REQUIREMENTS_NAME
        if not req.is_file():
            report.line("skipped", "no %s" % req)
        else:
            try:
                data, _ = ssf.read_toml(req)
            except ValueError as exc:
                report.line("FAIL", "%s does not parse as TOML (%s)" % (req, exc))
                data = {}
            groups = ((data or {}).get("hooks") or {}).get("PreToolUse") or []
            for group in groups:
                for entry in group.get("hooks") or []:
                    line = entry.get("command_windows") or entry.get("command") or ""
                    words = split_windows(line)
                    if words[:1] == ["&"]:
                        words = words[1:]
                    name = next((Path(w.replace("\\", "/")).name for w in words if w.endswith(".py")), None)
                    if name not in ssf.CODEX_PROBES or not words:
                        continue
                    if not check_interpreter(report, words[0], seen, home, timeout):
                        continue
                    # On Windows, the line goes through PowerShell exactly as Codex runs it (CODEX_SHELL above).
                    argv = list(CODEX_SHELL) + [line] if os.name == "nt" else words
                    if os.name != "nt":
                        report.line("note", "not Windows: %s run directly, not through PowerShell as Codex runs it" % name)
                    for (tool, command, what), expected in zip(ssf.CODEX_PROBES[name], ("deny", "none")):
                        got = ssf.decision(run(argv, ssf.codex_event(tool, command, home), home, timeout))
                        judge(report, "requirements.toml %s" % name, what, expected, got)
            check_acl(report, Path(args.codex_dir) / "catpilot-guardrails")
        print()

        print("GitHub Copilot CLI (policy dir: %s\\policy.d)" % args.copilot_dir)
        pol = Path(args.copilot_dir) / COPILOT_POLICY
        if not pol.is_file():
            report.line("skipped", "no %s" % pol)
        else:
            try:
                entries = json.loads(pol.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]
            except (ValueError, KeyError, TypeError):
                report.line("FAIL", "%s does not parse as a policy hook file" % pol)
                entries = []
            for entry in entries:
                argv = [entry.get("exec", "")] + [str(a) for a in entry.get("args") or []]
                name = next((Path(w.replace("\\", "/")).name for w in argv[1:] if w.endswith(".py")), None)
                if name not in ssf.COPILOT_PROBES:
                    continue
                if not check_interpreter(report, argv[0], seen, home, timeout):
                    continue
                for (tool, tool_input, what), expected in zip(ssf.COPILOT_PROBES[name], ("deny", "none")):
                    got = ssf.copilot_decision(run(argv, ssf.copilot_event(tool, tool_input, home), home, timeout))
                    judge(report, "policy.d %s" % name, what, expected, got)
            check_acl(report, Path(args.copilot_dir) / "catpilot-guardrails")
        print()

    print("%d missing, %d failed. Next: start Claude Code and run /status; 'Setting sources' must name the file." % (report.missing, report.failed))
    print("This runs the hooks directly; only a session shows the host applying a deny (docs/DEPLOY_ORG.md).")
    return 0 if report.failed == 0 and report.missing == 0 else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="action")
    for action in ("place", "remove", "verify"):
        p = sub.add_parser(action)
        p.add_argument("--cc-dir", required=True)
        p.add_argument("--codex-dir", required=True)
        p.add_argument("--copilot-dir", required=True)
        if action == "verify":
            p.add_argument("--timeout", type=int, default=TIMEOUT)
        else:
            p.add_argument("--python", required=True)
            p.add_argument("--server-url", required=True)
            p.add_argument("--previous-python", default="", help="the interpreter an earlier install named (place)")
    args = parser.parse_args(argv)
    try:
        if args.action == "place":
            return place(args)
        if args.action == "remove":
            return remove(args)
        if args.action == "verify":
            return verify(args)
    except UsageError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    parser.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
