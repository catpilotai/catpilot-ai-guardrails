"""Catpilot PreToolUse hook: the company's own enforcement rules, in monitor, ask or block.

hooks/claude-code/pretooluse-company-rules.py runs this module's main(). It reads the compiled company policy
(catpilot_guard/policy.py) from the absolute path given as `--policy` on its own command line, and `--host
claude-code|codex` says which tool runs it. deploy/org/install.sh registers it only when the rules file it was
given has an `enforcement` section (docs/spec/OVERLAY_V2.md §2.2).

Scope, stated exactly:
  - Runs only for the Bash tool, which Claude Code and Codex both name Bash.
  - Kind protected_branch: fires on a `git push` that force-pushes to (--force, -f, --force-with-lease,
    --force-if-includes, or a +refspec) or deletes (--delete, -d, or `:branch`) a branch one of the rule's values
    covers, including a bare force push while such a branch is checked out, and on `git push --mirror`, which
    rewrites every branch. Pushes are read the way the built-in destructive-operation check reads them
    (destructive.git_push_rewrites), through the same wrappers and `bash -c` bodies. A value ending in `/*`
    covers every branch under that prefix; case is ignored, as in the built-in check.
  - Kind deploy_host: accepted in the policy and not acted on yet.
  - Modes (§2.3): block denies. monitor decides nothing and writes a would_deny line. ask acts as block unless
    the hook's own command line has --ask (decision 2: ask means a person decides first). A Claude Code run with
    a program that approves (`claude -p` with a permission-prompt tool, an Agent SDK canUseTool callback) sends
    the same event as an interactive session, so the hook cannot tell that nobody was asked; an administrator
    adds --ask to the root-owned command once a host check shows a person answers there. With --ask, Claude Code
    asks the person in the default, acceptEdits and plan permission modes; other modes approve without asking a
    person or run with nobody to answer, so ask still acts as block there, as it does on Codex, which does not
    support ask, and on an unknown host. When several rules match, the strictest effect wins and each rule
    writes its own line.
  - After the policy's expires_on, every company rule acts in monitor until the file is renewed (decision 3).
  - A deny or ask reason names the rule ids and the approved alternative (use_instead_text), never a listed
    value, and never repeats the command.
  - A policy that is missing, unreadable, malformed, owned by the wrong user or writable by others, or
    arguments that cannot be read: no company rule applies, and the hook writes a policy_error line with a
    fixed label and returns no decision. The built-in checks run as their own hooks and are unaffected
    (§6.1 invariant 5). It never returns allow.
  - Fails closed on its input: a hook event it cannot read exits 2, which the host treats as a block.

Evidence lines (CATPILOT_EVIDENCE_LOG): deny, ask, would_deny and policy_error with the rule id, the mode that
applied, the policy's source SHA-256 and the session id. Never a command, a branch, a value or a path.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import json
import os
import sys

from . import DEFAULT_HOOK_HOST, HOOK_HOSTS, write_decision, write_reason
from . import policy as policy_module
from .destructive import _simple_commands, git_push_rewrites

MAX_INPUT_BYTES = 1_048_576
HOOK_NAME = "pretooluse-company-rules"
CLAUDE_CODE = "claude-code"
# Claude Code permission modes in which a person answers an ask. The others (bypassPermissions, dontAsk, auto, and
# any mode added later) approve without asking or run with nobody to answer, so ask acts as block there.
ASK_PERMISSION_MODES = ("default", "acceptEdits", "plan")
OPTIONS = ("--host", "--policy")
ASK_FLAG = "--ask"  # a flag, not an option: it takes no value
WHAT = {
    "protected_branch": "this push force-pushes to or deletes a branch the company protects",
}


def parse_args(argv: list) -> tuple:
    """(host, policy path, ok, ask). Each option at most once, as `--name value` or `--name=value`, and the flag
    --ask at most once; no --host means claude-code, as for the other hooks. ok is False for an unknown, repeated
    or valueless option, a host other than HOOK_HOSTS (host is then None), or no --policy. Values are never printed."""
    values: dict = {}
    ok = True
    ask = False
    i = 0
    while i < len(argv):
        if str(argv[i]) == ASK_FLAG:
            ok = ok and not ask
            ask = True
            i += 1
            continue
        name, sep, value = str(argv[i]).partition("=")
        i += 1
        if not sep:
            if i >= len(argv):
                return None, None, False, False
            value = str(argv[i])
            i += 1
        if name not in OPTIONS or name in values:
            ok = False
            continue
        values[name] = value
    host = values.get("--host", DEFAULT_HOOK_HOST)
    if host not in HOOK_HOSTS:
        host, ok = None, False
    policy_path = values.get("--policy")
    if not policy_path:
        ok = False
    return host, policy_path, ok, ask


def record_evidence(event: str, hook_event: object = None, host: str | None = None, **fields) -> None:
    """One evidence line through the shared writer. A missing or broken writer never changes the decision."""
    try:
        from . import evidence

        evidence.record_hook_event(HOOK_NAME, event, hook_event, host, **fields)
    except Exception:
        pass


def matched_rules(command: str, cwd: object, policy: policy_module.Policy) -> list:
    """The policy's rules this command fires, in policy order."""
    working_dir = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    pushes = []
    for argv in _simple_commands(command):
        if argv[0] == "git":
            push = git_push_rewrites(argv[1:], working_dir)
            if push is not None:
                pushes.append(push)
    if not pushes:
        return []
    fired = []
    for rule in policy.rules:
        if rule.kind != "protected_branch":
            continue
        for mirror, branches in pushes:
            if mirror or any(
                branch and any(policy_module.branch_matches(value, branch) for value in rule.values) for branch in branches
            ):
                fired.append(rule)
                break
    return fired


def can_ask(host: str | None, event: dict, ask_enabled: bool = False) -> bool:
    """Whether to return ask: only with --ask, and on Claude Code only in a mode where a person answers."""
    return ask_enabled and host == CLAUDE_CODE and event.get("permission_mode") in ASK_PERMISSION_MODES


def reason_for(effect: str, deciding: list) -> str:
    ids = ", ".join("`%s`" % rule.id for rule in deciding)
    names = "Catpilot company rule%s %s" % ("" if len(deciding) == 1 else "s", ids)
    what = "; ".join(dict.fromkeys(WHAT.get(rule.kind, "this command matches a company rule") for rule in deciding))
    alternative = next((rule.use_instead_text for rule in deciding if rule.use_instead_text), None)
    use = " Use instead: %s." % alternative if alternative else ""
    if effect == "ask":
        return "%s: %s. Approve only if this is intended.%s" % (names, what, use)
    if all(rule.mode == "ask" for rule in deciding):
        return (
            "%s: %s. The company asks a person to confirm this, and nobody can be asked here, so it was not run.%s "
            "If this exact command is intentional, run it yourself in your own terminal." % (names, what, use)
        )
    return "%s: %s.%s If this exact command is intentional, run it yourself in your own terminal." % (names, what, use)


def decide(event: dict, host: str | None, policy: policy_module.Policy | None, today=None, ask_enabled: bool = False) -> dict:
    if not isinstance(event, dict):
        raise ValueError("hook event must be an object")
    if event.get("tool_name") != "Bash":
        return {}
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    if policy is None or not command:
        return {}
    fired = matched_rules(command, event.get("cwd"), policy)
    if not fired:
        return {}
    expired = policy.expired(today)
    asking = can_ask(host, event, ask_enabled)
    effects = []
    for rule in fired:
        mode = "monitor" if expired else rule.mode
        effect = {"block": "deny", "ask": "ask" if asking else "deny", "monitor": None}[mode]
        effects.append((rule, mode, effect))
    final = "deny" if any(e == "deny" for _, _, e in effects) else "ask" if any(e == "ask" for _, _, e in effects) else None
    for rule, mode, effect in effects:
        line = "would_deny" if effect is None else final
        record_evidence(line, event, host, tool="Bash", rule_id=rule.id, mode=mode, policy_sha256=policy.source_sha256)
    if final is None:
        return {}
    deciding = [rule for rule, _, effect in effects if effect == final]
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": final,
            "permissionDecisionReason": reason_for(final, deciding),
        }
    }


def load_policy(event: dict, host: str | None, path: str | None, ok: bool):
    """The policy, or None after writing a policy_error line. Never raises."""
    try:
        if not ok:
            raise policy_module.PolicyError("bad-arguments")
        return policy_module.load(path)
    except policy_module.PolicyError as exc:
        label = exc.args[0] if exc.args and exc.args[0] in policy_module.ERROR_LABELS else "internal-error"
    except Exception:
        label = "internal-error"
    record_evidence("policy_error", event, host, label=label)
    return None


def main() -> int:
    host, path, ok, ask_enabled = parse_args(sys.argv[1:])
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("hook input too large")
        event = json.loads(payload)
        if not isinstance(event, dict):
            raise ValueError("hook event must be an object")
        policy = load_policy(event, host, path, ok) if event.get("tool_name") == "Bash" else None
        result = decide(event, host, policy, ask_enabled=ask_enabled)
    except Exception:
        # Any failure to read the event blocks: an ordinary non-zero exit would let the host run the command.
        record_evidence("input_error", host=host)
        write_reason(
            "Catpilot company-rules check could not read the hook input, so the command was not allowed. "
            "Review the command and retry.")
        return 2
    return write_decision(result)


if __name__ == "__main__":
    sys.exit(main())
