"""Catpilot PreToolUse hook: the company's own enforcement rules, in monitor, ask or block.

hooks/claude-code/pretooluse-company-rules.py runs this module's main(). It reads the compiled company policy
(catpilot_guard/policy.py) from the absolute path given as `--policy` on its own command line, and `--host
claude-code|codex|copilot-cli` says which tool runs it. deploy/org/install.sh registers it only when the rules file it was
given has an `enforcement` section (docs/spec/OVERLAY_V2.md §2.2).

Scope, stated exactly:
  - Runs only for the Bash tool, which Claude Code and Codex both name Bash; on Copilot CLI, bash, powershell and
    write_bash (input sent to a running shell), read through catpilot_guard/copilot.py.
  - Kind protected_branch: fires on a `git push` that force-pushes to (--force, -f, --force-with-lease,
    --force-if-includes, or a +refspec) or deletes (--delete, -d, or `:branch`) a branch one of the rule's values
    covers, including a bare force push while such a branch is checked out, and on `git push --mirror`, which
    rewrites every branch. Pushes are read the way the built-in destructive-operation check reads them
    (destructive.git_push_rewrites), through the same wrappers and `bash -c` bodies. A value ending in `/*`
    covers every branch under that prefix; case is ignored, as in the built-in check.
  - Kind deploy_host, an allow-list: fires on a deploy or publish whose target no value of the rule covers.
    catpilot_guard/deploy_targets.py says which commands deploy and to what: a named host (`scp dist/
    deploy@web1.example.org:/srv`), a hosting service's own domain when the command shows no name (`vercel --prod`
    deploys under vercel.app, so only a value `*.vercel.app` covers it), or a destination it cannot read (`rsync dist/
    $HOST:/srv`), which no value covers. A value `*.D` covers every name under D; any other value covers that host.
    Each deploy_host rule is its own allow-list, so list every approved host in one rule.
  - Kind package_registry, an allow-list: fires on a command that names a registry no value of the rule covers.
    catpilot_guard/registry_targets.py says which commands name one and how: `--registry` on npm, pnpm, yarn, bun and
    their runners, npm/pnpm/yarn `config set` of a registry key, pip and uv index options and `pip config set`, `poetry
    source add`, `uv publish --publish-url`, `twine --repository-url`, gem sources and hosts, `go env -w GOPROXY`,
    docker and podman push, pull, run, create and login with an explicit registry, and assignments such as
    NPM_CONFIG_REGISTRY, PIP_INDEX_URL and GOPROXY, also through `python -m`, `uv run`, `uvx` and the other runners it
    names. A command that names none (`npm install`, `docker pull ubuntu`) is no target, and a registry it cannot read
    (a variable, a URL that URL parsers read differently, a value xargs supplies) no value covers. A value `host`
    covers that host, `host/path` that path and below, `*.D` every name under D.
  - Kind cloud_account, an allow-list: fires on a command that names an account no value of the rule covers.
    catpilot_guard/cloud_targets.py says which: an ARN's account in aws, sam and cdk arguments, aws account-id
    options, gcloud --project and `config set project`, gsutil -u and `mb -p`, bq --project_id, az --subscription and
    resource ids, and assignments such as CLOUDSDK_CORE_PROJECT and AZURE_SUBSCRIPTION_ID, through the same runners.
    A profile names no account, so `aws --profile prod` is no target; a variable, a project number or a subscription
    name is unknown, and no value covers it. Values match exactly.
  - Modes (§2.3): block denies. monitor decides nothing and writes a would_deny line. ask acts as block unless
    the hook's own command line has --ask (decision 2: ask means a person decides first). A Claude Code run with
    a program that approves (`claude -p` with a permission-prompt tool, an Agent SDK canUseTool callback) sends
    the same event as an interactive session, so the hook cannot tell that nobody was asked; an administrator
    adds --ask to the root-owned command once a host check shows a person answers there. With --ask, Claude Code
    asks the person in the default, acceptEdits and plan permission modes; other modes approve without asking a
    person or run with nobody to answer, so ask still acts as block there, as it does on Codex, which does not
    support ask, and on an unknown host. On Copilot CLI, whose event carries no permission mode, --ask makes the
    hook return ask and Copilot settles it: it denies an ask in autopilot and the cloud agent; how it treats one
    under `copilot -p` or an allow-all mode is not verified. When several rules match, the strictest effect wins
    and each rule writes its own line.
  - After the policy's expires_on, every company rule acts in monitor until the file is renewed (decision 3).
  - Expiring exceptions (§3.1) relax one company rule, never a built-in check: the built-in checks are separate hooks
    and read no policy. The hook applies an exception until its expires_on (the day itself included) and only when it
    has no `where`: a repository name read from a working tree is something the agent can change, so only the
    pull-request check reads `where`. For protected_branch, an exception's allows are branches the rule stops
    protecting (a value ending in `/*` covers the prefix, as for the rule's values); for deploy_host, package_registry
    and cloud_account, extra approved hosts, registries or accounts, covered as the rule's values cover them, so an
    unknown target, which no value covers, no exception covers either. A rule fires when something it matches is
    covered by no rule value and no active exception; `git push --mirror` and the other pushes that can rewrite every branch are never excepted. When active
    exceptions cover everything a rule matched, the rule decides nothing and writes a would_deny line carrying the
    exception_id of each exception that covered a match, with the rule's own mode: the line records that exceptions
    covered all of the rule's matches, whether or not the rule would have decided anything (in monitor mode it would
    not) and whether or not another rule decides the command. An expired exception is ignored, and none outlives the
    policy.
  - A deny or ask reason names the rule ids and the approved alternative (use_instead_text), never a listed
    value, a host, a registry or an account, and never repeats the command.
  - A policy that is missing, unreadable, malformed, owned by the wrong user or writable by others, or
    arguments that cannot be read: no company rule applies, and the hook writes a policy_error line with a
    fixed label and returns no decision. The built-in checks run as their own hooks and are unaffected
    (§6.1 invariant 5). It never returns allow.
  - Fails closed on its input: a hook event it cannot read exits 2, which the host treats as a block.

Evidence lines (CATPILOT_EVIDENCE_LOG): deny, ask, would_deny and policy_error with the rule id, the mode that
applied, the policy's source SHA-256 and the session id, and on a would_deny line for a rule whose matches exceptions
all covered, the exception id. Never a command, a branch, a host, a registry, an account, a value or a path.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys

from . import COPILOT_CLI, DEFAULT_HOOK_HOST, HOOK_HOSTS, decision_for_host, event_for_host, write_decision, write_reason
from . import policy as policy_module
from .cloud_targets import account_covered, cloud_targets
from .deploy_targets import deploy_targets, host_covered
from .destructive import _simple_commands, git_push_rewrites
from .registry_targets import registry_covered, registry_targets, split_command

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
    "deploy_host": "this command deploys or publishes to a host the company has not approved",
    "package_registry": "this command names a package registry the company has not approved",
    "cloud_account": "this command names a cloud account the company has not approved",
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


def matched_rules(command: str, cwd: object, policy: policy_module.Policy, today=None) -> list:
    """(rule, exception ids) for each of the policy's rules this command matches, in policy order. The ids are empty
    when the rule fires. Otherwise active exceptions covered everything the rule matched, so it does not fire, and the
    ids name them, in policy order: for each match, the first exception that covers it."""
    working_dir = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    kinds = {rule.kind for rule in policy.rules}
    pushes = []
    if "protected_branch" in kinds:
        for argv in _simple_commands(command):
            if argv[0] == "git":
                push = git_push_rewrites(argv[1:], working_dir)
                if push is not None:
                    pushes.append(push)
    # One split of the command for the deploy, registry and account readers: a long command is split once, not per kind.
    split = split_command(command) if kinds & {"deploy_host", "package_registry", "cloud_account"} else ([], [])
    targets = deploy_targets(command, working_dir, commands=split[0]) if "deploy_host" in kinds else []
    registries = registry_targets(command, working_dir, split=split) if "package_registry" in kinds else []
    accounts = cloud_targets(command, working_dir, split=split) if "cloud_account" in kinds else []
    mirror = any(rewrites_every_branch for rewrites_every_branch, _ in pushes)
    branches = [branch for _, names in pushes for branch in names if branch]
    matched = []
    for rule in policy.rules:
        if rule.kind == "protected_branch":
            # A push that can rewrite every branch fires the rule as a whole: an exception names branches, not that.
            if mirror:
                matched.append((rule, ()))
                continue
            covered = _branch_covered
            hits = [branch for branch in branches if covered(rule.values, branch)]  # a protect-list: a listed branch fires
        elif rule.kind == "deploy_host":
            covered = _target_covered
            hits = [target for target in targets if not covered(rule.values, target)]  # an allow-list: an unlisted host fires
        elif rule.kind == "package_registry":
            covered = _registry_covered
            hits = [target for target in registries if not covered(rule.values, target)]  # allow-list, as deploy_host
        elif rule.kind == "cloud_account":
            covered = _account_covered
            hits = [target for target in accounts if not covered(rule.values, target)]  # allow-list, as deploy_host
        else:
            continue
        if not hits:
            continue
        exceptions = policy.active_exceptions(rule.id, today)
        used = set()
        for hit in hits:
            exception = next((e for e in exceptions if covered(e.allows, hit)), None)
            if exception is None:  # a match no exception covers: the rule fires
                used = set()
                break
            used.add(exception.id)
        matched.append((rule, tuple(e.id for e in exceptions if e.id in used)))
    return matched


def _branch_covered(values, branch: str) -> bool:
    return any(policy_module.branch_matches(value, branch) for value in values)


def _target_covered(values, target) -> bool:
    return any(host_covered(value, target) for value in values)


def _registry_covered(values, target) -> bool:
    return any(registry_covered(value, target) for value in values)  # an unknown registry: nothing covers it


def _account_covered(values, target) -> bool:
    return any(account_covered(value, target) for value in values)  # an unknown account: nothing covers it


def can_ask(host: str | None, event: dict, ask_enabled: bool = False) -> bool:
    """Whether to return ask: only with --ask. Claude Code: only in a mode where a person answers. Copilot CLI: its
    event names no mode, so the hook returns ask and Copilot settles it."""
    if not ask_enabled:
        return False
    if host == COPILOT_CLI:
        return True
    return host == CLAUDE_CODE and event.get("permission_mode") in ASK_PERMISSION_MODES


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
    today = today or dt.date.today()  # one date for the exceptions and the file's expiry, even across midnight
    matched = matched_rules(command, event.get("cwd"), policy, today)
    if not matched:
        return {}
    expired = policy.expired(today)
    asking = can_ask(host, event, ask_enabled)
    effects = []
    for rule, excepted_by in matched:
        mode = "monitor" if expired else rule.mode
        # A rule whose matches exceptions all covered decides nothing, whatever its mode.
        effect = None if excepted_by else {"block": "deny", "ask": "ask" if asking else "deny", "monitor": None}[mode]
        effects.append((rule, mode, effect, excepted_by))
    final = "deny" if any(e == "deny" for _, _, e, _ in effects) else "ask" if any(e == "ask" for _, _, e, _ in effects) else None
    for rule, mode, effect, excepted_by in effects:
        if excepted_by:
            # Exceptions covered all of the rule's matches: one would_deny line per exception that covered a match,
            # with the rule's own mode (OVERLAY_V2.md §3.1).
            for exception_id in excepted_by:
                record_evidence("would_deny", event, host, tool="Bash", rule_id=rule.id, mode=mode, exception_id=exception_id,
                                policy_sha256=policy.source_sha256)
            continue
        line = "would_deny" if effect is None else final
        record_evidence(line, event, host, tool="Bash", rule_id=rule.id, mode=mode, policy_sha256=policy.source_sha256)
    if final is None:
        return {}
    deciding = [rule for rule, _, effect, _ in effects if effect == final]
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
        event = event_for_host(json.loads(payload), host)
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
    return write_decision(decision_for_host(result, host))


if __name__ == "__main__":
    sys.exit(main())
