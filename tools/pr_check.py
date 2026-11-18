#!/usr/bin/env python3
"""Catpilot pull-request check: the company's enforcement rules, applied to the files a pull request adds or changes.

The second consumer of the compiled company policy (docs/spec/OVERLAY_V2.md §2.2), beside the company-rules hook. It
reads the same JSON policy (`tools/validate_overlay.py compile`) and the same matching code as the hook
(catpilot_guard/company_rules.py, catpilot_guard/deploy_targets.py), and reports on the files of a pull request
that can deploy or push.

    python tools/pr_check.py --policy POLICY --repo PATH --base REF [--format github|text]
    python tools/pr_check.py --policy POLICY --repo PATH --files F [F ...] [--format github|text]

--base REF scans the files added or changed in `REF...HEAD` in --repo (renames count as added; deleted files are
not scanned). --files scans the named files, given relative to --repo or as absolute paths inside it.

What it scans, exactly (by file name; every other file is ignored):

  .github/workflows/*.yml|yaml   each step's `run:` script, through the hook's matching for protected_branch and
  (any letter case)              deploy_host rules (the hook's command splitting reads every line). Literal `env:`
                                 values (workflow, then job, then step, the more specific winning) are read into
                                 `$X`, `${X}` and `${{ env.X }}`, but only until a step that can run code (any `run:`
                                 step, or any `uses:` but actions/checkout), which may set any variable for the steps
                                 after it through GITHUB_ENV, and not at all in a job with an action from another
                                 repository (its `pre:` runs before the first step) other than GitHub's own actions with
                                 no `pre:` (NO_PRE_ACTIONS); any other variable or `${{ ... }}` stays unknown, so a
                                 destination or a branch taken from one is one the check cannot read, which fires (as
                                 in the hook). A run step whose shell (its own, or `defaults.run.shell` of its job or
                                 workflow, or pwsh on a Windows runner named literally, also in a runs-on mapping's
                                 labels) is not bash or sh, with only the plain options `_readable_shell` allows,
                                 cannot be read; PowerShell is not read. On a runner the check cannot read (a matrix
                                 expression, a group with no labels) a step with no shell is read as bash, unless it
                                 holds what only PowerShell reads (`<#`, `Invoke-Expression`, `iex` but `iex -S`,
                                 the `&` call operator, a backtick ending a line unpaired or after a space), and then it cannot be
                                 read. The names in env: at every level say whether git is pointed elsewhere
                                 (GIT_DIR) or may mirror (GIT_CONFIG_*, or an env: that is an expression). Each step's `uses:`
                                 naming a deploy action (DEPLOY_ACTIONS) or a force-pushing action (PUSH_ACTIONS), and
                                 a `docker://` step's `entrypoint` and `args`, as a command
  action.yml|yaml (anywhere)     the same, for the steps of a composite action (`runs.steps`), with no env: value
                                 substituted (the calling job may have set any variable);
                                 for a Docker action, `runs.entrypoint` with `runs.args`, and `runs.pre-entrypoint`
                                 and `runs.post-entrypoint`, as commands
  package.json (anywhere)        each value under `scripts`, as a command
  vercel.json                    literal host names in `alias` and `domains`, and `buildCommand`, `installCommand`,
                                 `ignoreCommand` and `devCommand` as commands; the file alone implies no deploy
  netlify.toml                   `build.command`, `build.ignore`, `dev.command`, and each `context.<name>.command` and
                                 `.ignore`, as commands; the file alone implies no deploy
  fly.toml, fly.<name>.toml      `app = "x"`: the host x.fly.dev
  wrangler.toml|json|jsonc       at the top level and under each `env.<name>`: each `route`/`routes` pattern's literal
                                 host (`*.example.org/*` as the wildcard *.example.org), else its `zone_name`, else a
                                 host the check cannot read; the suffix workers.dev where `workers_dev = true`, or
                                 where there is no route and `workers_dev` is not false (wrangler's default; an
                                 environment inherits `workers_dev`, not routes); a Pages project
                                 (`pages_build_output_dir`): the suffix pages.dev
  firebase.json                  each `hosting` entry: its literal `site` as the host <site>.web.app, else the suffix
                                 web.app; and every `predeploy` and `postdeploy` command

A deploy action's `with:` inputs are read conservatively: a domain input counts only when it is a literal host name.
A push action's branch input that is not a literal name is unknown, and a force input that is not a literal false
counts as a force.

Each finding is decided by its rule's mode (§2.3; after the policy's expires_on every rule acts in monitor, as in the
hook): monitor is a warning and the check passes; ask and block are errors and the check fails, since nobody can be
asked in a pull-request check (decision 2). A file this check cannot read (unparseable, a symbolic link, larger than
1 MiB), or a run step in a shell it does not read, is reported with a fixed text, and fails the check when a rule
that file could reveal is in ask or block.

An annotation names the rule id, a fixed explanation for its kind and the approved alternative (use_instead), never a
listed value, the matched command or the host (§4: "A PR annotation points at the line in the diff. It never prints
the listed values"). The file and the line are named.

The policy is read as catpilot_guard.policy.parse reads it, without the hook's ownership check (a CI runner writes
it), but a symbolic link, anything but a regular file, and a policy inside --repo are refused: the rules must never
come from the repository under review.

Exit codes: 0 the check passes, 1 a rule fails it, 2 a usage or policy error (the reason is printed, without values).

A bare force push or a push to HEAD in a workflow names no branch the check can read (the branch a workflow runs on
is not the checkout's), so, like a variable, it fires every protected_branch rule.

Not covered: files the pull request does not add or change (an unchanged reusable workflow or script that a changed
file calls), scripts a command runs (`npm run deploy` is not followed into package.json), reusable workflows and
actions from other repositories, a variable that holds an option where no literal word follows it (`git push origin
$F` with F=--force; `git push $F origin main` counts as a force), a PowerShell step (read as unreadable until a
PowerShell reader exists), a Docker image's own entrypoint, deploy and push
actions not listed below, and everything the hook does not cover (hooks/README.md, exact coverage).

Standard library plus PyYAML. Python 3.11+ (tomllib).
"""
from __future__ import annotations

import argparse
import errno
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

try:
    import tomllib
except ImportError:  # Python before 3.11: TOML files are reported as unreadable
    tomllib = None

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from catpilot_guard import policy as policy_module  # noqa: E402
from catpilot_guard.company_rules import matched_rules  # noqa: E402
from catpilot_guard.destructive import git_config_assignment_harmful  # noqa: E402
from catpilot_guard.deploy_targets import HOST, HOST_NAME, SUFFIX, UNKNOWN, Target, deploy_targets, host_covered  # noqa: E402

MAX_FILE_BYTES = 1_048_576
EXPRESSION = re.compile(r"\$\{\{.*?\}\}", re.DOTALL)
EXPRESSION_VARIABLE = "$CATPILOT_EXPRESSION"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
FLY_CONFIG = re.compile(r"fly(?:\.[A-Za-z0-9_-]+)?\.toml")
BOTH_KINDS = ("protected_branch", "deploy_host")
DEPLOY_ONLY = ("deploy_host",)

# The fixed explanation an annotation gives for each kind. Never a value, a command or a host.
WHAT = {
    "protected_branch": "this file runs a git push that force-pushes to or deletes a branch the company protects",
    "deploy_host": "this file deploys or publishes to a host the company has not approved",
}
UNREADABLE = "Catpilot pull-request check: could not read this file, so it was not checked against the company rules."
UNREADABLE_STEP = ("Catpilot pull-request check: could not read this run step, whose shell is not bash or sh with plain options, "
                   "so it was not checked against the company rules.")

# Deploy actions a workflow step may name in `uses:`, by owner/repository, lowercase.
#   suffix           the hosting service's own domain the action deploys under
#   domain_inputs    `with:` inputs naming a custom domain; used only when a literal host name
#   domain_replaces  a literal custom domain replaces the suffix (the site is served there) instead of adding to it
#   host_inputs      `with:` inputs naming the destination host of a copy; a value that is not a literal host name,
#                    or no value, is a destination the check cannot read
#   cli, cli_input   the action runs this CLI with that input as its arguments, read as the hook reads the command;
#                    when the input holds an expression and no deploy is read, the suffix is assumed
#   cli_default      the arguments when the input is absent
#   subpaths         only these action paths inside the repository deploy (None: the repository's root action)
DEPLOY_ACTIONS = {
    "peaceiris/actions-gh-pages": {"suffix": "github.io", "domain_inputs": ("cname",), "domain_replaces": True},
    "actions/deploy-pages": {"suffix": "github.io"},
    "jamesives/github-pages-deploy-action": {"suffix": "github.io"},
    "amondnet/vercel-action": {"suffix": "vercel.app", "domain_inputs": ("alias-domains",)},
    "betahuhn/deploy-to-vercel-action": {"suffix": "vercel.app", "domain_inputs": ("alias_domains",)},
    "nwtgck/actions-netlify": {"suffix": "netlify.app"},
    "south-paw/action-netlify-deploy": {"suffix": "netlify.app"},
    "jsmrcaga/action-netlify-deploy": {"suffix": "netlify.app"},
    "netlify/actions": {"suffix": "netlify.app", "cli": "netlify", "cli_input": "args", "subpaths": ("cli",)},
    "cloudflare/wrangler-action": {"suffix": "workers.dev", "cli": "wrangler", "cli_input": "command", "cli_default": "deploy"},
    "cloudflare/pages-action": {"suffix": "pages.dev"},
    "firebaseextended/action-hosting-deploy": {"suffix": "web.app"},
    "superfly/flyctl-actions": {"suffix": "fly.dev", "cli": "flyctl", "cli_input": "args", "subpaths": (None,)},
    "appleboy/scp-action": {"host_inputs": ("host",)},
    "burnett01/rsync-deployments": {"host_inputs": ("remote_host",)},
    "easingthemes/ssh-deploy": {"host_inputs": ("remote_host",)},
}


class UsageError(Exception):
    """A usage or policy error. Its message is fixed text, never a value."""


class Unreadable(Exception):
    """A file the check cannot read."""


@dataclass(frozen=True)
class Commands:
    """A shell script a file runs. start_line is the line of its first line; exact says whether each line of text
    is on its own line of the file (a literal block), so a finding can point at it; key_line is the line to point
    at otherwise."""
    start_line: int
    text: str
    key_line: int
    exact: bool = False


@dataclass(frozen=True)
class Targets:
    """Deploy targets a file names (catpilot_guard/deploy_targets.Target), at a line."""
    line: int
    targets: tuple


@dataclass(frozen=True)
class Pushes:
    """Branches a push action force-pushes to (None: unknown), at a line."""
    line: int
    branches: tuple


@dataclass(frozen=True)
class UnreadableStep:
    """A run step whose shell this check does not read, at the line of its `run:`."""
    line: int


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    level: str  # "error" or "warning"
    message: str
    rule_id: str | None = None


@dataclass
class Result:
    findings: list = field(default_factory=list)
    scanned: int = 0
    changed: int = 0

    @property
    def failed(self) -> bool:
        return any(f.level == "error" for f in self.findings)


# ----------------------------------------------------------------- which files


def file_type(path: str) -> str | None:
    """The scanner for a repository-relative POSIX path, or None for a file this check ignores."""
    pure = PurePosixPath(path)
    name = pure.name
    if str(pure.parent).lower() == ".github/workflows" and pure.suffix.lower() in (".yml", ".yaml"):
        return "workflow"
    if name in ("action.yml", "action.yaml"):
        return "action"
    if name in ("package.json", "vercel.json", "netlify.toml", "firebase.json"):
        return name
    if FLY_CONFIG.fullmatch(name):
        return "fly.toml"
    if name in ("wrangler.toml", "wrangler.json", "wrangler.jsonc"):
        return name
    return None


# The kinds of rule each file type can reveal: a file that runs commands can push; a deploy configuration cannot.
RELEVANT_KINDS = {
    "workflow": BOTH_KINDS, "action": BOTH_KINDS, "package.json": BOTH_KINDS, "vercel.json": BOTH_KINDS,
    "netlify.toml": BOTH_KINDS, "firebase.json": BOTH_KINDS,
    "fly.toml": DEPLOY_ONLY, "wrangler.toml": DEPLOY_ONLY, "wrangler.json": DEPLOY_ONLY, "wrangler.jsonc": DEPLOY_ONLY,
}


# ----------------------------------------------------------------- helpers


def _line_of(raw: str, needles, default: int) -> int:
    """The 1-based line of the first needle found in raw, else default. Only the line number is ever reported."""
    for needle in needles:
        if needle:
            index = raw.find(needle)
            if index != -1:
                return raw.count("\n", 0, index) + 1
    return default


def _key_line(raw: str, key: str, default: int = 1) -> int:
    """The 1-based line of the first `key =` or `"key":` in a TOML or JSON file, else default."""
    name = re.escape(key)
    found = re.search(r"(?m)^[ \t]*[\"']?%s[\"']?[ \t]*[:=]" % name, raw) or re.search(r"[\"']%s[\"'][ \t]*:" % name, raw)
    return raw.count("\n", 0, found.start()) + 1 if found else default


def _value_line(raw: str, value: str, default: int) -> int:
    """The line where a string value appears in a JSON or TOML file, by its quoted forms, then its first line."""
    first = value.split("\n", 1)[0]
    escaped = json.dumps(value)[1:-1]
    escaped_utf8 = json.dumps(value, ensure_ascii=False)[1:-1]
    return _line_of(raw, ['"%s"' % escaped_utf8, '"%s"' % escaped, '"%s"' % value, "'%s'" % value, first.strip()], default)


def literal_host(text: object) -> str | None:
    """A literal host name from an input or a setting (`docs.example.org`, `https://docs.example.org/`), lowercase,
    or None when it is not one: an expression, a variable, a bare word, an address."""
    if not isinstance(text, str):
        return None
    value = text.strip().lower()
    if not value or "$" in value or "{{" in value or "}}" in value:
        return None
    value = value.split("://", 1)[-1].split("/", 1)[0].rsplit("@", 1)[-1]
    if re.fullmatch(r".+:[0-9]+", value):
        value = value.rsplit(":", 1)[0]
    value = value.rstrip(".")
    return value if HOST_NAME.fullmatch(value) and not re.fullmatch(r"[0-9.]+", value) else None


def _words(value: str) -> list:
    """The items of a list-valued input (one per line or comma-separated), each `${{ ... }}` as one variable."""
    return [word for word in re.split(r"[\s,]+", _expressions_as_variables(value)) if word]


def _strings(value: object) -> list:
    """A string, or the strings of a list; anything else gives nothing."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


# Contexts a pull request's author can set (GitHub's script-injection guidance: event titles, bodies, messages, branch
# names), unless the value is a number. Their text, which GitHub puts in before the shell runs, may end the word or the
# refspec, so a destination taken from one is unknown; any other expression (step outputs, inputs, env, matrix, vars)
# is the workflow's own and reads like a shell variable: `v${{ steps.v.outputs.major }}` is `v*`.
ATTACKER_CONTEXT = re.compile(
    r"\bgithub\s*(?:\.\s*|\[\s*['\"])\s*(?:event\b(?!['\"]?\s*\]?\s*\.\s*(?:number|inputs|pull_request\s*\.\s*number)\b)|head_ref\b)"
    r"|\bgithub\b(?!\s*(?:\.|\[))",  # the whole object (`toJSON(github)`)
    re.IGNORECASE)


def _expressions_as_variables(text: str) -> str:
    """Each `${{ ... }}` as a shell variable, keeping the line count, so a value taken from one is unreadable: the
    opaque placeholder for an expression that names an ATTACKER_CONTEXT, an ordinary variable for any other."""
    def placeholder(m) -> str:
        name = EXPRESSION_VARIABLE if ATTACKER_CONTEXT.search(m.group(0)) else "$CATPILOT_WORKFLOW_VALUE"
        return name + "\n" * m.group(0).count("\n")
    return EXPRESSION.sub(placeholder, text)


def logical_lines(text: str, first_line: int) -> list:
    """(line, text) for each line of a script, a backslash-continued line joined with the next."""
    out, buffer, start = [], [], None
    for offset, line in enumerate(text.split("\n")):
        if start is None:
            start = first_line + offset
        buffer.append(line)
        trailing = len(line) - len(line.rstrip("\\"))
        if trailing % 2 == 1:
            continue
        out.append((start, "\n".join(buffer)))
        buffer, start = [], None
    if buffer:
        out.append((start, "\n".join(buffer)))
    return out


def strip_jsonc(text: str) -> str:
    """JSON with comments and trailing commas (wrangler.jsonc) as JSON. Comments become spaces, keeping every newline,
    so line numbers stay. Raises Unreadable for an unterminated comment."""
    out, i, n, in_string = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_string:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
            i += 1
        elif c == '"':
            in_string = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            if end == -1:
                raise Unreadable()
            out.append("".join("\n" if ch == "\n" else " " for ch in text[i:end + 2]))
            i = end + 2
        else:
            out.append(c)
            i += 1
    stripped = "".join(out)
    result, in_string, i, n = [], False, 0, len(stripped)
    while i < n:
        c = stripped[i]
        if in_string:
            result.append(c)
            if c == "\\" and i + 1 < n:
                result.append(stripped[i + 1])
                i += 2
                continue
            if c == '"':
                in_string = False
        elif c == '"':
            in_string = True
            result.append(c)
        elif c == ",":
            j = i + 1
            while j < n and stripped[j] in " \t\r\n":
                j += 1
            if not (j < n and stripped[j] in "}]"):
                result.append(c)
        else:
            result.append(c)
        i += 1
    return "".join(result)


def _json(raw: str) -> object:
    try:
        return json.loads(raw)
    except (ValueError, RecursionError):
        raise Unreadable() from None


def _toml(raw: str) -> dict:
    if tomllib is None:
        raise Unreadable()
    try:
        return tomllib.loads(raw)
    except (ValueError, RecursionError):
        raise Unreadable() from None


# ----------------------------------------------------------------- YAML (workflows, composite actions)


# Push actions a workflow step may name in `uses:`, read for protected_branch rules. The input names and defaults are
# from memory of each action's documentation, not checked against its current release.
#   branch_input, default_branch  the branch it pushes to (None: the branch the workflow runs on, which is unknown)
#   force_inputs                  inputs that make the push a force push, with the first one's default
PUSH_ACTIONS = {
    "jamesives/github-pages-deploy-action": {"branch_input": "branch", "default_branch": "gh-pages",
                                             "force_inputs": ("force",), "force_default": True},
    "peaceiris/actions-gh-pages": {"branch_input": "publish_branch", "default_branch": "gh-pages",
                                   "force_inputs": ("force_orphan",), "force_default": False},
    "ad-m/github-push-action": {"branch_input": "branch", "default_branch": None,
                                "force_inputs": ("force", "force_with_lease"), "force_default": False},
}
# PowerShell is not read: its block comments (`<# ... #>`), backtick escapes and Invoke-Expression would hide a command
# from POSIX shell rules, so a pwsh or powershell step is unreadable until a PowerShell reader exists.
READABLE_SHELLS = ("bash", "sh")
# An env: value substituted into a script only when it is this plain: anything else could change how the script
# reads (a quote, a space, a `;`), so its variable stays unresolved, and unknown.
SAFE_LITERAL = re.compile(r"[A-Za-z0-9._/@:+=,-]*")
ENV_EXPRESSION = re.compile(r"\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
SHELL_VARIABLE = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def _pairs(node, depth: int = 0) -> list:
    """A YAML mapping node's (key, value) pairs, with `<<` merges expanded; nothing for any other node."""
    if not isinstance(node, yaml.MappingNode) or depth > 10:
        return []
    out = []
    for key, value in node.value:
        if isinstance(key, yaml.ScalarNode) and key.tag == "tag:yaml.org,2002:merge":
            merged = value.value if isinstance(value, yaml.SequenceNode) else [value]
            for item in merged:
                out.extend(_pairs(item, depth + 1))
        else:
            out.append((key, value))
    return out


def _values(node, name: str) -> list:
    """Every value node under key `name` in a mapping node: a key that appears twice is read twice."""
    return [value for key, value in _pairs(node) if isinstance(key, yaml.ScalarNode) and key.value == name]


def _scalar(node, name: str) -> str | None:
    """The last scalar value under `name`, "" when the value is not a scalar, None when absent."""
    found = None
    for value in _values(node, name):
        found = value.value if isinstance(value, yaml.ScalarNode) else ""
    return found


class RawValue(str):
    """A GIT_CONFIG_* env: value that is not a plain literal, kept as written so _git_environment can read its key's
    literal parts; never substituted into a script."""


def _env_level(node) -> tuple:
    """The `env:` of a workflow, job or step: (literal values by name, opaque). A value that is not a SAFE_LITERAL is
    None (unknown); opaque is True when an `env:` is not a mapping (an expression), which may set any name."""
    values, opaque = {}, False
    for env in _values(node, "env"):
        if not isinstance(env, yaml.MappingNode):
            opaque, values = True, {}
            continue
        for key, value in _pairs(env):
            if isinstance(key, yaml.ScalarNode):
                literal = isinstance(value, yaml.ScalarNode) and SAFE_LITERAL.fullmatch(value.value)
                if literal:
                    values[key.value] = value.value
                elif key.value.startswith("GIT_CONFIG_") and isinstance(value, yaml.ScalarNode):
                    values[key.value] = RawValue(value.value)
                else:
                    values[key.value] = None
    return values, opaque


def _merge_env(levels: list) -> dict:
    """The env a step sees, from the least specific level to the most (workflow, job, step): a later level overrides
    an earlier one, and an opaque level hides everything before it."""
    env: dict = {}
    for values, opaque in levels:
        if opaque:
            env = {}
        env.update(values)
    return env


def resolve_script(text: str, env: dict) -> str:
    """A run script with each `${{ env.X }}`, `$X` and `${X}` whose value is a literal in env replaced by it, and every
    other `${{ ... }}` read as a shell variable. A variable the script itself names (assigns, reads, exports, or
    mentions without `$`) is not replaced, since the script may change it; nor is any other variable, which stays
    unknown."""
    def literal(name: str) -> str | None:
        if env.get(name) is None or isinstance(env.get(name), RawValue):
            return None
        if re.search(r"(?<![\w$])(?<!\$\{)%s(?!\w)" % re.escape(name), EXPRESSION.sub("", text)):
            return None
        return env[name]

    text = ENV_EXPRESSION.sub(lambda m: literal(m.group(1)) if literal(m.group(1)) is not None else m.group(0), text)
    text = SHELL_VARIABLE.sub(lambda m: literal(m.group(1) or m.group(2)) if literal(m.group(1) or m.group(2)) is not None
                              else m.group(0), text)
    return _expressions_as_variables(text)


def resolve_input(value: str, env: dict) -> str:
    """An action input with each `${{ env.X }}` whose value is a literal replaced by it."""
    return ENV_EXPRESSION.sub(lambda m: env[m.group(1)] if env.get(m.group(1)) is not None and not isinstance(env.get(m.group(1)), RawValue)
                              else m.group(0), value)


def _scalar_inputs(step, env: dict) -> dict:
    """A step's `with:` inputs that are plain strings, by lowercase name (action inputs ignore case)."""
    inputs = {}
    for with_node in _values(step, "with"):
        for key, value in _pairs(with_node):
            if isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode):
                inputs[key.value.lower()] = resolve_input(value.value, env)
    return inputs


def _action_name(uses: str) -> tuple:
    """(owner/repository, path inside it or None) for a `uses:` reference, lowercase; (None, None) for a local or
    Docker action."""
    reference = uses.strip().split("@", 1)[0].lower()
    parts = reference.split("/")
    if reference.startswith(("./", "docker://")) or len(parts) < 2:
        return None, None
    return "/".join(parts[:2]), "/".join(parts[2:]) or None


def action_targets(uses: str, inputs: dict) -> list:
    """What a `uses:` deploy action deploys to, from DEPLOY_ACTIONS and its `with:` inputs; [] when not a deploy."""
    name, subpath = _action_name(uses)
    spec = DEPLOY_ACTIONS.get(name)
    if spec is None:
        return []
    if "subpaths" in spec and subpath not in spec["subpaths"]:
        return []
    if "host_inputs" in spec:
        targets = []
        for name in spec["host_inputs"]:
            words = _words(inputs.get(name, ""))
            targets.extend(Target(HOST, literal_host(w)) if literal_host(w) else Target(UNKNOWN) for w in words)
        return targets or [Target(UNKNOWN)]
    suffix = Target(SUFFIX, spec["suffix"])
    if "cli" in spec:
        arguments = inputs.get(spec["cli_input"])
        if arguments is None:
            arguments = spec.get("cli_default")
        if arguments is None:
            return []
        targets = []
        for line in _expressions_as_variables(arguments).split("\n"):
            if line.strip():
                targets.extend(deploy_targets("%s %s" % (spec["cli"], line)))
        if not targets and "${{" in arguments:
            targets = [suffix]
        return targets
    hosts = []
    for name in spec.get("domain_inputs", ()):
        hosts.extend(Target(HOST, h) for h in (literal_host(w) for w in _words(inputs.get(name, ""))) if h)
    if hosts and spec.get("domain_replaces"):
        return hosts
    return [suffix] + hosts


def _flag(value: str | None, default: bool) -> bool:
    """A boolean input: true or false as written, its default when absent, and true when it cannot be read."""
    if value is None or not value.strip():
        return default
    word = value.strip().lower()
    if word in ("false", "no", "0", "off"):
        return False
    return True


def literal_branch(value: str) -> str | None:
    """A branch name an input spells out, without refs/heads/; None when it is an expression or a variable."""
    branch = value.strip()
    branch = branch[len("refs/heads/"):] if branch.startswith("refs/heads/") else branch
    return branch if branch and SAFE_LITERAL.fullmatch(branch) else None


def action_pushes(uses: str, inputs: dict) -> list:
    """The branches a `uses:` push action force-pushes to (None: unknown), from PUSH_ACTIONS; [] for any other action
    or a push that is not forced."""
    name, _ = _action_name(uses)
    spec = PUSH_ACTIONS.get(name)
    if spec is None:
        return []
    first, *others = spec["force_inputs"]
    forced = _flag(inputs.get(first), spec["force_default"]) or any(_flag(inputs.get(i), False) for i in others)
    if not forced:
        return []
    value = inputs.get(spec["branch_input"])
    return [spec["default_branch"] if value is None or not value.strip() else literal_branch(value)]


# The shells a run step may name, with the options each may carry; anything else, such as `bash -c '...' _ {0}`, which
# hands the script to another program, is a shell the check does not read. `{0}` is the script file.
POSIX_SHELL_WORD = re.compile(r"[-+][euxvlo]+|[-+][oO]|--(?:noprofile|norc|login|posix)|\{0\}")
SHELL_OPTION_VALUE = re.compile(r"[a-z_]+")
def _readable_shell(shell: str | None) -> bool:
    """Whether a run step's shell is one this check reads: the default (None, bash on a runner that is not Windows),
    or bash or sh with only plain options (`bash --noprofile --norc -eo pipefail {0}`)."""
    if shell is None:
        return True
    if "${{" in shell:
        return False
    try:
        words = shlex.split(shell)
    except ValueError:
        return False
    if not words:
        return False
    name = os.path.basename(words[0]).lower()
    name = name[:-4] if name.endswith(".exe") else name
    if name not in READABLE_SHELLS:
        return False
    rest, index = words[1:], 0
    while index < len(rest):
        word = rest[index]
        if not POSIX_SHELL_WORD.fullmatch(word):
            return False
        if word[0] in "-+" and word[-1] in "oO" and not word.startswith("--"):  # -o, -eo, +O take a value
            index += 1
            if index >= len(rest) or not SHELL_OPTION_VALUE.fullmatch(rest[index]):
                return False
        index += 1
    return True


def _runner_labels(job) -> tuple:
    """(literal labels, unresolved): runs-on as a label, a list, or a mapping's `labels`. unresolved is True for an
    expression (a matrix) or a mapping with no labels (a runner group), whose operating system the check cannot read."""
    labels, unresolved = [], False
    for runs_on in _values(job, "runs-on"):
        nodes = runs_on.value if isinstance(runs_on, yaml.SequenceNode) else [runs_on]
        if isinstance(runs_on, yaml.MappingNode):
            found = _values(runs_on, "labels")
            nodes = [n for f in found for n in (f.value if isinstance(f, yaml.SequenceNode) else [f])]
            unresolved = unresolved or not nodes
        for node in nodes:
            if isinstance(node, yaml.ScalarNode) and "${{" not in node.value:
                labels.append(node.value.lower())
            else:
                unresolved = True
    return labels, unresolved


def _windows_runner(job) -> bool:
    """Whether a job's runs-on names a Windows runner literally, where a step with no shell runs pwsh."""
    return any("windows" in label for label in _runner_labels(job)[0])


# What only PowerShell reads as a command or a comment, in a step that may run in pwsh (a runner the check cannot
# read): such a step is unreadable rather than read with shell rules.
POWERSHELL_ONLY = re.compile(
    r"<#|#>|\binvoke-expression\b|(?<![.\w])iex\b(?![.\w-])(?!\s+-S\b)|\bstart-process\b"
    r"|^\s*&\s+[\"'$\w({]|[;|]\s+&\s+[\"'$\w({]"  # the call operator; not bash's `|&` or a case's `;&`
    r"|^(?:[^`\n]*`[^`\n]*`)*[^`\n]*(?<!`)`\r?$|\s`\r?$",  # PowerShell's continuation: a backtick ending a line,
    # unpaired, or after a space (PowerShell's escapes such as `n make the count unreliable)
    re.IGNORECASE | re.MULTILINE)


def _default_shell(node, inherited: str | None) -> str | None:
    """`defaults.run.shell` of a workflow or job, else the inherited one."""
    for defaults in _values(node, "defaults"):
        for run in _values(defaults, "run"):
            shell = _scalar(run, "shell")
            if shell is not None:
                inherited = shell
    return inherited


def _run_item(key, value, env: dict, git_env: str = "") -> Commands:
    key_line = key.start_mark.line + 1
    text = git_env + resolve_script(value.value, env)  # git_env stays on the first line, so line numbers hold
    if value.style == "|":
        return Commands(value.start_mark.line + 2, text, key_line, exact=True)
    if value.style == ">":
        return Commands(value.start_mark.line + 2, text, key_line)
    return Commands(value.start_mark.line + 1, text, key_line)


def _docker_command(*parts) -> str:
    return " ".join(part for part in parts if part and part.strip())


GIT_CONFIG_NAME = re.compile(r"GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+|PARAMETERS|GLOBAL|SYSTEM)")
GIT_PLACE_NAMES = {"GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR"}


def _git_environment(all_levels: list) -> str:
    """What the `env:` names a step runs with say about git, as an assignment the hook's reader sees at the start of
    each script: GIT_CONFIG_* may make a push a mirror, GIT_DIR and the like point git elsewhere. An `env:` that is an
    expression may set any of them. Read from every level, values or not."""
    names, opaque, merged = set(), False, {}
    for values, level_opaque in all_levels:
        names |= set(values)
        merged.update(values)
        opaque = opaque or level_opaque

    if opaque or any(GIT_CONFIG_NAME.fullmatch(name) and git_config_assignment_harmful(name, _expressions_as_variables(merged[name]) if isinstance(merged.get(name), RawValue) else merged.get(name)) for name in names):
        return "GIT_CONFIG_GLOBAL=from-env; "  # an assignment the reader always counts (git_config_assignment_harmful)
    if names & GIT_PLACE_NAMES:
        return "GIT_DIR=elsewhere; "
    return ""


def _step_items(step, levels: list | None, default_shell: str | None, maybe_pwsh: bool = False,
                all_levels: list | None = None) -> list:
    """A step's commands, targets and pushes. levels None: an earlier step may have changed any variable, so no
    env: value is substituted, not even the step's own (GitHub does not document whether it beats GITHUB_ENV).
    all_levels: the workflow's and job's env:, read for the names git reads (_git_environment) even then."""
    env = {} if levels is None else _merge_env(levels + [_env_level(step)])
    git_env = _git_environment((all_levels or []) + [_env_level(step)])
    shell = _scalar(step, "shell")
    shell = default_shell if shell is None else shell
    inputs = None
    items = []
    for key, value in _pairs(step):
        if not (isinstance(key, yaml.ScalarNode) and isinstance(value, yaml.ScalarNode)):
            continue
        if key.value == "run":
            if _readable_shell(shell) and not (shell is None and maybe_pwsh and POWERSHELL_ONLY.search(value.value)):
                items.append(_run_item(key, value, env, git_env))
            else:
                items.append(UnreadableStep(key.start_mark.line + 1))
        elif key.value == "uses":
            if inputs is None:
                inputs = _scalar_inputs(step, env)
            line = value.start_mark.line + 1
            targets = action_targets(value.value, inputs)
            if targets:
                items.append(Targets(line, tuple(targets)))
            pushes = action_pushes(value.value, inputs)
            if pushes:
                # With GIT_CONFIG_* the action's push may be a mirror: any branch.
                items.append(Pushes(line, tuple(None for _ in pushes) if git_env.startswith("GIT_CONFIG") else tuple(pushes)))
            if value.value.strip().lower().startswith("docker://"):
                command = _docker_command(inputs.get("entrypoint"), inputs.get("args"))
                if command:
                    items.append(Commands(line, git_env + _expressions_as_variables(command), line))
    return items


def _compose(raw: str):
    try:
        return yaml.compose(raw, Loader=yaml.SafeLoader)
    except (yaml.YAMLError, RecursionError, ValueError):
        raise Unreadable() from None


def _runs_code(step) -> bool:
    """Whether a step can run code, and so write GITHUB_ENV (which can be done without naming it): any `run:`, and any
    `uses:` but actions/checkout."""
    if _values(step, "run"):
        return True
    for uses in _values(step, "uses"):
        name = uses.value.strip().lower().split("@", 1)[0] if isinstance(uses, yaml.ScalarNode) else ""
        if name != "actions/checkout":
            return True
    return False


# GitHub's own actions whose action.yml declares no `pre:` (read from each repository's default branch on 2026-11-17).
NO_PRE_ACTIONS = {
    "actions/checkout", "actions/setup-node", "actions/setup-python", "actions/setup-go", "actions/setup-java",
    "actions/setup-dotnet", "actions/cache", "actions/upload-artifact", "actions/download-artifact",
    "actions/github-script", "actions/configure-pages", "actions/upload-pages-artifact", "actions/deploy-pages",
}


def _runs_pre(step) -> bool:
    """Whether a step's action may have a `pre:` (or `pre-entrypoint:`), which runs at the start of the job, before
    the first step: any action from another repository but NO_PRE_ACTIONS. Local actions cannot have one."""
    for uses in _values(step, "uses"):
        name = uses.value.strip().lower() if isinstance(uses, yaml.ScalarNode) else "?"
        if not name.startswith(("./", "docker://")) and name.split("@", 1)[0] not in NO_PRE_ACTIONS:
            return True
    return False


def _steps_items(steps, levels: list, shell: str | None, code_ran: bool = False, maybe_pwsh: bool = False) -> list:
    """The items of one job's (or composite action's) steps, in order: env: values are substituted only until a step
    that can run code, since it may set any variable for the steps after it. An action's `pre:` runs before the
    first step, so a job with one substitutes nothing; code_ran True substitutes nothing either."""
    items = []
    code_ran = code_ran or any(_runs_pre(step) for step in steps.value)
    for step in steps.value:
        items.extend(_step_items(step, None if code_ran else levels, shell, maybe_pwsh, all_levels=levels))
        code_ran = code_ran or _runs_code(step)
    return items


def scan_workflow(raw: str) -> list:
    root = _compose(raw)
    workflow_env = _env_level(root)
    workflow_shell = _default_shell(root, None)
    items = []
    for jobs in _values(root, "jobs"):
        for _, job in _pairs(jobs):
            shell = _default_shell(job, workflow_shell)
            if shell is None and _windows_runner(job):
                shell = "pwsh"  # GitHub's default shell on Windows runners
            maybe_pwsh = shell is None and _runner_labels(job)[1]
            for steps in _values(job, "steps"):
                if isinstance(steps, yaml.SequenceNode):
                    items.extend(_steps_items(steps, [workflow_env, _env_level(job)], shell, maybe_pwsh=maybe_pwsh))
    return items


def _docker_action_items(runs) -> list:
    """A Docker action's entrypoint with its args, and its pre- and post-entrypoints, as commands."""
    items = []
    entrypoint = _scalar(runs, "entrypoint")
    words = []
    for args in _values(runs, "args"):
        if isinstance(args, yaml.SequenceNode):
            words.extend(shlex.quote(_expressions_as_variables(a.value)) for a in args.value if isinstance(a, yaml.ScalarNode))
    command = _docker_command(entrypoint, " ".join(words))
    if command:
        anchor = (_values(runs, "entrypoint") or _values(runs, "args"))[0]
        line = anchor.start_mark.line + 1
        items.append(Commands(line, _expressions_as_variables(command), line))
    for name in ("pre-entrypoint", "post-entrypoint"):
        for value in _values(runs, name):
            if isinstance(value, yaml.ScalarNode) and value.value.strip():
                line = value.start_mark.line + 1
                items.append(Commands(line, _expressions_as_variables(value.value), line))
    return items


def scan_action(raw: str) -> list:
    root = _compose(raw)
    items = []
    for runs in _values(root, "runs"):
        if (_scalar(runs, "using") or "").strip().lower() == "docker":
            items.extend(_docker_action_items(runs))
        for steps in _values(runs, "steps"):
            if isinstance(steps, yaml.SequenceNode):
                # The calling job's earlier steps may already have set any variable through GITHUB_ENV.
                items.extend(_steps_items(steps, [], None, code_ran=True))
    return items


# ----------------------------------------------------------------- JSON and TOML files


def _command_items(raw: str, commands: list) -> list:
    return [Commands(line, text, line) for line, text in ((_value_line(raw, c, 1), c) for c in commands if c.strip())]


def scan_package_json(raw: str) -> list:
    data = _json(raw)
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return []
    return _command_items(raw, [value for value in scripts.values() if isinstance(value, str)])


def scan_vercel_json(raw: str) -> list:
    data = _json(raw)
    if not isinstance(data, dict):
        return []
    items = []
    for key in ("alias", "domains"):
        for value in _strings(data.get(key)):
            host = literal_host(value)
            if host:
                items.append(Targets(_value_line(raw, value, _key_line(raw, key)), (Target(HOST, host),)))
    keys = ("buildCommand", "installCommand", "ignoreCommand", "devCommand")
    commands = [data[key] for key in keys if isinstance(data.get(key), str)]
    return items + _command_items(raw, commands)


def scan_netlify_toml(raw: str) -> list:
    data = _toml(raw)
    tables = [(data.get("build"), ("command", "ignore")), (data.get("dev"), ("command",))]
    contexts = data.get("context")
    if isinstance(contexts, dict):
        tables.extend((context, ("command", "ignore")) for context in contexts.values())
    commands = [table[key] for table, keys in tables if isinstance(table, dict) for key in keys
                if isinstance(table.get(key), str)]
    return _command_items(raw, commands)


def scan_fly_toml(raw: str) -> list:
    data = _toml(raw)
    app = data.get("app")
    if not isinstance(app, str) or not DNS_LABEL.fullmatch(app.strip().lower()):
        return []
    return [Targets(_key_line(raw, "app"), (Target(HOST, app.strip().lower() + ".fly.dev"),))]


def route_targets(pattern: object, zone_name: object) -> list:
    """What a Workers route serves: its pattern's literal host; `*.D` as the wildcard host *.D, and `*D` as D and
    *.D; else its zone_name; else a host the check cannot read."""
    if isinstance(pattern, str):
        host = pattern.strip().lower().split("://", 1)[-1].split("/", 1)[0]
        if re.fullmatch(r".+:[0-9]+", host):
            host = host.rsplit(":", 1)[0]
        if host.startswith("*.") and HOST_NAME.fullmatch(host[2:]):
            return [Target(HOST, host)]
        if host.startswith("*") and HOST_NAME.fullmatch(host[1:]):
            return [Target(HOST, host[1:]), Target(HOST, "*." + host[1:])]
        if HOST_NAME.fullmatch(host):
            return [Target(HOST, host)]
    zone = literal_host(zone_name)
    return [Target(HOST, zone)] if zone else [Target(UNKNOWN)]


def _wrangler_items(raw: str, data: object) -> list:
    """Routes by host, and workers.dev where the Worker is served there: `workers_dev = true`, or no route and
    `workers_dev` not false (wrangler's default). Environments inherit `workers_dev`, not routes. A Pages project
    (`pages_build_output_dir`) deploys under pages.dev instead."""
    if not isinstance(data, dict):
        return []
    if "pages_build_output_dir" in data:
        return [Targets(_key_line(raw, "pages_build_output_dir"), (Target(SUFFIX, "pages.dev"),))]
    tables = [(data, None)]
    if isinstance(data.get("env"), dict):
        tables.extend((env, data.get("workers_dev")) for env in data["env"].values() if isinstance(env, dict))
    routes_line = _key_line(raw, "routes", _key_line(raw, "route"))
    found = re.search(r"[\"']?workers_dev[\"']?[ \t]*[:=][ \t]*true", raw)
    workers_dev_line = raw.count("\n", 0, found.start()) + 1 if found else 1
    items = []
    for table, inherited in tables:
        routes = []
        if "route" in table:
            routes.append(table["route"])
        if isinstance(table.get("routes"), list):
            routes.extend(table["routes"])
        for route in routes:
            pattern, zone = (route.get("pattern"), route.get("zone_name")) if isinstance(route, dict) else (route, None)
            line = _value_line(raw, pattern, routes_line) if isinstance(pattern, str) else routes_line
            items.append(Targets(line, tuple(route_targets(pattern, zone))))
        workers_dev = table.get("workers_dev", inherited)
        if workers_dev is True or (workers_dev is not False and not routes):
            items.append(Targets(workers_dev_line if workers_dev is True else 1, (Target(SUFFIX, "workers.dev"),)))
    return items


def scan_wrangler_toml(raw: str) -> list:
    return _wrangler_items(raw, _toml(raw))


def scan_wrangler_json(raw: str) -> list:
    return _wrangler_items(raw, _json(strip_jsonc(raw)))


def _deploy_hooks(node: object, found: list) -> None:
    """Every predeploy and postdeploy command anywhere in firebase.json, in document order."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("predeploy", "postdeploy"):
                found.extend(_strings(value))
            else:
                _deploy_hooks(value, found)
    elif isinstance(node, list):
        for value in node:
            _deploy_hooks(value, found)


def scan_firebase_json(raw: str) -> list:
    data = _json(raw)
    if not isinstance(data, dict):
        return []
    items = []
    if "hosting" in data:
        hosting = data["hosting"]
        # Each hosting entry deploys to its site's name under web.app; one with no literal site, to the project's
        # default site there.
        for site in hosting if isinstance(hosting, list) else [hosting]:
            name = site.get("site") if isinstance(site, dict) else None
            if isinstance(name, str) and DNS_LABEL.fullmatch(name.strip().lower()):
                target, line = Target(HOST, name.strip().lower() + ".web.app"), _value_line(raw, name, _key_line(raw, "site"))
            else:
                target, line = Target(SUFFIX, "web.app"), _key_line(raw, "hosting")
            items.append(Targets(line, (target,)))
    hooks: list = []
    _deploy_hooks(data, hooks)
    return items + _command_items(raw, hooks)


SCANNERS = {
    "workflow": scan_workflow,
    "action": scan_action,
    "package.json": scan_package_json,
    "vercel.json": scan_vercel_json,
    "netlify.toml": scan_netlify_toml,
    "fly.toml": scan_fly_toml,
    "wrangler.toml": scan_wrangler_toml,
    "wrangler.json": scan_wrangler_json,
    "wrangler.jsonc": scan_wrangler_json,
    "firebase.json": scan_firebase_json,
}


# ----------------------------------------------------------------- deciding


def rules_for_targets(targets, policy: policy_module.Policy, today=None) -> list:
    """The deploy_host rules some target fires: an allow-list, so a target no value of the rule, and no active exception
    to it (as the hook applies them), covers."""
    fired = []
    for rule in policy.rules:
        if rule.kind != "deploy_host":
            continue
        allows = list(rule.values) + [a for e in policy.active_exceptions(rule.id, today) for a in e.allows]
        if any(not any(host_covered(v, t) for v in allows) for t in targets):
            fired.append(rule)
    return fired


def hits_for(item, policy: policy_module.Policy, cwd: str, today=None) -> list:
    """(line, rule) for each rule an item fires. A script is decided as a whole, as the hook decides a command, and
    each rule is pointed at the lines that fire it on their own, or at the script's key when none does. Active
    exceptions without `where` apply as in the hook."""
    if isinstance(item, Targets):
        return [(item.line, rule) for rule in rules_for_targets(item.targets, policy, today)]
    if isinstance(item, Pushes):
        # As the hook reads a push: an unknown branch could be any branch, so it fires every protected_branch rule (no
        # exception covers it); a named branch the rule covers fires unless an active exception allows it.
        def fires(rule, branch) -> bool:
            if not branch:
                return True
            if not any(policy_module.branch_matches(v, branch) for v in rule.values):
                return False
            return not any(policy_module.branch_matches(a, branch)
                           for e in policy.active_exceptions(rule.id, today) for a in e.allows)
        return [(item.line, rule) for rule in policy.rules
                if rule.kind == "protected_branch" and any(fires(rule, b) for b in item.branches)]
    text = _expressions_as_variables(item.text)
    # matched_rules gives (rule, exception ids); a rule fires when no active exception covered all it matched.
    # Only the kinds this check documents: package_registry and cloud_account rules are not applied here yet.
    fired = [rule for rule, excepted_by in matched_rules(text, cwd, policy, today=today, branch_known=False)
             if not excepted_by and rule.kind in BOTH_KINDS]
    if not fired:
        return []
    ids = {rule.id for rule in fired}
    hits, placed = [], set()
    if item.exact:
        for line, logical in logical_lines(text, item.start_line):
            for rule in [r for r, excepted_by in matched_rules(logical, cwd, policy, today=today, branch_known=False) if not excepted_by]:
                if rule.id in ids:
                    hits.append((line, rule))
                    placed.add(rule.id)
    hits.extend((item.key_line, rule) for rule in fired if rule.id not in placed)
    return hits


def effective_mode(rule, policy: policy_module.Policy, today=None) -> str:
    return "monitor" if policy.expired(today) else rule.mode


def rule_message(rule, mode: str, policy: policy_module.Policy, expired: bool = False) -> str:
    use = " Use instead: %s." % rule.use_instead_text if rule.use_instead_text else ""
    if mode == "block":
        tail = " The rule is in block mode, so the check fails."
    elif mode == "ask":
        tail = (" The rule is in ask mode: the company asks a person to confirm this, and nobody can be asked in a "
                "pull-request check, so the check fails.")
    elif expired:
        tail = (" The company rules expired on %s, so every rule acts in monitor until they are renewed; the check "
                "passes." % policy.expires_on.isoformat())
    else:
        tail = " The rule is in monitor mode, so the check passes."
    return "Catpilot company rule `%s`: %s.%s%s" % (rule.id, WHAT.get(rule.kind, "this file matches a company rule"), use, tail)


def unreadable_finding(path: str, kind_of_file: str, policy: policy_module.Policy, today=None, line: int = 1,
                       text: str = UNREADABLE) -> Finding:
    """A fixed-text finding for a file, or a run step, the check cannot read: an error when a rule that it could
    reveal is in ask or block, else a warning."""
    relevant = RELEVANT_KINDS.get(kind_of_file, BOTH_KINDS)
    strict = [r for r in policy.rules if r.kind in relevant and effective_mode(r, policy, today) in ("ask", "block")]
    if strict:
        return Finding(path, line, "error", text + " A company rule in ask or block mode applies to it, so the check fails.")
    return Finding(path, line, "warning", text + " Every company rule that applies to it is in monitor mode, so the check passes.")


def check_file(path: str, raw: bytes | None, policy: policy_module.Policy, cwd: str, today=None) -> list:
    """The findings for one scanned file. raw None means the file could not be read."""
    kind_of_file = file_type(path)
    try:
        if raw is None:
            raise Unreadable()
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise Unreadable() from None
        items = SCANNERS[kind_of_file](text)
    except Exception:  # Unreadable, or a shape no scanner expected: fail as unreadable, never as clean
        return [unreadable_finding(path, kind_of_file, policy, today)]
    expired = policy.expired(today)
    findings, seen = [], set()
    for item in items:
        if isinstance(item, UnreadableStep):
            if (item.line, None) not in seen:
                seen.add((item.line, None))
                findings.append(unreadable_finding(path, kind_of_file, policy, today, item.line, UNREADABLE_STEP))
            continue
        for line, rule in hits_for(item, policy, cwd, today):
            if (line, rule.id) in seen:
                continue
            seen.add((line, rule.id))
            mode = effective_mode(rule, policy, today)
            level = "warning" if mode == "monitor" else "error"
            findings.append(Finding(path, line, level, rule_message(rule, mode, policy, expired), rule.id))
    return findings


# ----------------------------------------------------------------- files and the policy


def read_policy(path: str) -> policy_module.Policy:
    """The compiled policy. No ownership check (a CI runner writes it), but a symbolic link, anything but a regular
    file, and anything catpilot_guard.policy.parse refuses are refused. Raises UsageError with fixed text."""
    if os.path.islink(path):
        raise UsageError("the policy is a symbolic link; give the file itself")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise UsageError("the policy file does not exist") from None
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise UsageError("the policy is a symbolic link; give the file itself") from None
        raise UsageError("the policy file could not be opened") from None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise UsageError("the policy is not a regular file")
        chunks, size = [], 0
        while size <= policy_module.MAX_POLICY_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    except OSError:
        raise UsageError("the policy file could not be read") from None
    finally:
        os.close(fd)
    try:
        return policy_module.parse(b"".join(chunks))
    except policy_module.PolicyError:
        raise UsageError(
            "the policy is not a compiled Catpilot company policy (malformed); write it with "
            "`python tools/validate_overlay.py compile`") from None


def read_repo_file(repo_real: str, path: str) -> bytes | None:
    """A file's bytes, or None when it cannot be read: a symbolic link anywhere in its path inside the repository,
    not a regular file, or larger than MAX_FILE_BYTES."""
    full = os.path.join(repo_real, *PurePosixPath(path).parts)
    if os.path.realpath(full) != os.path.normpath(full):
        return None
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(full, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = os.read(fd, MAX_FILE_BYTES + 1)
        while data and len(data) <= MAX_FILE_BYTES:
            chunk = os.read(fd, MAX_FILE_BYTES + 1 - len(data))
            if not chunk:
                break
            data += chunk
        return None if len(data) > MAX_FILE_BYTES else data
    except OSError:
        return None
    finally:
        os.close(fd)


def changed_files(repo: str, base: str) -> list:
    """Repository-relative paths added or changed in base...HEAD (a rename counts as an addition)."""
    if not base or base.startswith("-"):
        raise UsageError("--base must name a commit or branch")
    command = [
        "git", "-C", repo, "-c", "core.quotepath=off", "diff", "--name-only", "-z", "--no-renames", "--no-ext-diff",
        "--no-textconv", "--diff-filter=ACMRT", "%s...HEAD" % base, "--",
    ]
    try:
        proc = subprocess.run(command, capture_output=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise UsageError("git could not be run to list the changed files") from None
    if proc.returncode != 0:
        raise UsageError("git could not list the files changed since --base (is it fetched, with enough history for "
                         "a merge base?)")
    return [name for name in proc.stdout.decode("utf-8", "surrogateescape").split("\0") if name]


def named_files(repo: str, files: list) -> list:
    """--files as repository-relative POSIX paths. Raises UsageError for one outside the repository or missing."""
    roots = (os.path.abspath(repo), os.path.realpath(repo))
    out = []
    for name in files:
        if os.path.isabs(name):
            candidates = [os.path.relpath(os.path.abspath(name), root) for root in roots]
            relative = next((c for c in candidates if not c.startswith("..")), None)
        else:
            relative = os.path.normpath(name)
        if relative is None or relative.startswith("..") or os.path.isabs(relative) or relative == ".":
            raise UsageError("--files names a path outside --repo")
        if not os.path.lexists(os.path.join(repo, relative)):
            raise UsageError("--files names a path that does not exist in --repo")
        out.append(PurePosixPath(*Path(relative).parts).as_posix())
    return out


def run_check(policy: policy_module.Policy, repo: str, paths: list, today=None) -> Result:
    result = Result(changed=len(paths))
    repo_real = os.path.realpath(repo)
    # The hook reads the checked-out branch for a bare force push; the branch a workflow runs on is not the
    # checkout's, so commands are matched from an empty directory that is no repository.
    with tempfile.TemporaryDirectory(prefix="catpilot-pr-check.") as cwd:
        for path in dict.fromkeys(paths):
            if file_type(path) is None:
                continue
            result.scanned += 1
            result.findings.extend(check_file(path, read_repo_file(repo_real, path), policy, cwd, today))
    return result


# ----------------------------------------------------------------- output


def _clean(text: str) -> str:
    """Text with control characters made visible, so a file name cannot start a new output line."""
    return "".join(ch if ch.isprintable() else "\\x%02x" % ord(ch) if ord(ch) < 256 else "\\u%04x" % ord(ch) for ch in text)


def _escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape_data(text).replace(":", "%3A").replace(",", "%2C")


def render(result: Result, policy: policy_module.Policy, fmt: str, today=None) -> list:
    lines = []
    expired = policy.expired(today)
    notice = ("The company rules expired on %s: every rule acts in monitor until they are renewed and recompiled, so "
              "nothing fails the check." % policy.expires_on.isoformat())
    if expired:
        lines.append("::warning title=Catpilot company rules expired::%s" % notice if fmt == "github" else "warning: " + notice)
    order = sorted(result.findings, key=lambda f: (f.path, f.line, f.level != "error", f.rule_id or ""))
    for finding in order:
        if fmt == "github":
            title = "Catpilot company rule" if finding.rule_id else "Catpilot pull-request check"
            lines.append("::%s file=%s,line=%d,title=%s::%s" % (
                finding.level, _escape_property(_clean(finding.path)), finding.line, title, _escape_data(finding.message)))
        else:
            lines.append("%s:%d: %s: %s" % (_clean(finding.path), finding.line, finding.level, finding.message))
    errors = sum(1 for f in result.findings if f.level == "error")
    warnings = len(result.findings) - errors
    lines.append(
        "Catpilot pull-request check: %d of %d changed file%s scanned; %d error%s, %d warning%s. The check %s." % (
            result.scanned, result.changed, "" if result.changed == 1 else "s", errors, "" if errors == 1 else "s",
            warnings, "" if warnings == 1 else "s", "fails" if result.failed else "passes"))
    return lines


def parse_args(argv: list):
    parser = argparse.ArgumentParser(
        prog="pr_check.py",
        description="Check the files a pull request adds or changes against the company's compiled enforcement "
        "rules. Annotations name the rule, never a listed value, a command or a host.",
    )
    parser.add_argument("--policy", required=True, help="the compiled policy JSON (tools/validate_overlay.py compile)")
    parser.add_argument("--repo", default=".", help="the checked-out repository under review (default: .)")
    which = parser.add_mutually_exclusive_group(required=True)
    which.add_argument("--base", help="scan the files added or changed in BASE...HEAD")
    which.add_argument("--files", nargs="+", help="scan these files (relative to --repo, or absolute inside it)")
    parser.add_argument("--format", choices=("github", "text"), default="text",
                        help="github: workflow-command annotations; text: file:line lines (default)")
    return parser.parse_args(argv)


def inside(path: str, directory: str) -> bool:
    real, base = os.path.realpath(path), os.path.realpath(directory)
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def main(argv: list | None = None) -> int:
    args = parse_args(list(sys.argv[1:] if argv is None else argv))
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    try:
        if not os.path.isdir(args.repo):
            raise UsageError("--repo is not a directory")
        if inside(args.policy, args.repo):
            raise UsageError("the policy is inside --repo; it must never come from the repository under review")
        policy = read_policy(args.policy)
        paths = changed_files(args.repo, args.base) if args.base is not None else named_files(args.repo, args.files)
        result = run_check(policy, args.repo, paths)
        for line in render(result, policy, args.format):
            print(line)
    except UsageError as exc:
        print("pr_check: %s" % exc, file=sys.stderr)
        return 2
    except Exception as exc:  # never a traceback: an exception's message could carry a value from a file
        print("pr_check: internal error (%s)" % type(exc).__name__, file=sys.stderr)
        return 2
    return 1 if result.failed else 0


if __name__ == "__main__":
    sys.exit(main())
