"""Catpilot PreToolUse hook for Claude Code: block high-blast-radius destructive CLI commands.

hooks/claude-code/pretooluse-destructive-ops.py runs this module's main(); hooks/harness/destructive_gate.py
calls decide(). It needs no other check module; it imports catpilot_guard/evidence.py only to write evidence.

Scope, stated exactly:
  - Runs only for the Bash tool (the matcher in settings selects it).
  - Splits the proposed command into simple commands the way a shell would
    (pipes, ;, &&, ||, subshells, and each line of a multi-line command), looks through sudo/env/time-style wrappers
    (also timeout, gtimeout, stdbuf, ionice, setsid, unbuffer) and a shell's
    command string (`bash -c "..."`, `bash -lc`, `sh -ec`, `bash -o pipefail -c`,
    `bash --login -c`), and checks each one against deterministic signatures
    from the cloud-cli-safety, database-safety, and local-cli-safety components
    of catpilot-security-core:
      * partial-resource replacements that wipe unspecified fields or env vars
        (az containerapp update --yaml / --replace-env-vars, aws lambda
        update-function-configuration --environment Variables={...}, gcloud run
        services update --set-env-vars, gcloud projects set-iam-policy)
      * unconfirmed cloud / IaC / Kubernetes mass deletion (terraform or tofu
        apply or destroy with -auto-approve, also after global options such as
        -chdir=DIR, kubectl delete of a namespace or with --all
        unless --dry-run=client|server, aws s3 rb --force, aws s3 rm --recursive
        without --dryrun, gsutil rm -r, gcloud app versions delete --all --quiet,
        gcloud run services delete --quiet)
      * irreversible local or history wipes: recursive rm of /, a top-level
        system directory, the home directory (~, $HOME, /Users/<name>,
        /home/<name>, or the running user's home by its absolute path), a
        credential directory (~/.ssh, ~/.aws, ..., also under those absolute
        home paths), or a bare variable that would expand to one of
        those when unset ("$TARGET", $TARGET/, ${TARGET}/*); chmod -R 777;
        dd to a raw block device; a force push (--force, -f, --force-with-lease,
        or a +refspec) or a deletion aimed at main, master, trunk, production,
        prod, staging, develop, or release/*, including a bare `git push -f`
        while the checked-out branch is one of those (unknown, so blocked, after
        a command in the line that may change it: commands_with_branch_context);
        git push --mirror, --all or --branches with a force or --prune, a forced
        or pruned refspec pattern, a forced matching refspec, a push given
        -c remote.<name>.mirror or GIT_CONFIG_*, and a bare push given
        -c remote.<name>.push (an option's value, as in -o ci.skip, is not read
        as the remote)
      * unconfirmed database or cache wipes: `prisma db push --accept-data-loss`,
        `prisma migrate reset --force`, `rails`/`rake` `db:drop`/`db:reset`/
        `db:schema:load`/`db:structure:load`, Django `flush --noinput`,
        `dropdb`, `redis-cli FLUSHALL`/`FLUSHDB`, and a `psql`/`mysql`/`mariadb`/
        `sqlite3`/`sqlcmd` command whose command line (flags, arguments, heredoc,
        here-string, or piped text) contains `DROP DATABASE`, `DROP SCHEMA`,
        `DROP TABLE`, `TRUNCATE`, or a `DELETE FROM` with no `WHERE` clause;
        also through `docker`/`podman exec`, `docker compose exec`/`run`,
        `kubectl exec --`, `railway run`, and package runners. SQL in a file
        (`-f`, `<`) is not read
      * direct credential exfiltration pipes (cat ~/.ssh/... | curl, env | curl)
        and pipe-to-shell with sudo
  - On a match, returns a PreToolUse "deny" decision with a plain-language
    reason and the safer alternative. Never echoes the command text.
  - On anything else, returns an empty decision so the host's own permission
    rules apply unchanged. It never returns "allow".
  - Fails closed: malformed or oversized input, or any unexpected error, exits 2
    (the host treats that as a blocking error).

What it is not: an adversarial control. It catches the accidental destructive
command an agent proposes; a command deliberately obfuscated (eval, base64,
variables holding the verb) can pass. Ordinary scoped work is not blocked:
removing a subdirectory of your home, a build directory, or force-pushing a
feature branch.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import shlex
import sys
from pathlib import Path

from . import decision_for_host, event_for_host, hook_host, write_decision, write_reason

MAX_INPUT_BYTES = 1_048_576

# --- whole-command signatures (cloud and infrastructure CLIs) -------------------------------
# (label, compiled_pattern, safe_alternative_note)
DESTRUCTIVE_PATTERNS = [
    (
        "az containerapp partial-YAML or replace-env-vars reset",
        re.compile(r"\baz\s+containerapp\s+update\b.*?\s(?:--yaml|--replace-env-vars)\b", re.IGNORECASE | re.DOTALL),
        "Query current state with `az containerapp show` first and use `--set-env-vars` (which merges) or include the full resource specification.",
    ),
    (
        "aws lambda environment full-map replacement",
        re.compile(r"\baws\s+lambda\s+update-function-configuration\b.*?\s--environment\s+[\"']?Variables=\{", re.IGNORECASE | re.DOTALL),
        "Query existing variables with `aws lambda get-function-configuration`, merge them in a JSON file, and pass the complete merged map from that file.",
    ),
    (
        "gcloud projects set-iam-policy full-binding replacement",
        re.compile(r"\bgcloud\s+projects\s+set-iam-policy\b", re.IGNORECASE),
        "Use `gcloud projects add-iam-policy-binding` so existing IAM bindings are preserved.",
    ),
    (
        "gcloud run services update --set-env-vars replacement",
        re.compile(r"\bgcloud\s+run\s+services\s+update\b.*?\s--set-env-vars\b", re.IGNORECASE | re.DOTALL),
        "Use `gcloud run services update --update-env-vars` so existing environment variables are preserved.",
    ),
    (
        "gcloud quiet service or version deletion",
        re.compile(r"\bgcloud\s+(?:app\s+versions\s+delete\s+--all|run\s+services\s+delete\b).*?\s--quiet\b", re.IGNORECASE | re.DOTALL),
        "Inspect existing revisions/versions first and require interactive confirmation before deleting.",
    ),
    (
        "terraform auto-approve apply or destroy",
        # terraform or OpenTofu (`tofu`, same CLI), with global options such as -chdir=DIR before the subcommand.
        re.compile(r"\b(?:terraform|tofu)(?:\s+-\S+)*\s+(?:apply|destroy)\b.*?\s--?auto-approve\b(?!=false)", re.IGNORECASE | re.DOTALL),
        "Run `terraform plan -out=tfplan`, show the plan to the user, and apply the reviewed plan without `-auto-approve`.",
    ),
    (
        "aws s3 recursive delete or force bucket removal",
        re.compile(
            r"\baws\s+s3\s+(?:rb\b.*?\s--force\b|rm\b.*?\s--recursive\b(?!.*--dryrun))",
            re.IGNORECASE | re.DOTALL,
        ),
        "List bucket contents with `aws s3 ls` and run with `--dryrun` before any recursive delete.",
    ),
    (
        "gsutil recursive bucket delete",
        re.compile(r"\bgsutil\s+(?:-m\s+)?rm\s+-(?:r|R|rf|fr)\s+gs://", re.IGNORECASE),
        "Inventory objects with `gsutil ls` and confirm with the user before deleting.",
    ),
    (
        "recursive chmod 777 or recursive chmod on credential directories",
        re.compile(
            r"\bchmod\s+-R\s+(?:777\b|[0-7]{3,4}\s+(?:~|\$HOME)(?:/\.(?:ssh|aws|openclaw|config/gcloud|kube|gnupg|docker))?\b)",
        ),
        "Scope `chmod` to specific files and use owner-only permissions (`700` for directories, `600` for key/credential files).",
    ),
    (
        "raw block-device overwrite via dd",
        re.compile(r"\bdd\b.*?\bof=/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+|rdisk\d+)\b", re.IGNORECASE | re.DOTALL),
        "Never write directly to raw block devices from an agent session.",
    ),
    (
        "credential or environment exfiltration pipe to network client",
        re.compile(
            r"(?:\bcat\s+[^\n|;]*(?:\.ssh/|\.aws/|\.openclaw/|\.config/gcloud/|\.kube/|\.gnupg/|\.netrc)[^\n|;]*|\b(?:env|printenv)\b)\s*\|\s*(?:curl|wget|http|xh|nc|socat)\b",
            re.IGNORECASE,
        ),
        "Never pipe local credentials, SSH keys, or environment dumps into an outbound network request.",
    ),
    (
        "pipe-to-shell with sudo",
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*sudo\s+(?:bash|sh|zsh)\b", re.IGNORECASE),
        "Download the script to a temporary file, inspect its contents and SHA-256 digest, and run only after review.",
    ),
]

# --- per-simple-command analysis (rm, git push, kubectl delete, db/migration) ---------------
RM_LABEL = "recursive rm of root, a system directory, home, a credential directory, or a bare variable"
RM_NOTE = (
    "Remove a specific subdirectory by name (for example `rm -rf ./build` or `rm -rf \"$BUILD_DIR/dist\"`), "
    "never a bare variable, the home directory, a credential directory, or a system directory."
)
GIT_LABEL = "git force-push, mirror, or deletion aimed at a protected branch"
GIT_NOTE = (
    "Never force-push to or delete `main`, `master`, `trunk`, `production`, `prod`, `staging`, `develop`, or "
    "`release/*`; push a feature branch (`--force-with-lease` is fine there) and merge through review."
)
KUBECTL_LABEL = "kubectl delete of a namespace or with --all"
KUBECTL_NOTE = "Preview with `--dry-run=client` and get explicit user confirmation naming the target namespace and resources."

PROTECTED_BRANCH = re.compile(r"^(?:main|master|trunk|production|prod|staging|develop|release/.+)$", re.IGNORECASE)
# The same list as names and prefixes, for a destination with shell expansions in it (pattern_may_match).
PROTECTED_NAMES = ("main", "master", "trunk", "production", "prod", "staging", "develop")
PROTECTED_PREFIXES = ("release/",)
HOME = r"(?:~|\$HOME|\$\{HOME\})"
CREDENTIAL_DIR = r"\.(?:ssh|aws|gnupg|kube|docker|openclaw|config(?:/gcloud)?)"
ABSOLUTE_HOME = r"/+(?:Users|home)/+[^/]+"  # /Users/<name>, /home/<name>
RM_DANGEROUS_TARGET = re.compile(
    r"^(?:"
    r"/+\*?"  # / and /*
    r"|/+(?:bin|boot|dev|etc|home|lib|lib64|opt|private|proc|root|sbin|srv|sys|usr|var|Users|System|Library|Applications|Volumes)/*\*?"
    rf"|{HOME}/*\*?"  # the home directory itself
    rf"|{HOME}/+{CREDENTIAL_DIR}/*\*?"  # credential directories
    rf"|{ABSOLUTE_HOME}/*\*?"  # a home directory by absolute path
    rf"|{ABSOLUTE_HOME}/+{CREDENTIAL_DIR}/*\*?"  # its credential directories
    r"|\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})/*\*?"  # a bare variable: unset expands to / or ""
    r")$"
)
WRAPPERS = {"sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice", "xargs", "caffeinate"}
# Wrappers that run another command, each with the options that take a separate value and the number of
# positional arguments that come before the command (timeout's DURATION).
TIMEOUT_VALUE_OPTIONS = {"-s", "--signal", "-k", "--kill-after"}
WRAPPER_SPECS = {
    "timeout": (TIMEOUT_VALUE_OPTIONS, 1),
    "gtimeout": (TIMEOUT_VALUE_OPTIONS, 1),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "ionice": ({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}, 0),
    "setsid": (set(), 0),
    "unbuffer": (set(), 0),
}
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Shell options that take a separate value (`bash -o pipefail -c ...`, `bash --rcfile FILE -c ...`).
SHELL_VALUE_OPTIONS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
KUBECTL_VALUE_FLAGS = {"-n", "--namespace", "-l", "--selector", "-f", "--filename", "-o", "--output", "--context",
                       "--cluster", "--kubeconfig", "--field-selector", "--grace-period", "--timeout", "-k", "--kustomize",
                       "-s", "--server", "--user", "--token", "--as"}
SEPARATORS = {";", "&", "&&", "|", "||", "|&", "(", ")", "\n"}


# A backslash-newline continues a line only when the backslash is not itself escaped: an odd number of backslashes.
LINE_CONTINUATION = re.compile(r"(?<!\\)((?:\\\\)*)\\\n")
SHELL_WORD_BREAKS = set(" \t\r\n;&|()")


def _strip_comments(command: str) -> str:
    """The command without its comments: an unquoted `#` at the start of a word, up to the end of its line. A
    shell ignores them, and a quote character inside one (`# what's left`) must not open a quote that hides the
    lines after it. The newline that ends a comment is kept."""
    out, i, quote, n = [], 0, None, len(command)
    while i < n:
        c = command[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
        elif c == "\\" and i + 1 < n:
            out.append(command[i:i + 2])
            i += 2
            continue
        elif quote == '"':
            out.append(c)
            if c == '"':
                quote = None
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "#" and (i == 0 or command[i - 1] in SHELL_WORD_BREAKS):
            end = command.find("\n", i)
            i = n if end == -1 else end
            continue
        else:
            out.append(c)
        i += 1
    return "".join(out)


def _tokens(command: str) -> list[str]:
    """The command's words and operators. An unquoted newline separates commands, as in a shell, a backslash-newline
    joins two lines into one, and comments are dropped, so every line of a multi-line command is read."""
    command = _strip_comments(LINE_CONTINUATION.sub(r"\1", command))
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        # Unbalanced quotes: fall back to whitespace splitting with quotes stripped.
        return [t.strip("\"'") for t in command.replace("\n", " ; ").replace(";", " ; ").replace("&&", " && ").replace("|", " | ").split()]


def _simple_commands(command: str, depth: int = 0):
    """Yield argv lists for each simple command, with wrappers removed and `sh -c` bodies expanded."""
    current: list[str] = []
    for token in _tokens(command) + [";"]:
        if token in SEPARATORS or set(token) <= set(";&|()\n"):
            if current:
                yield from _unwrap(current, depth)
            current = []
        else:
            current.append(token)


def _strip_wrappers(argv: list[str]) -> list[str]:
    """Drop leading assignments and wrapper commands (sudo, env, timeout 60, ...) with their options."""
    while True:
        while argv and ASSIGNMENT.match(argv[0]):
            argv = argv[1:]
        if not argv:
            return argv
        name = os.path.basename(argv[0].lstrip("`"))
        if name in WRAPPERS:
            argv = argv[1:]
            while argv and (argv[0].startswith("-") or ASSIGNMENT.match(argv[0])):
                takes_value = argv[0] in ("-u", "-g", "-n", "-C")
                argv = argv[2:] if takes_value else argv[1:]
        elif name in WRAPPER_SPECS:
            value_options, positionals = WRAPPER_SPECS[name]
            argv = _skip_options(argv[1:], value_options)[positionals:]
        else:
            return argv


def _shell_command_string(args: list[str]) -> str | None:
    """The command string a shell is given with -c (`bash -lc`, `sh -ec`, `bash -o pipefail -c`), or None.

    `args` are the shell's arguments without its name. Options come first; -c may sit in a cluster with other
    single-letter options, and -o/+o/-O/+O (also as the last letter of a cluster) and --rcfile/--init-file take
    a value. The command string is the first argument after the options, or after `--`.
    """
    index, has_c = 0, False
    while index < len(args):
        arg = args[index]
        if arg == "--":
            index += 1
            break
        if arg in SHELL_VALUE_OPTIONS:
            index += 2
        elif arg.startswith("--"):
            index += 1
        elif len(arg) > 1 and arg[0] in "-+":
            has_c = has_c or (arg[0] == "-" and "c" in arg[1:])
            index += 2 if arg[-1] in "oO" else 1
        else:
            break
    return args[index] if has_c and index < len(args) else None


def _unwrap(argv: list[str], depth: int):
    argv = _strip_wrappers(argv)
    if not argv:
        return
    name = os.path.basename(argv[0].lstrip("`"))
    if name in SHELLS and depth < 3:
        script = _shell_command_string(argv[1:])
        if script is not None:
            yield from _simple_commands(script, depth + 1)
            return
    yield [name] + argv[1:]


def _running_users_home_target(target: str) -> bool:
    """True when target is the running user's home directory by its absolute path, or a credential directory in it."""
    home = os.path.normpath(os.path.expanduser("~"))
    if not os.path.isabs(home) or home in ("/", "//"):
        return False
    parts = [re.escape(part) for part in home.strip("/").split("/") if part]
    pattern = r"^/+" + "/+".join(parts) + rf"(?:/+{CREDENTIAL_DIR})?/*\*?$"
    return re.match(pattern, target) is not None


def _rm_finding(args: list[str]) -> bool:
    recursive, options_done, targets = False, False, []
    for arg in args:
        if not options_done and arg == "--":
            options_done = True
        elif not options_done and arg.startswith("--"):
            recursive = recursive or arg == "--recursive"
        elif not options_done and arg.startswith("-") and len(arg) > 1:
            recursive = recursive or "r" in arg[1:].lower()
        else:
            targets.append(arg)
    return recursive and any(RM_DANGEROUS_TARGET.match(t) or _running_users_home_target(t) for t in targets)


def _git_dir(start: Path) -> Path | None:
    for directory in [start, *start.parents]:
        dot_git = directory / ".git"
        if dot_git.is_dir():
            return dot_git
        if dot_git.is_file():
            text = dot_git.read_text(encoding="utf-8", errors="replace").strip()
            if text.startswith("gitdir:"):
                path = Path(text.split(":", 1)[1].strip())
                return path if path.is_absolute() else (directory / path).resolve()
    return None


def current_branch(cwd: str, git_dir_path: str | None = None) -> str | None:
    """The checked-out branch for cwd, read from .git/HEAD (or from git_dir_path/HEAD, git's --git-dir); None when
    detached or not a repository."""
    try:
        if git_dir_path is not None:
            git_dir = Path(cwd).expanduser().joinpath(os.path.expanduser(git_dir_path)).resolve()
        else:
            git_dir = _git_dir(Path(cwd).expanduser().resolve())
        if git_dir is None:
            return None
        head = (git_dir / "HEAD").read_text(encoding="utf-8", errors="replace").strip()
        return head[len("ref: refs/heads/"):] if head.startswith("ref: refs/heads/") else None
    except OSError:
        return None


BRACED_EXPANSION = re.compile(r"\$\{[^}]*\}")
# A shell expansion inside a word, read as a glob's `*`: ${...}, $(...), $NAME, $1, $@ and the like, a backtick span,
# and a lone `$` (an unquoted substitution the shell-word reader split).
EXPANSION = re.compile(r"\$\{[^}]*\}|\$\([^)]*\)|\$[A-Za-z_][A-Za-z0-9_]*|\$[0-9@*#?$!-]|`[^`]*`?|\$")


class BranchPattern(str):
    """A force-pushed or deleted destination with shell expansions in it, as a glob in which each expansion is `*`
    (`release/$V` is `release/*`, `v$VERSION` is `v*`): it matters only if it could name a protected branch."""


def pattern_may_match(pattern: str, names, prefixes) -> bool:
    """Whether a BranchPattern could name one of the branches, ignoring case: one of names, or a branch under one of
    prefixes (each ending in `/`). git also reads `heads/X` and `refs/heads/X` as X, so those spellings count."""
    glob = pattern.casefold()
    for name in names:
        for spelling in (name, "heads/" + name, "refs/heads/" + name):
            if fnmatch.fnmatchcase(spelling.casefold(), glob):
                return True
    head = glob.split("*", 1)[0]
    for prefix in prefixes:
        for spelling in (prefix, "heads/" + prefix, "refs/heads/" + prefix):
            spelling = spelling.casefold()
            if spelling.startswith(head) or (head.startswith(spelling) and ("*" in glob or len(head) > len(spelling))):
                return True
    return False
# A destination that is the shell asking git for the checked-out branch, read as that branch: `"$(git branch
# --show-current)"`, `$(git rev-parse --abbrev-ref HEAD)`, `$(git symbolic-ref --short HEAD)`, or one in backticks.
CURRENT_BRANCH_SUBSTITUTION = re.compile(
    r"(?:\$\(|`)\s*git\s+(?:branch\s+--show-current|rev-parse\s+--abbrev-ref\s+HEAD|symbolic-ref\s+(?:-q\s+)?--short\s+HEAD)"
    r"\s*(?:\)|`)"
)
# git push options that take their value as the next argument.
PUSH_VALUE_OPTIONS = {"--push-option", "--repo", "--receive-pack", "--exec", "--recurse-submodules"}
# git's own options, before the subcommand, that take their value as the next argument. -C and --git-dir also say
# which repository's HEAD a bare push uses.
GIT_VALUE_OPTIONS = {"-c", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--list-cmds"}


def git_push_rewrites(args: list[str], cwd: str | None) -> tuple[bool, list[str | None]] | None:
    """What a `git` command's push would rewrite or delete: None when it is not a push, else (mirror, branches).

    `args` are git's arguments without its name. mirror is True when the push can rewrite or delete every branch:
    `--mirror`; `--all` or `--branches` with a force or `--prune`; and a refspec whose destination is a pattern
    (`refs/heads/*`) with a force, a `+`, `--prune` or `--delete`. Options that take a value (`-o`/`--push-option`,
    `--repo`, `--receive-pack`, `--exec`, `--recurse-submodules`) take it, so the value is not read as the remote, and
    git's own value options before `push` (`-C`, `-c`, `--git-dir`, `--work-tree`, `--namespace`, ...) take theirs;
    `-C` and `--git-dir` also say whose HEAD a bare push uses.
    branches are the destination branches a force push (--force, -f, --force-with-lease, --force-if-includes or a
    +refspec), a deletion (--delete, -d, or an empty source `:branch`) aims at, with refs/heads/ stripped and HEAD
    read as the checked-out branch ("" when that is unknown). A destination the command does not spell out, one
    holding a shell variable or a command substitution (`$BRANCH`, `"${TARGET}"`, a backtick), is None: unknown,
    except a substitution that asks git for the checked-out branch (CURRENT_BRANCH_SUBSTITUTION), read as the branch
    checked out in cwd (None when detached). `@` is HEAD, and `heads/X` is X, as git resolves them. A word that
    starts with a variable and is followed by a literal word, with two literal words besides (`git push $F origin
    main`, `git push origin $F main`; F may be --force), counts as a force; a trailing one (`git push origin main
    "$TAG"`) does not. A matching refspec (`:`) with a force or a `+` rewrites every branch both sides have, and so
    does a bare push given `-c remote.<name>.push=...`, or `-c push.default=matching` with a force. A bare force push,
    with no refspec, adds the checked-out branch, or None when it is detached or there is no repository.
    A `$` word before the subcommand, `-C` or `--git-dir` without a known directory, and a bare push given `-c
    push.default=upstream` or a `branch.*` setting make the checked-out branch unknown; `-c remote.<name>.mirror`
    (or `--config-env` for it) makes a mirror. cwd None means the checked-out branch is unknown, and
    CONFIGURED_BY_ENVIRONMENT (a line assigning GIT_CONFIG_*) makes any push a mirror (see
    commands_with_branch_context). The built-in check (_git_finding) treats None as protected, and the company-rules hook
    (catpilot_guard/company_rules.py) fires every protected_branch rule on it; both read pushes this way.
    """
    if cwd is CONFIGURED_BY_ENVIRONMENT:
        cwd = None  # GIT_CONFIG_* may set remote.<name>.mirror: any push may rewrite every branch
        environment_config = True
    else:
        environment_config = False
    repo = cwd
    index, git_dir_path, configs, unknown = 0, None, [], cwd is None
    while index < len(args) and (args[index].startswith("-") or args[index].startswith(("$", "`"))):
        arg = args[index]
        if arg.startswith(("$", "`")):
            unknown = True  # a variable before the subcommand may hold any option (`git $OPTS push`, OPTS=-C ../x)
            index += 1
        elif arg == "-C" and index + 1 < len(args):
            repo = os.path.join(repo, os.path.expanduser(args[index + 1])) if repo is not None else None
            unknown = unknown or repo is None
            index += 2
        elif arg == "-c" and index + 1 < len(args):
            configs.append(args[index + 1].lower())
            index += 2
        elif arg == "--config-env" and index + 1 < len(args):
            configs.append(args[index + 1].lower())  # NAME=ENVVAR: the value is unknown, the setting is not
            index += 2
        elif arg.startswith("--config-env="):
            configs.append(arg[len("--config-env="):].lower())
            index += 1
        elif arg == "--git-dir" and index + 1 < len(args):
            git_dir_path = args[index + 1]
            unknown = unknown or repo is None
            index += 2
        elif arg.startswith("--git-dir="):
            git_dir_path = arg[len("--git-dir="):]
            unknown = unknown or repo is None
            index += 1
        elif arg in GIT_VALUE_OPTIONS:
            index += 2
        else:
            index += 1
    if index >= len(args) or args[index] != "push":
        return None
    force = delete = mirror = every = prune = False
    positional: list[str] = []
    rest = args[index + 1:]
    i = 0
    while i < len(rest):
        arg = rest[i]
        i += 1
        if arg in ("--force", "--force-if-includes") or arg.startswith("--force-with-lease"):
            force = True
        elif arg == "--mirror":
            mirror = True
        elif arg in ("--all", "--branches"):
            every = True
        elif arg == "--prune":
            prune = True
        elif arg in ("--delete", "-d"):
            delete = True
        elif arg in PUSH_VALUE_OPTIONS:
            i += 1  # its value is the next argument
        elif arg.startswith("--"):
            continue
        elif arg.startswith("-") and len(arg) > 1:
            letters = arg[1:].split("o", 1)[0]  # what follows an o is -o's value (`-o"$OPT"`)
            if "$" in letters or "`" in letters:
                force = True  # `-$F`: the variable may hold f
            for position, letter in enumerate(arg[1:], start=1):
                if letter == "o":  # -o takes a value: the rest of the cluster, or the next argument
                    if position == len(arg) - 1:
                        i += 1
                    break
                force = force or letter == "f"
                delete = delete or letter == "d"
        else:
            positional.append(arg)
    mirror = mirror or (every and (force or prune))

    def variable(word: str) -> bool:
        return word.startswith(("$", "`")) and not CURRENT_BRANCH_SUBSTITUTION.fullmatch(word)

    literal = [word for word in positional if not variable(word)]
    if len(literal) >= 2 and any(variable(word) and any(not variable(after) for after in positional[i + 1:])
                                 for i, word in enumerate(positional)):
        force = True  # a variable before a literal word may hold --force
    known = not unknown

    def checked_out() -> str | None:
        return current_branch(repo, git_dir_path) if known else None

    settings = [c.replace(" ", "") for c in configs]
    if environment_config:
        mirror = True
    if any(re.fullmatch(r"remote\..+\.mirror=(?!false$|no$|off$|0$).*", c) or re.fullmatch(r"remote\..+\.mirror", c) for c in settings):
        mirror = True  # remote.<name>.mirror makes a push behave as --mirror
    if len(positional) <= 1 and any(c.startswith("remote.") and ".push=" in c for c in settings):
        mirror = True  # the configured refspecs may rewrite any branch
    if len(positional) <= 1 and force and "push.default=matching" in settings:
        mirror = True  # a forced matching push rewrites every branch both sides have
    if len(positional) <= 1 and any(c in ("push.default=upstream", "push.default=tracking") or c.startswith("branch.")
                                    for c in settings):
        known = False  # the bare push goes to the configured upstream, not to a branch of the same name
    branches: list[str | None] = []
    if not mirror:
        for spec in positional[1:]:
            plus = spec.startswith("+")
            if spec.lstrip("+") == ":":
                if plus or force:
                    mirror, branches = True, []  # the matching refspec: every branch both sides have
                    break
                continue  # an ordinary matching push
            # A ${...} expansion may hold a colon (`${B:-main}`) that is not the refspec's: read it as one variable.
            spec = BRACED_EXPANSION.sub("$VAR", spec.lstrip("+"))
            source, _, destination = spec.partition(":") if ":" in spec else (spec, "", spec)
            if "*" in destination and (delete or plus or force or prune):
                mirror = True  # a pattern can rewrite or delete every branch it covers
                branches = []
                break
            if not (delete or plus or force or (":" in spec and source == "")):
                continue
            if CURRENT_BRANCH_SUBSTITUTION.fullmatch(destination):
                # The shell runs it where it is, not in -C's repository.
                branches.append(None if cwd is None or unknown else current_branch(cwd))
                continue
            if "$" in destination or "`" in destination:
                # A variable or a substitution: a glob of what it could be. Under refs/ with a literal namespace other
                # than heads (a tag, a note) it is no branch; with an unknown namespace it could be refs/heads/.
                namespace = re.match(r"refs/([A-Za-z0-9._-]+)/", destination)
                if namespace and namespace.group(1) != "heads":
                    continue
                if destination.startswith("refs/") and not namespace:
                    branches.append(None)
                    continue
                name = destination[len("refs/heads/"):] if destination.startswith("refs/heads/") else destination
                glob = re.sub(r"\*+", "*", EXPANSION.sub("*", name))
                branches.append(None if glob.strip("*") == "" else BranchPattern(glob))
                continue
            for prefix in ("refs/heads/", "heads/"):
                if destination.startswith(prefix):
                    destination = destination[len(prefix):]
                    break
            if destination in ("HEAD", "@"):
                destination = (checked_out() or "") if known else None
            branches.append(destination)
        if not mirror and force and len(positional) <= 1:
            branches.append(checked_out())
    return mirror, branches


# What can change which branch a later command in the same line has checked out, or where it runs: the checked-out
# branch is then unknown, and so blocked, for the rest of the line (commands_with_branch_context). A command can only
# make the branch unknown, never name it: a switch may fail, run elsewhere, or take its name from a variable.
CONTEXT_COMMANDS = {"cd", "chdir", "pushd", "popd", "source", ".", "eval", "exec", "alias"}
GIT_CONTEXT_SUBCOMMANDS = {"checkout", "switch", "symbolic-ref", "init"}
# An assignment that points git at another repository or adds configuration.
GIT_ENVIRONMENT_ASSIGNMENT = re.compile(r"GIT_(?:DIR|WORK_TREE|COMMON_DIR|CONFIG_COUNT|CONFIG_KEY_\d+|CONFIG_VALUE_\d+|CONFIG_PARAMETERS)=")
GIT_CONFIG_ASSIGNMENT = re.compile(r"GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+|PARAMETERS)=")
ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
# Commands whose arguments may be assignments that reach a later command's environment.
ASSIGNING_COMMANDS = {"export", "declare", "typeset", "local", "readonly", "env", "sudo", "doas", "command", "nice", "nohup",
                      "timeout", "time"}
# Words after which the next word is still a command's first word.
COMMAND_PREFIX_WORDS = {"{", "!", "then", "do", "else", "elif", "if", "while", "until", "time"}
REBASE_VALUE_OPTIONS = {"--onto", "-X", "-s", "--strategy", "--strategy-option", "-x", "--exec", "-C"}


class _ConfiguredByEnvironment:
    """The branch context of a line that sets GIT_CONFIG_*: any push in it may be a mirror."""


CONFIGURED_BY_ENVIRONMENT = _ConfiguredByEnvironment()


def _git_subcommand(args: list[str]) -> tuple[str | None, list[str], bool]:
    """git's subcommand, its arguments, and whether an option before it names another repository or a variable may."""
    index, elsewhere = 0, False
    while index < len(args) and args[index].startswith(("-", "$", "`")):
        arg = args[index]
        elsewhere = elsewhere or arg.startswith(("-C", "--git-dir", "--work-tree", "$", "`"))
        index += 2 if arg in ("-C", "-c", "--git-dir", "--work-tree", "--config-env") or arg in GIT_VALUE_OPTIONS else 1
    return (args[index], args[index + 1:], elsewhere) if index < len(args) else (None, [], elsewhere)


def _changes_branch(argv: list[str]) -> bool:
    """Whether argv may change the checked-out branch or the directory for the commands after it."""
    name = os.path.basename(argv[0])
    if name in CONTEXT_COMMANDS:
        return True
    if name == "gh":
        return argv[1:3] == ["pr", "checkout"] or argv[1:2] == ["co"]
    if name != "git":
        return False
    sub, rest, _ = _git_subcommand(argv[1:])
    if sub in GIT_CONTEXT_SUBCOMMANDS:
        return True
    if sub == "branch":  # `git branch -m main` renames the checked-out branch
        return any(a in ("--move", "-m", "-M") or (a.startswith("-") and not a.startswith("--") and set(a[1:]) & {"m", "M"})
                   for a in rest)
    if sub == "rebase":  # `git rebase <upstream> <branch>` and `git rebase --root <branch>` check out <branch> first
        words, skip = [], False
        for a in rest:
            if skip:
                skip = False
            elif a in REBASE_VALUE_OPTIONS:
                skip = True
            elif not a.startswith("-"):
                words.append(a)
        return len(words) >= 2 or ("--root" in rest and len(words) >= 1)
    return sub == "stash" and rest[:1] == ["branch"]


def _shell_bodies(command: str, depth: int = 0) -> list[str]:
    """The command and every `bash -c`/`sh -c` body inside it, at any depth _unwrap reads."""
    bodies = [command]
    if depth >= 3:
        return bodies
    current: list[str] = []
    for token in _tokens(command) + [";"]:
        if token in SEPARATORS or set(token) <= set(";&|()\n"):
            argv = _strip_wrappers(current)
            if argv and os.path.basename(argv[0].lstrip("`")) in SHELLS:
                script = _shell_command_string(argv[1:])
                if script is not None:
                    bodies.extend(_shell_bodies(script, depth + 1))
            current = []
        else:
            current.append(token)
    return bodies


def _points_git_elsewhere(command: str) -> str | None:
    """"config" when a line (or a shell body in it) assigns GIT_CONFIG_*, "elsewhere" when it defines a function
    (which may stand in for git), assigns GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, or gives env a directory, else None.
    Read from shell words, with assignments only where they are assignments, so a quoted mention in a message (`-m
    "fix parse() edge case"`, `-m "GIT_DIR=x"`) is not one."""
    found = None
    for body in _shell_bodies(command):
        tokens = _tokens(body)
        at_start, assigning, previous = True, False, ""
        for i, token in enumerate(tokens):
            if token in SEPARATORS or set(token) <= set(";&|()\n"):
                if not previous.endswith(("$", "=")) and previous and previous not in SEPARATORS and not set(previous) <= set(";&|()\n"):
                    if token.startswith("()") or (token == "(" and i + 1 < len(tokens) and tokens[i + 1].startswith(")")):
                        found = found or "elsewhere"  # `name()`; not `arr=()` or `$()`
                at_start, assigning, previous = True, False, token
                continue
            if at_start and token in COMMAND_PREFIX_WORDS:
                previous = token
                continue
            if at_start and token == "function":
                found = found or "elsewhere"
            if (at_start or assigning) and ASSIGNMENT_WORD.match(token):
                if GIT_CONFIG_ASSIGNMENT.match(token):
                    return "config"
                if GIT_ENVIRONMENT_ASSIGNMENT.match(token):
                    found = found or "elsewhere"
                previous = token
                continue
            if at_start:
                name = os.path.basename(token)
                assigning = name in ASSIGNING_COMMANDS
                if name == "env":
                    for option in tokens[i + 1:]:
                        if not option.startswith("-"):
                            break
                        if option in ("-C", "--chdir") or option.startswith("--chdir=") or (not option.startswith("--") and "C" in option[1:]):
                            found = found or "elsewhere"
            elif token == "--chdir" or token.startswith("--chdir="):
                found = found or "elsewhere"
            at_start, previous = False, token
    return found


def commands_with_branch_context(command: str, cwd: str | None):
    """Each simple command, with the directory to read the checked-out branch from, or None when it is unknown: after
    a command earlier in the line that may change it or the directory (`cd`, `pushd`, `git checkout`, `git switch`,
    `git init`, `git rebase <upstream> <branch>`, `git stash branch`, `git branch -m`, `gh pr checkout`, `source`,
    `eval`, or a git subcommand given another repository), and for the whole line when it, or a shell body in it,
    defines a function, assigns GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, or gives env a directory. A line that assigns
    GIT_CONFIG_* yields CONFIGURED_BY_ENVIRONMENT, which makes any push in it a mirror. A command can only make the
    branch unknown, never name it. A script or program run earlier in the line that switches branches is not seen, nor
    a git alias or a setting in git's config files."""
    pointed = _points_git_elsewhere(command)
    branch_cwd = CONFIGURED_BY_ENVIRONMENT if pointed == "config" else (None if pointed else cwd)
    for argv in _simple_commands(command):
        yield argv, branch_cwd
        if branch_cwd is not CONFIGURED_BY_ENVIRONMENT and _changes_branch(argv):
            branch_cwd = None


def _git_finding(args: list[str], cwd: str | None) -> bool:
    push = git_push_rewrites(args, cwd)
    if push is None:
        return False
    mirror, branches = push
    return mirror or any(
        branch is None
        or (pattern_may_match(branch, PROTECTED_NAMES, PROTECTED_PREFIXES) if isinstance(branch, BranchPattern)
            else PROTECTED_BRANCH.match(branch))
        for branch in branches)


def _kubectl_finding(args: list[str]) -> bool:
    index = 0
    while index < len(args) and args[index].startswith("-"):
        index += 2 if args[index] in KUBECTL_VALUE_FLAGS else 1
    if index >= len(args) or args[index] != "delete":
        return False
    rest = args[index + 1:]
    for position, arg in enumerate(rest):
        if arg.startswith("--dry-run"):
            mode = arg.split("=", 1)[1] if "=" in arg else (rest[position + 1] if position + 1 < len(rest) else "client")
            if mode in ("client", "server"):
                return False
    positional, skip = [], False
    for arg in rest:
        if skip:
            skip = False
        elif arg in KUBECTL_VALUE_FLAGS:
            skip = True
        elif not arg.startswith("-"):
            positional.append(arg)
    kinds = positional[0].lower() if positional else ""
    if kinds in ("namespace", "namespaces", "ns") or kinds.startswith(("namespace/", "namespaces/", "ns/")):
        return True
    return any(arg in ("--all", "--all-namespaces", "-A") for arg in rest)


SQL_CLIENTS = {"psql", "mysql", "mariadb", "sqlite3", "sqlcmd"}
SQL_DROP_OR_TRUNCATE = re.compile(
    r"\bDROP\s+(?:DATABASE|SCHEMA|TABLE)\b"
    r"|\bTRUNCATE\s+(?:TABLE\s+)?[\"`\[]?[A-Za-z_]",  # TRUNCATE(x, 2) is MySQL's numeric function
    re.IGNORECASE,
)
SQL_DELETE_FROM = re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE)
SQL_WHERE = re.compile(r"\bWHERE\b", re.IGNORECASE)
RAILS_DESTRUCTIVE_TASKS = {"db:drop", "db:reset", "db:schema:load", "db:structure:load"}
# Options that take a separate value, per runner, so the command after them is found.
CONTAINER_VALUE_OPTIONS = {
    "-e", "--env", "--env-file", "-u", "--user", "-w", "--workdir", "--detach-keys", "--index",
    "--name", "-v", "--volume", "-p", "--publish", "--entrypoint", "-l", "--label",
}
RAILWAY_VALUE_OPTIONS = {"-s", "--service", "-e", "--environment"}
NPM_VALUE_OPTIONS = {"-p", "--package", "-w", "--workspace", "-c", "--call"}
YARN_PNPM_VALUE_OPTIONS = {"--cwd", "-C", "--dir", "--filter", "-F"}


def _skip_options(args: list[str], value_options: set[str]) -> list[str]:
    """Drop leading options (and the values of those in value_options); stop after `--`."""
    idx = 0
    while idx < len(args) and args[idx].startswith("-"):
        if args[idx] == "--":
            return args[idx + 1:]
        idx += 2 if args[idx] in value_options else 1
    return args[idx:]


def _unwrap_exec(name: str, args: list[str]) -> tuple[str, list[str]]:
    """Strip container and remote runners: docker/podman exec, docker compose exec/run, kubectl exec --, railway run."""
    if name in ("docker", "podman") and args[:1] == ["compose"]:
        name, args = "docker-compose", args[1:]
    if name == "kubectl" and args[:1] == ["exec"]:
        rest = args[args.index("--") + 1:] if "--" in args else []
        return (os.path.basename(rest[0]), rest[1:]) if rest else (name, args)
    if name == "railway" and args[:1] == ["run"]:
        rest = _skip_options(args[1:], RAILWAY_VALUE_OPTIONS)
        return (os.path.basename(rest[0]), rest[1:]) if rest else (name, args)
    if (name in ("docker", "podman") and args[:1] == ["exec"]) or (name == "docker-compose" and args[:1] in (["exec"], ["run"])):
        rest = _skip_options(args[1:], CONTAINER_VALUE_OPTIONS)
        if len(rest) >= 2:  # the container or service, then the command
            return os.path.basename(rest[1]), rest[2:]
    return name, args


def _unwrap_runner(name: str, args: list[str]) -> tuple[str, list[str]]:
    """Strip package/runtime runner prefixes (npx, npm exec, yarn/pnpm, bundle exec, poetry/uv run, python manage.py)."""
    if name in ("npx", "bunx", "pnpx"):
        idx = 0
        while idx < len(args) and args[idx].startswith("-"):
            idx += 2 if args[idx] in ("-p", "--package") else 1
        if idx < len(args):
            return os.path.basename(args[idx]), args[idx + 1:]
    elif name == "npm" and args[:1] in (["exec"], ["x"]):
        rest = _skip_options(args[1:], NPM_VALUE_OPTIONS)
        if rest:
            return os.path.basename(rest[0]), rest[1:]
    elif name in ("yarn", "pnpm"):
        rest = _skip_options(args, YARN_PNPM_VALUE_OPTIONS)
        if rest[:1] == ["workspace"] and len(rest) > 2:
            rest = rest[2:]
        if rest[:1] in (["dlx"], ["exec"], ["run"]):
            rest = rest[1:]
        if rest:
            return os.path.basename(rest[0]), rest[1:]
    elif name == "bundle" and len(args) >= 2 and args[0] == "exec":
        return os.path.basename(args[1]), args[2:]
    elif name in ("poetry", "uv", "pipenv") and len(args) >= 2 and args[0] == "run":
        return os.path.basename(args[1]), args[2:]
    elif name in ("python", "python3") and args:
        if args[0] == "-m" and len(args) >= 2:
            return os.path.basename(args[1]), args[2:]
        if os.path.basename(args[0]) in ("manage.py", "django-admin", "django-admin.py"):
            return os.path.basename(args[0]), args[1:]
    return name, args


def _destructive_sql(text: str) -> bool:
    """True when a ;-separated statement drops a database, schema, or table, truncates, or deletes with no WHERE."""
    for statement in text.split(";"):
        if SQL_DROP_OR_TRUNCATE.search(statement):
            return True
        delete = SQL_DELETE_FROM.search(statement)
        if delete and not SQL_WHERE.search(statement, delete.end()):
            return True
    return False


def _db_finding(name: str, args: list[str], command: str, depth: int = 0) -> tuple[str, str] | None:
    name, args = _unwrap_exec(name, args)
    script = _shell_command_string(args) if name in SHELLS else None
    if script is not None:
        # A shell started inside a container (docker compose exec db sh -c "psql ..."): check its commands too.
        if depth < 3:
            for inner in _simple_commands(script, depth + 1):
                hit = _db_finding(inner[0], inner[1:], command, depth + 1)
                if hit is not None:
                    return hit
        return None
    name, args = _unwrap_runner(name, args)
    if name in ("python", "python3") and args:
        name, args = _unwrap_runner(name, args)
    if name == "prisma":
        if args[:2] == ["db", "push"] and "--accept-data-loss" in args[2:]:
            return (
                "prisma db push --accept-data-loss",
                "Generate and review a migration with `prisma migrate dev --create-only`, then apply with `prisma migrate deploy` after taking a backup.",
            )
        if args[:2] == ["migrate", "reset"] and any(a in ("--force", "-f") for a in args[2:]):
            return (
                "prisma migrate reset --force",
                "Never run `prisma migrate reset --force` from an agent session; inspect migration status with `prisma migrate status` and confirm with the user.",
            )
    if name in ("rails", "rake"):
        for arg in args:
            lowered = arg.lower()
            if lowered in RAILS_DESTRUCTIVE_TASKS or lowered.startswith(("db:drop:", "db:reset:")):
                return (
                    "rails/rake destructive database reset or drop",
                    "Use incremental reversible migrations (`rails db:migrate`) after backing up the database; never run `db:drop`, `db:reset`, or `db:schema:load` from an agent session.",
                )
    if name in ("manage.py", "django-admin", "django-admin.py", "django"):
        if "flush" in args and any(a in ("--noinput", "--no-input") for a in args):
            return (
                "django flush --noinput",
                "Never flush all database tables non-interactively from an agent session; inspect and delete scoped records inside an explicit transaction after user confirmation.",
            )
    if name == "dropdb":
        return (
            "dropdb database deletion",
            "Verify the target database and have the user run `dropdb` directly after taking a verified backup.",
        )
    if name == "redis-cli" and any(a.lower() in ("flushall", "flushdb") for a in args):
        return (
            "redis-cli FLUSHALL/FLUSHDB",
            "Scan and delete specific keys with `SCAN` and `DEL`/`UNLINK` after confirming the key pattern and count with the user.",
        )
    # A SQL client reads its statements from flags (-c, -tAc, -e, -Q), positional arguments, a heredoc, a
    # here-string, or a pipe; rather than model each client's options, check the whole command line. SQL in a
    # file passed with -f or < is not read.
    if name in SQL_CLIENTS and _destructive_sql(command):
        return (
            "inline destructive SQL (DROP, TRUNCATE, or unscoped DELETE)",
            "Run `SELECT COUNT(*)` first, wrap mutating SQL in an explicit `BEGIN`/`COMMIT` transaction with a `WHERE` clause, and get explicit user confirmation before dropping tables or databases.",
        )
    return None


def find_destructive_op(command: str, cwd: str | None = None) -> tuple[str, str] | None:
    """Return (label, remediation) for the first destructive command found, or None."""
    if not command:
        return None
    for label, pattern, remediation in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return label, remediation
    working_dir = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    for argv, branch_cwd in commands_with_branch_context(command, working_dir):
        name, args = argv[0], argv[1:]
        if name == "rm" and _rm_finding(args):
            return RM_LABEL, RM_NOTE
        if name == "git" and _git_finding(args, branch_cwd):
            return GIT_LABEL, GIT_NOTE
        if name == "kubectl" and _kubectl_finding(args):
            return KUBECTL_LABEL, KUBECTL_NOTE
        db_hit = _db_finding(name, args, command)
        if db_hit is not None:
            return db_hit
    return None


# --- evidence (content-free) ---------------------------------------------------------------
# Written by catpilot_guard/evidence.py when CATPILOT_EVIDENCE_LOG or CATPILOT_EVIDENCE_SYSLOG is set:
# one line per deny or input error, with the hook, the tool, the operation label and the session id.
HOOK_NAME = "pretooluse-destructive-ops"
HOST = "claude-code"  # main()'s host with no --host (hook_host); decide() called from a harness passes no host


def record_evidence(event: str, hook_event: object = None, host: str | None = None, **fields) -> None:
    """One evidence line through the shared writer, imported here so that a missing or broken writer is a
    logging failure: it never changes the decision, and nothing here raises."""
    try:
        from . import evidence

        evidence.record_hook_event(HOOK_NAME, event, hook_event, host, **fields)
    except Exception:
        pass


def decide(event: dict, host: str | None = None) -> dict:
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
    found = find_destructive_op(command, event.get("cwd"))
    if found is None:
        return {}
    label, remediation = found
    record_evidence("deny", event, host, tool="Bash", label=label)
    reason = (
        f"Catpilot destructive-operation check: this command matches a high-blast-radius pattern ({label}). "
        f"{remediation} If this exact command is intentional, run it yourself in your own terminal."
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> int:
    host = hook_host()  # from --host: the evidence label, and Copilot CLI's event shape; never the decision
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("hook input too large")
        result = decide(event_for_host(json.loads(payload), host), host)
    except Exception:
        # Any failure blocks: an ordinary non-zero exit would let the host run the command.
        record_evidence("input_error", host=host)
        write_reason(
            "Catpilot destructive-operation check could not read the hook input, so the command was not allowed. "
            "Review the command and retry.")
        return 2
    return write_decision(decision_for_host(result, host))


if __name__ == "__main__":
    sys.exit(main())
