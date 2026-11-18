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
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
ENV_PAIR = re.compile(r"^[^=]+=")
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


def _simple_commands(command: str, depth: int = 0, assignments: list[str] | None = None):
    """Yield argv lists for each simple command, with wrappers removed and `sh -c` bodies expanded.

    When `assignments` is a list, every variable assignment dropped on the way (`NAME=value` before a command, on
    its own, or after `env`), in `bash -c` bodies too, is appended to it as written, as the commands are yielded."""
    current: list[str] = []
    for token in _tokens(command) + [";"]:
        if token in SEPARATORS or set(token) <= set(";&|()\n"):
            if current:
                yield from _unwrap(current, depth, assignments)
            current = []
        else:
            current.append(token)


def _strip_wrappers(argv: list[str], assignments: list[str] | None = None) -> list[str]:
    """Drop leading assignments and wrapper commands (sudo, env, timeout 60, ...) with their options. The assignments
    dropped are appended to `assignments` when it is a list."""
    while True:
        while argv and ASSIGNMENT.match(argv[0]):
            if assignments is not None:
                assignments.append(argv[0])
            argv = argv[1:]
        if not argv:
            return argv
        name = os.path.basename(argv[0].lstrip("`"))
        if name in WRAPPERS:
            argv = argv[1:]
            # env takes every word with `=` before the command as NAME=VALUE, a name the shell would refuse included
            # (`env 'A-B=x/y' rm -rf /` runs rm).
            pair = ENV_PAIR if name == "env" else ASSIGNMENT
            while argv and (argv[0].startswith("-") or pair.match(argv[0])):
                if assignments is not None and pair.match(argv[0]):
                    assignments.append(argv[0])
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


def _unwrap(argv: list[str], depth: int, assignments: list[str] | None = None):
    argv = _strip_wrappers(argv, assignments)
    if not argv:
        return
    name = os.path.basename(argv[0].lstrip("`"))
    if name in SHELLS and depth < 3:
        script = _shell_command_string(argv[1:])
        if script is not None:
            yield from _simple_commands(script, depth + 1, assignments)
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


BRACE_LIMIT = 64  # more words than this from one brace expansion is unknown
BRACE_WORD_LIMIT = 4096  # a word with braces longer than this is unknown at once


def expand_braces(word: str, limit: int = BRACE_LIMIT):
    """The words bash makes of `word` by brace expansion, or None when there would be more than limit (or the word is
    over BRACE_WORD_LIMIT characters). A port of bash 5.2's braces.c brace_expand (the review of #133 checked it against
    bash on 12,000 words): a `}` closes a brace only after a comma or a `..` at its level, `{x}` alone stays literal,
    sequences take steps and zero padding, and a word a brace makes empty is dropped. `${...}` is parameter expansion,
    not a brace: callers collapse it first. Quoting is already gone, so a quoted brace is expanded too (stricter)."""
    if "{" not in word:
        return [word]
    if len(word) > BRACE_WORD_LIMIT or word.count("{") > 4 * limit:
        return None
    try:
        return [w for w in _brace_expand(word, limit) if w != ""]
    except (_TooManyWords, RecursionError):
        return None



class _TooManyWords(Exception):
    pass

def _brace_gobbler(text, i, satisfy):
    level = 0
    commas = 0 if satisfy == "}" else 1
    n = len(text)
    while i < n:
        c = text[i]
        if c == "$" and i + 1 < n and text[i + 1] == "{":
            i += 2  # pass_next: skip the {
            level += 1
            continue
        if c == satisfy and level == 0 and commas > 0:
            if c == "{" and (i == 0) and (i + 1 < n and text[i + 1] == "}"):
                i += 1
                continue
            return i, c
        if c == "{":
            level += 1
        elif c == "}" and level:
            level -= 1
        elif satisfy == "}" and c == "," and level == 0:
            commas += 1
        elif satisfy == "}" and text.startswith("..", i) and (i + 2 >= n or text[i + 2] != satisfy) and level == 0:
            commas += 1
        i += 1
    return i, ""

def _legal_number(s):
    s2 = s.strip()
    return re.fullmatch(r"[+-]?\d+", s2) is not None and s2 == s.strip()

def _brace_sequence(text, limit):
    t = text.find("..")
    if t < 0:
        return None
    lhs, rhs = text[:t], text[t + 2:]
    if not lhs or not rhs:
        return None
    if re.fullmatch(r"\s*[+-]?\d+\s*", lhs):
        lt = "int"; lv = int(lhs)
    elif lhs[0].isascii() and lhs[0].isalpha() and len(lhs) == 1:
        lt = "char"
    else:
        lt = "bad"
    m = re.match(r"[+-]?\d+", rhs)
    if rhs[0].isdigit() or (rhs[0] in "+-" and len(rhs) > 1 and rhs[1].isdigit()):
        rt = "int"; rv = int(m.group(0)); ep = m.end()
        if ep < len(rhs) and rhs[ep] != ".":
            rt = "bad"
    elif rhs[0].isascii() and rhs[0].isalpha() and (len(rhs) == 1 or rhs[1] == "."):
        rt = "char"; ep = 1
    else:
        rt = "bad"; ep = 0
    incr = 1
    if rt != "bad":
        rest = rhs[ep:]
        if rest.startswith("..") and len(rest) > 2:
            m2 = re.match(r"[+-]?\d+", rest[2:])
            if m2:
                incr = int(m2.group(0)); rest = rest[2 + m2.end():]
            else:
                rest = rest[2:]
        if rest != "":
            rt = "bad"
    if lt != rt or lt == "bad":
        return None
    if lt == "char":
        a, b = ord(lhs[0]), ord(rhs[0]); width = 0
    else:
        a, b = lv, rv
        lhs_l = len(lhs); rhs_l = len(rhs[:ep])
        width = 0
        if (lhs_l > 1 and lhs[0] == "0") or (lhs_l > 2 and lhs[:2] == "-0"):
            width = lhs_l
        if ((rhs_l > 1 and rhs[0] == "0") or (rhs_l > 2 and rhs[:2] == "-0")) and width < rhs_l:
            width = rhs_l
    incr = abs(incr) or 1
    vals = range(a, b + 1, incr) if a <= b else range(a, b - 1, -incr)
    if len(vals) > limit:
        raise _TooManyWords
    if lt == "char":
        return [chr(v) for v in vals]
    return [("-" if v < 0 else "") + str(abs(v)).zfill(width - (1 if v < 0 else 0)) if width else str(v) for v in vals]

def _brace_expand(text, limit=64):
    i = 0
    n = len(text)
    c = ""
    while True:
        i, c = _brace_gobbler(text, i, "{")
        if c:
            j, c2 = _brace_gobbler(text, i + 1, "}")
            if not c2:
                i += 1
                continue
            break
        break
    preamble = text[:i]
    if c != "{":
        return [preamble]
    start = i + 1
    i, c = _brace_gobbler(text, start, "}")
    if not c:
        return [text]
    amble = text[start:i]
    if "," not in amble:
        tack = _brace_sequence(amble, limit)
        if tack is None:
            if i + 1 < n:
                tack = [text[start - 1:i + 1]]
            else:
                return [text]
    else:
        tack = _brace_amble(amble, limit)
    result = [preamble + t for t in tack]
    post = text[i + 1:]
    if post:
        tail = _brace_expand(post, limit)
        if len(result) * len(tail) > limit:
            raise _TooManyWords
        result = [r + t for r in result for t in tail]
    if len(result) > limit:
        raise _TooManyWords
    return result

def _brace_amble(text, limit):
    result = []
    i = start = 0
    while True:
        i, c = _brace_gobbler(text, i, ",")
        result.extend(_brace_expand(text[start:i], limit))
        if len(result) > limit:
            raise _TooManyWords
        if not c:
            break
        i += 1
        start = i
    return result


# The pull-request check's stand-in for a `${{ ... }}` expression (tools/pr_check.py EXPRESSION_VARIABLE).
OPAQUE_EXPANSION = "CATPILOT_EXPRESSION"


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
    """Both readings: braces expanded (unquoted) and words as written (quoted, empty words kept); the stricter wins."""
    expanded = _git_push_rewrites(args, cwd, True)
    if not any("{" in word or word == "" for word in args):
        return expanded
    raw = _git_push_rewrites(args, cwd, False)
    if expanded is None or raw is None:
        return expanded if raw is None else raw
    return expanded[0] or raw[0], expanded[1] + raw[1]


def _git_push_rewrites(args: list[str], cwd: str | None, expand: bool) -> tuple[bool, list[str | None]] | None:
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
    holding a shell variable or a command substitution (`$BRANCH`, `"${TARGET}"`, a backtick) is a BranchPattern,
    the literal text before it and then anything (`release/*`, `v*`), or None (unknown) when nothing literal comes
    first; a substitution that asks git for the checked-out branch (CURRENT_BRANCH_SUBSTITUTION) is read as the branch
    checked out in cwd (None when detached). Braces are expanded as bash expands them (expand_braces); more than 64
    words is unknown when the push forces or deletes. The refspec splits at its last colon. `@` is HEAD, and `heads/X` is X, as git resolves them. A word that
    starts with a variable and is followed by a literal word, with two literal words besides (`git push $F origin
    main`, `git push origin $F main`; F may be --force), counts as a force; a trailing one (`git push origin main
    "$TAG"`) does not. A matching refspec (`:`) with a force or a `+` rewrites every branch both sides have, and so
    does a bare push given `-c remote.<name>.push=...`, or `-c push.default=matching` with a force. A bare force push,
    with no refspec, adds the checked-out branch, or None when it is detached or there is no repository.
    A `$` word before the subcommand, `-C` or `--git-dir` without a known directory, and a bare push given `-c
    push.default=upstream` or a `branch.*` setting make the checked-out branch unknown; `-c remote.<name>.mirror`
    (or `--config-env` for it) makes a mirror. cwd None means the checked-out branch is unknown, and
    CONFIGURED_BY_ENVIRONMENT (a harmful GIT_CONFIG_*, or an earlier mirror setting) makes a bare push a mirror (see
    commands_with_branch_context). The built-in check (_git_finding) treats None as protected, and the company-rules hook
    (catpilot_guard/company_rules.py) fires every protected_branch rule on it; both read pushes this way.
    """
    if cwd is CONFIGURED_BY_ENVIRONMENT:
        cwd = None  # GIT_CONFIG_* may set remote.<name>.mirror: any push may rewrite every branch
        environment_config = True
    else:
        environment_config = False
    repo = cwd
    if expand and any("{" in word for word in args):
        # The shell expands braces in every word, git's own and the subcommand's included (`git {push,-f} origin main`).
        # Walk git's own options as git reads them (a value option's value is not the subcommand), expanding each word,
        # until the subcommand; the push's own words are expanded below, with placeholders.
        head, position = [], 0
        while position < len(args):
            word = args[position]
            position += 1
            words = [word] if "{" not in word else expand_braces(BRACED_EXPANSION.sub("$VAR", word))
            head.extend(words if words is not None else ["$CATPILOT_BRACES"])
            look = 0
            while look < len(head) and head[look].startswith(("-", "$", "`")):
                look += 2 if head[look] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env") \
                    or head[look] in GIT_VALUE_OPTIONS else 1
            if look < len(head):
                break  # the subcommand is reached
        head.extend(args[position:])
        args = head
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
    # The shell expands braces before git sees the words (`:{feature,develop}`, `{origin,HEAD:main}`, `{-f,}`), so options
    # are read after it. A word past the limit is a variable placeholder: unknown wherever it stands, and possibly --force.
    rest, too_many, unsure = [], False, False
    for word in args[index + 1:]:
        words = expand_braces(BRACED_EXPANSION.sub("$VAR", word)) if expand else [word]
        if words is None:
            rest.append("$CATPILOT_BRACES")
            too_many = True
            # `{,}--force`, `{+main,..}`, `:{a,..}`, `$F`; not a `-` inside a name (`release-{1..100}`).
            unsure = unsure or re.search(r"(?:^|[{,}])[-+]|[^\w./{},+-]", word) is not None
        else:
            rest.extend(words)
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
    if too_many:
        # The words past the limit may hold --force (an option-like brace, or beside a variable that may), or a pattern
        # refspec that --prune or --all would apply to.
        force = force or unsure or any(w.startswith(("$", "`")) and w != "$CATPILOT_BRACES" for w in positional)
        mirror = mirror or (every and (force or prune)) or (prune and unsure)

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
    bare = len([w for w in positional if w != "$CATPILOT_BRACES"]) <= 1
    if environment_config and bare:
        mirror = True  # a bare push; a refspec overrides remote.<name>.push, and git refuses one with
        # remote.<name>.mirror (an unquoted variable that is empty, making a bare push, is not seen)
    if any(re.fullmatch(r"remote\..+\.mirror=(?!false$|no$|off$|0$).*", c) or re.fullmatch(r"remote\..+\.mirror", c) for c in settings):
        mirror = True  # remote.<name>.mirror makes a push behave as --mirror
    if bare and any(c.startswith("remote.") and ".push=" in c for c in settings):
        mirror = True  # the configured refspecs may rewrite any branch
    if bare and force and "push.default=matching" in settings:
        mirror = True  # a forced matching push rewrites every branch both sides have
    if bare and any(c in ("push.default=upstream", "push.default=tracking") or c.startswith("branch.")
                                    for c in settings):
        known = False  # the bare push goes to the configured upstream, not to a branch of the same name
    branches: list[str | None] = [None] if too_many and (force or delete) else []
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
            # git splits a refspec at its last colon (`:/fix: x:main` pushes to main).
            source, _, destination = spec.rpartition(":") if ":" in spec else (spec, "", spec)
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
                # A variable or a substitution: a glob of what it could be, the literal text before it and then
                # anything. Under refs/ with a literal namespace other than heads (a tag, a note) it is no branch; with
                # an unknown namespace it could be refs/heads/. A `${{ ... }}` of the pull-request check is text GitHub
                # puts in before the shell runs, which may end the word: unknown. A value holding a space or a colon,
                # which splits the word or the refspec, is not seen (hooks/README.md).
                namespace = re.match(r"refs/([A-Za-z0-9._-]+)/", destination)
                if namespace and namespace.group(1) != "heads":
                    continue
                if OPAQUE_EXPANSION in destination:
                    branches.append(None)
                    continue
                if destination.startswith("refs/") and not namespace:
                    branches.append(None)
                    continue
                name = destination[len("refs/heads/"):] if destination.startswith("refs/heads/") else destination
                first = EXPANSION.search(name)
                glob = (name[:first.start()] if first else name) + "*"
                if glob == "*":
                    branches.append(None)
                elif fnmatch.fnmatchcase("@", glob) or fnmatch.fnmatchcase("head", glob.casefold()):
                    branches.append(checked_out())  # it could be `@` or HEAD, the checked-out branch
                    branches.append(BranchPattern(glob))
                else:
                    branches.append(BranchPattern(glob))
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
GIT_ENVIRONMENT_ASSIGNMENT = re.compile(r"GIT_(?:DIR|WORK_TREE|COMMON_DIR)(?:\+?=|$)")
GIT_CONFIG_ASSIGNMENT = re.compile(r"GIT_CONFIG_(?:COUNT|KEY_\d+|VALUE_\d+|PARAMETERS|GLOBAL|SYSTEM)(?:\+?=|$)")
ASSIGNMENT_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
# Commands whose arguments may be assignments that reach a later command's environment.
DECLARATION_COMMANDS = {"export", "declare", "typeset", "local", "readonly", "read"}
ASSIGNING_COMMANDS = DECLARATION_COMMANDS | WRAPPERS | set(WRAPPER_SPECS)
# Words after which the next word is still a command's first word.
COMMAND_PREFIX_WORDS = {"{", "!", "then", "do", "else", "elif", "if", "while", "until", "time"}
REBASE_VALUE_OPTIONS = {"--onto", "-X", "-s", "--strategy", "--strategy-option", "-x", "--exec", "-C"}


HARMFUL_CONFIG_KEY = re.compile(r"remote\..+\.(?:mirror|push)|push\.default|include\..*|includeif\..*", re.IGNORECASE)


def git_config_assignment_harmful(name: str, value: str | None) -> bool:
    """Whether a GIT_CONFIG_* variable may make a push a mirror or send it elsewhere. COUNT and VALUE_n alone do not;
    KEY_n does unless its literal key is harmless (a url.<...>.insteadOf whose subsection holds an expression is still
    an insteadOf); GIT_CONFIG_PARAMETERS does unless every key in its literal value is harmless; GIT_CONFIG_GLOBAL and
    GIT_CONFIG_SYSTEM do unless they are /dev/null. value None: not a literal."""
    if name == "GIT_CONFIG_COUNT" or name.startswith("GIT_CONFIG_VALUE_"):
        return False
    if name.startswith("GIT_CONFIG_KEY_"):
        if value is None or "$" in value:
            key = (value or "").lower()
            return not (key.startswith("url.") and key.endswith(".insteadof"))
        return bool(HARMFUL_CONFIG_KEY.fullmatch(value))
    if name == "GIT_CONFIG_PARAMETERS":
        if value is None:
            return True
        # `'key'='value'` or `'key=value'` pairs: the key is what comes before the first `=` of each quoted chunk.
        # The key of each `'key'='value'` or `'key=value'` pair; a value chunk is never a key.
        pair = r"'((?:[^']|'\\'')*)'(?:='(?:[^']|'\\'')*')?"  # git's `'\''` inside a quoted value (`O'\''Brien`)
        if re.sub(pair, "", value).strip() or OPAQUE_EXPANSION in value:
            return True  # `$MORE` or an escaped quote outside a pair, or an expression whose text may close the quote
        keys = [m.group(1).split("=", 1)[0] for m in re.finditer(pair, value)]
        keys = [key for key in keys if "." in key or "$" in key]
        insteadof = lambda key: key.lower().startswith("url.") and key.lower().endswith(".insteadof")
        return not keys or any(HARMFUL_CONFIG_KEY.fullmatch(key) or ("$" in key and not insteadof(key)) for key in keys)
    if name in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM"):
        return value != "/dev/null"
    return True


class _ConfiguredByEnvironment:
    """The branch context of a line that sets a harmful GIT_CONFIG_* (or a command that set a mirror setting): a bare
    push in it, or one whose refspecs are all variables, may be a mirror."""


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
    sub, rest, elsewhere = _git_subcommand(argv[1:])
    globals_, index = argv[1:argv.index(sub) if sub in argv else len(argv)], 0
    while index < len(globals_):
        word = globals_[index]
        if word in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env") or word in GIT_VALUE_OPTIONS:
            index += 2  # its value, whatever it holds
            continue
        if word.startswith(("$", "`")):
            return True  # a variable before the subcommand may make it anything (`git $X a=b switch main`)
        index += 1
    if sub == "checkout" and "--" in rest and rest.index("--") < len(rest) - 1:
        return False  # `git checkout [<tree-ish>] -- <paths>` restores files; the branch stays
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


GIT_CONFIG_READ_OPTIONS = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "-l", "--unset", "--unset-all",
                           "--remove-section", "--rename-section", "--show-origin", "--show-scope", "--name-only"}


GIT_CONFIG_VALUE_OPTIONS = {"-f", "--file", "--blob", "--type", "--comment", "--default", "--value"}


def _config_setting(argv: list[str]) -> str | None:
    """What argv sets that changes a later bare push: "mirror" for `git config` (or `git config set`) of a true
    remote.<name>.mirror, remote.<name>.push or an include, or `git remote add --mirror[=push]`; "unknown" for
    push.default matching, upstream or tracking (a bare force push then goes to branches the line does not name);
    else None. A read (`--get`, one positional) sets nothing."""
    if os.path.basename(argv[0]) != "git":
        return None
    sub, rest, _ = _git_subcommand(argv[1:])
    if sub == "remote":
        mirrors = rest[:1] == ["add"] and any(a in ("--mirror", "--mirror=push") for a in rest)
        return "mirror" if mirrors else None
    if sub != "config" or any(a in GIT_CONFIG_READ_OPTIONS for a in rest):
        return None
    words, skip = [], False
    for a in rest:
        if skip:
            skip = False
        elif a in GIT_CONFIG_VALUE_OPTIONS:
            skip = True  # `-f FILE`, `--type bool`: the value is not the key
        elif not a.startswith("-"):
            words.append(a)
    if words[:1] == ["set"]:
        words = words[1:]
    if len(words) < 2:
        return None
    key, value = words[0].lower(), words[1].lower()
    if re.fullmatch(r"remote\..+\.mirror", key):
        return None if value in ("false", "no", "off", "0") else "mirror"
    if re.fullmatch(r"remote\..+\.push|include\.path|includeif\..+\.path", key):
        return "mirror"
    if key == "push.default" and value in ("matching", "upstream", "tracking"):
        return "unknown"
    return None


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
    """"config" when a line (or a shell body in it) sets GIT_CONFIG_* (a mirror may follow), "elsewhere" when it
    defines a function (which may stand in for git), sets GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, or gives env a
    directory, else None. Read from shell words: an assignment counts at a command's start or as an argument of a
    command that passes it on (export, declare, read, env and the other wrappers), so a quoted mention in a message
    (`-m "fix parse() edge case"`, `-m "GIT_DIR=x"`) is not one."""
    found = None
    for body in _shell_bodies(command):
        tokens = _tokens(body)
        at_start, assigning, previous, env_options = True, False, "", False
        wrapper, skip, positionals = None, 0, 0
        for i, token in enumerate(tokens):
            if token in SEPARATORS or set(token) <= set(";&|()\n"):
                if previous and not previous.endswith(("$", "=")) and previous not in SEPARATORS and not set(previous) <= set(";&|()\n"):
                    if token.startswith("()") or (token == "(" and i + 1 < len(tokens) and tokens[i + 1].startswith(")")):
                        found = found or "elsewhere"  # `name()`; not `arr=()` or `$()`
                at_start, assigning, previous, env_options = True, False, token, False
                wrapper, skip, positionals = None, 0, 0
                continue
            if token == "--chdir" or token.startswith("--chdir="):
                found = found or "elsewhere"  # env's or sudo's, wherever it comes
            if env_options and skip:
                skip, previous = skip - 1, token  # -u's value, then env's options go on
                continue
            if env_options:
                if token.startswith("-"):
                    if token in ("-C", "--chdir") or token.startswith("--chdir=") or (not token.startswith("--") and "C" in token[1:]):
                        found = found or "elsewhere"
                    if token in ("-u", "--unset"):
                        skip = 1  # its value names a variable to unset
                    previous = token
                    continue
                env_options = False
            if token == "env" and (at_start or assigning):
                env_options = True  # env's own options follow, wherever env comes in a wrapper chain
            if at_start and token in COMMAND_PREFIX_WORDS:
                previous = token
                continue
            if at_start and token == "function":
                found = found or "elsewhere"
            if (at_start or assigning) and (ASSIGNMENT_WORD.match(token) or re.fullmatch(r"GIT_[A-Z_0-9]+", token)):
                if GIT_CONFIG_ASSIGNMENT.match(token):
                    name, _, value = token.partition("=")
                    if git_config_assignment_harmful(name.rstrip("+"), value if "=" in token else None):
                        return "config"
                    previous = token
                    continue
                if GIT_ENVIRONMENT_ASSIGNMENT.match(token):
                    found = found or "elsewhere"
                previous = token
                continue
            if at_start or assigning:
                if token.startswith("-"):
                    previous = token  # an option of a prefix word or of an assigning command (`time -p`, `env -i`)
                    if wrapper in WRAPPERS and token in ("-u", "-g", "-n", "-C"):
                        skip = 1  # its value (`sudo -u bob`, `env -u X`, `nice -n 5`)
                    elif wrapper in WRAPPER_SPECS and token in WRAPPER_SPECS[wrapper][0]:
                        skip = 1
                    continue
                if skip:
                    skip, previous = skip - 1, token
                    continue
                if wrapper in WRAPPER_SPECS and positionals:
                    positionals, previous = positionals - 1, token  # timeout's DURATION
                    continue
                if wrapper in DECLARATION_COMMANDS:
                    previous = token  # every argument of export/declare/read is a name or an assignment
                    continue
                if os.path.basename(token) in ASSIGNING_COMMANDS:
                    wrapper = os.path.basename(token)
                    positionals = WRAPPER_SPECS[wrapper][1] if wrapper in WRAPPER_SPECS else 0
                    at_start, assigning, previous = False, True, token
                    continue
            at_start, assigning, previous, wrapper = False, False, token, None
    return found


def commands_with_branch_context(command: str, cwd: str | None):
    """Each simple command, with the directory to read the checked-out branch from, or None when it is unknown: after
    a command earlier in the line that may change it or the directory (`cd`, `pushd`, `git checkout`, `git switch`,
    `git init`, `git rebase <upstream> <branch>`, `git stash branch`, `git branch -m`, `gh pr checkout`, `source`,
    `eval`, or a git subcommand given another repository), and for the whole line when it, or a shell body in it,
    defines a function, assigns GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, or gives env a directory. A line that assigns
    a harmful GIT_CONFIG_* (git_config_assignment_harmful), or follows a command that sets a mirror setting, yields
    CONFIGURED_BY_ENVIRONMENT, which makes a bare push a mirror. A command can only make the
    branch unknown, never name it. A script or program run earlier in the line that switches branches is not seen, nor
    a git alias or a setting in git's config files."""
    pointed = _points_git_elsewhere(command)
    branch_cwd = CONFIGURED_BY_ENVIRONMENT if pointed == "config" else (None if pointed else cwd)
    for argv in _simple_commands(command):
        yield argv, branch_cwd
        setting = _config_setting(argv)
        if setting == "mirror":
            branch_cwd = CONFIGURED_BY_ENVIRONMENT  # `git config remote.origin.mirror true && git push origin`
        elif branch_cwd is not CONFIGURED_BY_ENVIRONMENT and (setting == "unknown" or _changes_branch(argv)):
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
