"""Catpilot PreToolUse hook for Claude Code: block high-blast-radius destructive CLI commands.

hooks/claude-code/pretooluse-destructive-ops.py runs this module's main(); hooks/harness/destructive_gate.py
calls decide(). It needs no other check module; it imports catpilot_guard/evidence.py only to write evidence.

Scope, stated exactly:
  - Runs only for the Bash tool (the matcher in settings selects it).
  - Splits the proposed command into simple commands the way a shell would
    (pipes, ;, &&, ||, subshells, and each line of a multi-line command), reads
    the commands inside compound commands (after if, then, elif, else, while,
    until, do, !, {, coproc and function NAME, so in `if ...; then CMD; fi`,
    `for ...; do CMD; done`, `{ CMD; }`, `! CMD`, case branches and function
    bodies), drops comments where bash does (an escaped character or a carriage
    return does not start a word, and a comment's trailing backslash does not
    continue it), reads a $'...' string as bash does (\\' inside it does not
    end it) and, when it holds \\', also as dash does, reads a command with a
    carriage return each way a shell may (bash keeps it in the word, bash on
    Windows may drop it before a line feed, PowerShell ends the line there),
    looks through sudo/env/time-style wrappers
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
        prod, staging, develop, or release/*, or at a branch the shell expands
        (`$b`, `"$BRANCH"`), including a bare `git push -f`
        while the checked-out branch is one of those; git push --mirror, --all
        or --branches with a force or --prune, and a forced or pruned refspec
        pattern (an option's value, as in -o ci.skip, is not read as the remote)
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


# Unquoted characters that end a word, so that a `#` after one starts a comment. To bash a carriage return is an
# ordinary character, part of its word, and so is an escaped character (`\ `, `\;`).
SHELL_WORD_BREAKS = set(" \t\n;&|()")
# Reserved words that can come first in a simple command as _simple_commands splits it. After each of them but the
# closing words comes a command that runs (`then git push ...`, `while git push ...`, `do rm ...`, `! git push ...`,
# `{ git push ...; }`); the closing words end a compound command, and only redirections can follow them (`} > out`).
# `time` (and `time -p`) is in WRAPPERS.
RESERVED_PREFIXES = {"if", "then", "elif", "else", "do", "while", "until", "!", "{", "}", "fi", "done", "esac"}
# Reserved words that begin a compound command: `coproc NAME` is followed by one (`coproc NAME { cmd; }`); before a
# simple command there is no NAME (`coproc cmd args`).
COMPOUND_STARTS = {"{", "if", "while", "until", "for", "case", "select", "[["}
# Carriage returns that end a line where a CR-LF line ending is read as a line feed: before one, or at the very end.
CR_LINE_ENDING = re.compile(r"\r+(?=\n)|\r+\Z")


def _strip_comments(command: str, ansi_c: bool = True) -> str:
    """The command as a shell reads it before splitting it into words: comments dropped, each backslash-newline
    removed, and, with ansi_c, each ANSI-C string ($'...') written as a plain single-quoted string, so that the lexer
    splits words and lines where bash does. Without ansi_c, `$'` is `$` and a plain single quote, as dash reads it.

    A comment is an unquoted `#` at the start of a word, up to the end of its line: a quote character in one
    (`# what's left`) does not open a quote, and a backslash at its end does not continue it onto the next line. A
    word starts at the start of the command and after an unquoted, unescaped space, tab, newline or one of `;&|()`;
    after an escaped character (`a\\ #`), a carriage return or anything else, `#` is part of the word. A
    backslash-newline joins two lines, outside single quotes and when the backslash is not itself escaped. In
    $'...' a backslash escapes the next character, so `\\'` does not end it. The newline that ends a comment is kept."""
    out, i, quote, n = [], 0, None, len(command)
    word_start = True  # the next character starts a word
    while i < n:
        c = command[i]
        if quote == "'":
            out.append(c)
            if c == "'":
                quote = None
        elif quote == "$'":
            if c == "\\" and i + 1 < n:
                escaped = command[i + 1]
                # Inside the single-quoted copy: \' becomes ' (close, a quoted ', reopen), \\ becomes \; any other
                # escape stays as it is written, which does not change where the string ends.
                out.append("'\"'\"'" if escaped == "'" else "\\" if escaped == "\\" else command[i:i + 2])
                i += 2
                continue
            out.append(c)
            if c == "'":
                quote = None
        elif c == "\\" and i + 1 < n:
            if command[i + 1] != "\n":  # a backslash-newline is removed: the line goes on
                out.append(command[i:i + 2])
                word_start = False
            i += 2
            continue
        elif quote == '"':
            out.append(c)
            if c == '"':
                quote = None
        elif c == "$" and command.startswith("$$", i):
            out.append("$$")  # the shell's process id, so a quote after it is an ordinary one
            word_start = False
            i += 2
            continue
        elif ansi_c and c == "$" and command.startswith("$'", i):
            quote = "$'"
            out.append("'")
            word_start = False
            i += 2
            continue
        elif c in "'\"":
            quote = c
            out.append(c)
        elif c == "#" and word_start:
            end = command.find("\n", i)
            i = n if end == -1 else end
            continue
        else:
            out.append(c)
        word_start = quote is None and c in SHELL_WORD_BREAKS
        i += 1
    return "".join(out)


def _tokens(command: str, ansi_c: bool = True) -> list[str]:
    """The command's words and operators. An unquoted newline separates commands, as in a shell, a backslash-newline
    joins two lines into one, and comments are dropped, so every line of a multi-line command is read."""
    command = _strip_comments(command, ansi_c)
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
        lexer.whitespace = " \t"
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ValueError:
        # Unbalanced quotes: fall back to whitespace splitting with quotes stripped.
        return [t.strip("\"'") for t in command.replace("\n", " ; ").replace(";", " ; ").replace("&&", " && ").replace("|", " | ").split()]


def _readings(command: str, depth: int = 0) -> list:
    """(text, ansi_c) for each way a shell that may run the command reads it. Every reading is checked.

    A carriage return: bash and zsh read it as an ordinary character, part of its word, so `main\\r` is not main;
    bash on Windows may read a CR-LF line ending as a line feed, and PowerShell reads a carriage return as a line
    break. The tool's own shell may be any of these, so the command it is given (depth 0) is read all three ways; the
    text of a `bash -c` string inside it is as each reading left it.
    `$'...'`: bash, zsh and ksh read an ANSI-C string, which `\\'` does not end; dash (`sh` on Debian and Ubuntu) reads
    `$` and a plain single-quoted string, which `\\'` does end. Only a string with `\\'` in it ends in a different
    place, so a command with both `$'` and `\\'` is read both ways, at every depth (`sh -c` may start dash)."""
    texts = [command]
    if depth == 0 and "\r" in command:
        texts = list(dict.fromkeys([command, CR_LINE_ENDING.sub("", command), command.replace("\r", "\n")]))
    both = (True, False)
    return [(text, ansi_c) for text in texts for ansi_c in (both if "$'" in text and "\\'" in text else both[:1])]


def _simple_commands(command: str, depth: int = 0):
    """Yield argv lists for each simple command, with wrappers and leading reserved words removed and `sh -c` bodies
    expanded. A command with a carriage return, or with a $'...' string holding \\', is read each way a shell may
    read it (_readings); a simple command a later reading repeats is yielded once."""
    seen: set = set()
    for number, (reading, ansi_c) in enumerate(_readings(command, depth)):
        current: list[str] = []
        for token in _tokens(reading, ansi_c) + [";"]:
            if token in SEPARATORS or set(token) <= set(";&|()\n"):
                for argv in _unwrap(current, depth) if current else ():
                    if number == 0 or tuple(argv) not in seen:
                        seen.add(tuple(argv))
                        yield argv
                current = []
            else:
                current.append(token)


def _strip_wrappers(argv: list[str]) -> list[str]:
    """Drop leading assignments, reserved words (`then`, `do`, `!`, `{`, ...; `coproc` and a NAME before a compound
    command; `function NAME`) and wrapper commands (sudo, env, timeout 60, ...) with their options. Only the first
    word of a simple command can be a reserved word, so `echo then` keeps its argument."""
    while True:
        while argv and ASSIGNMENT.match(argv[0]):
            argv = argv[1:]
        if not argv:
            return argv
        word = argv[0].lstrip("`")
        if word in RESERVED_PREFIXES:
            argv = argv[1:]
            continue
        if word == "coproc":
            argv = argv[2:] if len(argv) > 2 and argv[2] in COMPOUND_STARTS else argv[1:]
            continue
        if word == "function":
            argv = argv[2:]  # function NAME { ...; }: the body follows the name
            continue
        name = os.path.basename(word)
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


# git push options that take their value as the next argument.
PUSH_VALUE_OPTIONS = {"--push-option", "--repo", "--receive-pack", "--exec", "--recurse-submodules"}
# git's own options, before the subcommand, that take their value as the next argument. -C and --git-dir also say
# which repository's HEAD a bare push uses.
GIT_VALUE_OPTIONS = {"-c", "--work-tree", "--namespace", "--super-prefix", "--config-env", "--list-cmds"}


def git_push_rewrites(args: list[str], cwd: str) -> tuple[bool, list[str | None]] | None:
    """What a `git` command's push would rewrite or delete: None when it is not a push, else (mirror, branches).

    `args` are git's arguments without its name. mirror is True when the push can rewrite or delete every branch:
    `--mirror`; `--all` or `--branches` with a force or `--prune`; and a refspec whose destination is a pattern
    (`refs/heads/*`) with a force, a `+`, `--prune` or `--delete`. Options that take a value (`-o`/`--push-option`,
    `--repo`, `--receive-pack`, `--exec`, `--recurse-submodules`) take it, so the value is not read as the remote, and
    git's own value options before `push` (`-C`, `-c`, `--git-dir`, `--work-tree`, `--namespace`, ...) take theirs;
    `-C` and `--git-dir` also say whose HEAD a bare push uses.
    branches are the destination branches a force push (--force, -f, --force-with-lease, --force-if-includes or a
    +refspec), a deletion (--delete, -d, or an empty source `:branch`) aims at, with refs/heads/ stripped and HEAD
    read as the checked-out branch ("" when that is unknown). A bare force push, with no refspec, adds the
    checked-out branch, or None when it is detached or there is no repository. The built-in check
    (_git_finding) and the company-rules hook (catpilot_guard/company_rules.py) both read pushes this way.
    """
    index, repo, git_dir_path = 0, cwd, None
    while index < len(args) and args[index].startswith("-"):
        arg = args[index]
        if arg == "-C" and index + 1 < len(args):
            repo = os.path.join(repo, os.path.expanduser(args[index + 1]))
            index += 2
        elif arg == "--git-dir" and index + 1 < len(args):
            git_dir_path = args[index + 1]
            index += 2
        elif arg.startswith("--git-dir="):
            git_dir_path = arg[len("--git-dir="):]
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
    branches: list[str | None] = []
    if not mirror:
        for spec in positional[1:]:
            plus = spec.startswith("+")
            spec = spec.lstrip("+")
            source, _, destination = spec.partition(":") if ":" in spec else (spec, "", spec)
            if "*" in destination and (delete or plus or force or prune):
                mirror = True  # a pattern can rewrite or delete every branch it covers
                branches = []
                break
            if not (delete or plus or force or (":" in spec and source == "")):
                continue
            destination = destination[len("refs/heads/"):] if destination.startswith("refs/heads/") else destination
            if destination == "HEAD":
                destination = current_branch(repo, git_dir_path) or ""
            branches.append(destination)
        if not mirror and force and len(positional) <= 1:
            branches.append(current_branch(repo, git_dir_path))
    return mirror, branches


def _git_finding(args: list[str], cwd: str) -> bool:
    push = git_push_rewrites(args, cwd)
    if push is None:
        return False
    mirror, branches = push
    # A destination the shell expands (`$b`, `"$BRANCH"`, `$(...)`, a backquote) cannot be read here, and may be a
    # protected branch (`for b in main; do git push -f origin $b; done`): like a branch that cannot be read, it blocks.
    return mirror or any(
        branch is None or PROTECTED_BRANCH.match(branch) or "$" in branch or "`" in branch for branch in branches
    )


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
    for argv in _simple_commands(command):
        name, args = argv[0], argv[1:]
        if name == "rm" and _rm_finding(args):
            return RM_LABEL, RM_NOTE
        if name == "git" and _git_finding(args, working_dir):
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
