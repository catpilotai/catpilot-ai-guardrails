"""Catpilot PreToolUse hook for Claude Code: block high-blast-radius destructive CLI commands.

hooks/claude-code/pretooluse-destructive-ops.py runs this module's main(); hooks/harness/destructive_gate.py
calls decide(). It needs no other check module; it imports catpilot_guard/evidence.py only to write evidence.

Scope, stated exactly:
  - Runs for the Bash and PowerShell tools (the matcher in settings selects them). A PowerShell command, and a
    `pwsh -Command`, `powershell -c` or `cmd /c` script inside a bash command, is read with PowerShell's or cmd's
    rules (catpilot_guard/powershell.py), and also checked for recursive Remove-Item, rd /s or del /s of a drive
    root, a system directory, home, a credential directory or a bare variable, and for Format-Volume, Clear-Disk,
    Remove-Partition, format <drive>:, diskpart, cipher /w and vssadmin delete shadows. On Windows, a Bash event
    from Codex or Copilot CLI, which may carry a PowerShell command, is read both ways.
  - Splits the proposed command into simple commands the way a shell would
    (pipes, ;, &&, ||, subshells, and each line of a multi-line command; a
    quoted or escaped operator such as ';' or \\; is a word), reads
    the commands inside compound commands (after if, then, elif, else, while,
    until, do, !, {, coproc and function NAME, so in `if ...; then CMD; fi`,
    `for ...; do CMD; done`, `{ CMD; }`, `! CMD` and function bodies), reads
    each command substitution's command ($( ), backquotes, <( ), >( ), also in
    double quotes) as a command of its own while keeping its word in place,
    drops redirections with their targets (`>/dev/null CMD`, `2>&1 CMD`,
    `git push -f > log`), ends a word at an unquoted < or > (`rm -rf ~>/dev/null`),
    reads a heredoc body as literal text whose lines are commands, drops
    comments only where bash does (not after an escaped character, a carriage
    return or the ) that ends $( ), <( ) or $(( )), and never inside quotes,
    ${ }, arithmetic or a heredoc body; a comment in backquotes ends at the next
    unescaped backquote; `case` statements are read with their patterns; a
    comment's trailing backslash does not continue it), reads a $'...'
    string as bash does (\\' inside it does not end it) and, when that can
    differ, also as dash does (a $'...' holding \\', or &>), reads a command with a
    carriage return each way a shell may (bash keeps it in the word, bash on
    Windows may drop it before a line feed, PowerShell ends the line there, a
    shell may ignore it), looks through sudo/env/time-style wrappers
    (also timeout, gtimeout, stdbuf, ionice, setsid, unbuffer, xargs, zsh's
    noglob, nocorrect, repeat N and =cmd, and the string of `env -S`) with their
    options, short or long, separate, attached or at the end of a cluster
    (WRAPPER_OPTIONS; an option not listed is read both as taking a value and
    as taking none; what xargs reads from its input is unknown, so a force push
    or deletion of it blocks), a shell's here-string
    (`bash <<< 'CMD'`) and a shell's command string, whatever redirections and
    options come first (`bash -c "..."`, `bash -lc`, `sh -ec`, `bash -o pipefail -c`,
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
        that may be one of those (`$b`, `"$BRANCH"`, `release/$V`: BranchPattern),
        including a bare `git push -f`
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
  - Fails closed: malformed or oversized input, a check that runs past
    HOOK_TIME_LIMIT_SECONDS (7 s; within_time_limit, SIGALRM) or a reading past
    READ_BUDGET_SECONDS (6 s), a command over MAX_COMMAND_CHARS_WITHOUT_TIMER
    where there is no such timer, or any unexpected error, exits 2 (the host
    treats that as a blocking error).

What it is not: an adversarial control. It catches the accidental destructive
command an agent proposes; a command deliberately obfuscated (eval, base64,
variables holding the verb) can pass. Ordinary scoped work is not blocked:
removing a subdirectory of your home, a build directory, or force-pushing a
feature branch.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import bisect
import fnmatch
import json
import os
import re
import shlex
import signal
import sys
import threading
import time
from pathlib import Path

from . import decision_for_host, event_for_host, hook_host, take_evidence_default, write_decision, write_reason

MAX_INPUT_BYTES = 1_048_576

class _Then:
    """A match of `first` and, after it, of `then`: what the regex `first.*?then` (DOTALL) matches, found with one
    search for each instead of one `.*?` scan from every `first`, so the time is linear in the command's length.
    unless: a pattern that must not come after the last `then` (aws s3 rm ... --recursive with no --dryrun after)."""

    def __init__(self, first: str, then: str, flags: int = 0, unless: str | None = None):
        self.first = re.compile(first, flags)
        self.then = re.compile(then, flags)
        self.unless = re.compile(unless, flags) if unless else None

    def search(self, command: str) -> bool:
        first = self.first.search(command)
        if first is None:
            return False
        if self.unless is None:
            return self.then.search(command, first.end()) is not None
        last = None
        for last in self.then.finditer(command, first.end()):
            pass
        return last is not None and self.unless.search(command, last.end()) is None


class _AnyOf:
    """Any of several matchers."""

    def __init__(self, *matchers):
        self.matchers = matchers

    def search(self, command: str) -> bool:
        return any(matcher.search(command) for matcher in self.matchers)


class _PipeIntoSudoShell:
    """`curl` or `wget` piped into `sudo bash|sh|zsh`: for each `| sudo SHELL`, only the pipeline segment before it
    (from the previous `|` or newline) is read, so the time is linear (the regex this replaces scanned to the end of
    the line from every curl)."""

    PIPE = re.compile(r"\|\s*sudo\s+(?:bash|sh|zsh)\b", re.IGNORECASE)
    SEPARATOR = re.compile(r"[|\n]")
    FETCH = re.compile(r"\b(?:curl|wget)\b", re.IGNORECASE)

    def search(self, command: str) -> bool:
        separators = [m.start() for m in self.SEPARATOR.finditer(command)]
        for pipe in self.PIPE.finditer(command):
            begin = bisect.bisect_left(separators, pipe.start())
            if self.FETCH.search(command, separators[begin - 1] + 1 if begin else 0, pipe.start()):
                return True
        return False


class _ExfiltrationPipe:
    """`cat` of a credential file (~/.ssh/, ~/.aws/, .netrc, ...), or `env` / `printenv`, piped into a network client
    (curl, wget, http, xh, nc, socat), blanks and newlines allowed around the `|`. For each `|` before a client, only
    the pipeline segment before it is read (from the previous `|`, `;` or newline), so the time is linear in the
    command's length: the single regex this replaces backtracked, in cubic time."""

    PIPE = re.compile(r"\|\s*(?:curl|wget|http|xh|nc|socat)\b", re.IGNORECASE)
    SEPARATOR = re.compile(r"[|;\n]")
    CAT = re.compile(r"\bcat\s", re.IGNORECASE)
    CREDENTIAL = re.compile(r"\.ssh/|\.aws/|\.openclaw/|\.config/gcloud/|\.kube/|\.gnupg/|\.netrc", re.IGNORECASE)
    DUMP = re.compile(r"\b(?:env|printenv)\Z", re.IGNORECASE)

    def search(self, command: str) -> bool:
        separators = [m.start() for m in self.SEPARATOR.finditer(command)]
        for pipe in self.PIPE.finditer(command):
            end = pipe.start()
            while end > 0 and command[end - 1].isspace():
                end -= 1
            begin = bisect.bisect_left(separators, end)  # the separators before the segment's end
            segment = command[separators[begin - 1] + 1 if begin else 0:end]
            cat = self.CAT.search(segment)
            if (cat and self.CREDENTIAL.search(segment, cat.end())) or self.DUMP.search(segment):
                return True
        return False


# --- whole-command signatures (cloud and infrastructure CLIs) -------------------------------
# (label, compiled_pattern, safe_alternative_note)
DESTRUCTIVE_PATTERNS = [
    (
        "az containerapp partial-YAML or replace-env-vars reset",
        _Then(r"\baz\s+containerapp\s+update\b", r"\s(?:--yaml|--replace-env-vars)\b", re.IGNORECASE),
        "Query current state with `az containerapp show` first and use `--set-env-vars` (which merges) or include the full resource specification.",
    ),
    (
        "aws lambda environment full-map replacement",
        _Then(r"\baws\s+lambda\s+update-function-configuration\b", r"\s--environment\s+[\"']?Variables=\{", re.IGNORECASE),
        "Query existing variables with `aws lambda get-function-configuration`, merge them in a JSON file, and pass the complete merged map from that file.",
    ),
    (
        "gcloud projects set-iam-policy full-binding replacement",
        re.compile(r"\bgcloud\s+projects\s+set-iam-policy\b", re.IGNORECASE),
        "Use `gcloud projects add-iam-policy-binding` so existing IAM bindings are preserved.",
    ),
    (
        "gcloud run services update --set-env-vars replacement",
        _Then(r"\bgcloud\s+run\s+services\s+update\b", r"\s--set-env-vars\b", re.IGNORECASE),
        "Use `gcloud run services update --update-env-vars` so existing environment variables are preserved.",
    ),
    (
        "gcloud quiet service or version deletion",
        _Then(r"\bgcloud\s+(?:app\s+versions\s+delete\s+--all|run\s+services\s+delete\b)", r"\s--quiet\b", re.IGNORECASE),
        "Inspect existing revisions/versions first and require interactive confirmation before deleting.",
    ),
    (
        "terraform auto-approve apply or destroy",
        # terraform or OpenTofu (`tofu`, same CLI), with global options such as -chdir=DIR before the subcommand.
        _Then(r"\b(?:terraform|tofu)(?:\s+-\S+)*\s+(?:apply|destroy)\b", r"\s--?auto-approve\b(?!=false)", re.IGNORECASE),
        "Run `terraform plan -out=tfplan`, show the plan to the user, and apply the reviewed plan without `-auto-approve`.",
    ),
    (
        "aws s3 recursive delete or force bucket removal",
        _AnyOf(
            _Then(r"\baws\s+s3\s+rb\b", r"\s--force\b", re.IGNORECASE),
            _Then(r"\baws\s+s3\s+rm\b", r"\s--recursive\b", re.IGNORECASE, unless=r"--dryrun"),
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
        _Then(r"\bdd\b", r"\bof=/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+|rdisk\d+)\b", re.IGNORECASE),
        "Never write directly to raw block devices from an agent session.",
    ),
    (
        "credential or environment exfiltration pipe to network client",
        _ExfiltrationPipe(),
        "Never pipe local credentials, SSH keys, or environment dumps into an outbound network request.",
    ),
    (
        "pipe-to-shell with sudo",
        _PipeIntoSudoShell(),
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
def _options(value: str = "", flags: str = "", long_value: tuple = (), long_flags: tuple = (), optional: str = "",
             split: str = "", long_split: tuple = (), replace: str = "", optional_replace: str = "",
             long_replace: tuple = (), positionals: int = 0) -> dict:
    """One wrapper's options. value: short options that take a value, attached (-uroot) or as the next word (-u
    root), also at the end of a cluster (-iC DIR); flags: short options that take none; optional: short options whose
    value is optional and only attached (xargs -e, -l); long_value and long_flags likewise (--user root, --user=root,
    an unambiguous prefix as getopt_long accepts; a long option whose value is optional takes it only after `=`, so
    it is listed as a flag). split: env -S STRING, whose words env runs. replace: xargs -I R, whose R in the command is
    replaced by input; optional_replace (-i[R]) and long_replace (--replace[=R]) default R to {}. positionals: words
    after the options and before the command (timeout's DURATION)."""
    return {"value": value, "flags": flags, "optional": optional, "long_value": set(long_value),
            "long_flags": set(long_flags), "split": split, "long_split": set(long_split), "replace": replace,
            "optional_replace": optional_replace, "long_replace": set(long_replace), "positionals": positionals}


TIMEOUT_OPTIONS = _options("ks", "v", ("--kill-after", "--signal"),
                           ("--foreground", "--preserve-status", "--verbose", "--help", "--version"), positionals=1)
# Commands that run the command after their options, each with its options (sudo(8), doas(1), env(1) GNU and BSD,
# xargs(1) GNU and BSD, nice(1), time(1), timeout(1), ...). An option not listed is read both ways, as taking the
# next word and as taking none, so an option this table does not know cannot hide the command.
WRAPPER_OPTIONS = {
    "sudo": _options("aCcDghpRrTtUu", "AbBEeHiKklNnPSsVv",
                     ("--chdir", "--chroot", "--close-from", "--command-timeout", "--group", "--host", "--other-user",
                      "--prompt", "--role", "--type", "--user"),
                     ("--askpass", "--background", "--bell", "--edit", "--help", "--list", "--login", "--no-update",
                      "--non-interactive", "--preserve-env", "--preserve-groups", "--remove-timestamp",
                      "--reset-timestamp", "--set-home", "--shell", "--stdin", "--validate", "--version")),
    "doas": _options("aCu", "Lns"),
    "env": _options("aCLPuU", "0iv", ("--argv0", "--chdir", "--unset"),
                    ("--block-signal", "--debug", "--default-signal", "--help", "--ignore-environment",
                     "--ignore-signal", "--list-signal-handling", "--null", "--version"),
                    split="S", long_split=("--split-string",)),
    "command": _options("", "pVv"),
    "builtin": _options(),
    "exec": _options("a", "cl"),
    "nohup": _options(long_flags=("--help", "--version")),
    "time": _options("fo", "ahlpqv", ("--format", "--output"),
                     ("--append", "--help", "--portability", "--quiet", "--verbose", "--version")),
    "nice": _options("n", "0123456789", ("--adjustment",), ("--help", "--version")),  # nice -5: an old-style value
    "xargs": _options("adELnPRSs", "0oprtx",
                      ("--arg-file", "--delimiter", "--max-args", "--max-chars", "--max-procs", "--process-slot-var"),
                      ("--eof", "--exit", "--help", "--interactive", "--max-lines", "--no-run-if-empty", "--null",
                       "--open-tty", "--show-limits", "--verbose", "--version"),
                      optional="el", replace="IJ", optional_replace="i", long_replace=("--replace",)),
    "caffeinate": _options("tw", "dimsu"),
    "noglob": _options(),  # zsh precommand modifiers (not `-`: a Markdown bullet in a heredoc body is not a command)
    "nocorrect": _options(),
    "timeout": TIMEOUT_OPTIONS,
    "gtimeout": TIMEOUT_OPTIONS,
    "stdbuf": _options("eio", "", ("--error", "--input", "--output"), ("--help", "--version")),
    "ionice": _options("cnPpu", "t", ("--class", "--classdata", "--pgid", "--pid", "--uid"),
                       ("--help", "--ignore", "--version")),
    "setsid": _options("", "cfw", (), ("--ctty", "--fork", "--wait", "--help", "--version")),
    "unbuffer": _options("", "p"),
    "repeat": _options(positionals=1),  # zsh: repeat N COMMAND
}
# The wrappers as _points_git_elsewhere reads them, word by word, for assignments a wrapper passes on: each one's
# options that take a separate value, and the positional arguments before its command (timeout's DURATION).
WRAPPERS = {"sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice", "xargs", "caffeinate"}
TIMEOUT_VALUE_OPTIONS = {"-s", "--signal", "-k", "--kill-after"}
WRAPPER_SPECS = {
    "timeout": (TIMEOUT_VALUE_OPTIONS, 1),
    "gtimeout": (TIMEOUT_VALUE_OPTIONS, 1),
    "stdbuf": ({"-i", "-o", "-e"}, 0),
    "ionice": ({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}, 0),
    "setsid": (set(), 0),
    "unbuffer": (set(), 0),
}
# What xargs puts in its command from its input: unknown here, so it is written as a substitution would be, which a
# force push or deletion cannot be read past (`... | xargs -I {} git push origin --delete {}`).
XARGS_INPUT = "`xargs input`"
# The most readings of one simple command's wrappers; past it the command cannot be read and the hook blocks.
MAX_WRAPPER_READINGS = 64
SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
# Shell options that take a separate value (`bash -o pipefail -c ...`, `bash --rcfile FILE -c ...`).
SHELL_VALUE_OPTIONS = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=")
KUBECTL_VALUE_FLAGS = {"-n", "--namespace", "-l", "--selector", "-f", "--filename", "-o", "--output", "--context",
                       "--cluster", "--kubeconfig", "--field-selector", "--grace-period", "--timeout", "-k", "--kustomize",
                       "-s", "--server", "--user", "--token", "--as"}
SEPARATORS = {";", "&", "&&", "|", "||", "|&", "(", ")", "\n"}


# Unquoted characters that end a word in a command, so that a `#` after one starts a comment. To bash a carriage
# return is an ordinary character, part of its word, and so is an escaped character (`\ `, `\;`).
SHELL_WORD_BREAKS = set(" \t\n;&|()")
SEPARATOR_CHARS = set(";&|()\n")
# Reserved words that can come first in a simple command as _simple_commands splits it. After each of them but the
# closing words comes a command that runs (`then git push ...`, `while git push ...`, `do rm ...`, `! git push ...`,
# `{ git push ...; }`); the closing words end a compound command, and only redirections can follow them (`} > out`).
# `time` (and `time -p`) is in WRAPPER_OPTIONS.
RESERVED_PREFIXES = {"if", "then", "elif", "else", "do", "while", "until", "!", "{", "}", "fi", "done", "esac"}
# Reserved words that begin a compound command: `coproc NAME` is followed by one (`coproc NAME { cmd; }`); before a
# simple command there is no NAME (`coproc cmd args`).
COMPOUND_STARTS = {"{", "if", "while", "until", "for", "case", "select", "[["}
# Carriage returns that end a line where a CR-LF line ending is read as a line feed: before one, or at the very end.
CR_LINE_ENDING = re.compile(r"\r+(?=\n)|\r+\Z")
# _scan puts this before each redirection it reads (unquoted, so a real one), with its fd number, operator and
# target: `2>&1`, `>/dev/null`, `> log`. A NUL, which bash drops from its input, cannot be in a command otherwise.
REDIRECT = "\x00"
# _scan puts this in a word where a quote opens or a character is escaped, so that a quoted or escaped `;`, `|` or
# `&` (`rm -rf ';' ~`) is a word, not an operator; it is taken out of every word after the split. A command with it
# (SOH, a control character no command needs) cannot be read.
QUOTED = "\x01"
REDIRECTION_OPERATOR = re.compile(r"<<<|<<-|<<|<>|<&|<|>>|>\||>&|>")
FD_PREFIX = re.compile(r"\d+|\{[A-Za-z_][A-Za-z0-9_]*\}")
HERE_STRING = re.compile(r"0?<<<")
# The command of a substitution that asks git for the checked-out branch (CURRENT_BRANCH_SUBSTITUTION): in double quotes
# _scan keeps it in its word instead of the `$()` placeholder.
CURRENT_BRANCH_COMMAND = re.compile(
    r"[ \t]*git[ \t]+(?:branch[ \t]+--show-current|rev-parse[ \t]+--abbrev-ref[ \t]+HEAD"
    r"|symbolic-ref[ \t]+(?:-q[ \t]+)?--short[ \t]+HEAD)[ \t]*")
# A first word that may expand to nothing, so the word after it is the command: a substitution's placeholder ($( ),
# backquotes) or a variable (`$(echo) rm -rf ~`, `$EMPTY rm -rf ~`).
EXPANSION_WORD = re.compile(r"(?:\$\(\(?\)?\)|\$[A-Za-z_][A-Za-z0-9_]*|\$\{(?:[^{}]|\{[^{}]*\})*\}|\$[@*#?$!0-9_-])+")
# Expansions at the start of a first word, which may expand to nothing: `$(echo)rm` and `${X}rm` run rm.
EXPANSION_PREFIX = re.compile(r"(?:\$\(\(?\)?\)|\$\{(?:[^{}]|\{[^{}]*\})*\})+")
# The innermost contexts (subshells aside) in which a `#` that begins a word starts a comment: the command itself, a
# command or process substitution, and backquotes. Never quotes, `${ }`, arithmetic or a heredoc body.
COMMENT_CONTEXTS = (None, "$(", "$(-", "`")
# The contexts _scan reads as a substitution, in a buffer of its own: $( ), <( ), >( ), backquotes, and $(( )).
BUFFERED = ("$(", "`", "$((")
# Words after which the next word is still in command position (`if case ...`, `! case ...`).
COMMAND_PREFIX_WORDS = {"if", "then", "elif", "else", "do", "while", "until", "!", "{", "time"}
# Reading stops past this many seconds and the hook blocks (main exits 2), so that a command that is slow to read is
# refused before the tool's hook timeout (10 s in deploy/org) runs out: Codex and Copilot CLI run a timed-out call.
READ_BUDGET_SECONDS = 6.0


# The hooks' whole check (the signatures' regexes, reading the command, one long lexer call) stops after this many
# seconds: within_time_limit's SIGALRM raises ReadTimeout wherever the check is, and main() exits 2.
HOOK_TIME_LIMIT_SECONDS = 7.0
# Where that timer is not running (Windows has no SIGALRM; a harness calls decide() itself), a longer command is
# refused instead, since nothing would stop a slow reading of it.
MAX_COMMAND_CHARS_WITHOUT_TIMER = 200_000
_timer = {"armed": False}


class ReadTimeout(ValueError):
    """Reading the command took too long, or would. A ValueError, so every caller fails closed."""


def _deadline(deadline: float | None = None) -> float:
    return time.monotonic() + READ_BUDGET_SECONDS if deadline is None else deadline


def within_time_limit(function, *args, **kwargs):
    """function(*args, **kwargs), stopped by ReadTimeout after HOOK_TIME_LIMIT_SECONDS: SIGALRM interrupts Python
    code and the regex engine alike. Without SIGALRM (Windows) or off the main thread it runs without the timer, and
    check_command_size refuses a long command."""
    if not hasattr(signal, "setitimer") or threading.current_thread() is not threading.main_thread():
        return function(*args, **kwargs)

    def expire(signum, frame):
        raise ReadTimeout("the check took too long")

    previous = signal.signal(signal.SIGALRM, expire)
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGALRM})  # an inherited mask must not hold the alarm back
    signal.setitimer(signal.ITIMER_REAL, HOOK_TIME_LIMIT_SECONDS)
    _timer["armed"] = True
    try:
        return function(*args, **kwargs)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        _timer["armed"] = False


def check_command_size(command: str) -> None:
    """Raise ReadTimeout for a command longer than MAX_COMMAND_CHARS_WITHOUT_TIMER when no timer is running."""
    if not _timer["armed"] and len(command) > MAX_COMMAND_CHARS_WITHOUT_TIMER:
        raise ReadTimeout("the command is too long to read without a time limit")


def _strip_comments(command: str, bash: bool = True) -> str:
    """The command as a shell reads it before splitting it into words (_scan)."""
    return _scan(command, bash)[0].replace(QUOTED, "")


def _literal(text: str) -> str:
    """text with every character the lexer could read as quoting or an operator escaped."""
    return re.sub(r"([^A-Za-z0-9_\n])", r"\\\1", text)


ANSI_C_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v",
                 "\\": "\\", "'": "'", '"': '"', "?": "?"}
ANSI_C_NUMERIC = {"x": (16, 2), "u": (16, 4), "U": (16, 8)}


def _ansi_c_escape(command: str, i: int) -> tuple:
    """(text, next index) for the escape at command[i] (a backslash) inside $'...', as bash 5 reads it: \\n, \\t and
    the other letters, \\NNN (octal), \\xHH, \\uHHHH, \\UHHHHHHHH and \\cX, written for a single-quoted copy (a `'` closes
    the quote, is quoted, and reopens it). A NUL, or a character the reader uses as a marker, is dropped (bash ends the
    string's value at a NUL); an escape bash does not know stays as it is written."""
    escaped = command[i + 1]
    value, j = None, i + 2
    if escaped in ANSI_C_SIMPLE:
        value = ANSI_C_SIMPLE[escaped]
    elif escaped in "01234567":
        k = i + 1
        while k < len(command) and k < i + 4 and command[k] in "01234567":
            k += 1
        value, j = chr(int(command[i + 1:k], 8) & 0xFF), k
    elif escaped in ANSI_C_NUMERIC:
        base, most = ANSI_C_NUMERIC[escaped]
        k = i + 2
        while k < len(command) and k < i + 2 + most and command[k] in "0123456789abcdefABCDEF":
            k += 1
        if k > i + 2:
            code = int(command[i + 2:k], base)
            value, j = (chr(code) if code < 0x110000 else ""), k
    elif escaped == "c" and i + 2 < len(command) and command[i + 2] not in "'\\":
        value, j = chr(ord(command[i + 2]) & 0x1F), i + 3
    if value is None:
        return command[i:i + 2], i + 2
    if not value or value in (REDIRECT, QUOTED) or 0xD800 <= ord(value) <= 0xDFFF:
        return "", j
    return ("'\"'\"'" if value == "'" else value), j


def _scan(command: str, bash: bool = True, dq_comment: bool | None = None) -> tuple:
    """(text, posix_differs, dq_hash). text is the command as a shell reads it before splitting it into words: comments
    dropped, each backslash-newline removed, each redirection operator marked with REDIRECT and joined to its target
    (`> log` is one word, and `>&`, `<&`, `&>` and `>|` stay whole), a space put where an unquoted `<` or `>` ends a
    word, heredoc bodies made safe to split, each command substitution (`$( )`, backquotes, `<( )`, `>( )`, also in
    double quotes) replaced in its word by `$()`, `<()` or `>()` and its command put on a line of its own at the end,
    each arithmetic expansion replaced by `$(())`, and each ANSI-C string ($'...') written as a plain single-quoted
    string, so that the lexer splits words and lines where bash does: `rm -rf $(echo) ~` keeps ~ as rm's argument, and
    `URL="$(vercel --prod)"` reads the deploy. bash=False reads the command as dash does (and as bash 3.2 does
    `{fd}>file`): `$'` is `$` and a plain single quote, `&>` is `&` then `>`, and `{fd}>file` is the word `{fd}` then
    `>file`; posix_differs is True when that reading can differ. dq_comment says whether a `#` that begins a word
    inside `$( )` inside double quotes starts a comment, as in bash 4 and later, dash and zsh, or is text, as in bash
    3.2 (default: as dash, so True when bash is False); dq_hash is True when the command has such a `#`.

    A comment is an unquoted `#` at the start of a word, up to the end of its line, or to the backquote that ends the
    backquoted command it is in: a quote character in one (`# what's left`) does not open a quote, and a backslash at
    its end does not continue it onto the next line. A word starts at the start of the command and after an unquoted,
    unescaped space, tab, newline or one of `;&|()`; after an escaped character (`a\\ #`), a carriage return, the `)`
    that ends `$( )`, `$(( ))`, `<( )` or `>( )`, or anything else, `#` is part of the word. A `#` starts a comment in
    the command itself, a subshell, a command substitution and backquotes, and never inside quotes, `${ }`,
    arithmetic or a heredoc body; while backquotes are open, a comment ends at the next unescaped backquote, which
    ends them in bash whatever lies between. A `case` statement is read with its patterns, so the `)` that ends a
    pattern (`$(case x in a) ...;; esac)`) does not end a subshell or substitution; `esac` ends it as the first word of
    a pattern list or of a command in a branch, and `case`, `in` and `esac` are read across backslash-newlines. A heredoc's body (the lines after the line
    with `<<WORD` or `<<-WORD`, up to WORD) is literal text to the shell, apart from substitutions when WORD is
    unquoted, so its quote characters are escaped here: its lines are still read as commands, but cannot open a quote
    that hides the commands after it. Inside a command substitution a body is read as commands only when what takes it
    may run it (_heredoc_runs): `git commit -m "$(cat <<'EOF' ... EOF)"` is text, apart from the substitutions of an
    unquoted body; `"$(cat <<'EOF' | bash ... EOF)"` is commands. A backslash-newline joins two lines, outside single quotes and when the backslash
    is not itself escaped, and `$` followed by a backslash-newline is read with what comes after it
    (`$\\<newline>'...'` is an ANSI-C string). In $'...' a backslash escapes the next character, so `\\'` does not end
    it. A NUL character cannot be read (shells differ: bash drops it, zsh keeps it), so it raises ValueError. The
    newline that ends a comment is kept."""
    if REDIRECT in command or QUOTED in command:
        raise ValueError("the command contains a NUL or SOH character")
    dq_comment = (not bash) if dq_comment is None else dq_comment
    out: list = []
    posix_differs = dq_hash = False
    stack: list = []  # the open contexts, innermost last: ' " $' ` ${ $(( (( $( $(- ( << <<'
    inners: list = []  # for each level of stack, the innermost context there that is not a subshell `(`
    quoted = [0]  # how many double-quoted strings are open
    ticks = [0]  # how many backquoted commands are open
    outer: list = []  # for each open substitution: [the text around it, word_begin, placeholder, opener, read it]
    sides: list = []  # the commands of closed substitutions, each read as a line of its own
    cases: list = []  # open `case` statements, innermost last: [depth in stack, "head" | "pattern" | "body", a
    # pattern has begun (after which `esac` is a pattern, not the end)]
    i, n = 0, len(command)
    word_start = True  # in a command context, the next character starts a word
    word_begin = 0  # where in out the current word began, to tell an fd number before `>` (2>) from a word (~>)
    command_start = True  # the next word is in command position (where `case` and `esac` are reserved words)
    last_word = ""  # the last word that ended in command position (`time` before `-p`)
    function_name = False  # the next word is a function's name, after which a command may follow
    pending: list = []  # heredocs whose bodies begin after the current line: (word, strip tabs, literal)
    heredoc = None  # the heredoc whose body is being read: (word, strip tabs, its depth in stack)

    def push(context: str) -> None:
        stack.append(context)
        inners.append(context if context != "(" else (inners[-1] if inners else None))
        quoted[0] += context == '"'
        ticks[0] += context == "`"

    def pop() -> str:
        inners.pop()
        context = stack.pop()
        quoted[0] -= context == '"'
        ticks[0] -= context == "`"
        while cases and cases[-1][0] > len(stack):
            cases.pop()
        return context

    def retop(context: str) -> None:
        stack[-1] = context
        inners[-1] = context

    def past_continuations(j: int) -> int:
        while command.startswith("\\\n", j):
            j += 2
        return j

    def reserved_at(word: str) -> bool:
        """The word `word` begins at i, read across backslash-newlines (`ca\\<newline>se` is case)."""
        j = i
        for letter in word:
            j = past_continuations(j)
            if j >= n or command[j] != letter:
                return False
            j += 1
        j = past_continuations(j)
        return j >= n or command[j] in " \t\n;&|)"

    def start_heredoc() -> None:
        nonlocal heredoc
        word, strip_tabs, literal, begins, nested = pending.pop(0)
        # Outside a substitution a body is read as commands, as before; inside one (`"$(cat <<'EOF' ...)"`, the idiom
        # for commit messages and PR bodies) only when what takes it may run it (_heredoc_runs).
        runs = not nested or _heredoc_runs(command[begins:i])
        heredoc = (word, strip_tabs, len(stack), runs, literal)
        if runs:
            push("<<'" if literal else "<<")

    def open_substitution(context: str, placeholder: str, opener: str, read: bool = True) -> None:
        nonlocal out, word_start, word_begin, command_start
        outer.append([out, word_begin, placeholder, opener, read])
        push(context)
        out, word_start, word_begin, command_start = [], True, 0, True

    def close_substitution() -> None:
        nonlocal out, word_start, word_begin, command_start
        inner = "".join(out)
        out, word_begin, placeholder, _, read = outer.pop()
        if read:
            sides.append(inner)
        if stack and stack[-1] == '"':
            # In double quotes, a substitution that asks git for the checked-out branch keeps its text, which
            # git_push_rewrites reads as that branch (CURRENT_BRANCH_SUBSTITUTION); unquoted, it is split into words.
            if placeholder == "$()" and CURRENT_BRANCH_COMMAND.fullmatch(inner):
                placeholder = "$(" + " ".join(inner.split()) + ")"
            out.append(placeholder)
        else:
            out.append(_literal(placeholder))
        word_start = command_start = False  # the substitution ends inside its word: `$(date)#x` is one word

    while i < n:
        if heredoc is not None and not heredoc[3] and (i == 0 or command[i - 1] == "\n"):
            # A body nothing runs: passed over, apart from the substitutions in an unquoted one, which the shell
            # runs; they are read as a double-quoted string's would be, as an argument of `:`.
            word, strip_tabs, _, _, literal = heredoc
            j, body_end, after = i, n, n
            while j < n:
                end = command.find("\n", j)
                end = n if end == -1 else end
                line = command[j:end]
                if (line.lstrip("\t") if strip_tabs else line) == word:
                    body_end, after = j, end + 1
                    break
                j = end + 1
            body = command[i:body_end]
            if not literal and ("$" in body or "`" in body):
                text, differs, hashes = _scan(': "' + _double_quoted(body) + '"', bash, dq_comment)
                posix_differs, dq_hash = posix_differs or differs, dq_hash or hashes
                sides.append(text)
            out.append("\n")
            i = min(after, n)
            heredoc = None
            word_start, word_begin, command_start = True, len(out), True
            if pending:
                start_heredoc()
            continue
        if heredoc is not None and (i == 0 or command[i - 1] == "\n"):
            word, strip_tabs, depth = heredoc[:3]
            end = command.find("\n", i)
            end = n if end == -1 else end
            line = command[i:end]
            if (line.lstrip("\t") if strip_tabs else line) == word:  # the body ends: back to the command
                while len(stack) > depth:
                    if pop() in BUFFERED:
                        close_substitution()
                out.append("\n")
                i = end + 1
                heredoc = None
                word_start, word_begin, command_start = True, len(out), True
                if pending:
                    start_heredoc()
                continue
        c = command[i]
        top = stack[-1] if stack else None
        if ticks[0] and top != "`":
            if c == "\\" and command.startswith("`", i + 1) and top in ("'", "$'", "<<'"):
                out.append("\\`")  # an escaped backquote: it does not end the backquoted command
                i += 2
                continue
            if c == "`":
                # bash ends backquotes at the first unescaped backquote, whatever is open inside them (`echo '`)
                while stack and stack[-1] != "`":
                    if pop() in BUFFERED:
                        close_substitution()
                top = "`"
        if top == "'":
            out.append(c)
            if c == "'":
                pop()
            i += 1
            continue
        if top == "$'":
            if c == "\\" and i + 1 < n:
                escaped = command[i + 1]
                posix_differs = posix_differs or escaped == "'"
                # Inside the single-quoted copy, each escape is written as the character bash makes of it
                # (_ansi_c_escape): \' becomes ' (close, a quoted ', reopen), \\ becomes \, \x61 becomes a, so
                # `m$'\x61'in` is main; an escape bash keeps stays as it is written. None changes where the string ends.
                text, i = _ansi_c_escape(command, i)
                out.append(text)
                continue
            out.append(c)
            if c == "'":
                pop()
            i += 1
            continue
        if top == "<<'":  # a heredoc body with a quoted word: literal text
            out.append("\\" + c if c in "'\"\\$`" else c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            if command[i + 1] != "\n":  # a backslash-newline is removed: the line goes on
                out.append(QUOTED + command[i:i + 2])  # `\;` is a word, not an operator
                word_start = command_start = False
            i += 2
            continue
        if c == "$":
            j = past_continuations(i + 1)
            follow = command[j] if j < n else ""
            word_start = command_start = False  # a substitution opened here starts its own command
            if follow == "$":
                out.append("$$")  # the shell's process id, so a quote after it is an ordinary one
                i = j + 1
            elif follow == "'" and bash and top not in ('"', "<<"):
                push("$'")
                out.append(QUOTED + "'")
                i = j + 1
            elif follow == "{":
                push("${")
                out.append("${")
                i = j + 1
            elif follow == "(":
                k = past_continuations(j + 1)
                if k < n and command[k] == "(":
                    open_substitution("$((", "$(())", "$((", read=False)  # arithmetic: `rm -rf $((0)) ~` keeps ~
                    i = k + 1
                else:
                    open_substitution("$(", "$()", "$(")  # a command begins inside $( )
                    i = j + 1
            else:
                out.append(c)
                i += 1
            continue
        if top in ('"', "<<"):  # a double-quoted string, or a heredoc body with an unquoted word
            if c == "`":
                open_substitution("`", "$()", "`")
            elif top == '"':
                out.append(c)
                if c == '"':
                    pop()
            else:
                out.append("\\" + c if c in "'\"" else c)
            i += 1
            continue
        if top == "`" and c == "`":
            pop()
            close_substitution()
            i += 1
            continue
        if c == "`":
            open_substitution("`", "$()", "`")  # `cmd` is read like $(cmd)
            i += 1
            continue
        if c in "'\"":
            push(c)
            out.append(QUOTED + c)  # `';'` is a word, not an operator
            word_start = command_start = False
            i += 1
            continue
        if top == "${":
            out.append(c)
            if c == "}":
                pop()
            elif c == "{":
                push("${")  # zsh nests braces here; bash ends at the first `}`: nesting drops no text
            i += 1
            continue
        if top in ("$((", "((") and c == ")":
            if command.startswith(")", i + 1):
                pop()
                if top == "$((":
                    close_substitution()
                else:
                    out.append("))")
                    word_start = command_start = False
                i += 2
                continue
            if top == "$((":  # `$((cmd); ...)`: a command substitution whose first command is a subshell
                retop("$(")
                outer[-1][2], outer[-1][4] = "$()", True  # its placeholder and its command, as for $( )
                out.insert(0, "(")
            else:
                retop("$(-")
            out.append(c)
            word_start, word_begin, command_start = True, len(out), True
            i += 1
            continue
        if top in ("$((", "((") and c != "(":
            out.append(c)
            i += 1
            continue
        # A command context: the command itself, ( ), $( ), <( ), >( ) or backquotes; or a `(` inside arithmetic.
        inner = inners[-1] if inners else None
        if c == "#" and word_start and inner in COMMENT_CONTEXTS:
            if inner in ("$(", "$(-") and quoted[0]:
                dq_hash = True  # bash 3.2 reads no comment inside "$( )"; bash 4 and later, dash and zsh do
            if inner not in ("$(", "$(-") or not quoted[0] or dq_comment:
                end = command.find("\n", i)
                end = n if end == -1 else end
                if ticks[0]:  # bash ends backquotes at the first unescaped backquote, whatever lies between
                    j = i
                    while j < end and command[j] != "`":
                        j += 2 if command[j] == "\\" else 1
                    end = min(j, end)
                i = end
                continue
        if word_start and inner in COMMENT_CONTEXTS:
            if cases and cases[-1][0] == len(stack):
                state = cases[-1][1]
                if state == "head" and reserved_at("in"):
                    cases[-1][1] = "pattern"
                elif reserved_at("esac") and ((state == "pattern" and not cases[-1][2]) or
                                              (state == "body" and command_start)):
                    cases.pop()
                elif state == "pattern" and c not in SHELL_WORD_BREAKS:
                    cases[-1][2] = True  # a pattern has begun: `esac` after `(` or `|` is a pattern
            if command_start and reserved_at("case"):
                cases.append([len(stack), "head", False])
        in_pattern = bool(cases) and cases[-1][0] == len(stack) and cases[-1][1] == "pattern"
        if c == "(":
            if in_pattern and word_start:  # a pattern's optional `(`: `case x in (a) ...`
                cases[-1][2] = True
                out.append(c)
                i += 1
                continue
            if word_start and top not in ("$((", "((") and command.startswith("(", i + 1):
                push("((")  # `(( ))`: an arithmetic command
                out.append("((")
                i += 2
                word_start = command_start = False
                continue
            push("(")
            out.append(c)
            i += 1
            word_start, word_begin, command_start = True, len(out), True
            continue
        if c == ")":
            if in_pattern:  # the end of a case pattern, not of a subshell or substitution
                cases[-1][1] = "body"
                out.append(c)
                i += 1
                word_start, word_begin, command_start = True, len(out), True
                continue
            if top in ("$(", "$(-"):
                pop()
                if top == "$(":
                    close_substitution()
                else:
                    out.append(c)
                    word_start = command_start = False
                i += 1
                continue
            function = False
            if top == "(":
                pop()
                k = len(out)
                while k and out[k - 1] in (" ", "\t"):
                    k -= 1
                function = bool(k) and out[k - 1] == "("  # `f()`: a function's body, a command, follows
            out.append(c)
            i += 1
            word_start, word_begin, command_start = True, len(out), function
            continue
        if c in "<>":
            if command.startswith("(", i + 1):  # <( ) or >( ): a process substitution, part of its word (a<(x))
                open_substitution("$(", c + "()", c + "(")
                i += 2
                continue
            prefix = "".join(out[word_begin:]) if not word_start else ""
            if prefix and FD_PREFIX.fullmatch(prefix) and prefix.startswith("{"):
                posix_differs = True  # dash and bash 3.2 read `{fd}` as a word of its own
            if prefix and FD_PREFIX.fullmatch(prefix) and (bash or not prefix.startswith("{")):
                del out[word_begin:]  # 2> or {fd}>: the fd number belongs to the redirection
            else:
                if not word_start:
                    out.append(" ")  # `<` and `>` end a word: `rm -rf ~>/dev/null` removes ~
                prefix = ""
            operator = REDIRECTION_OPERATOR.match(command, i).group()
            out.append(REDIRECT + prefix + _literal(operator))
            operator_at = i
            i += len(operator)
            while i < n and command[i] in " \t":  # `> log` is `>log`: the target joins its operator
                i += 1
            word_start, word_begin = False, len(out)
            if operator in ("<<", "<<-"):
                before = len(pending)
                i = _heredoc_word(command, i, operator == "<<-", out, pending)
                if len(pending) > before:  # where its command begins, and whether it is in a substitution
                    pending[-1] = pending[-1] + (_command_begins(command, operator_at), bool(outer))
            continue
        if c == "&" and command.startswith("&>", i) and bash:
            operator = "&>>" if command.startswith("&>>", i) else "&>"
            posix_differs = True  # dash reads `&` (in the background) and then `>`
            out.append(("" if word_start else " ") + REDIRECT + _literal(operator))  # &>file does not end the command
            i += len(operator)
            while i < n and command[i] in " \t":
                i += 1
            word_start, word_begin = False, len(out)
            continue
        if c == "&" and command.startswith("&&", i):
            out.append("&&")
            i += 2
            word_start, word_begin, command_start = True, len(out), True
            continue
        if c == ";" and cases and cases[-1][0] == len(stack) and cases[-1][1] == "body" and command.startswith(
                (";;", ";&"), i):
            cases[-1][1:] = ["pattern", False]  # ;; ;& ;;& end a case branch: a pattern follows
        if c in " \t" and not word_start:  # a word ends: a reserved word keeps command position, an assignment not
            word = "".join(out[word_begin:])
            if function_name:
                command_start, function_name = True, False  # `function f case ...`
            elif command_start and word == "function":
                function_name = True
            else:
                command_start = command_start and (word in COMMAND_PREFIX_WORDS or (word == "-p" and last_word == "time"))
            last_word = word
        out.append(c)
        i += 1
        if c in SHELL_WORD_BREAKS:
            word_start, word_begin = True, len(out)
            if c in ";&|\n":
                command_start = True
            if c == "\n" and pending and heredoc is None:
                start_heredoc()
        else:
            word_start = False
    copied = 0
    while outer:  # a substitution left open (bash refuses the command): read its text as a command, and in its word
        while stack and pop() not in BUFFERED:
            pass
        inner_text = "".join(out)
        copied += len(inner_text)
        if copied > 8 * n + 100_000:  # deeply nested open substitutions copy their text once per level
            raise ReadTimeout("the command's open substitutions are too deeply nested to read")
        sides.append(inner_text)
        out, word_begin, _, opener, _ = outer.pop()
        out.append(_literal(opener) + inner_text)
    return "".join(out) + "".join("\n" + side for side in sides), posix_differs, dq_hash


# What may run a heredoc body it is given: shells, interpreters, remote shells and database clients. A heredoc in a
# substitution is read as commands when one of these is anywhere in the rest of its line (`cat <<EOF | bash`).
HEREDOC_RUNNERS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ssh", "su", "python", "python2", "python3", "node",
                   "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "tclsh", "expect", "osascript", "psql",
                   "mysql", "mariadb", "sqlite3", "sqlcmd", "redis-cli", "mongo", "mongosh", "pwsh", "powershell",
                   "cmd", "xargs", "eval", "source", ".", "exec", "docker", "podman", "kubectl", "at", "batch",
                   "crontab", "sudo", "doas", "env", "time", "nohup", "timeout"}
# What only reads or writes a body as text. A heredoc in a substitution given to one of these, with no runner in the
# rest of its line, is text (`git commit -m "$(cat <<'EOF' ... EOF)"`); given to anything else it is read as commands.
HEREDOC_TEXT_READERS = {"cat", "tee", "head", "tail", "wc", "sort", "uniq", "tr", "cut", "fold", "column", "less",
                        "more", "grep", "egrep", "fgrep", "base64", "md5sum", "sha1sum", "sha256sum", "shasum",
                        "printf", "echo", "read", "mapfile", "readarray", "true", ":", "git", "gh", "jq", "yq"}


def _command_begins(command: str, at: int) -> int:
    """Where the simple command holding command[at] begins: after the nearest `;`, `&`, `|`, `(`, `)`, backquote or
    newline before it (a heuristic for _heredoc_runs; a quote is not tracked)."""
    k = at
    while k > 0 and command[k - 1] not in ";&|()`\n":
        k -= 1
    return k


def _heredoc_runs(line: str) -> bool:
    """Whether a heredoc whose command and the rest of its line are `line` may be run: a runner (HEREDOC_RUNNERS)
    anywhere in it, or a command that is not one of HEREDOC_TEXT_READERS (stricter: unknown commands may run it)."""
    words = [w for w in re.split(r"[\s;&|()<>`\"']+", line) if w]
    if any(os.path.basename(w).lstrip("$") in HEREDOC_RUNNERS for w in words):
        return True
    for w in words:
        if ASSIGNMENT.match(w):
            continue
        return os.path.basename(w) not in HEREDOC_TEXT_READERS
    return True


def _double_quoted(body: str) -> str:
    """A heredoc body (unquoted word) as the text of a double-quoted string that expands as the body does: a `"`
    is escaped, and a backslash before a `"` stays a backslash."""
    out, k, n = [], 0, len(body)
    while k < n:
        ch = body[k]
        if ch == "\\" and k + 1 < n:
            out.append('\\\\\\"' if body[k + 1] == '"' else body[k:k + 2])
            k += 2
            continue
        out.append('\\"' if ch == '"' else ch)
        k += 1
    return "".join(out)


def _heredoc_word(command: str, i: int, strip_tabs: bool, out: list, pending: list) -> int:
    """Read the word after `<<` at command[i:]: append it, made literal, to out, add (word, strip_tabs, quoted) to
    pending, and return where it ends. The word ends at an unquoted blank, newline or operator; quoting any part of
    it makes the body literal (no substitutions), and the quotes are not part of the word."""
    word: list = []
    quoted = False
    j, n = i, len(command)
    while j < n and command[j] not in " \t\n;&|()<>":
        ch = command[j]
        if ch == "'":
            end = command.find("'", j + 1)
            end = n if end == -1 else end
            word.append(command[j + 1:end])
            quoted, j = True, end + 1
        elif ch == '"':
            k = j + 1
            while k < n and command[k] != '"':
                if command[k] == "\\" and k + 1 < n and command[k + 1] in '"\\$`':
                    k += 1
                word.append(command[k])
                k += 1
            quoted, j = True, k + 1
        elif ch == "\\" and j + 1 < n:
            word.append(command[j + 1])
            quoted, j = True, j + 2
        else:
            word.append(ch)
            j += 1
    text = "".join(word)
    out.append(_literal(text))
    if text:
        pending.append((text, strip_tabs, quoted))
    return min(j, n)


def _tokens(command: str, bash: bool = True) -> list[str]:
    """The command's words and operators. An unquoted newline separates commands, as in a shell, a backslash-newline
    joins two lines into one, and comments are dropped, so every line of a multi-line command is read."""
    return _lex(_strip_comments(command, bash))


def _lex(command: str) -> list[str]:
    """The words and operators of a command _scan has prepared."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|()\n")
        lexer.whitespace = " \t"
        lexer.whitespace_split = True
        lexer.commenters = ""
        return list(lexer)
    except ReadTimeout:
        raise  # the hook's timer: never read as an unbalanced quote
    except ValueError:
        # Unbalanced quotes: fall back to whitespace splitting with quotes stripped.
        command = command.replace(QUOTED, "")
        return [t.strip("\"'") for t in command.replace("\n", " ; ").replace(";", " ; ").replace("&&", " && ").replace("|", " | ").split()]


def _readings(command: str, depth: int = 0) -> list:
    """The command's text as each shell that may run it reads a carriage return. Every reading is checked.

    bash and zsh read a carriage return as an ordinary character, part of its word, so `main\\r` is not main; bash on
    Windows may read a CR-LF line ending as a line feed, PowerShell reads a carriage return as a line break, and a
    shell that ignores carriage returns (Cygwin's igncr) reads `rm -rf \\r~` as `rm -rf ~`, which reading one as a
    blank also finds. The tool's own shell may be any of these, so the command it is given (depth 0) is read each of
    those four ways; the text of a `bash -c` string inside it is as each reading left it. A command whose only
    carriage returns end its lines is read two ways, since the last two readings are then the second."""
    if depth or "\r" not in command:
        return [command]
    crlf = CR_LINE_ENDING.sub("", command)
    return list(dict.fromkeys([command, crlf, crlf.replace("\r", "\n"), crlf.replace("\r", " ")]))


def _simple_commands(command: str, depth: int = 0, deadline: float | None = None, memo: dict | None = None,
                     assignments: list | None = None, words: list | None = None):
    """Yield argv lists for each simple command, with leading assignments, reserved words, redirections and wrappers
    removed, redirections with their target attached (`2>&1`, `>/dev/null`) dropped, and `sh -c` bodies and shell
    here-strings expanded. A simple command a later reading repeats is yielded once.

    Each carriage-return reading (_readings) is read as bash, zsh and ksh read it; one in which that can differ from
    dash (_scan: a $'...' string holds `\\'`, or `&>` was read as one operator) is read again as dash reads it ($'
    is `$` and a plain single-quoted string, which `\\'` ends; `&>` is `&` and then `>`), since `sh -c` may start
    dash. memo holds what each `bash -c` string inside yields, so a string that several readings leave the same is
    read once.

    When `assignments` is a list, every variable assignment dropped on the way (`NAME=value` before a command, on its
    own, or after `env` or `sudo`), in `bash -c` bodies too, is appended to it as written, as the commands are yielded;
    a command read more than one way may add one more than once. When `words` is a list, the words of each reading,
    and of each `bash -c` string inside, are appended to it as one list (_reading_words), for _points_git_elsewhere.

    Raises ReadTimeout once the deadline (READ_BUDGET_SECONDS from the first call, by default) has passed, checked
    before each reading and at each word _strip_wrappers reads, or before an extra reading that would not finish by
    then, judged by the slowest reading so far."""
    deadline = _deadline(deadline)
    memo = {} if memo is None else memo
    seen: set = set()
    slowest = 0.0
    number = 0
    for text in _readings(command, depth):
        variants = [(True, False)]  # bash 3.2's reading first; others where they can differ (_scan)
        for bash, dq_comment in variants:
            started = time.monotonic()
            if started + slowest >= deadline:
                raise ReadTimeout("the command took too long to read")
            prepared, posix_differs, dq_hash = _scan(text, bash, dq_comment)
            if len(variants) == 1:
                if posix_differs or dq_hash:
                    variants.append((False, True))  # dash
                if dq_hash:
                    variants.append((True, True))  # bash 4 and later, and zsh: a comment in "$( )", and $'...'
            tokens = _lex(prepared)
            if words is not None:
                words.append(_reading_words(tokens))
            slowest = max(slowest, time.monotonic() - started)
            current: list[str] = []
            for token in tokens + [";"]:
                # An empty word ('' or $'') is an argument, not a separator: `rm -rf $'' ~` removes ~.
                if token in SEPARATORS or (token and set(token) <= SEPARATOR_CHARS):
                    for argv in _unwrap(current, depth, deadline, memo, assignments, words) if current else ():  # checks the deadline
                        if number == 0 or tuple(argv) not in seen:
                            seen.add(tuple(argv))
                            yield argv
                    current = []
                else:
                    current.append(token.replace(QUOTED, "") if QUOTED in token else token)
            number += 1


def _split_string(text: str) -> list[str]:
    """The words of `env -S STRING`: split on blanks, with quotes as in a shell."""
    try:
        return shlex.split(text, posix=True)
    except ReadTimeout:
        raise  # the hook's timer: never read as an unbalanced quote
    except ValueError:
        return text.split()


def _long_option(option: str, known: set) -> str | None:
    """The known long option `option` names, itself or as an unambiguous prefix (getopt_long), or None."""
    if option in known:
        return option
    matches = [name for name in known if name.startswith(option)]
    return matches[0] if len(matches) == 1 else None


def _wrapper_commands(name: str, rest: list, xargs: tuple | None = None, deadline: float | None = None,
                      assignments: list | None = None) -> list:
    """Each way `name` (a WRAPPER_OPTIONS wrapper) reads the words after it: (rest, xargs) for each reading, rest
    holding the command it runs. rest is a stack, last word first (rest[-1] is the next word), which this consumes:
    passing over a word is one pop, and env -S's string is pushed in place, so a long run of options costs time in
    proportion to its length. Its options and positionals are passed over; env passes over every word with `=` in it
    before the command (GNU env takes `=x` too), and sudo every one that does not start with `/`, unless its options
    ended at `--` (sudo's is_envar); xargs adds a link to the xargs chain (its -I replacement string, or None when its
    input follows the command), applied by _xargs_command. An option the table does not know is read both ways, so
    there may be several readings, each with a copy of the stack. The NAME=VALUE words env and sudo pass over are
    appended to `assignments` when it is a list. Raises ValueError past MAX_WRAPPER_READINGS, and ReadTimeout past the
    deadline."""
    spec = WRAPPER_OPTIONS[name]
    known_long = spec["long_value"] | spec["long_flags"] | spec["long_split"] | spec["long_replace"]
    readings: list = []
    todo = [(rest, None)]  # (the word stack, xargs's replacement string)
    while todo:
        if len(readings) + len(todo) > MAX_WRAPPER_READINGS:
            raise ValueError("too many ways to read the command's wrappers")
        rest, replace = todo.pop(0)
        ended = False  # the options ended at `--`
        while rest:
            if deadline is not None and time.monotonic() >= deadline:
                raise ReadTimeout("the command took too long to read")
            arg = rest[-1]
            if arg == "--":
                rest.pop()
                ended = True
                break
            if arg == "-" and name == "env":  # env - is env -i
                rest.pop()
                continue
            if arg.startswith("--"):
                rest.pop()
                option, equals, value = arg.partition("=")
                known = _long_option(option, known_long)
                if known in spec["long_split"]:
                    text = value if equals else (rest.pop() if rest else "")
                    rest.extend(reversed(_split_string(text)))
                elif known in spec["long_replace"]:
                    replace = value if equals else "{}"
                elif equals or known in spec["long_flags"]:
                    pass
                elif known in spec["long_value"]:
                    if rest:
                        rest.pop()
                else:  # unknown: it may take the next word, or none
                    todo.append((rest[:-1], replace))
                continue
            if not arg.startswith("-") or len(arg) == 1:
                break
            # A cluster of short options: each letter is a flag, until one that takes a value, which is the rest of
            # the cluster or else the next word.
            rest.pop()
            letters, k, split = arg[1:], 0, None
            while k < len(letters):
                letter, attached = letters[k], letters[k + 1:]
                if letter in spec["split"]:
                    split = attached if attached else (rest.pop() if rest else "")
                    break
                if letter in spec["replace"]:
                    replace = attached if attached else (rest.pop() if rest else "")
                    break
                if letter in spec["optional_replace"]:
                    replace = attached or "{}"
                    break
                if letter in spec["value"]:
                    if not attached and rest:
                        rest.pop()
                    break
                if letter in spec["optional"]:
                    break
                if letter not in spec["flags"]:  # unknown: it may take a value (the rest of the cluster, or the next
                    todo.append((rest[:] if attached else rest[:-1], replace))  # word), or be a flag
                k += 1
            if split is not None:
                rest.extend(reversed(_split_string(split)))
        for _ in range(spec["positionals"]):
            if rest:
                rest.pop()
        if name == "env":
            while rest and "=" in rest[-1]:
                word = rest.pop()
                if assignments is not None:
                    assignments.append(word)
        elif name == "sudo" and not ended:
            while rest and "=" in rest[-1] and not rest[-1].startswith("/"):
                word = rest.pop()
                if assignments is not None:
                    assignments.append(word)
        readings.append((rest, (replace, xargs) if name == "xargs" and rest else xargs))
    return readings


def _xargs_command(command: list, xargs: tuple | None) -> list:
    """The command with what xargs reads from its input written as XARGS_INPUT: in place of each -I replacement
    string in its arguments, or after them, once for each xargs whose input follows the command."""
    replaces, appended = [], 0
    while xargs is not None:
        replace, xargs = xargs
        if replace:
            replaces.append(replace)
        else:
            appended += 1
    args = command[1:]
    for replace in dict.fromkeys(replaces):
        args = [arg.replace(replace, XARGS_INPUT) for arg in args]
    return command[:1] + args + [XARGS_INPUT] * appended


def _strip_wrappers(argv: list[str], deadline: float | None = None, assignments: list | None = None) -> list:
    """Each command a simple command may run: leading assignments, redirections (`>/dev/null`, `2>&1`, `> log`),
    words that may expand to nothing ($(cmd), $VAR), reserved words (`then`, `do`, `!`, `{`, ...; `coproc` and a NAME
    before a compound command; `function NAME`) and wrapper commands (sudo, env, timeout 60, xargs, noglob, ...) with
    their options passed over (_wrapper_commands); an option a wrapper's table does not know gives two readings. Only
    the first word of a simple command can be a reserved word, so `echo then` keeps its argument. The words are kept
    as a stack, last word first, so a long run of assignments or wrappers costs time in proportion to its length.
    The assignments passed over are appended to `assignments` when it is a list. Raises ValueError past
    MAX_WRAPPER_READINGS, and ReadTimeout past the deadline."""
    commands: list = []
    todo = [(argv[::-1], None)]  # (the word stack, last word first; the xargs chain)
    while todo:
        if len(commands) + len(todo) > MAX_WRAPPER_READINGS:
            raise ValueError("too many ways to read the command's wrappers")
        rest, xargs = todo.pop(0)
        while rest:
            if deadline is not None and time.monotonic() >= deadline:
                raise ReadTimeout("the command took too long to read")
            first = rest[-1]
            # An empty command name ('' or "") runs nothing, and one that only expands ($(cmd), $VAR) may expand to
            # nothing: what follows is read as the command, which is the stricter reading.
            if not first or ASSIGNMENT.match(first) or EXPANSION_WORD.fullmatch(first):
                rest.pop()
                if assignments is not None and first and ASSIGNMENT.match(first):
                    assignments.append(first)
                continue
            word = first.lstrip("`")
            if word.startswith(REDIRECT) or word in RESERVED_PREFIXES:  # `>/dev/null rm -rf ~`, `then rm -rf ~`
                rest.pop()
                continue
            if word == "coproc":
                rest.pop()
                if len(rest) >= 2 and rest[-2] in COMPOUND_STARTS:
                    rest.pop()  # coproc NAME { ...; }
                continue
            if word == "function":
                rest.pop()
                if rest:
                    rest.pop()  # function NAME { ...; }: the body follows the name
                continue
            name = _command_name(word)
            if name not in WRAPPER_OPTIONS:
                break
            rest.pop()
            readings = _wrapper_commands(name, rest, xargs, deadline, assignments)
            todo.extend(readings[1:])
            rest, xargs = readings[0]
        if rest:
            commands.append(_xargs_command(rest[::-1], xargs))
    return commands


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


def _here_string_script(args: list[str], redirections: list[str]) -> str | None:
    """The script a shell reads from a here-string (`bash <<< 'rm -rf ~'`, `sh -s <<<"..."`), or None. args are the
    shell's arguments without its redirections; a shell given a script file reads the here-string as that script's
    input, so then None, unless -s says its operands are arguments."""
    script = None
    for word in redirections:
        here = HERE_STRING.match(word, len(REDIRECT))
        if here:
            script = word[here.end():]
    if script is None:
        return None
    reads_stdin, index = False, 0
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
            reads_stdin = reads_stdin or (arg[0] == "-" and "s" in arg[1:])
            index += 2 if arg[-1] in "oO" else 1  # -euo pipefail: o takes the next word
        else:
            break
    return script if index >= len(args) or reads_stdin else None


def _command_name(word: str) -> str:
    """The command a first word runs: its last path component, after any expansion it starts with (`$(echo)rm`,
    which may expand to nothing); zsh's `=rm` runs rm."""
    name = os.path.basename(EXPANSION_PREFIX.sub("", word.lstrip("`"), count=1) or word)
    return name[1:] if name.startswith("=") and len(name) > 1 else name


def _unwrap(argv: list[str], depth: int, deadline: float | None = None, memo: dict | None = None,
            assignments: list | None = None, readings: list | None = None):
    for command in _strip_wrappers(argv, deadline, assignments):
        name = _command_name(command[0])
        # Redirections are not arguments (`git push -f > log` is a bare push), and a shell's options may follow them.
        args = [arg for arg in command[1:] if not arg.startswith(REDIRECT)]
        # An argument that starts with an expansion may lose it, and an option may be left (`rm `echo`-rf ~`,
        # `bash $(echo)-c '...'`): read that too. Only an option: `rm -rf "$(pwd)/bin"` is no `/bin`.
        bare = [_bare(arg) for arg in args]
        if name in SHELLS and depth < 3:
            redirections = [arg for arg in command[1:] if arg.startswith(REDIRECT)]
            script = None
            for words in (args, bare) if bare != args else (args,):
                script = _shell_command_string(words)
                if script is None:
                    script = _here_string_script(words, redirections)
                if script is not None:
                    break
            if script is not None:
                if memo is None:
                    yield from _simple_commands(script, depth + 1, deadline, None, assignments, readings)
                else:
                    key = (script, depth + 1)
                    if key not in memo:
                        memo[key] = list(_simple_commands(script, depth + 1, deadline, memo, assignments, readings))
                    yield from memo[key]
                continue
        if depth < 3:
            # `pwsh -Command "..."`, `powershell -c ...`, `powershell.exe -EncodedCommand ...` and `cmd /c ...`: the
            # script is read with PowerShell's or cmd's rules (catpilot_guard/powershell.py, docs/spec/WINDOWS.md
            # §3.2), never with this reader's, under the same deadline.
            from . import powershell

            shell = powershell._command_name(name)
            if shell in powershell.POWERSHELLS or shell == "cmd":
                script = powershell.powershell_script(shell, args) if shell != "cmd" else powershell.cmd_script(args)
                if script is not None:
                    if shell == "cmd":
                        yield from powershell._cmd_commands(script, depth + 1, assignments, deadline)
                    else:
                        yield from powershell.simple_commands(script, depth + 1, assignments, deadline)
                    continue
        yield [name] + args
        if bare != args:
            yield [name] + bare


def _bare(word: str) -> str:
    """word without the expansion it starts with, when what is left is an option (`$(echo)-rf` -> `-rf`)."""
    left = EXPANSION_PREFIX.sub("", word, count=1)
    return left if left.startswith("-") else word


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
# Characters the expansion may scan for one whole command, every word and both hooks' readings of it counted apart: a
# crafted word scans its text once per brace (about a million characters for one 4 KB word), and the hook must finish
# well inside its timeout (review of #133). Past it, every later word with braces is unknown.
BRACE_SCAN_LIMIT = 400_000


class BraceBudget:
    """The scanning one command may still spend on brace expansion (BRACE_SCAN_LIMIT), shared by its words."""

    def __init__(self, chars: int = BRACE_SCAN_LIMIT):
        self.left = chars

    def spend(self, chars: int) -> None:
        self.left -= chars
        if self.left < 0:
            raise _TooManyWords


def expand_braces(word: str, limit: int = BRACE_LIMIT, budget: BraceBudget | None = None):
    """The words bash makes of `word` by brace expansion, or None when there would be more than limit (or the word is
    over BRACE_WORD_LIMIT characters). A port of bash 5.2's braces.c brace_expand (the review of #133 checked it against
    bash on 12,000 words): a `}` closes a brace only after a comma or a `..` at its level, `{x}` alone stays literal,
    sequences take steps and zero padding, and a word a brace makes empty is dropped. `${...}` is parameter expansion,
    not a brace: callers collapse it first. Quoting is already gone, so a quoted brace is expanded too (stricter).
    budget, shared by a command's words, also makes the word None once spent; without one the word gets a fresh one."""
    if "{" not in word:
        return [word]
    if len(word) > BRACE_WORD_LIMIT or word.count("{") > 4 * limit:
        return None
    budget = budget if budget is not None else BraceBudget()
    if budget.left < 0:
        return None
    try:
        words = [w for w in _brace_expand(word, limit, budget) if w != ""]
        budget.spend(sum(len(w) for w in words))  # every word made is read again by the caller
    except (_TooManyWords, RecursionError):
        return None
    return words



class _TooManyWords(Exception):
    pass

def _brace_gobbler(text, i, satisfy, budget):
    start = i
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
            budget.spend(i - start + 1)
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
    budget.spend(i - start + 1)
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

def _brace_expand(text, limit, budget):
    i = 0
    n = len(text)
    c = ""
    while True:
        i, c = _brace_gobbler(text, i, "{", budget)
        if c:
            j, c2 = _brace_gobbler(text, i + 1, "}", budget)
            if not c2:
                i += 1
                continue
            break
        break
    preamble = text[:i]
    if c != "{":
        return [preamble]
    start = i + 1
    i, c = _brace_gobbler(text, start, "}", budget)
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
        tack = _brace_amble(amble, limit, budget)
    result = [preamble + t for t in tack]
    post = text[i + 1:]
    if post:
        tail = _brace_expand(post, limit, budget)
        if len(result) * len(tail) > limit:
            raise _TooManyWords
        result = [r + t for r in result for t in tail]
    if len(result) > limit:
        raise _TooManyWords
    return result

def _brace_amble(text, limit, budget):
    result = []
    i = start = 0
    while True:
        i, c = _brace_gobbler(text, i, ",", budget)
        result.extend(_brace_expand(text[start:i], limit, budget))
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


def git_push_rewrites(args: list[str], cwd: str | None, budget: BraceBudget | None = None) -> tuple[bool, list[str | None]] | None:
    """Both readings: braces expanded (unquoted) and words as written (quoted, empty words kept); the stricter wins.
    budget is the command's BraceBudget, shared by its git commands; None gives this one a fresh one."""
    expanded = _git_push_rewrites(args, cwd, True, budget if budget is not None else BraceBudget())
    if not any("{" in word or word == "" for word in args):
        return expanded
    raw = _git_push_rewrites(args, cwd, False)
    if expanded is None or raw is None:
        return expanded if raw is None else raw
    return expanded[0] or raw[0], expanded[1] + raw[1]


def _git_push_rewrites(args: list[str], cwd: str | None, expand: bool, budget: BraceBudget | None = None) -> tuple[bool, list[str | None]] | None:
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
            words = [word] if "{" not in word else expand_braces(BRACED_EXPANSION.sub("$VAR", word), budget=budget)
            if words is None:
                # Past the limit (or the budget), the word may hold the subcommand itself (`git {push,-f,origin,main,...}`,
                # `git {p..p}ush -f`) or a setting (`{-c,remote.origin.mirror=true}`): a push nobody can read.
                return False, [None]
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
        words = expand_braces(BRACED_EXPANSION.sub("$VAR", word), budget=budget) if expand else [word]
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
            # Its value is the next argument. A placeholder there may hold more words (`--repo {x,origin} +main`), so
            # what follows may be a refspec: unknown, and possibly a force.
            unsure = unsure or (i < len(rest) and rest[i] == "$CATPILOT_BRACES")
            i += 1
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
DIRECTORY_COMMANDS = {"cd", "chdir", "pushd", "popd"}  # change only the directory, which a subshell keeps to itself
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


def _is_separator(token: str) -> bool:
    """Whether a token of _lex is an operator: a quoted or escaped `;` still holds QUOTED, and an empty word is a word."""
    return token in SEPARATORS or (bool(token) and set(token) <= SEPARATOR_CHARS)


def _reading_words(tokens: list) -> list:
    """One reading's tokens (_lex) as _points_git_elsewhere reads them: operators as they are, redirections left out,
    QUOTED removed from each word, and a quoted or escaped operator or an empty word written `''`, so that it is never
    read as an operator."""
    out = []
    for token in tokens:
        if _is_separator(token):
            out.append(token)
        elif not token.startswith(REDIRECT):  # `>/dev/null GIT_DIR=x git push -f`: a redirection is not a word
            word = token.replace(QUOTED, "") if QUOTED in token else token
            out.append(word if word and not _is_separator(word) else "''")
    return out


FUNCTION_BODY_STARTS = {"{", "(", "((", "if", "for", "while", "until", "case", "select", "[["}


def _defines_function(tokens: list, i: int) -> bool:
    """Whether the `()` at tokens[i] (one token, or `(` then `)`) is followed by a function body: a compound command,
    perhaps on a later line. A heredoc body's text (`fix parse() bug`), which the reader also reads as commands, is not
    a definition; nothing after the `()` is read as one (stricter)."""
    rest = tokens[i][2:] if tokens[i].startswith("()") else tokens[i + 1][1:]
    j = i + (1 if tokens[i].startswith("()") else 2)
    if rest.lstrip("\n"):  # `()(`, `();`: punctuation after it in the same token
        return rest.lstrip("\n").startswith("(")
    while j < len(tokens) and tokens[j] == "\n":
        j += 1
    return j >= len(tokens) or tokens[j] in FUNCTION_BODY_STARTS or tokens[j].startswith("(")


def _points_git_elsewhere(command: str, deadline: float | None = None, readings: list | None = None) -> str | None:
    """"config" when a line (or a shell body in it) sets GIT_CONFIG_* (a mirror may follow), "elsewhere" when it
    defines a function (which may stand in for git), sets GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, or gives env a
    directory, else None. Read from shell words: an assignment counts at a command's start or as an argument of a
    command that passes it on (export, declare, read, env and the other wrappers), so a quoted mention in a message
    (`-m "fix parse() edge case"`, `-m "GIT_DIR=x"`) is not one. The words are _simple_commands' (its `words`; given
    as readings when the caller has them), so a line is read here as it is checked: inside compound commands, with
    comments dropped where bash drops them, each way a carriage return or $'...' may be read, and every `bash -c`
    string inside. Raises ReadTimeout past the deadline."""
    found = None
    deadline = _deadline(deadline)
    if readings is None:
        readings = []
        for _ in _simple_commands(command, 0, deadline, None, None, readings):
            pass
    for tokens in readings:
        at_start, assigning, previous, env_options = True, False, "", False
        wrapper, skip, positionals = None, 0, 0
        for i, token in enumerate(tokens):
            if not i % 4096 and time.monotonic() >= deadline:
                raise ReadTimeout("the command took too long to read")
            if token in SEPARATORS or set(token) <= set(";&|()\n"):
                if previous and not previous.endswith(("$", "=")) and previous not in SEPARATORS and not set(previous) <= set(";&|()\n"):
                    if token.startswith("()") or (token == "(" and i + 1 < len(tokens) and tokens[i + 1].startswith(")")):
                        if _defines_function(tokens, i):
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


def read_command(command: str, deadline: float | None = None) -> tuple:
    """(commands, assignments, readings): every simple command of _simple_commands, the assignments it dropped, and
    the words of each reading, from one pass, so that the branch context, the registry, account and deploy readers
    and _points_git_elsewhere share one reading of a long command. Raises ReadTimeout past the deadline."""
    assignments: list = []
    readings: list = []
    commands = list(_simple_commands(command, 0, _deadline(deadline), None, assignments, readings))
    return commands, assignments, readings


def commands_with_branch_context(command: str, cwd: str | None, deadline: float | None = None, read: tuple | None = None):
    """Each simple command, with the directory to read the checked-out branch from, or None when it is unknown: after
    a command earlier in the line that may change it or the directory (`cd`, `pushd`, `git checkout`, `git switch`,
    `git init`, `git rebase <upstream> <branch>`, `git stash branch`, `git branch -m`, `gh pr checkout`, `source`,
    `eval`, or a git subcommand given another repository), and for the whole line when it, or a shell body in it,
    defines a function, assigns GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR, or gives env a directory. A line that assigns
    a harmful GIT_CONFIG_* (git_config_assignment_harmful), or follows a command that sets a mirror setting, yields
    CONFIGURED_BY_ENVIRONMENT, which makes a bare push a mirror. A command can only make the
    branch unknown, never name it. A script or program run earlier in the line that switches branches is not seen, nor
    a git alias or a setting in git's config files.

    The commands are _simple_commands' (compound commands, comments and every reading, under one deadline), and the
    assignments it drops count as well. The commands of a substitution are read after the rest of the line, though
    the shell runs them first, so in a line with a substitution a command that changes the context applies to the
    whole line, except a change of directory (`cd`, `pushd`, `popd`), which a substitution makes in its own subshell;
    a checkout there still changes the repository's HEAD. read is read_command(command), when the caller has it. Raises ReadTimeout past the deadline."""
    deadline = _deadline(deadline)
    commands, assignments, readings = read if read is not None else read_command(command, deadline)
    pointed = _points_git_elsewhere(command, deadline, readings)
    branch_cwd = CONFIGURED_BY_ENVIRONMENT if pointed == "config" else (None if pointed else cwd)
    for assignment in assignments:
        if branch_cwd is CONFIGURED_BY_ENVIRONMENT:
            break
        name, equals, value = assignment.partition("=")
        name = name.rstrip("+")
        if GIT_CONFIG_ASSIGNMENT.match(name) and git_config_assignment_harmful(name, value if equals else None):
            branch_cwd = CONFIGURED_BY_ENVIRONMENT
        elif GIT_ENVIRONMENT_ASSIGNMENT.match(name):
            branch_cwd = None
    if any(mark in command for mark in ("$(", "`", "<(", ">(")):
        for argv in commands:
            if CURRENT_BRANCH_COMMAND.fullmatch(" ".join(argv)):
                continue  # `"$(git symbolic-ref --short HEAD)"` asks for the branch; it does not change it
            if os.path.basename(argv[0]) in DIRECTORY_COMMANDS:
                continue  # a `cd` in a substitution runs in a subshell (`ROOT="$(cd .. && pwd)"`); a checkout does not
            setting = _config_setting(argv)
            if setting == "mirror":
                branch_cwd = CONFIGURED_BY_ENVIRONMENT
                break
            if setting == "unknown" or _changes_branch(argv):
                branch_cwd = None
    for argv in commands:
        yield argv, branch_cwd
        setting = _config_setting(argv)
        if setting == "mirror":
            branch_cwd = CONFIGURED_BY_ENVIRONMENT  # `git config remote.origin.mirror true && git push origin`
        elif branch_cwd is not CONFIGURED_BY_ENVIRONMENT and (setting == "unknown" or _changes_branch(argv)):
            branch_cwd = None


def _git_finding(args: list[str], cwd: str | None, budget: BraceBudget | None = None) -> bool:
    push = git_push_rewrites(args, cwd, budget)
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


def _db_finding(name: str, args: list[str], command: str, depth: int = 0,
                deadline: float | None = None) -> tuple[str, str] | None:
    name, args = _unwrap_exec(name, args)
    script = _shell_command_string(args) if name in SHELLS else None
    if script is not None:
        # A shell started inside a container (docker compose exec db sh -c "psql ..."): check its commands too.
        if depth < 3:
            for inner in _simple_commands(script, depth + 1, deadline):
                hit = _db_finding(inner[0], inner[1:], command, depth + 1, deadline)
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


POWERSHELL = "powershell"  # find_destructive_op's shell for Claude Code's PowerShell tool
SHELL_TOOLS = ("Bash", "PowerShell")  # the tools whose tool_input.command the checks read


def find_destructive_op(command: str, cwd: str | None = None, shell: str = "bash",
                        deadline: float | None = None) -> tuple[str, str] | None:
    """Return (label, remediation) for the first destructive command found, or None. shell "powershell" reads the
    command with PowerShell's rules (catpilot_guard/powershell.py); a PowerShell or cmd script inside a bash command
    is read with them either way. Raises ReadTimeout (a ValueError) when reading the command takes longer than
    READ_BUDGET_SECONDS from deadline's start (one deadline for every reading of the command: pass decide()'s), so
    the hook blocks."""
    if not command:
        return None
    check_command_size(command)
    deadline = _deadline(deadline)
    for label, pattern, remediation in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return label, remediation
    from . import powershell

    working_dir = cwd if isinstance(cwd, str) and cwd else os.getcwd()
    budget = BraceBudget()  # one for the whole command, so many crafted words cannot outlast the hook's timeout
    if shell == POWERSHELL:
        reader = powershell.commands_with_branch_context(command, working_dir, deadline)
    else:
        reader = commands_with_branch_context(command, working_dir, deadline)
    for argv, branch_cwd in reader:
        name, args = argv[0], argv[1:]
        if name == "rm" and _rm_finding(args):
            return RM_LABEL, RM_NOTE
        if name == "git" and _git_finding(args, branch_cwd, budget):
            return GIT_LABEL, GIT_NOTE
        if name == "kubectl" and _kubectl_finding(args):
            return KUBECTL_LABEL, KUBECTL_NOTE
        db_hit = _db_finding(name, args, command, 0, deadline)
        if db_hit is not None:
            return db_hit
        windows = powershell.windows_finding(argv)
        if windows is not None:
            return windows
        # The whole-command signatures again on each simple command as its words were read: a command the line
        # carries encoded or inside a script string (`pwsh -EncodedCommand ...`) is not in the line's own text.
        joined = " ".join(argv)
        for label, pattern, remediation in DESTRUCTIVE_PATTERNS:
            if pattern.search(joined):
                return label, remediation
    return None


# --- evidence (content-free) ---------------------------------------------------------------
# Written by catpilot_guard/evidence.py when CATPILOT_EVIDENCE_LOG, CATPILOT_EVIDENCE_SYSLOG or CATPILOT_EVIDENCE_HTTPS is set:
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


# Hosts whose shell tool reports Bash for PowerShell too: Copilot CLI names its powershell tool Bash, and Codex's tool
# name for a Windows shell command is not documented (docs/spec/WINDOWS.md §3.1, to check). On Windows a command from
# them is read both ways, and either reading can deny it.
BOTH_WAYS_HOSTS = ("codex", "copilot-cli")


def decide(event: dict, host: str | None = None, windows: bool | None = None) -> dict:
    if not isinstance(event, dict):
        raise ValueError("hook event must be an object")
    tool = event.get("tool_name")
    if tool not in SHELL_TOOLS:
        return {}
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    deadline = _deadline()  # one reading budget for the command, however many ways it is read
    found = find_destructive_op(command, event.get("cwd"), POWERSHELL if tool == "PowerShell" else "bash", deadline)
    if found is None and tool == "Bash" and host in BOTH_WAYS_HOSTS and (os.name == "nt" if windows is None else windows):
        found = find_destructive_op(command, event.get("cwd"), POWERSHELL, deadline)
    if found is None:
        return {}
    label, remediation = found
    record_evidence("deny", event, host, tool=tool, label=label)
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
    host = hook_host(take_evidence_default())  # from --host: the evidence label, and Copilot CLI's event shape; never the decision
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("hook input too large")
        result = within_time_limit(decide, event_for_host(json.loads(payload), host), host)
    except ReadTimeout:
        record_evidence("input_error", host=host)  # the closest event in docs/spec/EVIDENCE.md: it was not read
        write_reason(
            "Catpilot destructive-operation check could not finish reading this command in time (it is very long, "
            "or nested deeply), so it was not allowed. Split it into shorter commands, or run it yourself in your own "
            "terminal.")
        return 2
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
