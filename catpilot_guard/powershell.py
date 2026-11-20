"""A PowerShell command reader: the simple commands a PowerShell command line runs, as argv lists.

docs/spec/WINDOWS.md §3.2. Used for Claude Code's PowerShell tool (tool_name "PowerShell"), and from the POSIX
reader (catpilot_guard/destructive.py) for `pwsh -Command`, `powershell -c`, `powershell.exe` with a script
string and `cmd /c` inside any command, so every reader that splits commands (the destructive check, the company
rules, and the deploy, registry and cloud readers) gets the same argv lists from PowerShell as from bash.

What it splits on, as PowerShell does:
  - single quotes (no escapes; '' is a quote) and double quotes (backtick escapes, "" is a quote, $ expansion),
    including the typographic quotes PowerShell also accepts, and here-strings (@' '@, @" "@)
  - backtick line continuation; a backtick outside quotes makes the next character literal
  - ;, newlines, |, &&, || and & (the call operator at a command's start, a background job after one)
  - comments (# to the end of the line, <# #>) and redirections (>, >>, 2>, 2>&1, *>, ...), dropped
  - script blocks { }, subexpressions $( ) @( ), hashtables @{ } and parenthesized expressions ( ): what is inside
    is read as commands too, and the word that holds one is unknown
  - commas outside quotes, which make an array: each element is its own argument

What it unwraps:
  - Invoke-Expression and iex with a literal string
  - pwsh and powershell with -Command, -c or -EncodedCommand (base64 of UTF-16LE text, decoded and read), and
    powershell.exe with a script string as its first argument; pwsh's first argument is a script file, not read
  - cmd /c and cmd /k, read with cmd's simpler rules (double quotes, ^ escapes, &, &&, ||, |)
  - Start-Process with -FilePath and -ArgumentList
  - `bash -c` and the other shells, through the POSIX reader
  - an assignment statement's right-hand side, which runs as a command (`$out = git push ...`); an assignment to
    $env:NAME is passed on as NAME=value, as a POSIX assignment is, for the registry and cloud readers
  - a pipeline that feeds Remove-Item from Get-ChildItem, Get-Item or a literal path, with no path of its own: the
    paths it reads are added to Remove-Item's arguments with -Path, so the destructive check sees the target

Unknown: a variable ($x, $env:X, ${x}), a subexpression, a script block or a string built at run time is kept as
written, so the readers treat it as they treat a shell variable. An encoded command that is not valid base64 of
UTF-16LE text, or one given as an expression, is unknown and not read. Splatting (@args), dynamic parameter names,
.NET calls and scripts a command runs are not read (§4).

Parameter names are matched as PowerShell matches them: in any letter case, by unambiguous prefix (-r, -Rec and
-Recurse are the same), with the en dash, em dash and horizontal bar accepted for the hyphen.

windows_finding() is the destructive check's part for Windows: Remove-Item and its aliases (rm, del, erase, rd,
rmdir, ri) with -Recurse, and rd /s and del /s, on a dangerous target, and the commands that wipe disks, volumes or
shadow copies. Standard library only. Python 3.8+.
"""
from __future__ import annotations

import base64
import binascii
import ntpath
import os
import re
import time

from .destructive import (
    CONFIGURED_BY_ENVIRONMENT,
    GIT_CONFIG_ASSIGNMENT,
    GIT_ENVIRONMENT_ASSIGNMENT,
    RM_DANGEROUS_TARGET,
    SHELLS,
    ReadTimeout,
    _deadline,
    _changes_branch,
    _config_setting,
    _running_users_home_target,
    _shell_command_string,
    _simple_commands,
    _strip_wrappers,
    git_config_assignment_harmful,
)

MAX_DEPTH = 4  # nested unwraps (iex in pwsh -c in cmd /c ...); deeper is not read
MAX_NESTING = 32  # blocks, subexpressions and parentheses inside one another; deeper is not read
DASHES = "-\u2013\u2014\u2015"
SINGLE_QUOTES = "'\u2018\u2019\u201a\u201b"
DOUBLE_QUOTES = '"\u201c\u201d\u201e'
SPACES = " \t\f\v\u00a0"
OPENERS = {"(": ")", "{": "}"}
REDIRECTION = re.compile(r"(?:[1-6*]?>>?(?:&[12])?|<)")
VARIABLE = re.compile(r"\$(?:\{[^}]*\}|[A-Za-z_][\w]*(?::[A-Za-z_][\w]*)?|[$?^_])")
EXECUTABLE_SUFFIX = re.compile(r"\.(?:exe|com|cmd|bat)$", re.IGNORECASE)
POWERSHELLS = {"pwsh", "powershell", "powershell_ise"}
INVOKE_EXPRESSION = {"invoke-expression", "iex"}
START_PROCESS = {"start-process", "saps", "start"}


class Word(str):
    """A word as PowerShell passes it, quotes removed. literal is False when part of it is resolved only at run time
    (a variable, a subexpression, a script block, a parenthesized expression), kept as written. bare is True when it
    begins outside quotes, so it can be a parameter name."""

    literal = True
    bare = True


class Op(str):
    """An operator: ;, newline, |, ||, &&, & or a redirection."""


def _word(text: str, literal: bool, bare: bool) -> Word:
    word = Word(text)
    word.literal, word.bare = literal, bare
    return word


def _close(text: str, i: int, opener: str) -> int:
    """The index just past the bracket that closes the one at text[i], honoring quotes, escapes and nesting; len(text)
    when it is not closed."""
    closer, depth, n = OPENERS[opener], 0, len(text)
    while i < n:
        c = text[i]
        if c == "`":
            i += 2
            continue
        if c in SINGLE_QUOTES:
            i += 1
            while i < n and text[i] not in SINGLE_QUOTES:
                i += 1
        elif c in DOUBLE_QUOTES:
            i += 1
            while i < n and text[i] not in DOUBLE_QUOTES:
                i += 2 if text[i] == "`" else 1
        elif c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _expandable(text: str, nested: list) -> tuple:
    """(value, literal) of a double-quoted string's content: backtick escapes applied, variables and subexpressions
    kept as written (and their commands read through nested)."""
    out, literal, i, n = [], True, 0, len(text)
    escapes = {"n": "\n", "t": "\t", "r": "\r", "0": "\0", "a": "\a", "b": "\b", "f": "\f", "v": "\v", "e": "\x1b"}
    while i < n:
        c = text[i]
        if c == "`" and i + 1 < n:
            out.append(escapes.get(text[i + 1], text[i + 1]))
            i += 2
        elif c == "$" and text.startswith("$(", i):
            end = _close(text, i + 1, "(")
            nested.append(text[i + 2:end - 1])
            out.append(text[i:end])
            literal, i = False, end
        elif c == "$" and VARIABLE.match(text, i):
            match = VARIABLE.match(text, i)
            out.append(match.group(0))
            literal, i = False, match.end()
        else:
            out.append(c)
            i += 1
    return "".join(out), literal


def _lex(text: str, nested: list) -> list:
    """The words and operators of a PowerShell command line. The text of every block, subexpression and parenthesized
    expression is appended to nested, to be read as commands too."""
    tokens: list = []
    parts: list = []
    started, literal, bare = False, True, True
    i, n = 0, len(text)

    def end_word():
        nonlocal started, literal, bare
        if started:
            tokens.append(_word("".join(parts), literal, bare))
        parts.clear()
        started, literal, bare = False, True, True

    def begin(quoted: bool = False):
        nonlocal started, bare
        if not started:
            bare = not quoted
        started = True

    while i < n:
        c = text[i]
        if c in SPACES:
            end_word()
            i += 1
        elif c in "\r\n":
            end_word()
            tokens.append(Op("\n"))
            i += 1
        elif c == "`":
            if text.startswith("`\r\n", i):
                end_word()
                i += 3
            elif i + 1 < n and text[i + 1] in "\r\n":
                end_word()
                i += 2
            else:
                begin()
                parts.append(text[i + 1:i + 2])
                i += 2
        elif c == "#" and not started:
            while i < n and text[i] not in "\r\n":
                i += 1
        elif c == "<" and text.startswith("<#", i) and not started:
            end = text.find("#>", i + 2)
            i = n if end == -1 else end + 2
        elif c in SINGLE_QUOTES:
            begin(quoted=True)
            i += 1
            while i < n:
                if text[i] in SINGLE_QUOTES:
                    if i + 1 < n and text[i + 1] in SINGLE_QUOTES:
                        parts.append("'")
                        i += 2
                        continue
                    i += 1
                    break
                parts.append(text[i])
                i += 1
        elif c in DOUBLE_QUOTES:
            begin(quoted=True)
            i += 1
            start = i
            while i < n:
                if text[i] == "`":
                    i += 2
                    continue
                if text[i] in DOUBLE_QUOTES:
                    if i + 1 < n and text[i + 1] in DOUBLE_QUOTES:
                        i += 2
                        continue
                    break
                if text.startswith("$(", i):
                    i = _close(text, i + 1, "(")
                    continue
                i += 1
            content = re.sub("[%s]{2}" % DOUBLE_QUOTES, '"', text[start:i])
            value, plain = _expandable(content, nested)
            parts.append(value)
            literal = literal and plain
            i += 1
        elif c == "@" and text.startswith(("@'", '@"'), i) and text[i + 2:i + 3] in ("\r", "\n"):
            quote = text[i + 1]
            end = text.find("\n" + quote + "@", i + 2)
            end = n if end == -1 else end
            body = text[i + 2:end].lstrip("\r\n").rstrip("\r")
            begin(quoted=True)
            if quote == "'":
                parts.append(body)
            else:
                value, plain = _expandable(body, nested)
                parts.append(value)
                literal = literal and plain
            i = end + 3
        elif text.startswith("$(", i) or (not started and text.startswith(("@(", "@{"), i)):
            end = _close(text, i + 1, text[i + 1])
            nested.append(text[i + 2:end - 1])
            begin()
            parts.append(text[i:end])
            literal, i = False, end
        elif c in "({":
            end = _close(text, i, c)
            nested.append(text[i + 1:end - 1])
            begin()
            parts.append(text[i:end])
            literal, i = False, end
        elif c == "$" and VARIABLE.match(text, i):
            match = VARIABLE.match(text, i)
            begin()
            parts.append(match.group(0))
            literal, i = False, match.end()
        elif c == "@" and not started and re.match(r"@[A-Za-z_]", text[i:i + 2]):
            match = re.match(r"@[\w:]+", text[i:])
            begin()
            parts.append(match.group(0))  # splatting: unknown
            literal, i = False, i + match.end()
        elif c == ";":
            end_word()
            tokens.append(Op(";"))
            i += 1
        elif c == "|":
            end_word()
            op = "||" if text.startswith("||", i) else "|"
            tokens.append(Op(op))
            i += len(op)
        elif c == "&":
            end_word()
            op = "&&" if text.startswith("&&", i) else "&"
            tokens.append(Op(op))
            i += len(op)
        elif c == ",":
            end_word()
            i += 1
        elif (c in "<>" or (c in "123456*" and not started and text[i + 1:i + 2] == ">")) and REDIRECTION.match(text, i):
            end_word()
            match = REDIRECTION.match(text, i)
            tokens.append(Op(">" if not match.group(0).endswith(("&1", "&2")) else ">&"))
            i = match.end()
        else:
            begin()
            parts.append(c)
            i += 1
    end_word()
    return tokens


def _command_name(word: str) -> str:
    """A command word as the readers compare it: its last path component, without .exe/.com/.cmd/.bat, lowercase.
    A module-qualified cmdlet (Microsoft.PowerShell.Management\\Remove-Item) is its cmdlet name."""
    return EXECUTABLE_SUFFIX.sub("", ntpath.basename(word.rstrip("\\/"))).lower() if word else word


def _raw_pipelines(text: str, nested: list) -> list:
    """The pipelines of a command line, each a list of argv lists of Words, before unwrapping."""
    pipelines, pipeline, argv = [], [], []
    skip_target = False

    def end_element():
        if argv:
            pipeline.append(list(argv))
        argv.clear()

    def end_pipeline():
        end_element()
        if pipeline:
            pipelines.append(list(pipeline))
        pipeline.clear()

    for token in _lex(text, nested):
        if skip_target:
            skip_target = False
            if not isinstance(token, Op):
                continue  # a redirection's file
        if isinstance(token, Op):
            if token == ">":
                skip_target = True
            elif token == ">&":
                pass
            elif token == "|":
                end_element()
            elif token == "&" and not argv:
                pass  # the call operator: the next word is the command
            else:
                end_pipeline()
        elif not argv and token == "." and token.bare:
            continue  # dot-sourcing: the next word is the command or script
        else:
            argv.append(token)
    end_pipeline()
    return pipelines


# --- parameters ---------------------------------------------------------------------------------------------------
COMMON_SWITCHES = ("verbose", "debug", "whatif", "confirm")
COMMON_VALUES = ("erroraction", "warningaction", "informationaction", "errorvariable", "warningvariable",
                 "informationvariable", "outvariable", "outbuffer", "pipelinevariable", "progressaction")
COMMON_ALIASES = {"vb": "verbose", "db": "debug", "wi": "whatif", "cf": "confirm", "ea": "erroraction",
                  "wa": "warningaction", "infa": "informationaction", "ev": "errorvariable", "wv": "warningvariable",
                  "iv": "informationvariable", "ov": "outvariable", "ob": "outbuffer", "pv": "pipelinevariable",
                  "proga": "progressaction"}


class Parameters:
    """A cmdlet's arguments read as PowerShell binds them: named values, switches and positionals."""

    def __init__(self, args: list, switches: tuple, values: tuple, aliases: dict | None = None):
        self.values: dict = {}
        self.switches: dict = {}
        self.positionals: list = []
        names = tuple(switches) + COMMON_SWITCHES + tuple(values) + COMMON_VALUES
        known_aliases = dict(COMMON_ALIASES, **(aliases or {}))
        i = 0
        while i < len(args):
            arg = args[i]
            i += 1
            if not (getattr(arg, "bare", True) and len(arg) > 1 and arg[0] in DASHES and not arg[1].isdigit()):
                self.positionals.append(arg)
                continue
            name, colon, value = arg[1:].partition(":")
            resolved = resolve(name, names, known_aliases)
            if resolved is None:
                continue  # an unknown or ambiguous parameter: PowerShell refuses the command
            if resolved in values or resolved in COMMON_VALUES:
                if not colon:
                    if i >= len(args):
                        continue
                    value, i = args[i], i + 1
                self.values.setdefault(resolved, []).append(value)
            else:
                self.switches[resolved] = not colon or value.strip().lower() not in ("$false", "0", "$null")


def resolve(name: str, names: tuple, aliases: dict) -> str | None:
    """A parameter's full name from what was typed: an alias, the whole name, or an unambiguous prefix; else None."""
    lowered = name.lower()
    if lowered in aliases:
        return aliases[lowered]
    if lowered in names:
        return lowered
    candidates = {full for full in names if full.startswith(lowered)}
    return candidates.pop() if lowered and len(candidates) == 1 else None


# --- unwrapping ---------------------------------------------------------------------------------------------------
POWERSHELL_PARAMETERS = ("command", "commandwithargs", "encodedcommand", "file", "executionpolicy", "windowstyle",
                         "workingdirectory", "version", "psconsolefile", "configurationname", "configurationfile",
                         "outputformat", "inputformat", "settingsfile", "custompipename", "encodedarguments",
                         "noprofile", "noninteractive", "nologo", "noexit", "sta", "mta", "login", "interactive",
                         "noprofileloadtime", "help")
POWERSHELL_VALUES = ("executionpolicy", "windowstyle", "workingdirectory", "version", "psconsolefile",
                     "configurationname", "configurationfile", "outputformat", "inputformat", "settingsfile",
                     "custompipename", "encodedarguments")
POWERSHELL_ALIASES = {"c": "command", "cwa": "commandwithargs", "e": "encodedcommand", "ec": "encodedcommand",
                      "enc": "encodedcommand", "f": "file", "ex": "executionpolicy", "ep": "executionpolicy",
                      "w": "windowstyle", "wd": "workingdirectory", "v": "version", "o": "outputformat",
                      "of": "outputformat", "if": "inputformat", "l": "login", "i": "interactive", "nop": "noprofile",
                      "noni": "noninteractive", "nol": "nologo", "noe": "noexit"}


def decode_encoded(value: str) -> str | None:
    """The text of an -EncodedCommand value (base64 of UTF-16LE), or None when it is not one."""
    try:
        raw = base64.b64decode("".join(value.split()), validate=True)
        if len(raw) % 2:
            return None
        return raw.decode("utf-16-le")
    except ReadTimeout:
        raise  # the hook's timer (a ValueError): never read as a value that does not decode
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


def powershell_script(name: str, args: list) -> str | None:
    """The script a pwsh or powershell command line runs as a string, or None: a script file (-File, or pwsh's first
    argument), standard input (-Command -), no script, an encoded command that does not decode, or one built at run
    time. A parameter may begin with - or /, as powershell.exe accepts."""
    names = POWERSHELL_PARAMETERS
    i = 0
    while i < len(args):
        arg = args[i]
        if len(arg) > 1 and (arg[0] in DASHES or arg[0] == "/") and getattr(arg, "bare", True):
            resolved = resolve(arg[1:].lstrip("-"), names, POWERSHELL_ALIASES)
            if resolved in ("command", "commandwithargs"):
                rest = args[i + 1:]
                if not rest or rest[0] == "-":
                    return None
                return " ".join(rest)
            if resolved == "encodedcommand":
                value = args[i + 1] if i + 1 < len(args) else None
                if value is None or not getattr(value, "literal", True):
                    return None
                return decode_encoded(value)
            if resolved == "file":
                return None
            i += 2 if resolved in POWERSHELL_VALUES else 1
            continue
        # The first argument that is not a parameter: powershell.exe runs it (and the rest) as a command; pwsh as a file.
        return " ".join(args[i:]) if name.startswith("powershell") else None
    return None


def cmd_script(args: list) -> str | None:
    """The command line cmd runs with /c or /k, or None (an interactive cmd, or one given no command)."""
    for i, arg in enumerate(args):
        lowered = arg.lower()
        if lowered in ("/c", "/k"):
            return " ".join(args[i + 1:]) or None
        if lowered.startswith(("/c", "/k")) and not lowered.startswith(("/c:",)):
            return " ".join([arg[2:]] + list(args[i + 1:]))
        if not arg.startswith("/"):
            return None
    return None


CMD_INTERNAL = {"rd", "rmdir", "del", "erase", "dir", "copy", "move", "type", "cd", "chdir", "md", "mkdir"}


def _cmd_commands(text: str, depth: int, assignments: list | None, deadline: float | None = None):
    """Each simple command of a cmd command line: split on &, &&, ||, | and newlines outside double quotes, with ^
    escapes; `set NAME=value` is passed on as an assignment."""
    commands, words, word, started, i, n, quoted = [], [], [], False, 0, len(text), False
    plain = True

    def end_word():
        nonlocal started, plain
        if started:
            words.append(_word("".join(word), plain, True))
        word.clear()
        started, plain = False, True

    def end_command():
        end_word()
        if words:
            commands.append(list(words))
        words.clear()

    while i < n:
        c = text[i]
        if quoted:
            if c == '"':
                quoted = False
            else:
                word.append(c)
            i += 1
            continue
        if c == "^" and i + 1 < n:
            word.append(text[i + 1])
            started, i = True, i + 2
        elif c == '"':
            quoted, started = True, True
            i += 1
        elif c in " \t,;":
            end_word()
            i += 1
        elif c in "&|\r\n()":
            end_command()
            i += 2 if text[i:i + 2] in ("&&", "||") else 1
        elif c in "<>":
            end_word()
            i += 1
            while i < n and text[i] in ">&12":
                i += 1
            while i < n and text[i] in " \t":
                i += 1
            while i < n and text[i] not in " \t&|\r\n":
                i += 1  # the redirection's file
        else:
            if c == "%":
                plain = False
            word.append(c)
            started = True
            i += 1
    end_command()
    for argv in commands:
        first = argv[0].lstrip("@")
        head, slash, tail = first.partition("/")
        if slash and head.lower() in CMD_INTERNAL:  # `rd/s/q C:\` is `rd /s /q C:\`
            argv = [_word(head, True, True)] + [_word("/" + s, True, True) for s in tail.split("/") if s] + argv[1:]
        else:
            argv = [_word(first, argv[0].literal, True)] + argv[1:]
        if not argv[0]:
            continue
        name = _command_name(argv[0])
        if name == "set" and len(argv) > 1 and "=" in argv[1]:
            if assignments is not None:
                assignments.append(" ".join(argv[1:]).strip('"'))
            continue
        yield from _expand(argv, depth, assignments, cmd=True, deadline=deadline)


ASSIGNMENT_STATEMENT = re.compile(r"^(\$(?:\{[^}]*\}|[\w]+(?::[\w()]+)?))(=|\+=|-=|\*=|/=|%=|\?\?=)(.*)$", re.DOTALL)
ASSIGNMENT_OPERATORS = {"=", "+=", "-=", "*=", "/=", "%=", "??="}


def _environment_name(variable: str) -> str | None:
    """NAME for $env:NAME or ${env:NAME}, else None."""
    match = re.fullmatch(r"\$(?:\{env:([^}]+)\}|env:([\w()]+))", variable, re.IGNORECASE)
    return (match.group(1) or match.group(2)) if match else None


def _expand(argv: list, depth: int, assignments: list | None, cmd: bool = False, deadline: float | None = None):
    """The simple commands one argv runs: itself, or what it unwraps to. Raises ReadTimeout past the deadline."""
    if not argv:
        return
    if deadline is not None and time.monotonic() >= deadline:
        raise ReadTimeout("the command took too long to read")
    first = argv[0]
    statement = ASSIGNMENT_STATEMENT.match(first) if first.startswith("$") else None
    if statement or (first.startswith("$") and len(argv) > 1 and argv[1] in ASSIGNMENT_OPERATORS):
        variable = statement.group(1) if statement else first
        operator = statement.group(2) if statement else argv[1]
        rest = ([_word(statement.group(3), first.literal, True)] if statement and statement.group(3) else []) + \
            list(argv[1 if statement else 2:])
        name = _environment_name(variable)
        if name and operator == "=" and assignments is not None:
            value = rest[0] if len(rest) == 1 and getattr(rest[0], "literal", True) else "$(...)"
            assignments.append("%s=%s" % (name, value))
        if rest and getattr(rest[0], "bare", True):  # a bare word runs a command; a quoted one is a value
            yield from _expand(rest, depth, assignments, deadline=deadline)
        return
    # sudo, env, timeout and the other wrappers, with their options as destructive._strip_wrappers reads them: an
    # option it does not know gives two readings, and each is read.
    for stripped in _strip_wrappers(list(argv), deadline, assignments):
        yield from _expand_command(stripped, depth, assignments, cmd, deadline)


def _expand_command(argv: list, depth: int, assignments: list | None, cmd: bool, deadline: float | None):
    word = argv[0]
    name = _command_name(word) if getattr(word, "literal", True) else word
    args = argv[1:]
    if depth < MAX_DEPTH and getattr(word, "literal", True):
        script = None
        if name in INVOKE_EXPRESSION and not cmd:
            given = Parameters(args, (), ("command",))
            values = given.values.get("command", []) + given.positionals
            if values and all(getattr(v, "literal", True) for v in values):
                script = " ".join(values)
            if script is not None:
                yield from simple_commands(script, depth + 1, assignments, deadline)
                return
        elif name in POWERSHELLS:
            script = powershell_script(name, args)
            if script is not None:
                yield from simple_commands(script, depth + 1, assignments, deadline)
                return
        elif name == "cmd":
            script = cmd_script(args)
            if script is not None:
                yield from _cmd_commands(script, depth + 1, assignments, deadline)
                return
        elif name in SHELLS:
            script = _shell_command_string(args)
            if script is not None:  # a bash script inside: bash's reader, under the same deadline
                yield from _simple_commands(script, depth + 1, deadline, None, assignments)
                return
        elif name in START_PROCESS and not cmd:
            given = Parameters(args, ("loaduserprofile", "nonewwindow", "passthru", "wait", "usenewenvironment"),
                               ("filepath", "argumentlist", "credential", "workingdirectory", "redirectstandarderror",
                                "redirectstandardinput", "redirectstandardoutput", "verb", "windowstyle", "environment"),
                               {"args": "argumentlist", "lup": "loaduserprofile", "nnw": "nonewwindow"})
            files = given.values.get("filepath", []) + given.positionals[:1]
            arguments = given.values.get("argumentlist", []) + given.positionals[1:]
            if files and getattr(files[0], "literal", True):
                inner = [files[0]] + [_word(a, all(getattr(x, "literal", True) for x in arguments), True)
                                      for a in windows_split(" ".join(arguments))]
                yield from _expand(inner, depth + 1, assignments, deadline=deadline)
                return
    yield [_word(name, getattr(word, "literal", True), True)] + list(args)


def windows_split(line: str) -> list:
    """A Windows command line split into arguments as the C runtime splits it: whitespace outside double quotes,
    and backslashes are literal except before a quote."""
    out, word, started, quoted, i, n = [], [], False, False, 0, len(line)
    while i < n:
        c = line[i]
        if c == "\\":
            run = len(line[i:]) - len(line[i:].lstrip("\\"))
            if i + run < n and line[i + run] == '"':
                word.append("\\" * (run // 2))
                if run % 2:
                    word.append('"')
                    i += run + 1
                else:
                    i += run
                started = True
                continue
            word.append("\\" * run)
            started, i = True, i + run
        elif c == '"':
            quoted, started = not quoted, True
            i += 1
        elif c in " \t" and not quoted:
            if started:
                out.append("".join(word))
            word, started = [], False
            i += 1
        else:
            word.append(c)
            started, i = True, i + 1
    if started:
        out.append("".join(word))
    return out


# --- reading ------------------------------------------------------------------------------------------------------
GET_ITEM = {"get-childitem", "gci", "ls", "dir", "get-item", "gi", "resolve-path", "rvpa"}
REMOVE_ITEM = {"remove-item", "rm", "del", "erase", "rd", "rmdir", "ri"}
CMD_REMOVE = {"del", "erase", "rd", "rmdir"}
REMOVE_SWITCHES = ("recurse", "force")
REMOVE_VALUES = ("path", "literalpath", "filter", "include", "exclude", "credential", "stream")
PATH_ALIASES = {"lp": "literalpath", "pspath": "literalpath"}
GET_SWITCHES = ("recurse", "force", "name", "directory", "file", "hidden", "readonly", "system", "followsymlink")
GET_VALUES = ("path", "literalpath", "filter", "include", "exclude", "depth", "attributes", "credential", "stream")
CMD_SWITCH = re.compile(r"^/[A-Za-z?](?::\S*)?$")


def _paths(name: str, args: list) -> list:
    if name in GET_ITEM:
        given = Parameters(args, GET_SWITCHES, GET_VALUES, PATH_ALIASES)
    else:
        given = Parameters(args, REMOVE_SWITCHES, REMOVE_VALUES, PATH_ALIASES)
    paths = given.values.get("path", []) + given.values.get("literalpath", []) + given.positionals
    return [p for p in paths if not (name in CMD_REMOVE and CMD_SWITCH.match(p))]


def _feed_removals(pipeline: list) -> list:
    """The pipeline with each Remove-Item that has no path of its own given the paths the pipeline feeds it: the
    first command's, when that is Get-ChildItem, Get-Item or Resolve-Path, or the first element itself when it is a
    quoted path or a variable that names a place ($HOME, $env:USERPROFILE, ...). With -Filter, -Include or -Exclude
    on the Get-ChildItem, only a drive root or system directory is fed. A variable that holds items
    (`$files | Remove-Item -Recurse`) is not read."""
    if len(pipeline) < 2:
        return pipeline
    head = pipeline[0]
    head_name = _command_name(head[0]) if getattr(head[0], "literal", True) else None
    if head_name in GET_ITEM:
        fed = _paths(head_name, head[1:])
        given = Parameters(head[1:], GET_SWITCHES, GET_VALUES, PATH_ALIASES)
        if any(given.values.get(k) for k in ("filter", "include", "exclude")):
            # Only the matching children go down the pipeline, so the folder itself is the target only when it is a
            # drive root or a system directory, where even a filtered removal is not something an agent should run.
            fed = [p for p in fed if dangerous_target(p, system_only=True)]
    elif len(head) == 1 and (not head[0].bare or PLACE.match(head[0].lower().replace("/", "\\"))):
        fed = [head[0]]
    else:
        return pipeline
    out = [head]
    for argv in pipeline[1:]:
        name = _command_name(argv[0]) if getattr(argv[0], "literal", True) else None
        if name in REMOVE_ITEM and fed and not _paths(name, argv[1:]):
            argv = list(argv) + [p for path in fed for p in (_word("-Path", True, True), path)]
        out.append(argv)
    return out


def _flatten(text: str, depth: int, assignments: list | None, nesting: int = 0, deadline: float | None = None):
    nested: list = []
    if deadline is not None and time.monotonic() >= deadline:
        raise ReadTimeout("the command took too long to read")
    for pipeline in _raw_pipelines(text, nested):
        for argv in _feed_removals(pipeline):
            yield from _expand(argv, depth, assignments, deadline=deadline)
    if nesting < MAX_NESTING:
        for inner in nested:
            yield from _flatten(inner, depth, assignments, nesting + 1, deadline)


def simple_commands(command: str, depth: int = 0, assignments: list | None = None, deadline: float | None = None):
    """Yield the argv list of each simple command a PowerShell command line runs, unwrapped as the module docstring
    says; the command name is its last path component, lowercase, without .exe. When `assignments` is a list, each
    assignment to $env:NAME (and cmd's `set NAME=value`) is appended to it as NAME=value. Raises ReadTimeout (a
    ValueError) past the deadline, READ_BUDGET_SECONDS from the first call by default."""
    yield from _flatten(command, depth, assignments, 0, _deadline(deadline))


def split_command(command: str, deadline: float | None = None) -> tuple:
    """(the simple commands, the assignments): what registry_targets, cloud_targets and deploy_targets read."""
    assignments: list = []
    return list(simple_commands(command, assignments=assignments, deadline=deadline)), assignments


DEFINES_COMMANDS = re.compile(r"(?i)(?:^|[\s;{(|&])(?:function|filter)\s|\b(?:set-alias|new-alias|sal|nal)\b")
LOCATION_COMMANDS = {"set-location", "sl", "cd", "chdir", "push-location", "pushd", "pop-location", "popd",
                     "invoke-expression", "iex", "invoke-item", "ii"}


def commands_with_branch_context(command: str, cwd: str | None, deadline: float | None = None):
    """destructive.commands_with_branch_context for a PowerShell command line: each simple command, with the directory
    to read the checked-out branch from, None once it may have changed (Set-Location and its aliases, git checkout,
    git switch and the others destructive._changes_branch names, an iex it could not read), and None for the whole
    line when it defines a function or an alias, or assigns $env:GIT_DIR, GIT_WORK_TREE or GIT_COMMON_DIR. A harmful
    $env:GIT_CONFIG_* yields CONFIGURED_BY_ENVIRONMENT, as in bash."""
    assignments: list = []
    commands = list(simple_commands(command, assignments=assignments, deadline=deadline))
    branch_cwd = cwd
    for assignment in assignments:
        name, _, value = assignment.partition("=")
        if GIT_CONFIG_ASSIGNMENT.match(assignment) and git_config_assignment_harmful(name, value):
            branch_cwd = CONFIGURED_BY_ENVIRONMENT
            break
        if GIT_ENVIRONMENT_ASSIGNMENT.match(assignment):
            branch_cwd = None
    if branch_cwd is not CONFIGURED_BY_ENVIRONMENT and DEFINES_COMMANDS.search(command):
        branch_cwd = None
    for argv in commands:
        yield argv, branch_cwd
        setting = _config_setting(argv)
        if setting == "mirror":
            branch_cwd = CONFIGURED_BY_ENVIRONMENT
        elif branch_cwd is not CONFIGURED_BY_ENVIRONMENT and (
                setting == "unknown" or argv[0] in LOCATION_COMMANDS or _changes_branch(argv)):
            branch_cwd = None


# --- the destructive check's part for Windows ---------------------------------------------------------------------
REMOVE_LABEL = ("recursive Remove-Item, rd /s or del /s of a drive root, a system directory, home, a credential "
                "directory, or a bare variable")
REMOVE_NOTE = ("Remove a specific subdirectory by name (for example `Remove-Item -Recurse -Force .\\build`), never a "
               "drive root, a bare variable, the home directory, a credential directory, or a system directory.")
WIPE_LABEL = "disk, volume or shadow-copy wipe (Format-Volume, Clear-Disk, Remove-Partition, format, diskpart, cipher /w, vssadmin)"
WIPE_NOTE = ("Never format, clean or wipe a disk, a volume or its shadow copies from an agent session; check the target and "
             "have the person run it directly.")
WIPE_CMDLETS = {"format-volume", "clear-disk", "remove-partition"}
DRIVE = re.compile(r"^[a-z]:\\?$")
# Variables and %VARIABLES% that name a dangerous place, as their lowercase path with ~ for the home directory.
PLACES = (
    (r"\$(?:home|\{home\}|env:userprofile|\{env:userprofile\}|env:home|\{env:home\})", "~"),
    (r"\$env:homedrive\$env:homepath|%homedrive%%homepath%|%userprofile%|%home%", "~"),
    (r"\$(?:env:appdata|\{env:appdata\})|%appdata%", "~\\appdata\\roaming"),
    (r"\$(?:env:localappdata|\{env:localappdata\})|%localappdata%", "~\\appdata\\local"),
    (r"\$(?:env:systemroot|\{env:systemroot\}|env:windir|\{env:windir\})|%systemroot%|%windir%", "c:\\windows"),
    (r"\$(?:env:programfiles\(x86\)|\{env:programfiles\(x86\)\})|%programfiles\(x86\)%", "c:\\program files (x86)"),
    (r"\$(?:env:programfiles|\{env:programfiles\}|env:programw6432|\{env:programw6432\})|%programfiles%|%programw6432%",
     "c:\\program files"),
    (r"\$(?:env:programdata|\{env:programdata\}|env:allusersprofile|\{env:allusersprofile\})|%programdata%|%allusersprofile%",
     "c:\\programdata"),
    (r"\$(?:env:systemdrive|\{env:systemdrive\})|%systemdrive%", "c:"),
    (r"\$(?:env:public|\{env:public\})|%public%", "c:\\users\\public"),
)
PLACE = re.compile(r"^(?:%s)(?=\\|$)" % "|".join("(%s)" % pattern for pattern, _ in PLACES))
SYSTEM_PLACES = re.compile(r"^[a-z]:\\(?:windows(?:\\system32)?|program files(?: \(x86\))?|programdata|users)$")
HOME_PLACES = re.compile(r"^~(?:\\(?:\.ssh|\.aws|\.azure|\.kube|\.docker|\.gnupg|\.openclaw|\.config|\.config\\gcloud"
                         r"|appdata\\roaming\\gcloud))?$")
BARE_VARIABLE = re.compile(r"^(?:\$(?:\{[^}]*\}|[\w]+(?::[\w()]+)?)|%[^%]+%)$")
POSIX_SYSTEM_TARGET = re.compile(r"^/+(?:[A-Za-z0-9]+/*)?\*?$")  # / and one-segment system directories such as /etc
NOT_A_PATH = {"$_", "$psitem", "$null", "$true", "$false"}


def _home_prefix() -> str | None:
    home = os.path.expanduser("~")
    if not home or home == "~" or not ntpath.isabs(home.replace("/", "\\")):
        return None
    return home.replace("/", "\\").rstrip("\\").lower() or None


def dangerous_target(target: str, system_only: bool = False) -> bool:
    """Whether a Remove-Item or rd /s target is a drive root, a system directory, a home directory, a credential
    directory in one, or a bare variable, in any spelling: / or \\, any case, a trailing \\ or \\*, a provider prefix
    (FileSystem::) or a \\\\?\\ prefix. POSIX spellings (/, /etc, ~/.ssh) are read as destructive.RM_DANGEROUS_TARGET
    reads them. With system_only, only a drive root or a system directory counts: home directories, credential
    directories and bare variables do not."""
    if target.strip().lower() in NOT_A_PATH:
        return False  # the pipeline's current item, or no path at all
    if RM_DANGEROUS_TARGET.match(target) or _running_users_home_target(target):
        if not system_only:
            return True
        if POSIX_SYSTEM_TARGET.match(target):
            return True
    text = target.strip().replace("/", "\\")
    if not text:
        return False
    lowered = text.lower()
    lowered = re.sub(r"^(?:microsoft\.powershell\.core\\)?filesystem::", "", lowered)
    lowered = re.sub(r"^\\\\[?.]\\", "", lowered)
    rooted = lowered.startswith("\\")
    lowered = re.sub(r"\\+", r"\\", lowered)
    lowered = re.sub(r"(?:\\?\*(?:\.\*)?)+$", "", lowered).rstrip("\\")
    if not lowered:
        return rooted  # \ or \* is the current drive's root; * alone is the working directory's items
    if lowered in NOT_A_PATH:
        return False
    match = PLACE.match(lowered)
    if match:
        index = next(i for i, group in enumerate(match.groups()) if group is not None)
        lowered = PLACES[index][1] + lowered[match.end():]
    home = _home_prefix()
    if home and (lowered == home or lowered.startswith(home + "\\")):
        lowered = "~" + lowered[len(home):]
    lowered = re.sub(r"^(?:[a-z]:)?\\users\\(?!public(?:\\|$))[^\\]+", "~", lowered)
    if system_only:
        return bool(DRIVE.match(lowered) or SYSTEM_PLACES.match(lowered))
    return bool(DRIVE.match(lowered) or SYSTEM_PLACES.match(lowered) or HOME_PLACES.match(lowered)
                or BARE_VARIABLE.match(lowered))


def _whatif(args: list) -> bool:
    return Parameters(args, (), ()).switches.get("whatif", False)


def windows_finding(argv: list) -> tuple | None:
    """(label, remediation) when one simple command is a Windows deletion or wipe the destructive check blocks."""
    name, args = _command_name(argv[0]), argv[1:]
    lowered = [a.lower() for a in args]
    if name in REMOVE_ITEM:
        given = Parameters(args, REMOVE_SWITCHES, REMOVE_VALUES, PATH_ALIASES)
        recursive = given.switches.get("recurse", False) or (name in CMD_REMOVE and any(p.lower() == "/s" for p in given.positionals))
        if recursive and not given.switches.get("whatif", False) and any(dangerous_target(t) for t in _paths(name, args)):
            return REMOVE_LABEL, REMOVE_NOTE
        return None
    if name in WIPE_CMDLETS and not _whatif(args):
        return WIPE_LABEL, WIPE_NOTE
    if name == "format" and any(DRIVE.match(a.replace("/", "\\")) for a in lowered):
        return WIPE_LABEL, WIPE_NOTE
    if name == "diskpart":  # it reads its script from /s FILE or from piped input
        return WIPE_LABEL, WIPE_NOTE
    if name == "cipher" and any(a.startswith("/w") for a in lowered):
        return WIPE_LABEL, WIPE_NOTE
    if name == "vssadmin" and lowered[:2] == ["delete", "shadows"]:
        return WIPE_LABEL, WIPE_NOTE
    if name == "wmic" and "shadowcopy" in lowered and "delete" in lowered:
        return WIPE_LABEL, WIPE_NOTE
    return None
