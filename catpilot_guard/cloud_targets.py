"""What cloud account a shell command names: the targets the company-rules hook checks against cloud_account rules.

cloud_targets(command) splits the command the way the destructive-operation check does (pipes, `;`, `&&`, each line,
wrappers such as sudo, env and timeout, and `bash -c` bodies). It also reads the variable assignments that split drops
(`NAME=value` before a command, on its own, or after `env`) and the arguments of export, declare, typeset, local and
readonly. It looks through package runners as catpilot_guard/deploy_targets.py does (npx, bunx, pnpx, `npm exec`,
`pnpm dlx`/`exec`, `yarn dlx`/`exec`, `npx -c` strings; `npx aws-cdk` is cdk), and through the runners
registry_targets.runner_split names, as the package_registry reader does: `python -m MODULE` (`python -m awscli` is
aws), `poetry run`, `uv run`, `uv tool run`, `uvx`, `pipenv run` and `bundle exec`, past their own options. A command
is named without a Windows `.exe`, `.cmd` or `.bat` (`az.cmd`, `gcloud.cmd`). It returns one Target for each account the command names explicitly. A command that names none is no target: `aws s3 ls`, `gcloud
run deploy` and `az group list` act in the account of the active profile or configuration, which the hook does not
read. A Target is one of:

  an account   "aws:<12 digits>", "gcp:<project id>" or "azure:<subscription GUID>", lowercase
  unknown      an account the hook cannot read: a variable (`--project $PROJECT`, `arn:aws:iam::${ACCOUNT}:role/x`,
               `"arn:aws:iam::$(cat id):role/x"`, `arn:${PARTITION}:iam::...`, `--role-arn $ROLE`), a GCP project given
               by number or in any form a project id cannot take, an Azure subscription given by name, an account
               option whose value is not an account id, an account option last in the command with nothing after it
               (xargs or stdin supplies the value: `xargs gcloud run deploy --project`), a runner with more than three
               options this module does not know before its command

What is recognized, exactly:

  aws, sam, cdk   every ARN in any argument, whatever option or JSON document it sits in: partitions aws, aws-cn,
                  aws-us-gov and every other aws-*, with a 12-digit account field (an empty field, `aws` for an
                  AWS-owned resource, and `*` name none); an ARN with a variable anywhere in its partition or in its
                  account field is unknown, and so is one with a variable in its service or region and no 12-digit account
                  field (the variable may hold colons, or spaces the pattern stops at)
  aws             --account-id, --aws-account-id, --source-account (`-` names none), --account-ids (each id, comma- or
                  space-separated), as `OPT X` or `OPT=X`, and their abbreviations, which the AWS CLI's parser takes
                  (down to `--acc`, `--aws`, `--source-ac`; `--account-i` is read as --account-ids); --role-arn (down
                  to `--role-a`) holding a variable is unknown; `aws configure set [profile.NAME.]sso_account_id ID`,
                  and `role_arn` holding a variable; shorter abbreviations the CLI also takes (`--a`, `--ac`, `--aw`,
                  `--sou`, not codebuild's own `--source`): every 12-digit run in the first value is an account, and
                  a variable, a missing value, a file (`file://`, `fileb://`) or a JSON document (`[`, `{`) is
                  unknown; any other value names nothing, since another option may share them (`--ac private` is
                  --acl); later values (--a and --ac may be --account-ids) count only as 12 digits
  cdk             an environment argument `aws://ACCOUNT/REGION` (`unknown-account` names none)
  gcloud          --project and --billing-project, as `OPT X` or `OPT=X`; `gcloud config set project|core/project X`;
                  `gcloud [alpha|beta|preview] projects SUBCOMMAND PROJECT_ID` for every subcommand but list and search
  gsutil          -u PROJECT before the command (the requester-pays project); `gsutil mb|ls|hmac|kms -p PROJECT`;
                  every one of them (getopt keeps the last of several), with long options between the short ones
                  (`gsutil mb --retention 1d -p PROJECT`)
  bq              --project_id X, --project_id=X (also with one dash, as absl flags take it)
  az              --subscription X, --subscription=X, abbreviated down to `--s`: it is a global argument of nearly
                  every az command, so az's parser takes any prefix as it or refuses it as ambiguous;
                  --subscription-id; --subscriptions (each one); `az account set -s|-n|--name X` (`--name`
                  abbreviated down to `--n`); the /subscriptions/<id>/ of a resource id or management URL in any
                  argument, also percent-decoded (`/subscriptions%2F<id>`)
  assignments     CLOUDSDK_CORE_PROJECT, GOOGLE_CLOUD_PROJECT (gcp); AZURE_SUBSCRIPTION_ID, ARM_SUBSCRIPTION_ID (azure);
                  the ARN in AWS_ROLE_ARN (aws)

Coverage (account_covered): exact match only, ignoring case. An unknown target is covered by nothing.

Not recognized: a profile or configuration given by name, which names no account the hook can read (`--profile`,
AWS_PROFILE, `gcloud --configuration`, `gcloud config configurations activate`, `az account set` to a subscription
name); the account of a role a profile assumes; accounts inside terraform, pulumi or CDK code and state, and the
accounts they deploy to; SDK calls in scripts; a role_arn or sso_account_id written into ~/.aws/config (or any file)
with printf, echo, tee or a heredoc, rather than with `aws configure set`; arguments xargs or stdin supplies, other
than an option left last without its value; a GCP project inside a service-account email, a bucket or a BigQuery
table reference (`project:dataset.table`); a 12-digit id outside an ARN or the options above; `gcloud config set
account`, which names a person, not a project; gcloud and bq abbreviations, which their parsers refuse; pipx, pdm,
hatch and rye and the commands they run; and other clouds and tools (oci, doctl, eksctl, kubectl contexts).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from .deploy_targets import RUNNERS, _call_string, _tool
from .destructive import ASSIGNMENT
from .registry_targets import command_name, runner_split, split_command

ACCOUNT = "account"
UNKNOWN = "unknown"

ARN_START = re.compile(r"arn:", re.IGNORECASE)
ARN = re.compile(r"arn:aws(?:-[a-z]+)*:([^:\s\"',]*):([^:\s\"',]*):([^:\s\"',]*):", re.IGNORECASE)
# An ARN the pattern above cannot read: a variable anywhere in its partition (`arn:${PARTITION}:...`, `arn:aws-${P}:`),
# or a variable in its service, region or account field that holds what that pattern stops at
# (`arn:aws:iam::$(cat id):role/x`).
VARIABLE_ARN = re.compile(r"arn:(?:[A-Za-z0-9-]*[$`]|aws(?:-[a-z]+)*:(?:[^:\"',]*:){0,2}[^:\"',]*?[$`])", re.IGNORECASE)
CDK_ENVIRONMENT = re.compile(r"^aws://([^/]*)/")
AZURE_SUBSCRIPTION_PATH = re.compile(r"/subscriptions/([^/\s\"',?]+)", re.IGNORECASE)
AWS_ID = re.compile(r"[0-9]{12}")
GCP_PROJECT = re.compile(r"[a-z][a-z0-9-]{5,29}")
AZURE_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
# Account options: {name: the shortest abbreviation the parser takes}. The AWS CLI's and az's parsers (argparse) take a
# unique prefix; a prefix of another option of the same command is refused there, so reading it costs nothing. Shorter
# forms are left out where they are another command's own option: `--source` (codebuild), `--role` (lambda),
# `--source-a` (`--source-arn`).
AWS_ACCOUNT_OPTIONS = {"--account-id": "--account-id", "--aws-account-id": "--aws", "--source-account": "--source-ac"}
AWS_ACCOUNT_LIST_OPTIONS = {"--account-ids": "--acc"}  # and every abbreviation of --account-id, which may be either
AWS_ROLE_ARN = {"--role-arn": "--role-a"}
# Shorter abbreviations the AWS CLI also takes where the command has no other option with that prefix (`--a`, `--ac`,
# `--aw`, `--sou`). They may be another option's abbreviation too (`--ac` for --acl), so from the first value every
# standalone 12-digit run is an account, and a variable, a missing value, a file (`file://`, `fileb://`) or a JSON
# document (`[`, `{`) is unknown; any other value names nothing. --a and --ac may be --account-ids, which takes several
# values: the later ones count only when they are 12 digits.
AWS_SHORT_ACCOUNT_LIST_OPTIONS = {"--account-ids": "--a"}
AWS_SHORT_ACCOUNT_OPTIONS = {"--aws-account-id": "--aw", "--source-account": "--sou"}
AWS_ID_RUN = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
AWS_CONFIG_KEYS = ("sso_account_id", "role_arn")
GCLOUD_PROJECT_OPTIONS = {"--project": "--project", "--billing-project": "--billing-project"}
BQ_PROJECT_OPTIONS = {"--project_id": "--project_id", "-project_id": "-project_id"}
# --subscription is a global argument of nearly every az command, so any prefix (`--s`, `--su`) is it or is refused.
AZ_SUBSCRIPTION_OPTIONS = {"--subscription": "--s", "--subscription-id": "--subscription-"}
AZ_ACCOUNT_SET_OPTIONS = {"-s": "-s", "-n": "-n", "--name": "--n"}
GSUTIL_PROJECT_COMMANDS = {"mb": "bcklp", "ls": "p", "hmac": "puse", "kms": "kp"}
AWS_VALUE_OPTIONS = {"--profile", "--region", "--output", "--endpoint-url", "--query", "--cli-input-json",
                     "--cli-input-yaml", "--ca-bundle", "--color", "--cli-read-timeout", "--cli-connect-timeout",
                     "--cli-binary-format"}
GCLOUD_VALUE_OPTIONS = {"--project", "--billing-project", "--account", "--configuration", "--verbosity", "--format",
                        "--impersonate-service-account", "--flags-file", "--flatten", "--trace-token", "--region",
                        "--zone", "--name", "--organization", "--folder", "--labels", "--member", "--role", "--condition",
                        "--filter", "--limit", "--page-size", "--sort-by"}
GCLOUD_TRACKS = {"alpha", "beta", "preview"}
GSUTIL_VALUE_LETTERS = "ohui"
GSUTIL_LONG_VALUE_OPTIONS = {"--impersonate-service-account", "--trace-token", "--perf-trace-token"}
AZ_VALUE_OPTIONS = {"--subscription", "-s", "-n", "--name", "-o", "--output", "--query", "-g", "--resource-group"}
EXPORTERS = {"export", "declare", "typeset", "local", "readonly"}
GCP_VARIABLES = {"CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT"}
AZURE_VARIABLES = {"AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID"}
PACKAGES = {"aws-cdk": "cdk", "awscli": "aws"}


@dataclass(frozen=True)
class Target:
    kind: str  # ACCOUNT or UNKNOWN
    name: str | None = None  # "aws:<id>", "gcp:<project>" or "azure:<guid>"; None for UNKNOWN


def _has_variable(text: str) -> bool:
    return "$" in text or "`" in text


def aws_account(value: str, none: tuple = ()) -> Target | None:
    """A 12-digit AWS account id as a target; a value in `none` names no account; anything else is unknown."""
    if value in none:
        return None
    return Target(ACCOUNT, "aws:" + value) if AWS_ID.fullmatch(value) else Target(UNKNOWN)


def gcp_project(value: str) -> Target:
    value = value.lower()
    return Target(ACCOUNT, "gcp:" + value) if GCP_PROJECT.fullmatch(value) else Target(UNKNOWN)


def azure_subscription(value: str) -> Target:
    value = value.lower()
    return Target(ACCOUNT, "azure:" + value) if AZURE_GUID.fullmatch(value) else Target(UNKNOWN)


def _arns(text: str) -> list:
    """The account of each ARN in text: 12 digits; unknown for a variable in the account field, or in the partition,
    service or region when the account field is not 12 digits (a variable there may hold colons that move the
    fields); nothing for an empty field, aws or *."""
    out = []
    for start in ARN_START.finditer(text):
        match = ARN.match(text, start.start())
        if match is not None:
            service, region, field = match.groups()
            if AWS_ID.fullmatch(field):
                out.append(Target(ACCOUNT, "aws:" + field))
            elif _has_variable(field) or _has_variable(service + region):
                out.append(Target(UNKNOWN))
        elif VARIABLE_ARN.match(text, start.start()):
            out.append(Target(UNKNOWN))
    return out


def _named(name: str, options: dict, exclude=()) -> bool:
    """Whether an argument names one of these options, exactly or abbreviated down to the shortest form given. exclude
    is a tuple of names, or a function of the name that is true for names to leave out."""
    if callable(exclude) and exclude(name) or not callable(exclude) and name in exclude:
        return False
    return any(name.startswith(shortest) and canonical.startswith(name) for canonical, shortest in options.items())


def _option_values(args: list, options: dict, many: bool = False, exclude=()) -> list:
    """The values of these options ({name: shortest abbreviation}): `OPT X` or `OPT=X`; with many, every argument up to
    the next option. None for an option with nothing after it (xargs or stdin supplies the value). Stops at `--`."""
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        name, sep, value = arg.partition("=")
        if name.startswith("-") and _named(name, options, exclude):
            if sep:
                out.append(value)
                i += 1
                continue
            j = i + 1
            while j < len(args) and not (args[j].startswith("-") and len(args[j]) > 1 and j > i + 1):
                if args[j] == "--":
                    break
                out.append(args[j])
                j += 1
                if not many:
                    break
            if j == i + 1:
                out.append(None)
            i = j
            continue
        i += 1
    return out


def _option_value_lists(args: list, options: dict, many: bool, exclude=()) -> list:
    """For each occurrence of these options, the list of its values (`[None]` for one with nothing after it), so the
    first value of each can be told from the others."""
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        name, sep, value = arg.partition("=")
        if name.startswith("-") and _named(name, options, exclude):
            if sep:
                out.append([value])
                i += 1
                continue
            j = i + 1
            values = []
            while j < len(args) and args[j] != "--" and not (args[j].startswith("-") and len(args[j]) > 1 and j > i + 1):
                values.append(args[j])
                j += 1
                if not many:
                    break
            out.append(values or [None])
            i = max(j, i + 1)
            continue
        i += 1
    return out


def _short_account_values(values: list) -> list:
    """The accounts of a short aws abbreviation's values (AWS_SHORT_ACCOUNT_OPTIONS)."""
    first, later = values[0], values[1:]
    if first is None or _has_variable(first):
        return [Target(UNKNOWN)]
    out = [Target(ACCOUNT, "aws:" + run) for run in AWS_ID_RUN.findall(first)]
    if first.lower().startswith(("file://", "fileb://", "[", "{")):
        out.append(Target(UNKNOWN))  # a file or a JSON document the hook does not read whole
    for value in later:
        out.extend(Target(ACCOUNT, "aws:" + one) for one in re.split(r"[,\s]+", value) if AWS_ID.fullmatch(one))
    return out


def _read(value: str | None, read) -> Target | None:
    """read(value) for a value; unknown for a variable or a missing value."""
    if value is None or _has_variable(value):
        return Target(UNKNOWN)
    return read(value)


def _positionals(args: list, value_options: set) -> list:
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        if arg.startswith("-") and len(arg) > 1:
            i += 2 if (arg in value_options and "=" not in arg) else 1
            continue
        out.append(arg)
        i += 1
    return out


def _aws(args: list) -> list:
    out = []
    for value in _option_values(args, AWS_ACCOUNT_OPTIONS):
        out.append(_read(value, lambda v: aws_account(v, none=("-",))))
    for value in _option_values(args, AWS_ACCOUNT_LIST_OPTIONS, many=True, exclude=("--account-id",)):
        if value is None:
            out.append(Target(UNKNOWN))
            continue
        for one in re.split(r"[,\s]+", value):
            if one:
                out.append(_read(one, lambda v: aws_account(v, none=("-",))))
    for value in _option_values(args, AWS_ROLE_ARN):
        if value is None or _has_variable(value):
            out.append(Target(UNKNOWN))
    # Left to the long forms, and `--source`, which is another command's own option (codebuild create-project).
    strict = lambda name: name == "--source" or _named(name, AWS_ACCOUNT_OPTIONS) or _named(name, AWS_ACCOUNT_LIST_OPTIONS)  # noqa: E731
    for options, many in ((AWS_SHORT_ACCOUNT_LIST_OPTIONS, True), (AWS_SHORT_ACCOUNT_OPTIONS, False)):
        for values in _option_value_lists(args, options, many, exclude=strict):
            out.extend(_short_account_values(values))
    words = _positionals(args, AWS_VALUE_OPTIONS)
    if words[:2] == ["configure", "set"] and len(words) >= 3 and words[2].split(".")[-1] in AWS_CONFIG_KEYS:
        value = words[3] if len(words) >= 4 else None
        if words[2].split(".")[-1] == "sso_account_id":
            out.append(_read(value, aws_account))
        elif value is None or (_has_variable(value) and not _arns(value)):
            out.append(Target(UNKNOWN))  # role_arn: its ARN, when there is one, is read with every other ARN
    return out


def _cdk(args: list) -> list:
    out = []
    for arg in args:
        match = CDK_ENVIRONMENT.match(arg)
        if match:
            account = match.group(1)
            if _has_variable(account):
                out.append(Target(UNKNOWN))
            elif account != "unknown-account":
                out.append(aws_account(account))
    return out


def _gcloud(args: list) -> list:
    out = [_read(v, gcp_project) for v in _option_values(args, GCLOUD_PROJECT_OPTIONS)]
    words = _positionals(args, GCLOUD_VALUE_OPTIONS)
    if words[:1] and words[0] in GCLOUD_TRACKS:
        words = words[1:]
    asks_help = "--help" in args or "-h" in args
    if words[:2] == ["config", "set"] and len(words) >= 3 and words[2] in ("project", "core/project"):
        if len(words) >= 4 or not asks_help:
            out.append(_read(words[3] if len(words) >= 4 else None, gcp_project))
    elif words[:1] == ["projects"] and len(words) >= 2 and words[1] not in ("list", "search"):
        if len(words) >= 3 or not asks_help:
            out.append(_read(words[2] if len(words) >= 3 else None, gcp_project))
    return out


def _gsutil_letters(args: list, letters_with_value: str, wanted: str, long_values: set | frozenset = frozenset(),
                    guess: bool = False) -> tuple:
    """getopt-style options at the start of args, short and long interleaved: ([every value of the short option
    `wanted`, "" for one last with nothing after it], the index of the first word that is not an option). getopt keeps
    the last of several, so each is read. A long option in long_values takes the next word; with guess, so does any
    other long option followed by a word that is not an option (`--retention 1d`), which reads further rather than
    less."""
    values: list = []
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) > 1:
        if args[i] == "--":
            return values, i + 1
        if args[i].startswith("--"):
            takes = "=" not in args[i] and (args[i] in long_values or
                                            guess and i + 1 < len(args) and not args[i + 1].startswith("-"))
            i += 2 if takes else 1
            continue
        letters = args[i][1:]
        for k, letter in enumerate(letters):
            if letter in letters_with_value:
                value = letters[k + 1:]
                if not value:
                    i += 1
                    value = args[i] if i < len(args) else ""
                if letter == wanted:
                    values.append(value)
                break
        i += 1
    return values, i


def _gsutil(args: list) -> list:
    """gsutil's -u before the command, and -p after mb, ls, hmac and kms, each one of them: getopt style, so in a
    cluster (`-mu PROJECT`) or attached (`-uPROJECT`)."""
    values, command_at = _gsutil_letters(args, GSUTIL_VALUE_LETTERS, "u", GSUTIL_LONG_VALUE_OPTIONS)
    out = [_read(value or None, gcp_project) for value in values]
    words = args[command_at:]
    if words[:1] and words[0] in GSUTIL_PROJECT_COMMANDS:
        rest = words[1:]
        if words[0] in ("hmac", "kms") and rest and not rest[0].startswith("-"):
            rest = rest[1:]  # the subcommand: hmac create, kms authorize
        values, _ = _gsutil_letters(rest, GSUTIL_PROJECT_COMMANDS[words[0]], "p", guess=True)
        out.extend(_read(value or None, gcp_project) for value in values)
    return out


def _bq(args: list) -> list:
    return [_read(v, gcp_project) for v in _option_values(args, BQ_PROJECT_OPTIONS)]


def _az(args: list) -> list:
    out = [_read(v, azure_subscription) for v in _option_values(args, AZ_SUBSCRIPTION_OPTIONS)]
    for value in _option_values(args, {"--subscriptions": "--subscriptions"}, many=True):  # az graph query
        out.append(_read(value, azure_subscription))
    words = _positionals(args, AZ_VALUE_OPTIONS)
    if words[:2] == ["account", "set"]:
        out.extend(_read(v, azure_subscription) for v in _option_values(args, AZ_ACCOUNT_SET_OPTIONS))
    for arg in args:
        for text in dict.fromkeys((arg, unquote(arg))):  # also as decoded: /subscriptions%2F<id>
            for match in AZURE_SUBSCRIPTION_PATH.finditer(text):
                value = match.group(1)
                out.append(Target(UNKNOWN) if _has_variable(value) else azure_subscription(value))
    return out


def _assignment_targets(assignment: str) -> list:
    name, _, value = assignment.partition("=")
    upper = name.upper()
    if not value:
        return []
    if upper in GCP_VARIABLES:
        return [Target(UNKNOWN) if _has_variable(value) else gcp_project(value)]
    if upper in AZURE_VARIABLES:
        return [Target(UNKNOWN) if _has_variable(value) else azure_subscription(value)]
    if upper == "AWS_ROLE_ARN":
        return _arns(value) or ([Target(UNKNOWN)] if _has_variable(value) else [])
    return []


def _argv_targets(argv: list, depth: int) -> list:
    name = command_name(argv[0])
    argv = [name] + list(argv[1:])
    if depth < 3 and (name in RUNNERS or (name == "npm" and argv[1:2] in (["exec"], ["x"]))):
        call = _call_string(argv[2:] if name == "npm" else argv[1:])
        if call is not None:  # npx -c 'aws ...' runs the string as a shell command
            return cloud_targets(call, depth=depth + 1)
    split = runner_split(name, list(argv[1:])) if depth < 4 else None
    if split is not None:  # python -m awscli, poetry|uv|pipenv run, uv tool run, uvx, bundle exec
        out = [Target(UNKNOWN)] if split[2] else []  # more unknown runner options than are read both ways
        return out + [t for inner in split[1] for t in _argv_targets(inner, depth + 1)]
    name, args = _tool(argv)
    name = PACKAGES.get(name, name)
    out = []
    if name in ("aws", "sam", "cdk"):
        for arg in args:
            out.extend(_arns(arg))
    if name == "aws":
        out.extend(_aws(args))
    elif name == "cdk":
        out.extend(_cdk(args))
    elif name == "gcloud":
        out.extend(_gcloud(args))
    elif name == "gsutil":
        out.extend(_gsutil(args))
    elif name == "bq":
        out.extend(_bq(args))
    elif name == "az":
        out.extend(_az(args))
    elif name in EXPORTERS:
        out.extend(t for arg in args if ASSIGNMENT.match(arg) for t in _assignment_targets(arg))
    return out


def cloud_targets(command: str, cwd: str | None = None, depth: int = 0, split: tuple | None = None) -> list:
    """Every account the command names, in order: each command's own, then the assignments the split dropped. cwd is
    accepted for symmetry with deploy_targets and not used. split is registry_targets.split_command(command), when the
    caller has it."""
    targets: list = []
    commands, assignments = split if split is not None else split_command(command)
    for argv in commands:
        targets.extend(_argv_targets(argv, depth))
    for assignment in assignments:
        targets.extend(_assignment_targets(assignment))
    return [t for t in targets if t is not None]


def account_covered(value: str, target: Target) -> bool:
    """Whether a cloud_account value covers a target: exact match, ignoring case. Unknown: nothing covers it."""
    return target.kind == ACCOUNT and bool(target.name) and value.lower() == target.name
