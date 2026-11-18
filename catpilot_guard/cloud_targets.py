"""What cloud account a shell command names: the targets the company-rules hook checks against cloud_account rules.

cloud_targets(command) splits the command the way the destructive-operation check does (pipes, `;`, `&&`, each line,
wrappers such as sudo, env and timeout, and `bash -c` bodies). It also reads the variable assignments that split drops
(`NAME=value` before a command, on its own, or after `env`) and the arguments of export, declare, typeset, local and
readonly. It looks through package runners as catpilot_guard/deploy_targets.py does (npx, bunx, pnpx, `npm exec`,
`pnpm dlx`/`exec`, `yarn dlx`/`exec`, `npx -c` strings; `npx aws-cdk` is cdk). It returns one Target for each account
the command names explicitly. A command that names none is no target: `aws s3 ls`, `gcloud run deploy` and `az group
list` act in the account of the active profile or configuration, which the hook does not read. A Target is one of:

  an account   "aws:<12 digits>", "gcp:<project id>" or "azure:<subscription GUID>", lowercase
  unknown      an account the hook cannot read: a variable (`--project $PROJECT`, `arn:aws:iam::${ACCOUNT}:role/x`,
               `--role-arn $ROLE`), a GCP project given by number or in any form a project id cannot take, an Azure
               subscription given by name, an account option whose value is not an account id

What is recognized, exactly:

  aws, sam, cdk   every ARN in any argument, whatever option or JSON document it sits in: partitions aws, aws-cn,
                  aws-us-gov and every other aws-*, with a 12-digit account field (an empty field, `aws` for an
                  AWS-owned resource, and `*` name none)
  aws             --account-id, --aws-account-id, --source-account (`-` names none), --account-ids (each id, comma- or
                  space-separated), as `OPT X` or `OPT=X`; --role-arn holding a variable is unknown;
                  `aws configure set [profile.NAME.]sso_account_id ID`
  cdk             an environment argument `aws://ACCOUNT/REGION` (`unknown-account` names none)
  gcloud          --project and --billing-project, as `OPT X` or `OPT=X`; `gcloud config set project|core/project X`;
                  `gcloud [alpha|beta|preview] projects SUBCOMMAND PROJECT_ID` for every subcommand but list and search
  gsutil          -u PROJECT before the command (the requester-pays project)
  bq              --project_id X, --project_id=X
  az              --subscription X, --subscription=X; `az account set -s|-n|--name X`; the /subscriptions/<id>/ of a
                  resource id or management URL in any argument
  assignments     CLOUDSDK_CORE_PROJECT, GOOGLE_CLOUD_PROJECT (gcp); AZURE_SUBSCRIPTION_ID, ARM_SUBSCRIPTION_ID (azure);
                  the ARN in AWS_ROLE_ARN (aws)

Coverage (account_covered): exact match only, ignoring case. An unknown target is covered by nothing.

Not recognized: a profile or configuration given by name, which names no account the hook can read (`--profile`,
AWS_PROFILE, `gcloud --configuration`, `gcloud config configurations activate`, `az account set` to a subscription
name); the account of a role a profile assumes; accounts inside terraform, pulumi or CDK code and state, and the
accounts they deploy to; SDK calls in scripts; a GCP project inside a service-account email, a bucket or a BigQuery
table reference (`project:dataset.table`); a 12-digit id outside an ARN or the options above; `gcloud config set
account`, which names a person, not a project; and other clouds and tools (oci, doctl, eksctl, kubectl contexts).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .deploy_targets import RUNNERS, _call_string, _tool
from .destructive import ASSIGNMENT, _simple_commands

ACCOUNT = "account"
UNKNOWN = "unknown"

ARN = re.compile(r"arn:aws(?:-[a-z]+)*:[^:\s\"',]*:[^:\s\"',]*:([^:\s\"',]*):", re.IGNORECASE)
CDK_ENVIRONMENT = re.compile(r"^aws://([^/]*)/")
AZURE_SUBSCRIPTION_PATH = re.compile(r"/subscriptions/([^/\s\"',?]+)", re.IGNORECASE)
AWS_ID = re.compile(r"[0-9]{12}")
GCP_PROJECT = re.compile(r"[a-z][a-z0-9-]{5,29}")
AZURE_GUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
AWS_ACCOUNT_OPTIONS = ("--account-id", "--aws-account-id", "--source-account")
AWS_VALUE_OPTIONS = {"--profile", "--region", "--output", "--endpoint-url", "--query", "--cli-input-json",
                     "--cli-input-yaml", "--ca-bundle", "--color", "--cli-read-timeout", "--cli-connect-timeout",
                     "--cli-binary-format"}
GCLOUD_VALUE_OPTIONS = {"--project", "--billing-project", "--account", "--configuration", "--verbosity", "--format",
                        "--impersonate-service-account", "--flags-file", "--flatten", "--trace-token", "--region",
                        "--zone", "--name", "--organization", "--folder", "--labels", "--member", "--role", "--condition",
                        "--filter", "--limit", "--page-size", "--sort-by"}
GCLOUD_TRACKS = {"alpha", "beta", "preview"}
GSUTIL_VALUE_LETTERS = "ohui"
AZ_VALUE_OPTIONS = {"--subscription", "-s", "-n", "--name", "-o", "--output", "--query", "-g", "--resource-group"}
EXPORTERS = {"export", "declare", "typeset", "local", "readonly"}
GCP_VARIABLES = {"CLOUDSDK_CORE_PROJECT", "GOOGLE_CLOUD_PROJECT"}
AZURE_VARIABLES = {"AZURE_SUBSCRIPTION_ID", "ARM_SUBSCRIPTION_ID"}
PACKAGES = {"aws-cdk": "cdk"}


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
    """The account of each ARN in text: 12 digits, unknown for a variable, nothing for an empty field, aws or *."""
    out = []
    for match in ARN.finditer(text):
        field = match.group(1)
        if _has_variable(field):
            out.append(Target(UNKNOWN))
        elif AWS_ID.fullmatch(field):
            out.append(Target(ACCOUNT, "aws:" + field))
    return out


def _option_values(args: list, options: tuple, many: bool = False) -> list:
    """The values of these options: `OPT X` or `OPT=X`; with many, every argument up to the next option. Stops at `--`."""
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            break
        name, sep, value = arg.partition("=")
        if name in options and sep:
            out.append(value)
        elif arg in options:
            j = i + 1
            while j < len(args) and not (args[j].startswith("-") and len(args[j]) > 1 and j > i + 1):
                if args[j] == "--":
                    break
                out.append(args[j])
                j += 1
                if not many:
                    break
            i = j
            continue
        i += 1
    return out


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
        out.append(Target(UNKNOWN) if _has_variable(value) else aws_account(value, none=("-",)))
    for value in _option_values(args, ("--account-ids",), many=True):
        for one in re.split(r"[,\s]+", value):
            if one:
                out.append(Target(UNKNOWN) if _has_variable(one) else aws_account(one))
    for value in _option_values(args, ("--role-arn",)):
        if _has_variable(value):
            out.append(Target(UNKNOWN))
    words = _positionals(args, AWS_VALUE_OPTIONS)
    if words[:2] == ["configure", "set"] and len(words) >= 4 and words[2].split(".")[-1] == "sso_account_id":
        out.append(Target(UNKNOWN) if _has_variable(words[3]) else aws_account(words[3]))
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
    out = [Target(UNKNOWN) if _has_variable(v) else gcp_project(v) for v in _option_values(args, ("--project", "--billing-project"))]
    words = _positionals(args, GCLOUD_VALUE_OPTIONS)
    if words[:1] and words[0] in GCLOUD_TRACKS:
        words = words[1:]
    if words[:2] == ["config", "set"] and len(words) >= 4 and words[2] in ("project", "core/project"):
        out.append(Target(UNKNOWN) if _has_variable(words[3]) else gcp_project(words[3]))
    elif words[:1] == ["projects"] and len(words) >= 3 and words[1] not in ("list", "search"):
        out.append(Target(UNKNOWN) if _has_variable(words[2]) else gcp_project(words[2]))
    return out


def _gsutil(args: list) -> list:
    """gsutil's -u before the command: getopt style, so in a cluster (`-mu PROJECT`) or attached (`-uPROJECT`)."""
    i = 0
    while i < len(args) and args[i].startswith("-") and len(args[i]) > 1 and not args[i].startswith("--"):
        letters = args[i][1:]
        for k, letter in enumerate(letters):
            if letter in GSUTIL_VALUE_LETTERS:
                value = letters[k + 1:] or (args[i + 1] if i + 1 < len(args) else "")
                if not letters[k + 1:]:
                    i += 1
                if letter == "u" and value:
                    return [Target(UNKNOWN) if _has_variable(value) else gcp_project(value)]
                break
        i += 1
    return []


def _bq(args: list) -> list:
    return [Target(UNKNOWN) if _has_variable(v) else gcp_project(v) for v in _option_values(args, ("--project_id",))]


def _az(args: list) -> list:
    out = [Target(UNKNOWN) if _has_variable(v) else azure_subscription(v) for v in _option_values(args, ("--subscription",))]
    words = _positionals(args, AZ_VALUE_OPTIONS)
    if words[:2] == ["account", "set"]:
        out.extend(Target(UNKNOWN) if _has_variable(v) else azure_subscription(v) for v in _option_values(args, ("-s", "-n", "--name")))
    for arg in args:
        for match in AZURE_SUBSCRIPTION_PATH.finditer(arg):
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
    name = argv[0].rsplit("/", 1)[-1].lower()
    if depth < 3 and (name in RUNNERS or (name == "npm" and argv[1:2] in (["exec"], ["x"]))):
        call = _call_string(argv[2:] if name == "npm" else argv[1:])
        if call is not None:  # npx -c 'aws ...' runs the string as a shell command
            return cloud_targets(call, depth=depth + 1)
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


def cloud_targets(command: str, cwd: str | None = None, depth: int = 0) -> list:
    """Every account the command names, in order: each command's own, then the assignments the split dropped. cwd is
    accepted for symmetry with deploy_targets and not used."""
    targets: list = []
    assignments: list = []
    for argv in _simple_commands(command, assignments=assignments):
        targets.extend(_argv_targets(argv, depth))
    for assignment in assignments:
        targets.extend(_assignment_targets(assignment))
    return [t for t in targets if t is not None]


def account_covered(value: str, target: Target) -> bool:
    """Whether a cloud_account value covers a target: exact match, ignoring case. Unknown: nothing covers it."""
    return target.kind == ACCOUNT and bool(target.name) and value.lower() == target.name
