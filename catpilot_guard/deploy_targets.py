"""What a shell command deploys or publishes to: the targets the company-rules hook checks against deploy_host rules.

deploy_targets(command) splits the command the way the destructive-operation check does (pipes, `;`, `&&`, each line,
the commands inside compound commands such as `if ...; then vercel --prod; fi`, wrappers such as sudo, env and timeout,
and `bash -c` bodies), looks through package runners (npx, bunx, pnpx,
`npm exec`/`npm x`, `pnpm dlx`/`exec`, `yarn dlx`/`exec`), reading a package name with a version (`vercel@latest`) or
a package whose command has another name (`netlify-cli`, `firebase-tools`, `@railway/cli`, `@aws-amplify/cli`), and
returns a Target for each deploy or publish it recognizes, each distinct Target once. A Target is one of:

  a host       a name the command names itself, such as the destination of `scp dist/ deploy@web1.example.org:/srv`
               or the domain given to `surge`
  a suffix     a hosting service's own domain, when the command deploys there under a name the command does not
               show: `vercel` deploys to a *.vercel.app name, `netlify deploy` to *.netlify.app, and so on
  unknown      a destination the hook cannot read: a variable (`rsync dist/ $HOST:/srv`), an SSH alias without a dot
               (`scp f prod:/srv`, from ~/.ssh/config), an IPv6 or other address in brackets

What is recognized, exactly:

  vercel, vc         every run except help, version and the non-deploy subcommands in VERCEL_OTHER   suffix vercel.app
  netlify, ntl       deploy                                                                          suffix netlify.app
  fly, flyctl        deploy, launch (unless --no-deploy), machine run / machines run                 suffix fly.dev
  firebase           deploy, hosting:channel:deploy                                                  suffix web.app
  wrangler           deploy, publish, versions deploy, versions upload                               suffix workers.dev
  wrangler pages     deploy, publish                                                                 suffix pages.dev
  surge              every run except help, version and its account commands (SURGE_OTHER); its   host, else suffix
                     domain argument when given                                                      surge.sh
  gh-pages           every run except help and version                                               suffix github.io
  railway            up, redeploy                                                                    suffix up.railway.app
  amplify            publish                                                                         suffix amplifyapp.com
  git push           to a remote named heroku, or to a git.heroku.com URL                            suffix herokuapp.com
  scp, rsync         an upload: a remote destination after the first path ([user@]host:path,          host, or unknown
                     scp://, sftp://, rsync://)

Every scp or rsync upload to another machine counts, a backup to a dev box included, and a host without a dot cannot be
listed in a rule, so a deploy_host rule fires on those too: start such rules in monitor. Not recognized: a deploy a
script or CI job runs internally, a vendor this list does not name, a custom domain set in a project file (the service's
own domain is the target then), `ssh` sessions, `curl` uploads, container pushes (a package_registry matter, read by
registry_targets.py) and cloud object copies (a cloud_account matter, read by cloud_targets.py when they name an account).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .destructive import _deadline, _simple_commands, _skip_options

HOST = "host"
SUFFIX = "suffix"
UNKNOWN = "unknown"

HELP_OR_VERSION = {"-h", "--help", "-v", "--version", "-V", "help", "version"}
VERCEL_OTHER = {
    "env", "link", "pull", "whoami", "login", "logout", "build", "dev", "ls", "list", "logs", "inspect", "domains",
    "domain", "dns", "certs", "cert", "alias", "aliases", "secrets", "secret", "teams", "team", "switch", "projects",
    "project", "init", "remove", "rm", "bisect", "git", "integration", "integrations", "telemetry", "target", "targets",
    "blob", "install", "i", "open", "help", "version", "cache", "redirects", "mcp", "microfrontends", "guidance",
    "curl", "httpstat", "rolling-release", "integration-resource", "webhooks", "webhook", "flags", "upgrade", "update",
    "completion", "usage", "api", "contract", "edge-config",
}
SURGE_OTHER = {"login", "logout", "whoami", "list", "teardown", "token", "plan", "card", "invite", "revoke", "ssl",
               "encrypt", "files", "audit", "dns", "zone", "nuke", "help", "version"}
# name -> (deploying first words, deploying first-two-word pairs, the suffix)
DEPLOYERS = {
    "netlify": ({"deploy"}, set(), "netlify.app"),
    "fly": ({"deploy", "launch"}, {("machine", "run"), ("machines", "run")}, "fly.dev"),
    "firebase": ({"deploy", "hosting:channel:deploy"}, set(), "web.app"),
    "railway": ({"up", "redeploy"}, set(), "up.railway.app"),
    "amplify": ({"publish"}, set(), "amplifyapp.com"),
}
ALIASES = {"vc": "vercel", "ntl": "netlify", "flyctl": "fly"}
# npm package names whose command has another name.
PACKAGES = {"netlify-cli": "netlify", "firebase-tools": "firebase", "@railway/cli": "railway", "@aws-amplify/cli": "amplify",
            "@vercel/cli": "vercel"}
RUNNERS = {"npx", "bunx", "pnpx"}
# Options of these tools that take a value, so the value is not read as the subcommand.
VALUE_OPTIONS = {
    "vercel": {"--token", "-t", "--scope", "-S", "--cwd", "--local-config", "-A", "--global-config", "-Q", "--team", "-T",
               "--target", "-e", "--env", "-b", "--build-env", "-m", "--meta", "--regions", "--archive"},
    "netlify": {"--auth", "--cwd", "--filter", "--site", "-s", "--dir", "-d", "--functions", "-f", "--message", "-m",
                "--alias", "--context", "--prod-if-unlocked"},
    "fly": {"-a", "--app", "-c", "--config", "-t", "--access-token", "-o", "--org", "-i", "--image", "-r", "--region",
            "--strategy", "-e", "--env", "--build-arg", "--dockerfile"},
    "firebase": {"-P", "--project", "--token", "--config", "-c", "--only", "--except", "-m", "--message"},
    "railway": {"-s", "--service", "-e", "--environment"},
    "amplify": set(),
    "wrangler": {"-c", "--config", "-e", "--env", "--cwd", "--name", "--compatibility-date", "--project-name", "--branch"},
    "surge": {"--domain", "-d", "--project", "-p"},
}
HOST_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+")
REMOTE_URI = re.compile(r"^(?:scp|sftp|rsync)://", re.IGNORECASE)
SCP_VALUE_OPTIONS = {"-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J", "-D", "-X"}
RSYNC_VALUE_OPTIONS = {"-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from",
                       "--filter", "-f", "--port", "--password-file", "--log-file", "--bwlimit", "--chmod", "--chown",
                       "--temp-dir", "-T", "--partial-dir", "--compare-dest", "--copy-dest", "--link-dest", "-M",
                       "--remote-option", "--rsync-path", "--timeout", "--contimeout", "--block-size", "-B", "--max-size",
                       "--min-size", "--suffix", "--backup-dir", "--out-format", "--info", "--debug", "--max-delete",
                       "--modify-window", "--iconv", "--sockopts", "--usermap", "--groupmap", "--checksum-choice",
                       "--compress-choice", "--compress-level", "--skip-compress", "--address"}


@dataclass(frozen=True)
class Target:
    kind: str  # HOST, SUFFIX or UNKNOWN
    name: str | None = None  # the host or the suffix, lowercase; None for UNKNOWN


def _positionals(args: list, value_options: set) -> list:
    """The arguments that are not options or option values, in order."""
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            out.extend(args[i + 1:])
            break
        if arg.startswith("-") and len(arg) > 1:
            i += 2 if (arg in value_options and "=" not in arg) else 1
            continue
        out.append(arg)
        i += 1
    return out


def _package_command(raw: str) -> str:
    """The command a package runner starts for a package spec: `vercel@latest` -> vercel, `@railway/cli@3` -> railway."""
    spec = raw.strip()
    if spec.startswith("@"):
        scope, _, rest = spec[1:].partition("/")
        name = "@" + scope + "/" + rest.split("@", 1)[0] if rest else spec
    else:
        name = spec.split("@", 1)[0]
    name = name.lower()
    if name in PACKAGES:
        return PACKAGES[name]
    return os.path.basename(name)


def _call_string(args: list) -> str | None:
    """The command string given with -c/--call to npx or npm exec, which runs it as a shell command. Only the runner's
    own options count, before the package name: a tool's own -c after it (wrangler's config file) is the tool's."""
    i = 0
    while i < len(args) and args[i].startswith("-"):
        arg = args[i]
        if arg in ("-c", "--call"):
            return args[i + 1] if i + 1 < len(args) else None
        if arg.startswith("--call="):
            return arg[len("--call="):]
        i += 2 if arg in ("-p", "--package", "-w", "--workspace") else 1
    return None


def _tool(argv: list) -> tuple:
    """(command name, its arguments), looking through package runners. The name is lowercase: macOS runs `VERCEL` too."""
    name, args = os.path.basename(argv[0]).lower(), list(argv[1:])
    raw = None
    if name in RUNNERS:
        i = 0
        while i < len(args) and args[i].startswith("-"):
            i += 2 if args[i] in ("-p", "--package", "-c", "--call") else 1
        if i < len(args):
            raw, args = args[i], args[i + 1:]
    elif name == "npm" and args[:1] in (["exec"], ["x"]):
        rest = _skip_options(args[1:], {"-p", "--package", "-w", "--workspace", "-c", "--call"})
        if rest:
            raw, args = rest[0], rest[1:]
    elif name in ("yarn", "pnpm"):
        # yarn/pnpm [options] [workspace X] [run|dlx|exec] TOOL ...: a script name or a package's command.
        rest = _skip_options(args, {"--cwd", "-C", "--dir", "--filter", "-F"})
        if rest[:1] == ["workspace"] and len(rest) > 2:
            rest = rest[2:]
        if rest[:1] in (["dlx"], ["exec"], ["run"]):
            rest = _skip_options(rest[1:], {"-p", "--package"})
        if rest:
            raw, args = rest[0], rest[1:]
    if raw is not None:
        name = _package_command(raw)
        if args[:1] == ["--"]:
            args = args[1:]
    return ALIASES.get(name, name), args


def _deployer(name: str, args: list, cwd: str | None = None) -> Target | None:
    if any(arg in HELP_OR_VERSION for arg in args[:1]) or any(arg in ("-h", "--help", "--version") for arg in args):
        return None
    words = _positionals(args, VALUE_OPTIONS.get(name, set()))
    if name == "vercel":
        if not args:
            return Target(SUFFIX, "vercel.app")
        if not words or words[0].lower() in ("deploy", "redeploy", "promote", "rollback"):
            return Target(SUFFIX, "vercel.app")  # `vercel --prod`, `vercel deploy`, ...
        if words[0].lower() in VERCEL_OTHER:
            return None
        # Any other first word is a directory to deploy (`vercel dist`), which may not exist until the build before
        # it runs. VERCEL_OTHER lists the subcommands that are not deploys.
        return Target(SUFFIX, "vercel.app")
    if name == "wrangler":
        if words[:1] == ["pages"] and words[1:2] and words[1] in ("deploy", "publish"):
            return Target(SUFFIX, "pages.dev")
        if words[:1] and words[0] in ("deploy", "publish"):
            return Target(SUFFIX, "workers.dev")
        if words[:1] == ["versions"] and words[1:2] and words[1] in ("deploy", "upload"):
            return Target(SUFFIX, "workers.dev")
        return None
    if name == "surge":
        if words and words[0].lower() in SURGE_OTHER:
            return None
        domain = None
        for i, arg in enumerate(args):
            if arg in ("--domain", "-d") and i + 1 < len(args):
                domain = args[i + 1]
            elif arg.startswith("--domain="):
                domain = arg[len("--domain="):]
        if domain is None and len(words) >= 2:
            domain = words[1]
        if domain is not None:
            host = domain.lower().split("://", 1)[-1].split("/", 1)[0]
            return Target(HOST, host) if HOST_NAME.fullmatch(host) else Target(UNKNOWN)
        return Target(SUFFIX, "surge.sh")
    if name == "gh-pages":
        return Target(SUFFIX, "github.io")
    spec = DEPLOYERS.get(name)
    if spec is None or not words:
        return None
    firsts, pairs, suffix = spec
    if name == "fly" and words[0] == "launch" and "--no-deploy" in args:
        return None
    if words[0] in firsts or tuple(words[:2]) in pairs:
        return Target(SUFFIX, suffix)
    return None


def _remote_host(spec: str) -> Target | None:
    """The host of a remote copy spec ([user@]host:path, scp://, sftp://, rsync://), or None for a local path."""
    if REMOTE_URI.match(spec):
        rest = spec.split("://", 1)[1].split("/", 1)[0]
        host = rest.rsplit("@", 1)[-1]
        if host.startswith("["):
            return Target(UNKNOWN)
        host = host.split(":", 1)[0]
    else:
        if ":" not in spec or spec.startswith(("/", "./", "../", "~")):
            return None
        if spec.startswith("[") or "@[" in spec:
            return Target(UNKNOWN)  # an address in brackets, IPv6 or otherwise
        host = spec.split(":", 1)[0].rsplit("@", 1)[-1]
        if "/" in host:  # a local path with a colon in it
            return None
    if not host:
        return None
    if "$" in host or "`" in host:
        return Target(UNKNOWN)
    return Target(HOST, host.lower()) if HOST_NAME.fullmatch(host) else Target(UNKNOWN)


def _copy_destination(name: str, args: list) -> Target | None:
    """A copy's remote destination. The destination is the last path: when it is remote, that host, whatever the
    sources (a remote-to-remote copy included). When it is local the copy is a download, unless a remote path follows
    a local one, which means an option value this list does not know trails the real destination."""
    words = _positionals(args, SCP_VALUE_OPTIONS if name == "scp" else RSYNC_VALUE_OPTIONS)
    if len(words) < 2:
        return None
    kinds = [_remote_host(word) for word in words]
    if kinds[-1] is not None:
        return kinds[-1]
    for i in range(len(kinds) - 2, 0, -1):
        if kinds[i] is not None and any(k is None for k in kinds[:i]):
            return kinds[i]
    return None


def _git_push_heroku(args: list) -> Target | None:
    index = 0
    while index < len(args) and args[index].startswith("-"):
        index += 2 if args[index] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix",
                                      "--config-env") else 1
    if index >= len(args) or args[index] != "push":
        return None
    words = _positionals(args[index + 1:], {"-o", "--push-option", "--repo", "--receive-pack", "--exec", "--recurse-submodules"})
    if not words:
        return None
    remote = words[0].lower()
    if remote == "heroku":
        return Target(SUFFIX, "herokuapp.com")
    if "://" in remote:
        host = remote.split("://", 1)[1].split("/", 1)[0].rsplit("@", 1)[-1].split(":", 1)[0]
    else:
        host = remote.split(":", 1)[0].rsplit("@", 1)[-1] if ":" in remote else ""
    if host in ("git.heroku.com", "heroku.com"):
        return Target(SUFFIX, "herokuapp.com")
    return None


def deploy_targets(command: str, cwd: str | None = None, depth: int = 0, deadline: float | None = None,
                   commands: list | None = None) -> list:
    """Every deploy or publish target the command names, each once, in the order first named. cwd, where the command
    runs, tells a directory `vercel dist` deploys from a subcommand it does not know. commands is the command's simple
    commands, when the caller has split it already (company_rules splits once for every kind, with
    registry_targets.split_command, which reads it as destructive._simple_commands does). Raises ReadTimeout (a
    ValueError) past the reading deadline, as destructive._simple_commands does."""
    deadline = _deadline(deadline)
    targets: list = []

    def add(target):
        if target is not None and target not in targets:
            targets.append(target)

    for argv in (commands if commands is not None else _simple_commands(command, 0, deadline)):
        # bash keeps the carriage return of a CR-LF line ending in the line's last word, where it is no part of a
        # host: `scp f host.example.org:/srv` sent with CR-LF reaches host.example.org, as the other readings say.
        argv = [word.rstrip("\r") for word in argv]
        base = os.path.basename(argv[0]).lower()
        if depth < 3 and (base in RUNNERS or (base == "npm" and argv[1:2] in (["exec"], ["x"]))):
            call = _call_string(argv[2:] if base == "npm" else argv[1:])
            if call is not None:  # npx -c 'vercel --prod' runs the string as a shell command
                for target in deploy_targets(call, cwd, depth + 1, deadline):
                    add(target)
                continue
        name, args = _tool(argv)
        if name in ("scp", "rsync"):
            target = _copy_destination(name, args)
        elif name == "git":
            target = _git_push_heroku(args)
        else:
            target = _deployer(name, args, cwd)
        add(target)
    return targets


def host_covered(value: str, target: Target) -> bool:
    """Whether a deploy_host value covers a target. An exact value covers that host; `*.D` covers every host under D,
    and a suffix target under or equal to D. An unknown target is covered by nothing."""
    value = value.lower()
    if target.kind == UNKNOWN or not target.name:
        return False
    if value.startswith("*."):
        base = value[2:]
        return target.name.endswith("." + base) or (target.kind == SUFFIX and target.name == base)
    return target.kind == HOST and target.name == value
