"""What a shell command deploys or publishes to: the targets the company-rules hook checks against deploy_host rules.

deploy_targets(command) splits the command the way the destructive-operation check does (pipes, `;`, `&&`, each line,
wrappers such as sudo, env and timeout, and `bash -c` bodies), looks through package runners (npx, pnpm dlx, yarn dlx,
npm exec, bunx), and returns one Target for each deploy or publish it recognizes. A Target is one of:

  a host       a name the command names itself, such as the destination of `scp dist/ deploy@web1.example.org:/srv`
               or the domain given to `surge`
  a suffix     a hosting service's own domain, when the command deploys there under a name the command does not
               show: `vercel` deploys to a *.vercel.app name, `netlify deploy` to *.netlify.app, and so on
  unknown      a destination the hook cannot read, such as `rsync dist/ $HOST:/srv`

What is recognized, exactly (DEPLOYERS below, and _copy_destination):

  vercel, vc                 with no subcommand, or deploy, redeploy, promote, rollback      suffix vercel.app
  netlify, ntl               deploy                                                          suffix netlify.app
  fly, flyctl                deploy, launch (unless --no-deploy)                             suffix fly.dev
  firebase                   deploy                                                          suffix web.app
  wrangler                   deploy, publish                                                 suffix workers.dev
  wrangler pages             deploy, publish                                                 suffix pages.dev
  surge                      any run; its domain argument when given                         host, else suffix surge.sh
  gh-pages                   any run                                                         suffix github.io
  railway                    up                                                              suffix up.railway.app
  amplify                    publish                                                         suffix amplifyapp.com
  git push heroku ...        a push to a remote named heroku                                 suffix herokuapp.com
  scp, rsync                 a destination of the form [user@]host:path or rsync://host/...  host, or unknown when the
                                                                                             host is a variable

Not recognized: a deploy a script or a CI job runs internally, a vendor this list does not name, a custom domain set in
a project file rather than on the command line (the service's own suffix is the target then), `ssh` sessions, `curl`
uploads, container pushes (a registry is a package_registry matter) and cloud object copies (a cloud_account matter).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .destructive import _simple_commands, _unwrap_runner

HOST = "host"
SUFFIX = "suffix"
UNKNOWN = "unknown"

# name -> (deploying subcommands, or None for "every run"; the suffix; deploys with no subcommand at all)
DEPLOYERS = {
    "vercel": ({"deploy", "redeploy", "promote", "rollback"}, "vercel.app", True),
    "vc": ({"deploy", "redeploy", "promote", "rollback"}, "vercel.app", True),
    "netlify": ({"deploy"}, "netlify.app", False),
    "ntl": ({"deploy"}, "netlify.app", False),
    "fly": ({"deploy", "launch"}, "fly.dev", False),
    "flyctl": ({"deploy", "launch"}, "fly.dev", False),
    "firebase": ({"deploy"}, "web.app", False),
    "railway": ({"up"}, "up.railway.app", False),
    "amplify": ({"publish"}, "amplifyapp.com", False),
    "gh-pages": (None, "github.io", True),
}
# Options of these tools that take a value, so the value is not read as the subcommand.
VALUE_OPTIONS = {
    "vercel": {"--token", "-t", "--scope", "-S", "--cwd", "--local-config", "-A", "--global-config", "-Q", "--team", "-T"},
    "vc": {"--token", "-t", "--scope", "-S", "--cwd", "--local-config", "-A", "--global-config", "-Q", "--team", "-T"},
    "netlify": {"--auth", "--cwd", "--filter"},
    "ntl": {"--auth", "--cwd", "--filter"},
    "fly": {"-a", "--app", "-c", "--config", "-t", "--access-token", "-o", "--org"},
    "flyctl": {"-a", "--app", "-c", "--config", "-t", "--access-token", "-o", "--org"},
    "firebase": {"-P", "--project", "--token", "--config", "-c"},
    "railway": {"-s", "--service", "-e", "--environment"},
    "amplify": set(),
    "wrangler": {"-c", "--config", "-e", "--env", "--cwd"},
}
HOST_NAME = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+")
SCP_VALUE_OPTIONS = {"-P", "-i", "-o", "-F", "-c", "-l", "-S", "-J", "-D", "-X"}
RSYNC_VALUE_OPTIONS = {"-e", "--rsh", "--exclude", "--include", "--exclude-from", "--include-from", "--files-from",
                       "--filter", "-f", "--port", "--password-file", "--log-file", "--bwlimit", "--chmod", "--chown",
                       "--temp-dir", "-T", "--partial-dir", "--compare-dest", "--copy-dest", "--link-dest", "-M",
                       "--remote-option", "--rsync-path", "--timeout", "--contimeout", "--block-size", "-B", "--max-size",
                       "--min-size", "--suffix", "--backup-dir", "--out-format", "--info", "--debug"}


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


def _deployer(name: str, args: list) -> Target | None:
    if name == "wrangler":
        words = _positionals(args, VALUE_OPTIONS["wrangler"])
        if words[:1] == ["pages"] and words[1:2] and words[1] in ("deploy", "publish"):
            return Target(SUFFIX, "pages.dev")
        if words[:1] and words[0] in ("deploy", "publish"):
            return Target(SUFFIX, "workers.dev")
        return None
    if name == "surge":
        # surge [project] [domain], or --domain DOMAIN
        domain = None
        for i, arg in enumerate(args):
            if arg in ("--domain", "-d") and i + 1 < len(args):
                domain = args[i + 1]
            elif arg.startswith("--domain="):
                domain = arg[len("--domain="):]
        words = _positionals(args, {"--domain", "-d", "--project", "-p"})
        if domain is None and len(words) >= 2:
            domain = words[1]
        if domain is not None:
            host = domain.lower().split("://", 1)[-1].split("/", 1)[0]
            return Target(HOST, host) if HOST_NAME.fullmatch(host) else Target(UNKNOWN)
        return Target(SUFFIX, "surge.sh")
    spec = DEPLOYERS.get(name)
    if spec is None:
        return None
    subcommands, suffix, bare = spec
    if subcommands is None:
        return Target(SUFFIX, suffix)
    words = _positionals(args, VALUE_OPTIONS.get(name, set()))
    if not words:
        return Target(SUFFIX, suffix) if bare else None
    word = words[0]
    if name in ("fly", "flyctl") and word == "launch" and "--no-deploy" in args:
        return None
    if word in subcommands:
        return Target(SUFFIX, suffix)
    if bare and name in ("vercel", "vc") and (os.sep in word or word in (".", "..")):
        return Target(SUFFIX, suffix)  # `vercel ./dist` deploys that directory
    return None


def _remote_host(spec: str) -> Target | None:
    """The host of an scp/rsync remote spec ([user@]host:path, rsync://[user@]host/path), or None for a local path."""
    if spec.startswith("rsync://"):
        rest = spec[len("rsync://"):].split("/", 1)[0]
        host = rest.rsplit("@", 1)[-1].split(":", 1)[0]
    else:
        if ":" not in spec or spec.startswith(("/", "./", "../", "~")):
            return None
        before = spec.split(":", 1)[0]
        if "/" in before:  # a local path with a colon in it
            return None
        host = before.rsplit("@", 1)[-1].strip("[]")
    if not host:
        return None
    if "$" in host or "`" in host:
        return Target(UNKNOWN)
    return Target(HOST, host.lower()) if HOST_NAME.fullmatch(host) else Target(UNKNOWN)


def _copy_destination(name: str, args: list) -> Target | None:
    options = SCP_VALUE_OPTIONS if name == "scp" else RSYNC_VALUE_OPTIONS
    words = _positionals(args, options)
    if len(words) < 2:
        return None
    return _remote_host(words[-1])  # an upload: the destination is remote


def _git_push_heroku(args: list) -> Target | None:
    index = 0
    while index < len(args) and args[index].startswith("-"):
        index += 2 if args[index] in ("-C", "-c", "--git-dir", "--work-tree", "--namespace") else 1
    if index >= len(args) or args[index] != "push":
        return None
    words = _positionals(args[index + 1:], {"-o", "--push-option", "--repo", "--receive-pack", "--exec", "--recurse-submodules"})
    return Target(SUFFIX, "herokuapp.com") if words[:1] == ["heroku"] else None


def deploy_targets(command: str) -> list:
    """Every deploy or publish target the command names, in order."""
    targets = []
    for argv in _simple_commands(command):
        name, args = _unwrap_runner(argv[0], argv[1:])
        name = os.path.basename(name)
        if name in ("scp", "rsync"):
            target = _copy_destination(name, args)
        elif name == "git":
            target = _git_push_heroku(args)
        else:
            target = _deployer(name, args)
        if target is not None:
            targets.append(target)
    return targets


def host_covered(value: str, target: Target) -> bool:
    """Whether a deploy_host value covers a target. An exact value covers that host; `*.D` covers every host under D,
    and a suffix target under D (a service's own domain is a subdomain of nothing the company lists otherwise). An
    unknown target is covered by nothing."""
    value = value.lower()
    if target.kind == UNKNOWN or not target.name:
        return False
    if value.startswith("*."):
        base = value[2:]
        return target.name.endswith("." + base) or (target.kind == SUFFIX and target.name == base)
    return target.kind == HOST and target.name == value
