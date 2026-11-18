"""What package registry a shell command names: the targets the company-rules hook checks against package_registry rules.

registry_targets(command) splits the command the way the destructive-operation check does (pipes, `;`, `&&`, each line,
wrappers such as sudo, env and timeout, and `bash -c` bodies). It also reads the variable assignments that split drops
(`NAME=value` before a command, on its own, or after `env`) and the arguments of export, declare, typeset, local and
readonly. It looks through package runners (npx, bunx, pnpx, `npm exec`/`npm x`, `pnpm dlx`/`exec`, `yarn dlx`/`exec`,
and the `-c` string of npx and `npm exec`), `poetry run`, `uv run`, `pipenv run`, `bundle exec` and `python -m pip`.
It returns one Target for each registry the command names explicitly. A command that names none is no target: `npm
install`, `pip install requests`, `docker pull ubuntu` and `twine upload dist/*` use the tool's configured or default
registry, which the hook does not read. A Target is one of:

  a registry   host[/path]: the URL's host, lowercase, without credentials or port, and its path, lowercase, with empty
               and `.` segments dropped, `..` applied and no trailing slash; for an image, the registry host and the
               repository path without its tag or digest
  unknown      a registry the hook cannot read: a variable where the host would be (`--registry $REGISTRY`, `docker
               push $IMAGE`), or a host that is not a dotted name (`localhost:5000/app`, an IP address, `[::1]`)

What is recognized, exactly:

  npm, pnpm, yarn, bun,      any run with `--registry URL` or `--registry=URL`, or npm's `--@scope:registry=URL`,
  npx, bunx, pnpx            anywhere in its arguments: an install, a publish, a login, a runner's package source
  npm|pnpm config set, set   the keys `registry` and `@scope:registry`, as `KEY URL` or `KEY=URL`
  yarn config set            `registry`, `npmRegistryServer`, `npmPublishRegistry`, and either under `npmScopes.<scope>.`
  pip, pip3, pip3.N,         install, download, wheel: `-i`/`--index-url`, `--extra-index-url`, `-f`/`--find-links`, as
  python[3[.N]] -m pip       `OPT URL`, `OPT=URL` or `-iURL`
  pip config set             `<section>.index-url`, `.extra-index-url`, `.find-links`: each URL of the value
  uv pip install|sync|       the pip options above, and `--default-index` and `--index` (`URL` or `NAME=URL`)
  compile; uv add|lock|sync
  poetry source add          its URL; `poetry config repositories.<name> URL`
  twine                      `--repository-url URL`
  gem install|fetch|update   `-s`/`--source URL`; `gem sources -a|--add URL`; `gem push|yank|owner --host URL`
  go env -w                  `GOPROXY=...`
  docker, podman             push and pull (also `image push`/`image pull`): an image whose first path component has a
                             dot or a colon or is localhost (`ghcr.io/org/app:1`, `registry.example.org:5000/app`,
                             podman's `docker://` form); login: its server argument
  assignments                NPM_CONFIG_REGISTRY, PNPM_CONFIG_REGISTRY, BUN_CONFIG_REGISTRY, YARN_REGISTRY,
                             YARN_NPM_REGISTRY_SERVER, YARN_NPM_PUBLISH_REGISTRY (any case); PIP_INDEX_URL,
                             PIP_EXTRA_INDEX_URL, PIP_FIND_LINKS; UV_INDEX_URL, UV_EXTRA_INDEX_URL, UV_DEFAULT_INDEX,
                             UV_INDEX, UV_FIND_LINKS; POETRY_REPOSITORIES_<NAME>_URL; TWINE_REPOSITORY_URL; RUBYGEMS_HOST;
                             GOPROXY (each entry of a comma- or pipe-separated list; `direct` and `off` name none)

A value is read as a URL: `scheme://[credentials@]host[:port][/path]`, skipping the credentials, variables in them
included. A value without a scheme is read as https:// where the option only takes a URL, and as a local path, which
names no registry, for find-links; a value starting with /, ./, ../ or ~, and a file:// URL, name none. A variable in
the host is unknown; a variable in the path ends the path there, so only a value with no path, or a shorter one, can
cover it.

Coverage (registry_covered): a value `host` covers that host with any path; `host/path` covers that host when the
target's path is that path or under it, by whole segments (`pypi.example.org/simple` covers `/simple` and
`/simple/x`, not `/simple2` and not the bare host); `*.D` covers every name under D, not D itself, with the same path
rule. Paths compare ignoring case, as the validator compares values for duplicates. An unknown target is covered by
nothing. Ports are not compared: a value cannot carry one.

Not recognized: a registry set in a file (`.npmrc`, `.yarnrc.yml`, `pip.conf`, `pyproject.toml`, a requirements
file's `--index-url` line, `~/.docker/config.json`), including one a command writes with `echo` or `tee`; a configured
repository given by name (`twine upload -r NAME`, `poetry publish -r NAME`); a package given as a URL, tarball or git
remote (`npm install https://host/pkg.tgz`, `pip install https://host/pkg.whl`); Docker Hub, which an image with no
registry and `docker login` with no server use; `docker build --push`, `buildx`, `tag` and compose; registries a script
or CI job uses internally; and other ecosystems (cargo, maven, gradle, nuget, composer, conda, helm, apt, brew).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from .deploy_targets import HOST_NAME, RUNNERS, _call_string, _tool
from .destructive import ASSIGNMENT, YARN_PNPM_VALUE_OPTIONS, _simple_commands, _skip_options, _unwrap_runner

REGISTRY = "registry"
UNKNOWN = "unknown"

NPM_FAMILY = {"npm", "pnpm", "yarn", "bun", "npx", "bunx", "pnpx"}
SCOPED_REGISTRY_FLAG = re.compile(r"^--@[^:=\s]+:registry(?:=|$)")
NPM_CONFIG_KEY = re.compile(r"^(?:registry|@[^:=\s]+:registry)$")
YARN_CONFIG_KEY = re.compile(r"^(?:registry|npmRegistryServer|npmPublishRegistry|npmScopes\.[^.\s]+\.(?:npmRegistryServer|npmPublishRegistry))$")
PIP_NAME = re.compile(r"^pip(?:[0-9]+(?:\.[0-9]+)?)?$")
PYTHON_NAME = re.compile(r"^(?:python|pypy)(?:[0-9]+(?:\.[0-9]+)?)?$")
PYTHON_VALUE_OPTIONS = {"-W", "-X", "-c", "--check-hash-based-pycs"}
PIP_VALUE_OPTIONS = {"--editor", "--proxy", "--cert", "--client-cert", "--timeout", "--retries", "--log", "--log-file", "--cache-dir",
                     "--python", "--exists-action", "--trusted-host", "--use-feature", "--use-deprecated",
                     "--resume-retries", "--keyring-provider", "--local-log", "--config-settings", "-C"}
PIP_FETCHING = {"install", "download", "wheel"}
PIP_CONFIG_KEY = re.compile(r"^[A-Za-z0-9_-]+\.(?:index-url|extra-index-url|find-links)$")
UV_VALUE_OPTIONS = {"--directory", "--project", "--config-file", "--cache-dir", "--color", "-p", "--python", "--python-preference"}
UV_PIP_COMMANDS = {"install", "sync", "compile"}
UV_COMMANDS = {"add", "lock", "sync"}
POETRY_VALUE_OPTIONS = {"-C", "--directory", "-P", "--project", "--priority"}
GEM_SOURCE_COMMANDS = {"install", "fetch", "update"}
GEM_HOST_COMMANDS = {"push", "yank", "owner"}
# Options of each tool whose value is a registry URL: (options, whether a value without a scheme is a local path).
INDEX_OPTIONS = {"-i": False, "--index-url": False, "--extra-index-url": False, "-f": True, "--find-links": True}
UV_INDEX_OPTIONS = dict(INDEX_OPTIONS, **{"--default-index": False, "--index": False})
DOCKER_GLOBAL_VALUE_OPTIONS = {"--config", "-c", "--context", "-H", "--host", "-l", "--log-level", "--tlscacert",
                               "--tlscert", "--tlskey", "--connection", "--url", "--identity", "--root", "--runroot",
                               "--storage-driver", "--storage-opt", "--cgroup-manager", "--events-backend", "--hooks-dir",
                               "--imagestore", "--network-cmd-path", "--network-config-dir", "--tmpdir", "--module",
                               "--ssh", "--runtime", "--conmon", "--volumepath"}
DOCKER_TRANSFER_VALUE_OPTIONS = {"--platform", "--authfile", "--cert-dir", "--creds", "--format", "-f", "--sign-by",
                                 "--sign-by-sigstore", "--sign-by-sigstore-private-key", "--sign-passphrase-file",
                                 "--compression-format", "--compression-level", "--digestfile", "--retry", "--retry-delay",
                                 "--arch", "--os", "--variant", "--decryption-key", "--encryption-key", "--encrypt-layer",
                                 "--policy", "--signature-policy"}
DOCKER_LOGIN_VALUE_OPTIONS = {"-u", "--username", "-p", "--password", "--authfile", "--cert-dir", "--secret", "--compat-auth-file"}
LOCAL_TRANSPORT = re.compile(r"^(?:docker-archive|docker-daemon|oci|oci-archive|dir|containers-storage|sif):")
EXPORTERS = {"export", "declare", "typeset", "local", "readonly"}
# Assignments that name a registry, by upper-cased name: whether a value without a scheme is a local path.
NPM_VARIABLES = {"NPM_CONFIG_REGISTRY", "PNPM_CONFIG_REGISTRY", "BUN_CONFIG_REGISTRY", "YARN_REGISTRY",
                 "YARN_NPM_REGISTRY_SERVER", "YARN_NPM_PUBLISH_REGISTRY"}
URL_VARIABLES = {"PIP_INDEX_URL": False, "PIP_EXTRA_INDEX_URL": False, "PIP_FIND_LINKS": True, "UV_INDEX_URL": False,
                 "UV_EXTRA_INDEX_URL": False, "UV_DEFAULT_INDEX": False, "UV_INDEX": False, "UV_FIND_LINKS": True,
                 "TWINE_REPOSITORY_URL": False, "RUBYGEMS_HOST": False}
POETRY_VARIABLE = re.compile(r"^POETRY_REPOSITORIES_[A-Z0-9_]+_URL$")
SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
LOCAL_PREFIXES = ("/", "./", "../", "~")
HOME_VARIABLES = {"$HOME", "${HOME}", "$PWD", "${PWD}"}  # a path under them is local


@dataclass(frozen=True)
class Target:
    kind: str  # REGISTRY or UNKNOWN
    name: str | None = None  # host[/path], lowercase; None for UNKNOWN


def _has_variable(text: str) -> bool:
    return "$" in text or "`" in text


def _host_target(host: str, path: str) -> Target:
    """A registry target for a host and a path, or unknown when the host is not a dotted name."""
    host = host.lower().rstrip(".")
    if _has_variable(host) or host.startswith("[") or not HOST_NAME.fullmatch(host) or host.rsplit(".", 1)[-1].isdigit():
        return Target(UNKNOWN)
    segments: list = []
    for segment in path.split("/"):
        if _has_variable(segment):
            break
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment.lower())
    return Target(REGISTRY, "/".join([host] + segments))


def url_target(value: str, path_without_scheme: bool = False) -> Target | None:
    """The registry a URL value names, unknown, or None for a local path or an empty value. A value without a scheme
    is a local path when path_without_scheme (find-links), and otherwise read as https://."""
    value = value.strip()
    if not value:
        return None
    match = SCHEME.match(value)
    if match is None:
        first = value.split("/", 1)[0]
        if value == "." or value.startswith(LOCAL_PREFIXES) or value.lower().startswith("file:") or first in HOME_VARIABLES:
            return None
        if _has_variable(first):
            return Target(UNKNOWN)
        if path_without_scheme:
            return None
        rest = value
    else:
        if match.group(1).lower() == "file":
            return None
        rest = value[match.end():]
    authority = re.split(r"[/?#]", rest, 1)[0]
    path = re.split(r"[?#]", rest[len(authority):], 1)[0]
    host = authority.rsplit("@", 1)[-1]  # credentials, variables in them included, are skipped
    if host.startswith("["):
        return Target(UNKNOWN)
    return _host_target(host.split(":", 1)[0], path)


def _option_values(args: list, options: dict) -> list:
    """(value, path_without_scheme) for each of these options in args: `OPT VALUE`, `OPT=VALUE`, and `-xVALUE` for a
    single-letter option."""
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        name, sep, value = arg.partition("=")
        if name in options and name.startswith("--") and sep:
            out.append((value, options[name]))
        elif arg in options:
            if i + 1 < len(args):
                out.append((args[i + 1], options[arg]))
                i += 1
        elif len(arg) > 2 and arg[:2] in options and not arg.startswith("--"):
            out.append((arg[2:], options[arg[:2]]))
        i += 1
    return out


def _registry_flags(args: list) -> list:
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--registry" or SCOPED_REGISTRY_FLAG.match(arg) and "=" not in arg:
            if i + 1 < len(args):
                out.append(url_target(args[i + 1]))
                i += 1
        elif arg.startswith("--registry=") or SCOPED_REGISTRY_FLAG.match(arg):
            out.append(url_target(arg.split("=", 1)[1]))
        i += 1
    return out


def _positionals(args: list, value_options: set) -> list:
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


def _config_set(words: list, key_pattern) -> list:
    """`config set KEY URL`, `config set KEY=URL`, or `set ...` (npm and pnpm's shorthand): the URL when KEY matches."""
    if words[:2] == ["config", "set"]:
        rest = words[2:]
    elif words[:1] == ["set"]:
        rest = words[1:]
    else:
        return []
    out = []
    i = 0
    while i < len(rest):
        key, sep, value = rest[i].partition("=")
        if sep:
            if key_pattern.match(key):
                out.append(url_target(value))
            i += 1
        else:
            if key_pattern.match(key) and i + 1 < len(rest):
                out.append(url_target(rest[i + 1]))
            i += 2
    return out


def _npm_config(name: str, args: list) -> list:
    """npm, pnpm and yarn's `config set` of a registry key."""
    if name in ("npm", "pnpm"):
        return _config_set(_positionals(args, {"--registry", "-w", "--workspace", "-C", "--dir", "--filter", "-F"}), NPM_CONFIG_KEY)
    if name == "yarn":
        return _config_set(_positionals(args, {"--registry", "--cwd"}), YARN_CONFIG_KEY)
    return []


def _pip(args: list) -> list:
    words = _positionals(args, PIP_VALUE_OPTIONS | set(INDEX_OPTIONS))
    if not words:
        return []
    if words[0] in PIP_FETCHING:
        start = args.index(words[0]) + 1
        return [url_target(v, local) for v, local in _option_values(args[start:], INDEX_OPTIONS)]
    if words[0] == "config" and len(words) >= 4 and words[1] == "set" and PIP_CONFIG_KEY.match(words[2]):
        local = words[2].endswith(".find-links")
        return [url_target(v, local) for v in words[3].split()]
    return []


def _uv(args: list) -> list:
    words = _positionals(args, UV_VALUE_OPTIONS | set(UV_INDEX_OPTIONS))
    if not ((words[:1] == ["pip"] and words[1:2] and words[1] in UV_PIP_COMMANDS) or (words[:1] and words[0] in UV_COMMANDS)):
        return []
    out = []
    for value, local in _option_values(args, UV_INDEX_OPTIONS):
        name, sep, rest = value.partition("=")
        if sep and not SCHEME.match(value) and "/" not in name and ":" not in name:
            value = rest  # --index NAME=URL
        out.append(url_target(value, local))
    return out


def _poetry(args: list) -> list:
    words = _positionals(args, POETRY_VALUE_OPTIONS)
    if words[:2] == ["source", "add"] and len(words) >= 4:
        return [url_target(words[3])]
    if words[:1] == ["config"] and len(words) >= 3 and words[1].startswith("repositories."):
        return [url_target(words[2])]
    return []


def _gem(args: list) -> list:
    words = _positionals(args, {"-s", "--source", "--host", "-a", "--add", "-r", "--remove", "-v", "--version",
                                "-i", "--install-dir", "-n", "--bindir", "--platform", "-g", "--file", "-k", "--key",
                                "--otp", "-p", "--http-proxy"})
    if not words:
        return []
    if words[0] in GEM_SOURCE_COMMANDS:
        return [url_target(v) for v, _ in _option_values(args, {"-s": False, "--source": False})]
    if words[0] == "sources":
        return [url_target(v) for v, _ in _option_values(args, {"-a": False, "--add": False})]
    if words[0] in GEM_HOST_COMMANDS:
        return [url_target(v) for v, _ in _option_values(args, {"--host": False})]
    return []


def _goproxy(value: str) -> list:
    out = []
    for entry in re.split(r"[,|]", value):
        entry = entry.strip()
        if entry and entry.lower() not in ("direct", "off"):
            out.append(url_target(entry))
    return out


def _go(args: list) -> list:
    if args[:1] != ["env"] or "-w" not in args:
        return []
    out = []
    for arg in args[1:]:
        name, sep, value = arg.partition("=")
        if sep and name == "GOPROXY":
            out.extend(_goproxy(value))
    return out


def image_target(ref: str) -> Target | None:
    """The registry an image reference names, unknown, or None for Docker Hub (no registry named) or a local transport."""
    if ref.startswith("docker://"):
        ref = ref[len("docker://"):]
    elif LOCAL_TRANSPORT.match(ref):
        return None
    name = ref.split("@", 1)[0]  # a digest
    first, slash, rest = name.partition("/")
    if not slash:
        return Target(UNKNOWN) if _has_variable(name.split(":", 1)[0]) else None
    if _has_variable(first):
        return Target(UNKNOWN)
    if "." not in first and ":" not in first and first.lower() != "localhost":
        return None  # a Docker Hub namespace: no registry named
    if first.startswith("["):
        return Target(UNKNOWN)
    segments = rest.split("/")
    segments[-1] = segments[-1].split(":", 1)[0]  # the tag
    return _host_target(first.rsplit(":", 1)[0] if first.count(":") == 1 else first, "/".join(segments))


def _login_server(server: str) -> Target | None:
    if SCHEME.match(server):
        return url_target(server)
    if _has_variable(server.split("/", 1)[0]):
        return Target(UNKNOWN)
    host, _, path = server.partition("/")
    if host.startswith("["):
        return Target(UNKNOWN)
    return _host_target(host.split(":", 1)[0], path)


def _container(args: list) -> list:
    words = _positionals(args, DOCKER_GLOBAL_VALUE_OPTIONS)
    if not words:
        return []
    start = args.index(words[0])
    command, rest = words[0], args[start + 1:]
    if command == "image" and len(words) > 1:
        command = words[1]
        rest = args[args.index(words[1], start + 1) + 1:]
    if command in ("push", "pull"):
        refs = _positionals(rest, DOCKER_TRANSFER_VALUE_OPTIONS)
        if command == "push":
            refs = refs[-1:]  # podman push IMAGE DESTINATION: the destination
        return [image_target(ref) for ref in refs]
    if command == "login" and words[0] == "login":
        servers = _positionals(rest, DOCKER_LOGIN_VALUE_OPTIONS)
        return [_login_server(servers[0])] if servers else []
    return []


def _assignment_targets(assignment: str) -> list:
    name, _, value = assignment.partition("=")
    upper = name.upper()
    if upper in NPM_VARIABLES:
        return [url_target(value)]
    if upper in URL_VARIABLES:
        local = URL_VARIABLES[upper]
        if upper in ("PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_FIND_LINKS"):
            values = value.split()
        else:
            values = [value]
        out = []
        for one in values:
            key, sep, rest = one.partition("=")
            if upper == "UV_INDEX" and sep and not SCHEME.match(one) and "/" not in key and ":" not in key:
                one = rest
            out.append(url_target(one, local))
        return out
    if POETRY_VARIABLE.match(upper):
        return [url_target(value)]
    if upper == "GOPROXY":
        return _goproxy(value)
    return []


def _resolve(argv: list) -> tuple:
    """(name, args) with `python -m pip`, `poetry|uv|pipenv run` and `bundle exec` looked through."""
    name, args = os.path.basename(argv[0]).lower(), list(argv[1:])
    for _ in range(3):
        if PYTHON_NAME.match(name) or name == "py":
            i = 0
            while i < len(args) and args[i].startswith("-") and args[i] != "-m":
                i += 2 if args[i] in PYTHON_VALUE_OPTIONS else 1
            if args[i:i + 1] == ["-m"] and i + 1 < len(args):
                name, args = os.path.basename(args[i + 1]).lower(), args[i + 2:]
                continue
            return name, args
        if name in ("poetry", "uv", "pipenv", "bundle") and args[:1] in (["run"], ["exec"]):
            inner, rest = _unwrap_runner(name, args)
            if inner != name:
                name, args = inner.lower(), rest
                continue
        return name, args
    return name, args


def _is_runner(name: str, args: list) -> bool:
    if name in RUNNERS:
        return True
    if name == "npm":
        return args[:1] in (["exec"], ["x"])
    if name in ("pnpm", "yarn"):
        return _skip_options(args, YARN_PNPM_VALUE_OPTIONS)[:1] in (["dlx"], ["exec"])
    return False


def _argv_targets(argv: list, depth: int, flags: bool = True) -> list:
    name, args = _resolve(argv)
    if name in NPM_FAMILY:
        # --registry anywhere in the arguments, a runner's own and its package's alike, read once.
        out = _registry_flags(args) if flags else []
        if _is_runner(name, args):
            if depth >= 3:
                return out
            call = _call_string(args[1:] if name == "npm" else args)
            if call is not None:  # npx -c 'npm install --registry ...' runs the string as a shell command
                return out + registry_targets(call, depth=depth + 1)
            inner, inner_args = _tool([name] + args)
            if inner != name:
                return out + _argv_targets([inner] + list(inner_args), depth + 1, flags=False)
            return out
        return out + _npm_config(name, args)
    if PIP_NAME.match(name):
        return _pip(args)
    if name == "uv":
        return _uv(args)
    if name == "poetry":
        return _poetry(args)
    if name == "twine":
        return [url_target(v) for v, _ in _option_values(args, {"--repository-url": False})]
    if name == "gem":
        return _gem(args)
    if name == "go":
        return _go(args)
    if name in ("docker", "podman"):
        return _container(args)
    if name in EXPORTERS:
        return [t for arg in args if ASSIGNMENT.match(arg) for t in _assignment_targets(arg)]
    return []


def registry_targets(command: str, cwd: str | None = None, depth: int = 0) -> list:
    """Every registry the command names, in order: each command's own, then the assignments the split dropped. cwd is
    accepted for symmetry with deploy_targets and not used."""
    targets: list = []
    assignments: list = []
    for argv in _simple_commands(command, assignments=assignments):
        targets.extend(_argv_targets(argv, depth))
    for assignment in assignments:
        targets.extend(_assignment_targets(assignment))
    return [t for t in targets if t is not None]


def _segments(path: str) -> list:
    out: list = []
    for segment in path.lower().split("/"):
        if segment in ("", "."):
            continue
        if segment == "..":
            if out:
                out.pop()
            continue
        out.append(segment)
    return out


def registry_covered(value: str, target: Target) -> bool:
    """Whether a package_registry value covers a target. `host` covers that host with any path, `host/path` the paths
    at or under it by whole segments, and `*.D` every name under D with the same path rule. Unknown: nothing covers it."""
    if target.kind != REGISTRY or not target.name:
        return False
    value_host, _, value_path = value.lower().partition("/")
    target_host, _, target_path = target.name.partition("/")
    if value_host.startswith("*."):
        if not target_host.endswith("." + value_host[2:]):
            return False
    elif target_host != value_host:
        return False
    wanted = _segments(value_path)
    return _segments(target_path)[:len(wanted)] == wanted
