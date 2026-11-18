"""What package registry a shell command names: the targets the company-rules hook checks against package_registry rules.

registry_targets(command) splits the command the way the destructive-operation check does (pipes, `;`, `&&`, each line,
wrappers such as sudo, env, xargs and timeout, and `bash -c` bodies). It also reads the variable assignments that split
drops (`NAME=value` before a command, on its own, or after `env`) and the arguments of export, declare, typeset, local
and readonly. It looks through package runners (npx, bunx, pnpx, `npm exec`/`npm x`, `pnpm dlx`/`exec`, `yarn
dlx`/`exec`, and the `-c` string of npx and `npm exec`) and through the runners runner_split names: `python -m MODULE`
(also `-mMODULE` and `-Im MODULE`), `poetry run`, `uv run`, `uv tool run`, `uvx`, `pipenv run` and `bundle exec`, skipping
each runner's own options, whose flags it knows (`uv run --frozen python -i x` runs python with -i); where a runner has
an option this module does not know, both readings (a flag, or an option that takes the next word) are read, and the
runner's own options are the ones some reading takes as its own. A command is named without a Windows `.exe`, `.cmd`
or `.bat` (`pip.exe` is pip, `npm.cmd` is npm). It returns one Target for each registry the command names explicitly. A
command that names none is no target: `npm install`, `pip install requests`, `docker pull ubuntu` and `twine upload
dist/*` use the tool's configured or default registry, which the hook does not read. A Target is one of:

  a registry   host[/path]: the URL's host, lowercase, without credentials or port, and its path, lowercase, with empty
               and `.` segments dropped, `..` applied, percent escapes decoded and no trailing slash, or no path at all
               when a segment cannot be read safely (see below); for an image, the registry host and the repository
               path without its tag or digest, ended before a segment that holds a variable
  unknown      a registry the hook cannot read: a variable where the host would be (`--registry $REGISTRY`, `docker
               push $IMAGE`); a host that is not a dotted name (`localhost:5000/app`, an IP address, `[::1]`); a URL
               whose authority holds a backslash or a character a URL authority cannot hold, or an `http:`/`https:`
               value without `//` after the colon (URL parsers disagree on which host those name); a `//host` or
               `\\host` value (a network-path reference, or a Windows UNC share for find-links); a value option last in the command, with nothing after it (xargs or stdin
               supplies the value: `xargs npm install --registry`); a docker or podman push, pull, run or create with no
               image; a runner, docker run or create with more than three options this module does not know before
               its command or image, which may then sit after any of them. Known limit: the shared splitter cuts a
               command at an unquoted `$(` (`docker run -v $(pwd):/app node:20 ...`), so such a run has no image and
               is unknown, which fires the rule; quote it (`-v "$(pwd)":/app`)

What is recognized, exactly:

  npm, pnpm, yarn, bun,      any run with `--registry URL`, `--registry=URL`, an abbreviation down to `--reg`, or
  npx, bunx, pnpx            npm's `--@scope:registry=URL`, with any number of leading dashes (nopt strips them:
                             `-registry`, `---reg=URL`, `-@acme:registry=URL`, `-reg`), anywhere in its arguments: an
                             install, a publish, a login, a runner's package source
  npm|pnpm config set, set   the keys `registry` and `@scope:registry`, as `KEY URL` or `KEY=URL`, anywhere after
                             `config set` or `set` wherever they are among the positional arguments (`npm --logl silent
                             config set ...`; also `npm c set` and `npm conf set`)
  yarn config set            `registry`, `npmRegistryServer`, `npmPublishRegistry`, and either under `npmScopes.<scope>.`
  pip, pip3, pip3.N,         install, download, wheel, lock: `-i`/`--index-url`, its hidden alias `--pypi-url`,
  python[3[.N]] -m pip       `--extra-index-url`, `-f`/`--find-links`, as `OPT URL`, `OPT=URL` or `-iURL`; any
                             abbreviation of the long options (`--ind`, `--ext`, `--fi`, `--pyp`: pip takes a unique
                             prefix); i or f at the end of a cluster of short options (`-Ui URL`); pip's general
                             options before the subcommand, abbreviated too (`pip --cache-d DIR install ...`)
  pip config set             `<section>.index-url`, `.pypi-url`, `.extra-index-url`, `.find-links` (any case, `_` for
                             `-`), past pip's own options (`pip config --timeout 30 set ...`): each URL
  uv                         pip, add, remove, sync, lock, export, tree, venv, build, version and tool subcommands, and
                             the own options of `uv run`, `uv tool run` and `uvx`: the pip options above (exact names:
                             uv takes no abbreviations), `--default-index` and `--index` (`URL` or `NAME=URL`); `uv
                             publish --publish-url URL` and `--check-url URL`
  poetry source add          its URL (unknown when it has none, unless the source is pypi); `poetry config
                             repositories.<name> URL`
  twine                      `--repository-url URL`, or an abbreviation down to `--repository-`
  gem install|fetch|update   `-s`/`--source URL`; `gem sources -a|--add URL`; `gem push|yank|owner --host URL`; the long
                             options abbreviated down to two letters (`--so`, `--ad`, `--ho`)
  go env -w                  `GOPROXY=...`
  docker, podman             push and pull (also `image push`/`image pull`), run and create (also `container run`/
                             `container create`, which pull a missing image): an image whose first path component has a
                             dot or a colon or is localhost (`ghcr.io/org/app:1`, `registry.example.org:5000/app`,
                             podman's `docker://` form); login: its server argument
  assignments                NPM_CONFIG_REGISTRY, PNPM_CONFIG_REGISTRY, BUN_CONFIG_REGISTRY, YARN_REGISTRY,
                             YARN_NPM_REGISTRY_SERVER, YARN_NPM_PUBLISH_REGISTRY (any case), and npm_config_@scope:registry
                             (which only env can set); PIP_INDEX_URL, PIP_PYPI_URL, PIP_EXTRA_INDEX_URL, PIP_FIND_LINKS;
                             UV_INDEX_URL, UV_EXTRA_INDEX_URL, UV_DEFAULT_INDEX, UV_INDEX, UV_FIND_LINKS, UV_PUBLISH_URL,
                             UV_PUBLISH_CHECK_URL; POETRY_REPOSITORIES_<NAME>_URL;
                             TWINE_REPOSITORY_URL; RUBYGEMS_HOST; GOPROXY (each entry of a comma- or pipe-separated list;
                             `direct` and `off` name none)

A value is read as a URL: `scheme://[credentials@]host[:port][/path]`, skipping the credentials, variables in them
included; the authority ends at the first /, \\, ? or #. A tab, newline or carriage return in the scheme or host is
removed, as every parser that accepts it removes it; one after the host leaves the host alone, since a WHATWG parser
(npm, uv) removes it (`.<TAB>.` is `..`) and urllib3 (pip, twine, poetry) encodes it (`.<TAB>.` is a name). A value
without a scheme is read as https:// where the option only takes a URL, and as a local path, which names no registry,
for find-links; a value starting with /, ./, ../ or ~, and a file:// URL, name none. A variable in the host is unknown. A
path segment that holds a variable, a `\\` (a path separator to the WHATWG and urllib3 parsers), a `;` (`..;` is `..`
to some servers) or a control character, a percent escape that decodes to `/`, `\\`, `;`, a control character or
another `%` (`%252e`), or a segment of only dots and spaces, decoded or not, other than `.` and `..` themselves
(`%2e%2e`, `...`, `..%20`, which some servers trim to `..`), may reach any path on the host once read, so the target is
the host alone, which only a value with no path covers; any other escape is decoded (`My%20Project` is `my project`).
Only ASCII letters are lowercased (KELVIN SIGN is not `k`). In an image, which cannot hold `..`, a variable ends the
path there instead (`ghcr.io/acme/$APP` is `ghcr.io/acme`).

Coverage (registry_covered): a value `host` covers that host with any path; `host/path` covers that host when the
target's path is that path or under it, by whole segments (`pypi.example.org/simple` covers `/simple` and
`/simple/x`, not `/simple2` and not the bare host); `*.D` covers every name under D, not D itself, with the same path
rule. Paths compare ignoring case, as the validator compares values for duplicates. An unknown target is covered by
nothing. Ports are not compared: a value cannot carry one.

Not recognized: a registry set in a file (`.npmrc`, `.yarnrc.yml`, `pip.conf`, `pyproject.toml`, `uv.toml`, a
requirements file's `--index-url` line, `~/.docker/config.json`), whether the file exists or a command writes it with
`echo`, `printf` or `tee` (a heredoc body line that reads as an assignment, such as `PIP_INDEX_URL=...` alone on its
line, is read as one, so writing it that way can fire the rule); arguments xargs or stdin supplies, other than an
option left last without its value; a configured repository given by name (`twine upload -r NAME`, `poetry publish -r
NAME`, `uv publish --index NAME`); a package given as a URL, tarball or git remote (`npm install https://host/pkg.tgz`,
`pip install https://host/pkg.whl`, `uv run --with URL`); Docker Hub, which an image with no registry and `docker
login` with no server use; `docker build --push`, `buildx`, `tag`, `service create` and compose; pipenv's own options
(`--pypi-mirror`, `pipenv install -i`); pipx, pdm, hatch and rye, their options and the commands they run; Bundler's
sources (`bundle add --source URL`, `bundle config mirror.<url> URL`, a Gemfile's `source`); options held in a variable
(`npm install $FLAGS`); registries a script or CI job uses internally; and other ecosystems (cargo, maven, gradle,
nuget, composer, conda, helm, apt, brew).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import os
import re
import string
from dataclasses import dataclass
from urllib.parse import unquote

from .deploy_targets import HOST_NAME, RUNNERS, _call_string, _tool
from .destructive import ASSIGNMENT, YARN_PNPM_VALUE_OPTIONS, _simple_commands, _skip_options

REGISTRY = "registry"
UNKNOWN = "unknown"

NPM_FAMILY = {"npm", "pnpm", "yarn", "bun", "npx", "bunx", "pnpx"}
SCOPED_REGISTRY_FLAG = re.compile(r"^@[^:=\s]+:registry$")  # after the leading dashes, which nopt strips
NPM_CONFIG_KEY = re.compile(r"^(?:registry|@[^:=\s]+:registry)$")
YARN_CONFIG_KEY = re.compile(r"^(?:registry|npmRegistryServer|npmPublishRegistry|npmScopes\.[^.\s]+\.(?:npmRegistryServer|npmPublishRegistry))$")
NPM_CONFIG_WORDS = {"config", "c", "con", "conf", "confi"}  # npm takes `c` as an alias and a unique prefix of a command
NPM_VALUE_OPTIONS = {"-w", "--workspace", "-C", "--dir", "--filter", "-F", "--prefix", "--userconfig", "--globalconfig", "-L",
                     "--location", "--loglevel", "--cache"}
PIP_NAME = re.compile(r"^pip(?:[0-9]+(?:\.[0-9]+)?)?$")
PYTHON_NAME = re.compile(r"^(?:python|pypy)(?:[0-9]+(?:\.[0-9]+)?)?$")
PYTHON_LONG_VALUE_OPTIONS = {"--check-hash-based-pycs"}
PIP_VALUE_OPTIONS = {"--editor", "--proxy", "--cert", "--client-cert", "--timeout", "--retries", "--log", "--log-file", "--cache-dir",
                     "--python", "--exists-action", "--trusted-host", "--use-feature", "--use-deprecated",
                     "--resume-retries", "--keyring-provider", "--local-log", "--config-settings", "-C"}
PIP_COMMANDS = {"install", "download", "uninstall", "freeze", "inspect", "list", "show", "check", "config", "search", "cache",
                "index", "wheel", "hash", "completion", "debug", "help", "lock"}
PIP_FETCHING = {"install", "download", "wheel", "lock"}
PIP_CONFIG_KEY = re.compile(r"^[^.\s]+\.(?:index[-_]url|pypi[-_]url|extra[-_]index[-_]url|find[-_]links)$", re.IGNORECASE)
# pip config's own long options and the general ones (pip 25.1's parser), so `pip config --timeout 30 set KEY URL` finds
# its words: {name: whether it takes a value}. pip takes a unique prefix of each (`--ed vim`).
PIP_CONFIG_LONG = dict(
    [(o, True) for o in ("--cache-dir", "--cert", "--client-cert", "--default-timeout", "--editor", "--exists-action",
                         "--keyring-provider", "--local-log", "--log", "--log-file", "--proxy", "--python",
                         "--resume-retries", "--retries", "--timeout", "--trusted-host", "--use-deprecated", "--use-feature")]
    + [(o, False) for o in ("--debug", "--disable-pip-version-check", "--global", "--help", "--isolated", "--no-cache-dir",
                            "--no-color", "--no-input", "--no-python-version-warning", "--quiet", "--require-venv",
                            "--require-virtualenv", "--site", "--user", "--verbose", "--version")])
# Long options whose value is a registry URL: {name: (the shortest abbreviation the tool takes, whether a value without
# a scheme is a local path)}. pip's parser (optparse) takes any unique prefix. No pip option is a prefix of
# --index-url, --extra-index-url or --find-links, so every prefix of those is read (an ambiguous one, such as `--i` in
# `pip install`, is refused by pip anyway). --pypi-url is pip's hidden alias of --index-url; `--py` is ambiguous with
# --python, so it is read from `--pyp`.
PIP_INDEX_LONG = {"--index-url": ("--i", False), "--extra-index-url": ("--e", False), "--find-links": ("--f", True),
                  "--pypi-url": ("--pyp", False)}
# uv's parser (clap) takes exact names only: `uv sync --extra dev` is the extras option, not an abbreviation.
UV_INDEX_LONG = {"--index-url": ("--index-url", False), "--extra-index-url": ("--extra-index-url", False),
                 "--find-links": ("--find-links", True), "--default-index": ("--default-index", False),
                 "--index": ("--index", False)}
UV_PUBLISH_LONG = {"--publish-url": ("--publish-url", False), "--check-url": ("--check-url", False)}
INDEX_SHORT = {"i": False, "f": True}
# The letters of pip's and uv's other short options that take a value: in a cluster, the rest is that option's value.
SHORT_VALUE_STOPS = set("CPbcdeoprtw")
TWINE_LONG = {"--repository-url": ("--repository-", False)}  # shorter is ambiguous with --repository NAME
# Ruby's OptionParser takes a unique prefix: two letters name each of these in its command.
GEM_SOURCE_LONG = {"--source": ("--so", False)}
GEM_ADD_LONG = {"--add": ("--ad", False)}
GEM_HOST_LONG = {"--host": ("--ho", False)}
GEM_SHORT_VALUE_STOPS = set("vingPpk")
UV_INDEX_COMMANDS = {"pip", "add", "remove", "sync", "lock", "export", "tree", "venv", "build", "tool", "version"}
UV_GLOBAL_VALUE_OPTIONS = {"--directory", "--project", "--config-file", "--cache-dir", "--color", "--python-preference",
                           "--allow-insecure-host", "--python", "-p"}
# Every uv option that takes a value, across run, tool run (uvx) and the global options, so a runner's command is found.
UV_VALUE_OPTIONS = UV_GLOBAL_VALUE_OPTIONS | {
    "--with", "--with-editable", "--with-requirements", "--from", "--package", "--extra", "--no-extra", "--group",
    "--no-group", "--only-group", "--env-file", "--index", "--default-index", "--index-url", "-i", "--extra-index-url",
    "--find-links", "-f", "--index-strategy", "--keyring-provider", "--resolution", "--prerelease", "--fork-strategy",
    "--exclude-newer", "--exclude-newer-package", "--no-build-package", "--no-binary-package", "--refresh-package",
    "--upgrade-package", "-P", "--reinstall-package", "--config-setting", "-C", "--config-settings-package", "--link-mode",
    "--no-build-isolation-package", "-w",
    "--constraints", "-c", "--overrides", "--build-constraints", "-b", "--python-platform", "--torch-backend",
}
# uv's long flags (`uv run --help`, `uv tool run --help`), so a runner's command is found past them; its short flags
# (-m, -n, -q, -s, -U, -v) take no value, as every short option not in UV_VALUE_OPTIONS.
UV_FLAGS = {
    "--active", "--all-extras", "--all-groups", "--all-packages", "--exact", "--inexact", "--frozen", "--locked",
    "--gui-script", "--script", "--module", "--isolated", "--managed-python", "--no-managed-python", "--native-tls",
    "--no-binary", "--no-build", "--no-build-isolation", "--no-config", "--no-default-groups", "--dev", "--no-dev",
    "--only-dev", "--no-editable", "--no-env-file", "--no-index", "--no-progress", "--no-project",
    "--no-python-downloads", "--no-sources", "--no-sync", "--offline", "--refresh", "--reinstall", "--upgrade",
    "--compile-bytecode", "--no-cache", "--quiet", "--verbose", "--help", "--version", "--preview", "--no-preview",
    "--show-resolution", "--no-install-project", "--no-install-workspace", "--no-install-local", "--lfs",
}
POETRY_GLOBAL_VALUE_OPTIONS = {"-C", "--directory", "-P", "--project"}
POETRY_FLAGS = {"--ansi", "--no-ansi", "--no-plugins", "--no-cache", "--no-interaction", "--quiet", "--verbose", "--help",
                "--version"}
POETRY_VALUE_OPTIONS = POETRY_GLOBAL_VALUE_OPTIONS | {"--priority"}
PIPENV_VALUE_OPTIONS = {"--python", "--pypi-mirror"}
PIPENV_FLAGS = {"--system", "--verbose", "--quiet", "--help", "--site-packages", "--clear"}
BUNDLE_VALUE_OPTIONS = {"--gemfile", "-r", "--retry"}
BUNDLE_FLAGS = {"--keep-file-descriptors", "--verbose", "--no-color", "--help"}
# Runners and the words that start their command: {name: (options that take a value, flags, verbs)}.
RUN_VERBS = {
    "poetry": (POETRY_GLOBAL_VALUE_OPTIONS, POETRY_FLAGS, (("run",),)),
    "uv": (UV_VALUE_OPTIONS, UV_FLAGS, (("run",), ("tool", "run"))),
    "pipenv": (PIPENV_VALUE_OPTIONS, PIPENV_FLAGS, (("run",),)),
    "bundle": (BUNDLE_VALUE_OPTIONS, BUNDLE_FLAGS, (("exec",),)),
}
PACKAGE_VERSION = re.compile(r"[@=<>!~\[;]")  # where a package spec's version or extras start (`ruff@0.6`, `x[cli]`)
GEM_VALUE_OPTIONS = {"--config-file", "-s", "--source", "--host", "-a", "--add", "-r", "--remove", "-v", "--version", "-i",
                     "--install-dir", "-n", "--bindir", "--platform", "-g", "--file", "-k", "--key", "--otp", "-p",
                     "--http-proxy"}
GEM_SOURCE_COMMANDS = {"install", "fetch", "update"}
GEM_HOST_COMMANDS = {"push", "yank", "owner"}
DOCKER_GLOBAL_VALUE_OPTIONS = {"--config", "-c", "--context", "-H", "--host", "-l", "--log-level", "--tlscacert",
                               "--tlscert", "--tlskey", "--connection", "--url", "--identity", "--root", "--runroot",
                               "--storage-driver", "--storage-opt", "--cgroup-manager", "--events-backend", "--hooks-dir",
                               "--imagestore", "--network-cmd-path", "--network-config-dir", "--tmpdir", "--module",
                               "--ssh", "--runtime", "--conmon", "--volumepath", "--db-backend", "--runtime-flag",
                               "--cdi-spec-dir", "--out"}
# Every docker and podman subcommand, so the one that matters is found past a global option this module does not know.
DOCKER_COMMANDS = {
    "attach", "build", "builder", "buildx", "commit", "compose", "config", "container", "context", "cp", "create", "diff",
    "events", "exec", "export", "history", "image", "images", "import", "info", "inspect", "kill", "load", "login",
    "logout", "logs", "manifest", "network", "node", "pause", "plugin", "port", "ps", "pull", "push", "rename", "restart",
    "rm", "rmi", "run", "save", "search", "secret", "service", "stack", "start", "stats", "stop", "swarm", "system", "tag",
    "top", "trust", "unpause", "update", "version", "volume", "wait", "init", "scout", "sbom", "debug", "pod", "machine",
    "generate", "play", "kube", "healthcheck", "mount", "unmount", "unshare", "untag", "auto-update", "farm", "artifact",
    "quadlet", "help",
}
DOCKER_TRANSFER_VALUE_OPTIONS = {"--platform", "--authfile", "--cert-dir", "--creds", "--format", "-f", "--sign-by",
                                 "--sign-by-sigstore", "--sign-by-sigstore-private-key", "--sign-passphrase-file",
                                 "--compression-format", "--compression-level", "--digestfile", "--retry", "--retry-delay",
                                 "--arch", "--os", "--variant", "--decryption-key", "--encryption-key", "--encrypt-layer",
                                 "--policy", "--signature-policy"}
DOCKER_LOGIN_VALUE_OPTIONS = {"-u", "--username", "-p", "--password", "--authfile", "--cert-dir", "--secret", "--compat-auth-file"}
# docker and podman run/create: the options that take a value and the flags, so the image is found. An option in
# neither set is read both ways (see _command_starts).
DOCKER_RUN_VALUE_OPTIONS = {
    "-a", "--attach", "--add-host", "--annotation", "--blkio-weight", "--blkio-weight-device", "--cap-add", "--cap-drop",
    "--cgroup-parent", "--cgroupns", "--cidfile", "--cpu-count", "--cpu-percent", "--cpu-period", "--cpu-quota",
    "--cpu-rt-period", "--cpu-rt-runtime", "-c", "--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--device",
    "--device-cgroup-rule", "--device-read-bps", "--device-read-iops", "--device-write-bps", "--device-write-iops", "--dns",
    "--dns-opt", "--dns-option", "--dns-search", "--domainname", "--entrypoint", "-e", "--env", "--env-file", "--expose",
    "--gpus", "--group-add", "--health-cmd", "--health-interval", "--health-retries", "--health-start-interval",
    "--health-start-period", "--health-timeout", "-h", "--hostname", "--ip", "--ip6", "--ipc", "--isolation",
    "--kernel-memory", "-l", "--label", "--label-file", "--link", "--link-local-ip", "--log-driver", "--log-opt",
    "--mac-address", "-m", "--memory", "--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
    "--network", "--net", "--network-alias", "--net-alias", "--oom-score-adj", "--pid", "--pids-limit", "--platform", "-p",
    "--publish", "--pull", "--restart", "--runtime", "--security-opt", "--shm-size", "--stop-signal", "--stop-timeout",
    "--storage-opt", "--sysctl", "--tmpfs", "--ulimit", "-u", "--user", "--userns", "--uts", "-v", "--volume",
    "--volume-driver", "--volumes-from", "-w", "--workdir", "--detach-keys",
    # podman's own
    "--arch", "--authfile", "--cert-dir", "--creds", "--decryption-key", "--os", "--variant", "--pod", "--pod-id-file",
    "--secret", "--pidfile", "--conmon-pidfile", "--gidmap", "--uidmap", "--subgidname", "--subuidname", "--init-path",
    "--passwd-entry", "--group-entry", "--personality", "--preserve-fds", "--rdt-class", "--requires", "--retry",
    "--retry-delay", "--seccomp-policy", "--timeout", "--tz", "--umask", "--unsetenv", "--cgroup-conf", "--cgroups",
    "--chrootdirs", "--health-on-failure", "--health-startup-cmd", "--health-startup-interval",
    "--health-startup-retries", "--health-startup-success", "--health-startup-timeout", "--health-log-destination",
    "--health-max-log-count", "--health-max-log-size", "--hostuser", "--image-volume", "--sdnotify", "--systemd",
    "--shm-size-systemd", "--env-merge", "--hosts-file",
}
DOCKER_RUN_FLAGS = {"--rm", "--read-only", "--init", "--privileged", "--detach", "-d", "--interactive", "--tty",
                    "--sig-proxy", "--oom-kill-disable", "--no-healthcheck", "--disable-content-trust", "--publish-all",
                    "--quiet", "--use-api-socket", "--replace", "--http-proxy", "--no-hosts", "--read-only-tmpfs",
                    "--env-host", "--rmi", "--tls-verify", "--help", "--rootfs"}
LOCAL_TRANSPORT = re.compile(r"^(?:docker-archive|docker-daemon|oci|oci-archive|dir|containers-storage|sif):")
EXPORTERS = {"export", "declare", "typeset", "local", "readonly"}
# Assignments that name a registry, by upper-cased name: whether a value without a scheme is a local path.
NPM_VARIABLES = {"NPM_CONFIG_REGISTRY", "PNPM_CONFIG_REGISTRY", "BUN_CONFIG_REGISTRY", "YARN_REGISTRY",
                 "YARN_NPM_REGISTRY_SERVER", "YARN_NPM_PUBLISH_REGISTRY"}
URL_VARIABLES = {"PIP_INDEX_URL": False, "PIP_PYPI_URL": False, "PIP_EXTRA_INDEX_URL": False, "PIP_FIND_LINKS": True,
                 "UV_INDEX_URL": False, "UV_EXTRA_INDEX_URL": False, "UV_DEFAULT_INDEX": False, "UV_INDEX": False,
                 "UV_FIND_LINKS": True,
                 "UV_PUBLISH_URL": False, "UV_PUBLISH_CHECK_URL": False, "TWINE_REPOSITORY_URL": False,
                 "RUBYGEMS_HOST": False}
LIST_VARIABLES = {"PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_FIND_LINKS"}
POETRY_VARIABLE = re.compile(r"^POETRY_REPOSITORIES_[A-Z0-9_]+_URL$")
SCOPED_NPM_VARIABLE = re.compile(r"^NPM_CONFIG_@[^:=\s]+:REGISTRY$")  # env 'npm_config_@acme:registry=URL' npm ...
SCHEME = re.compile(r"^([A-Za-z][A-Za-z0-9+.-]*)://")
# A web scheme not followed by `//`: `https:evil.example`, `https:/\evil.example`. A WHATWG parser (npm, uv) still reads
# a host from it, so the hook does not guess which.
WEB_SCHEME = re.compile(r"^(?:https?|wss?|ftp):", re.IGNORECASE)
# The characters a URL authority can hold (RFC 3986 userinfo, host and port, percent escapes), with { } and ` for the
# shell variables a credential may hold. Anything else (a backslash, a space, a quote) is read differently by different
# URL parsers.
URL_AUTHORITY = re.compile(r"[A-Za-z0-9\-._~!$&'()*+,;=:@\[\]%{}`]*")
# A last label a WHATWG parser reads as an IPv4 number (`1.2.3.0x4` is 1.2.3.4).
NUMERIC_LABEL = re.compile(r"[0-9]+|0x[0-9a-f]*")
PATH_ENDERS = ("\\", ";")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# A segment of only dots and spaces other than `.` and `..` (`...`, `.. `, `..%20`): some servers trim it to `..`.
DOTS_AND_SPACES = re.compile(r"[. ]+")
ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)  # `K` (U+212A) must not become `k`
LOCAL_PREFIXES = ("/", "./", "../", "~")
HOME_VARIABLES = {"$HOME", "${HOME}", "$PWD", "${PWD}"}  # a path under them is local


@dataclass(frozen=True)
class Target:
    kind: str  # REGISTRY or UNKNOWN
    name: str | None = None  # host[/path], lowercase; None for UNKNOWN


def _has_variable(text: str) -> bool:
    return "$" in text or "`" in text


def _segment(raw: str) -> str | None:
    """A URL path segment as a server reads it, with ASCII letters lowercased, or None when it cannot be read safely: it
    holds a variable, a `\\`, a `;` or a control character; a percent escape decodes to `/`, `\\`, `;`, a control
    character or another `%` (which a second decoding would read); or it is only dots and spaces, decoded or not, other
    than `.` and `..` themselves (`%2e%2e`, `...`, `..%20`). `My%20Project` is read as `my project`."""
    if _has_variable(raw) or CONTROL.search(raw) or any(c in raw for c in PATH_ENDERS):
        return None
    if raw in ("", ".", ".."):
        return raw
    if "%" in raw:
        decoded = unquote(raw)
        if "%" in decoded or "/" in decoded or CONTROL.search(decoded) or any(c in decoded for c in PATH_ENDERS):
            return None
        raw = decoded
    if DOTS_AND_SPACES.fullmatch(raw):
        return None
    return raw.translate(ASCII_LOWER)


def _host_target(host: str, path: str, image: bool = False) -> Target:
    """A registry target for a host and a path, or unknown when the host is not a dotted name. A path segment _segment
    cannot read may be `..` once read (`%2e%2e`, `$X` holding `../..`, `..\\`, `..;`), which reaches any path on the host,
    so the target is the host alone, which only a value with no path covers. An image path cannot hold `..` (Docker's
    reference grammar), so there the path ends before that segment."""
    host = host.translate(ASCII_LOWER).rstrip(".")
    if (_has_variable(host) or host.startswith("[") or not HOST_NAME.fullmatch(host)
            or NUMERIC_LABEL.fullmatch(host.rsplit(".", 1)[-1])):
        return Target(UNKNOWN)
    segments: list = []
    for raw in path.split("/"):
        segment = _segment(raw)
        if segment is None:
            if not image:
                segments = []
            break
        if segment in ("", "."):
            continue
        if segment == "..":
            if segments:
                segments.pop()
            continue
        segments.append(segment)
    return Target(REGISTRY, "/".join([host] + segments))


def url_target(value: str, path_without_scheme: bool = False) -> Target | None:
    """The registry a URL value names, unknown, or None for a local path or an empty value. A value without a scheme
    is a local path when path_without_scheme (find-links), and otherwise read as https://. Tabs, newlines and carriage
    returns are removed, as a WHATWG parser (npm, uv) removes them; urllib3 (pip, twine, poetry) keeps one in the path,
    encoded, so after the host they leave the host alone (`.<TAB>.` is `..` to one and a name to the other)."""
    cleaned: list = []
    removed_at: list = []  # where in the cleaned value each removed character stood
    for c in value.strip():
        if c in "\t\n\r":
            removed_at.append(len(cleaned))
        else:
            cleaned.append(c)
    value = "".join(cleaned)
    if not value:
        return None
    match = SCHEME.match(value)
    if match is None:
        if WEB_SCHEME.match(value):
            return Target(UNKNOWN)
        first = value.split("/", 1)[0]
        if value.startswith(("//", "\\\\")):
            return Target(UNKNOWN)  # a network-path reference, or a Windows UNC share for find-links
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
    # The authority ends at /, ?, # or a backslash, which the WHATWG parser (npm, uv) and urllib3 (pip, twine, poetry)
    # take as the start of the path, though Python's urllib.parse does not: a backslash there is unknown.
    authority = re.split(r"[/\\?#]", rest, maxsplit=1)[0]
    if rest[len(authority):len(authority) + 1] == "\\" or not URL_AUTHORITY.fullmatch(authority):
        return Target(UNKNOWN)
    path = re.split(r"[?#]", rest[len(authority):], maxsplit=1)[0]
    if any(at > len(value) - len(rest) + len(authority) for at in removed_at):
        path = ""  # a tab or newline after the host: the parsers disagree on the path
    host = authority.rsplit("@", 1)[-1]  # credentials, variables in them included, are skipped
    if host.startswith("["):
        return Target(UNKNOWN)
    return _host_target(host.split(":", 1)[0], path)


def _url(value: str | None, local: bool = False) -> Target | None:
    """url_target, and unknown for an option with no value after it."""
    return Target(UNKNOWN) if value is None else url_target(value, local)


def _long_option(name: str, longs: dict) -> str | None:
    """The long option an argument names, exactly or abbreviated down to the shortest form the tool takes, or None."""
    for canonical, spec in longs.items():
        if name.startswith(spec[0]) and canonical.startswith(name):
            return canonical
    return None


def _values(args: list, longs: dict, shorts: dict | None = None, stops: set | None = None) -> list:
    """(value, path_without_scheme) for each of these options in args, value None when the option is last with nothing
    after it. longs: {name: (shortest abbreviation, local)}, as `OPT VALUE` or `OPT=VALUE`. shorts: {letter: local}, as
    `-x VALUE` or `-xVALUE`; with stops, the letters of the tool's other short options that take a value, also at the
    end of a cluster of flags (`-Ux VALUE`, `-UxVALUE`), as getopt-style parsers read it."""
    out, i = [], 0
    while i < len(args):
        arg, local, wants_next = args[i], False, False
        if arg.startswith("--"):
            name, sep, attached = arg.partition("=")
            canonical = _long_option(name, longs)
            if canonical is not None:
                local = longs[canonical][1]
                if sep:
                    out.append((attached, local))
                else:
                    wants_next = True
        elif shorts and arg.startswith("-") and len(arg) > 1:
            letters = arg[1:]
            for k, letter in enumerate(letters):
                if letter in shorts:
                    local = shorts[letter]
                    if letters[k + 1:]:
                        out.append((letters[k + 1:], local))
                    else:
                        wants_next = True
                    break
                if stops is None or letter in stops:
                    break
        if wants_next:
            if i + 1 < len(args):
                out.append((args[i + 1], local))
                i += 1
            else:
                out.append((None, local))
        i += 1
    return out


def _registry_option(arg: str) -> bool:
    """Whether an argument, before any `=`, is npm's --registry or --@scope:registry. nopt strips any number of leading
    dashes and takes a unique prefix (`--re` is ambiguous): `--reg`, `-registry`, `---regi=URL`, `-reg` (also npm's
    shorthand) and `-@acme:registry=URL` all set it."""
    name = arg.split("=", 1)[0]
    if not name.startswith("-"):
        return False
    bare = name.lstrip("-")
    return (len(bare) >= 3 and "registry".startswith(bare)) or bool(SCOPED_REGISTRY_FLAG.match(bare))


def _registry_flags(args: list) -> list:
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if _registry_option(arg):
            if "=" in arg:
                out.append(url_target(arg.split("=", 1)[1]))
            elif i + 1 < len(args):
                out.append(url_target(args[i + 1]))
                i += 1
            else:
                out.append(Target(UNKNOWN))
        i += 1
    return out


def _positionals(args: list, value_options: set, takes_value=None) -> list:
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            out.extend(args[i + 1:])
            break
        if arg.startswith("-") and len(arg) > 1:
            valued = "=" not in arg and (arg in value_options or (takes_value is not None and takes_value(arg)))
            i += 2 if valued else 1
            continue
        out.append(arg)
        i += 1
    return out


def _command_starts(args: list, value_options: set, flags: set | frozenset = frozenset(), unsure: set | None = None,
                    consumed: set | None = None) -> list:
    """Where the first positional argument (a runner's command, an image) may start, past leading options. `--` ends
    the options; a short option in value_options takes the rest of its cluster or the next word. A long option in
    neither set may be a flag or take the next word, so both readings are kept, for up to three such options. unsure,
    when given, gets "budget" when a fourth such option is read only as a flag. consumed, when given, gets the index of
    every option, and of every known option's value, that some reading takes as the runner's own."""
    starts: list = []
    seen: set = set()  # (position, budget) already walked: each is walked once, so the work stays linear

    def walk(i: int, budget: int) -> None:
        while i < len(args):
            if (i, budget) in seen:
                return
            seen.add((i, budget))
            arg = args[i]
            if arg == "--":
                if i + 1 < len(args):
                    starts.append(i + 1)
                return
            if arg == "-" or not arg.startswith("-"):
                starts.append(i)
                return
            if consumed is not None:
                consumed.add(i)
            if arg.startswith("--"):
                if "=" in arg or arg in flags:
                    i += 1
                elif arg in value_options:
                    if consumed is not None and i + 1 < len(args):
                        consumed.add(i + 1)
                    i += 2
                else:
                    if budget:
                        walk(i + 2, budget - 1)
                    elif unsure is not None:
                        unsure.add("budget")
                    i += 1
                continue
            letters, step = arg[1:], 1
            for k, letter in enumerate(letters):
                if "-" + letter in value_options:
                    step = 1 if letters[k + 1:] else 2
                    break
            if step == 2 and consumed is not None and i + 1 < len(args):
                consumed.add(i + 1)
            i += step

    walk(0, 3)
    return sorted(set(starts))


def _python_module(args: list) -> list | None:
    """[module, its arguments] for `python [options] -m MODULE ...`, or None (a script, -c code, stdin). Python's own
    options may be clustered (`-Im pip`) and -m may hold its module (`-mpip`)."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg in ("-", "--") or not arg.startswith("-"):
            return None
        if arg.startswith("--"):
            i += 2 if arg in PYTHON_LONG_VALUE_OPTIONS else 1
            continue
        letters = arg[1:]
        for k, letter in enumerate(letters):
            if letter == "c":
                return None
            if letter == "m":
                inner = [letters[k + 1:]] + args[i + 1:] if letters[k + 1:] else args[i + 1:]
                # The package a module belongs to names the tool: `-m pip.__main__` is pip.
                return [inner[0].split(".", 1)[0]] + inner[1:] if inner else None
            if letter in "WX":
                if not letters[k + 1:]:
                    i += 1
                break
        i += 1
    return None


def _run_split(args: list, offset: int, value_options: set, flags: set, package: bool = False) -> tuple:
    """(own arguments, inner argvs, unsure). The own arguments are the options, with their values, that some reading of
    the runner's options takes as its own, so a runner option after one this module does not know is still read
    (`uvx --new-option x --index-url URL ruff`), and the command's own options are not (`uv run --frozen python -i x`)."""
    rest = args[offset:]
    unsure: set = set()
    consumed: set = set()
    starts = _command_starts(rest, value_options, flags, unsure, consumed)
    own = args[:offset] + [rest[i] for i in sorted(consumed)]
    inners = []
    for start in starts:
        command = PACKAGE_VERSION.split(rest[start], maxsplit=1)[0] if package else rest[start]
        inners.append([command] + rest[start + 1:])
    return own, inners, "budget" in unsure


def runner_split(name: str, args: list) -> tuple | None:
    """For a command that runs another one: (the runner's own arguments, [the command it runs, as an argv, for each
    reading of the runner's options], whether more options than it reads both ways left the command unsure); None for
    any other command. Python's -m (`python3 -m pip`, `-mpip`, `-Im pip`), `poetry run`, `uv run`, `uv tool run`,
    `uvx`, `pipenv run` and `bundle exec`, past their own options (`uv --directory d run --no-project pip`, `uv run --
    pip`). npx and the other package runners are deploy_targets._tool's. cloud_targets.py looks through the same runners
    with this."""
    if PYTHON_NAME.match(name) or name == "py":
        inner = _python_module(args)
        return None if inner is None else ([], [inner], False)
    if name == "uvx":
        return _run_split(args, 0, UV_VALUE_OPTIONS, UV_FLAGS, package=True)
    spec = RUN_VERBS.get(name)
    if spec is None:
        return None
    value_options, flags, verbs = spec
    for start in _command_starts(args, value_options, flags):
        for verb in verbs:
            if args[start:start + len(verb)] == list(verb):
                return _run_split(args, start + len(verb), value_options, flags, package=verb == ("tool", "run"))
    return None


def _config_set(words: list, key_pattern, config_words=("config",)) -> list:
    """`config set KEY URL`, `config set KEY=URL`, or `set ...` (npm and pnpm's shorthand): the URL when KEY matches;
    unknown for a matching KEY with no value after it. The words are found anywhere among the positional arguments, so
    the value of a global option this module does not know (`npm --logl silent config set ...`) does not hide them."""
    for k, word in enumerate(words):
        if word in config_words and words[k + 1:k + 2] == ["set"]:
            rest = words[k + 2:]
            break
        if word == "set":
            rest = words[k + 1:]
            break
    else:
        return []
    out = []
    for i, word in enumerate(rest):  # a matching key anywhere, so an option's value cannot shift the pairs
        key, sep, value = word.partition("=")
        if not key_pattern.match(key):
            continue
        if sep:
            out.append(url_target(value))
        else:
            out.append(url_target(rest[i + 1]) if i + 1 < len(rest) else Target(UNKNOWN))
    return out


def _npm_config(name: str, args: list) -> list:
    """npm, pnpm and yarn's `config set` of a registry key."""
    if name in ("npm", "pnpm"):
        return _config_set(_positionals(args, NPM_VALUE_OPTIONS, _registry_option), NPM_CONFIG_KEY, NPM_CONFIG_WORDS)
    if name == "yarn":
        return _config_set(_positionals(args, {"--cwd"}, _registry_option), YARN_CONFIG_KEY)
    return []


def _pip_subcommand(args: list) -> int | None:
    """The index of pip's subcommand: the first argument past the general options that names a pip command. A word that
    names none is taken as the value of an option this module does not know. A general option abbreviated
    (`pip --cache-d install config set ...`) takes its value as pip does."""
    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-") and len(arg) > 1:
            i += 2 if "=" not in arg and (arg in PIP_VALUE_OPTIONS or _pip_config_takes_value(arg)) else 1
            continue
        if arg in PIP_COMMANDS:
            return i
        i += 1
    return None


def _pip(args: list) -> list:
    sub = _pip_subcommand(args)
    if sub is None:
        return []
    command, rest = args[sub], args[sub + 1:]
    if command in PIP_FETCHING:
        return [_url(v, local) for v, local in _values(rest, PIP_INDEX_LONG, INDEX_SHORT, SHORT_VALUE_STOPS)]
    if command == "config":
        words = _positionals(rest, set(), _pip_config_takes_value)
        k = words.index("set") if "set" in words else -1
        if k >= 0 and len(words) > k + 1 and PIP_CONFIG_KEY.match(words[k + 1]):
            if len(words) < k + 3:
                return [Target(UNKNOWN)]
            local = words[k + 1].lower().replace("_", "-").endswith(".find-links")
            return [url_target(v, local) for v in _list_values(words[k + 2])]
    return []


def _pip_config_takes_value(arg: str) -> bool:
    """Whether a pip config argument is a long option that takes the next word: exactly, or as a prefix of one."""
    if arg in PIP_CONFIG_LONG:
        return PIP_CONFIG_LONG[arg]
    return arg.startswith("--") and len(arg) > 2 and any(v for o, v in PIP_CONFIG_LONG.items() if o.startswith(arg))


def _list_values(value: str) -> list:
    """The URLs of a list value: split on any whitespace, as pip splits it, and on spaces only, as uv may, so that a tab
    a WHATWG parser removes inside one URL is read both ways."""
    return list(dict.fromkeys([v for v in value.split() + value.split(" ") if v.strip()]))


def _index_url(value: str) -> str:
    """The URL of a uv index value: `NAME=URL` (--index, UV_INDEX) or a URL."""
    name, sep, rest = value.partition("=")
    if sep and not SCHEME.match(value) and "/" not in name and ":" not in name:
        return rest
    return value


def _uv_index_targets(args: list) -> list:
    out = []
    for value, local in _values(args, UV_INDEX_LONG, INDEX_SHORT, SHORT_VALUE_STOPS):
        out.append(Target(UNKNOWN) if value is None else url_target(_index_url(value), local))
    return out


def _uv(args: list) -> list:
    """uv's subcommands other than its runners: index options anywhere for those that resolve or install, and the
    publish URLs for `uv publish` (whose --index is a name)."""
    for start in _command_starts(args, UV_VALUE_OPTIONS, UV_FLAGS):
        command = args[start]
        if command == "publish":
            return [_url(v, local) for v, local in _values(args, UV_PUBLISH_LONG)]
        if command in UV_INDEX_COMMANDS:
            return _uv_index_targets(args)
    return []


def _poetry(args: list) -> list:
    words = _positionals(args, POETRY_VALUE_OPTIONS)
    if words[:2] == ["source", "add"] and len(words) >= 3:
        if len(words) >= 4:
            return [url_target(words[3])]
        return [] if words[2].lower() == "pypi" else [Target(UNKNOWN)]  # poetry takes no URL only for PyPI
    if words[:1] == ["config"] and len(words) >= 3 and words[1].startswith("repositories."):
        return [url_target(words[2])]
    return []


def _gem(args: list) -> list:
    words = _positionals(args, GEM_VALUE_OPTIONS)
    if not words:
        return []
    if words[0] in GEM_SOURCE_COMMANDS:
        longs, shorts = GEM_SOURCE_LONG, {"s": False}
    elif words[0] == "sources":
        longs, shorts = GEM_ADD_LONG, {"a": False}
    elif words[0] in GEM_HOST_COMMANDS:
        longs, shorts = GEM_HOST_LONG, None
    else:
        return []
    return [_url(v) for v, _ in _values(args, longs, shorts, GEM_SHORT_VALUE_STOPS)]


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
    return _host_target(first.rsplit(":", 1)[0] if first.count(":") == 1 else first, "/".join(segments), image=True)


def _login_server(server: str) -> Target | None:
    if SCHEME.match(server):
        return url_target(server)
    if _has_variable(server.split("/", 1)[0]):
        return Target(UNKNOWN)
    host, _, path = server.partition("/")
    if host.startswith("["):
        return Target(UNKNOWN)
    return _host_target(host.split(":", 1)[0], path)


def _positional_indices(args: list, value_options: set) -> list:
    out, i = [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return out + list(range(i + 1, len(args)))
        if arg.startswith("-") and len(arg) > 1:
            i += 2 if (arg in value_options and "=" not in arg) else 1
            continue
        out.append(i)
        i += 1
    return out


def _container(args: list) -> list:
    # The subcommand is the first word that names one, so the value of a global option this module does not know is
    # not taken for it.
    indices = [i for i in _positional_indices(args, DOCKER_GLOBAL_VALUE_OPTIONS) if args[i] in DOCKER_COMMANDS]
    if not indices:
        return []
    first = indices[0]
    command, rest = args[first], args[first + 1:]
    if command in ("image", "container"):
        inner = _positional_indices(rest, set())
        if not inner:
            return []
        command, rest = rest[inner[0]], rest[inner[0] + 1:]
    if command in ("push", "pull"):
        refs = _positionals(rest, DOCKER_TRANSFER_VALUE_OPTIONS)
        if command == "push":
            refs = refs[-1:]  # podman push IMAGE DESTINATION: the destination
        if not refs:
            return [] if "--help" in rest else [Target(UNKNOWN)]  # xargs or stdin supplies the image
        return [image_target(ref) for ref in refs]
    if command in ("run", "create"):  # pulls the image when it is not there
        unsure: set = set()
        starts = _command_starts(rest, DOCKER_RUN_VALUE_OPTIONS, DOCKER_RUN_FLAGS, unsure)
        if not starts:
            return [] if "--help" in rest else [Target(UNKNOWN)]
        return [image_target(rest[s]) for s in starts] + ([Target(UNKNOWN)] if "budget" in unsure else [])
    if command == "login" and args[first] == "login":
        servers = _positionals(rest, DOCKER_LOGIN_VALUE_OPTIONS)
        return [_login_server(servers[0])] if servers else []
    return []


def _assignment_targets(assignment: str) -> list:
    name, _, value = assignment.partition("=")
    upper = name.upper()
    if upper in NPM_VARIABLES or SCOPED_NPM_VARIABLE.match(upper):
        return [url_target(value)]
    if upper in URL_VARIABLES:
        local = URL_VARIABLES[upper]
        values = _list_values(value) if upper in LIST_VARIABLES else [value]
        out = []
        for one in values:
            if upper in ("UV_INDEX", "UV_DEFAULT_INDEX"):
                one = _index_url(one)
            out.append(url_target(one, local))
        return out
    if POETRY_VARIABLE.match(upper):
        return [url_target(value)]
    if upper == "GOPROXY":
        return _goproxy(value)
    return []


def _is_runner(name: str, args: list) -> bool:
    if name in RUNNERS:
        return True
    if name == "npm":
        return args[:1] in (["exec"], ["x"])
    if name in ("pnpm", "yarn"):
        return _skip_options(args, YARN_PNPM_VALUE_OPTIONS)[:1] in (["dlx"], ["exec"])
    return False


def command_name(word: str) -> str:
    """A command word as the readers compare it: its base name, lowercase, without a Windows `.exe`, `.cmd` or `.bat`
    (npm.cmd, az.cmd, gcloud.cmd)."""
    name = os.path.basename(word).lower()
    return name[:-4] if name.endswith((".exe", ".cmd", ".bat")) else name


def _argv_targets(argv: list, depth: int, flags: bool = True) -> list:
    name, args = command_name(argv[0]), list(argv[1:])
    split = runner_split(name, args) if depth < 4 else None
    if split is not None:
        own, inners, unsure = split
        out = _uv_index_targets(own) if name in ("uv", "uvx") else []  # uv run's and uvx's own index options
        if unsure:
            out.append(Target(UNKNOWN))  # more unknown runner options than are read both ways
        for inner in inners:
            out.extend(_argv_targets(inner, depth + 1))
        return out
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
        return [_url(v) for v, _ in _values(args, TWINE_LONG)]
    if name == "gem":
        return _gem(args)
    if name == "go":
        return _go(args)
    if name in ("docker", "podman"):
        return _container(args)
    if name in EXPORTERS:
        return [t for arg in args if ASSIGNMENT.match(arg) for t in _assignment_targets(arg)]
    return []


def split_command(command: str) -> tuple:
    """(the simple commands, the assignments the split dropped): what registry_targets, cloud_targets and deploy_targets
    read, so a caller with several of them splits the command once."""
    assignments: list = []
    return list(_simple_commands(command, assignments=assignments)), assignments


def registry_targets(command: str, cwd: str | None = None, depth: int = 0, split: tuple | None = None) -> list:
    """Every registry the command names, in order: each command's own, then the assignments the split dropped. cwd is
    accepted for symmetry with deploy_targets and not used. split is split_command(command), when the caller has it."""
    targets: list = []
    commands, assignments = split if split is not None else split_command(command)
    for argv in commands:
        targets.extend(_argv_targets(argv, depth))
    for assignment in assignments:
        targets.extend(_assignment_targets(assignment))
    return [t for t in targets if t is not None]


def _segments(path: str) -> list:
    out: list = []
    for segment in path.translate(ASCII_LOWER).split("/"):
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
    value_host, _, value_path = value.translate(ASCII_LOWER).partition("/")
    target_host, _, target_path = target.name.partition("/")
    if value_host.startswith("*."):
        if not target_host.endswith("." + value_host[2:]):
            return False
    elif target_host != value_host:
        return False
    wanted = _segments(value_path)
    return _segments(target_path)[:len(wanted)] == wanted
