"""The pull-request check (tools/pr_check.py) and its workflow template (deploy/ci/catpilot-pr-check.yml):
docs/spec/OVERLAY_V2.md §2.2 (the pull-request check consumer), §2.3 (modes: monitor annotates and passes, ask and
block fail), §4 (an annotation never prints a listed value) and §6.1. Offline, in temporary git repositories."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
import unittest.mock
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from catpilot_guard import policy as pol  # noqa: E402
from catpilot_guard.deploy_targets import HOST, SUFFIX, UNKNOWN  # noqa: E402

import pr_check  # noqa: E402

TOOL = ROOT / "tools" / "pr_check.py"
TEMPLATE = ROOT / "deploy" / "ci" / "catpilot-pr-check.yml"
REQUIREMENTS = ROOT / "deploy" / "ci" / "requirements-pr-check.txt"
SHA = "b" * 64
USE_INSTEAD = "Internal App Platform (company sign-in)"
# Planted so a test can show none of them reaches an annotation: a listed host and branch, and a host and branch
# that the scanned files deploy or push to.
HOST_MARKER = "zq-marker.apps.example.org"
BRANCH_MARKER = "zq-marker-branch"
CMD_HOST_MARKER = "zq-cmdmarker.example.net"
CMD_BRANCH_MARKER = "zq-cmdmarker-branch"
MARKERS = (HOST_MARKER, BRANCH_MARKER, CMD_HOST_MARKER, CMD_BRANCH_MARKER)
GIT_ENV = {
    "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "t@example.org",
    "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "t@example.org", "GIT_TERMINAL_PROMPT": "0",
}


def host_rule(mode="block", values=("*.apps.example.org", HOST_MARKER), rule_id="deploy-hosts", use_instead=USE_INSTEAD) -> dict:
    rule = {"id": rule_id, "kind": "deploy_host", "mode": mode, "values": list(values)}
    if use_instead:
        rule["use_instead_text"] = use_instead
    return rule


def branch_rule(mode="block", values=("main", "release/*", BRANCH_MARKER, CMD_BRANCH_MARKER), rule_id="protected-branches") -> dict:
    return {"id": rule_id, "kind": "protected_branch", "mode": mode, "values": list(values)}


def policy_dict(rules=None, expires="2099-01-01") -> dict:
    return {
        "format": "catpilot-company-policy", "format_version": 1, "source_sha256": SHA, "expires_on": expires,
        "rules": rules if rules is not None else [branch_rule(), host_rule()],
    }


def parsed(rules=None, expires="2099-01-01") -> pol.Policy:
    return pol.parse(json.dumps(policy_dict(rules, expires)).encode())


def findings(path: str, text: str, rules=None, expires="2099-01-01") -> list:
    """(line, rule id or None, level) for one file's content."""
    with tempfile.TemporaryDirectory() as cwd:
        out = pr_check.check_file(path, text.encode("utf-8"), parsed(rules, expires), cwd)
    return [(f.line, f.rule_id, f.level) for f in out]


def targets(uses: str, inputs: dict | None = None) -> list:
    return [(t.kind, t.name) for t in pr_check.action_targets(uses, {k.lower(): v for k, v in (inputs or {}).items()})]


def workflow(steps: str) -> str:
    """A workflow whose steps start on line 7."""
    return "name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n" + textwrap.indent(textwrap.dedent(steps), "      ")


def git(repo: Path, *args: str) -> str:
    env = dict(os.environ, **GIT_ENV, HOME=str(repo.parent))
    proc = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, env=env, check=True)
    return proc.stdout


class RepoCase(unittest.TestCase):
    """A temporary repository and policy file, and the tool run as a subprocess."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.policy = self.base / "policy.json"
        self.write_policy()

    def write_policy(self, rules=None, expires="2099-01-01"):
        self.policy.write_text(json.dumps(policy_dict(rules, expires)), encoding="utf-8")

    def put(self, path: str, text: str | bytes) -> Path:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(text, bytes):
            target.write_bytes(text)
        else:
            target.write_text(text, encoding="utf-8")
        return target

    def run_tool(self, *args: str, policy: Path | None = None, python_flags: tuple = ()) -> subprocess.CompletedProcess:
        env = {k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}
        env.update(GIT_ENV, HOME=str(self.base))
        command = [sys.executable, *python_flags, str(TOOL), "--policy", str(policy or self.policy), "--repo", str(self.repo), *args]
        return subprocess.run(command, capture_output=True, text=True, env=env, cwd=str(self.base), timeout=120)


# ----------------------------------------------------------------- scanners


class FileTypeTests(unittest.TestCase):
    def test_which_files_are_scanned(self):
        cases = {
            ".github/workflows/deploy.yml": "workflow", ".github/workflows/ci.yaml": "workflow",
            ".github/workflows/sub/x.yml": None, "workflows/deploy.yml": None, ".github/workflows/notes.md": None,
            "action.yml": "action", ".github/actions/deploy/action.yaml": "action",
            "package.json": "package.json", "apps/web/package.json": "package.json", "package-lock.json": None,
            "vercel.json": "vercel.json", "site/netlify.toml": "netlify.toml", "fly.toml": "fly.toml",
            ".GitHub/Workflows/Deploy.YML": "workflow", ".github/workflows/x.Yaml": "workflow",
            "fly.staging.toml": "fly.toml", "flyer.toml": None, "wrangler.toml": "wrangler.toml",
            "worker/wrangler.jsonc": "wrangler.jsonc", "wrangler.json": "wrangler.json", "firebase.json": "firebase.json",
            "README.md": None, "src/deploy.sh": None,
        }
        for path, want in cases.items():
            with self.subTest(path=path):
                self.assertEqual(pr_check.file_type(path), want)


class WorkflowScanTests(unittest.TestCase):
    def test_each_run_line_is_matched_and_pointed_at(self):
        text = workflow("""\
            - uses: actions/checkout@v4
            - name: build and deploy
              run: |
                npm ci
                npm run build
                vercel --prod --token "$TOKEN"
            - run: scp -r dist deploy@${{ secrets.DEPLOY_HOST }}:/srv
            - run: git push --force origin main
            - run: npm test
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text),
                         [(12, "deploy-hosts", "error"), (13, "deploy-hosts", "error"), (14, "protected-branches", "error")])

    def test_a_covered_deploy_and_an_ordinary_push_pass(self):
        text = workflow("""\
            - run: |
                rsync -av dist/ app@web1.apps.example.org:/srv
                git push origin main
                git push --force origin feature/x
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text), [])

    def test_continued_lines_point_at_their_first_line(self):
        text = workflow("""\
            - run: |
                echo start
                rsync -av \\
                  dist/ \\
                  deploy@web1.example.org:/srv
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text), [(9, "deploy-hosts", "error")])

    def test_folded_and_plain_scripts_point_at_the_run_key(self):
        text = workflow("""\
            - run: >
                netlify deploy
                --prod
            - name: plain
              run: firebase deploy --only hosting
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text), [(7, "deploy-hosts", "error"), (11, "deploy-hosts", "error")])

    def test_the_script_is_decided_as_a_whole_like_the_hook(self):
        # Inside a quoted string, the second line is not a command, though it looks like one on its own.
        text = workflow("""\
            - run: |
                MESSAGE='deploy notes
                vercel --prod is for later'
                echo "$MESSAGE"
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text), [])

    def test_a_rule_no_single_line_fires_points_at_the_key(self):
        with tempfile.TemporaryDirectory() as cwd:
            policy = parsed()
            item = pr_check.Commands(start_line=20, text="vercel --prod", key_line=19, exact=True)
            self.assertEqual([(line, rule.id) for line, rule in pr_check.hits_for(item, policy, cwd)], [(20, "deploy-hosts")])
            with unittest.mock.patch.object(pr_check, "logical_lines", return_value=[(20, "echo split")]):
                self.assertEqual([(line, rule.id) for line, rule in pr_check.hits_for(item, policy, cwd)], [(19, "deploy-hosts")])

    def test_protected_branch_pushes(self):
        cases = {
            "git push --force origin main": True, "git push origin :release/2026.11": True,
            "git push --mirror origin": True, "git push -f origin " + BRANCH_MARKER: True,
            "git push origin main": False, "git push --force origin feature/x": False,
            # The branch a workflow runs on is not something the check can read, so it is unknown, which fires.
            "git push --force": True, "git push --force origin HEAD": True,
            "git push --force origin $BRANCH": True, 'git push -f origin "${TARGET}"': True,
            "git push --force origin ${{ matrix.branch }}": True,
            "git push --force origin ${{ github.event.repository.default_branch }}": True,
            "git push --force origin HEAD:$(git rev-parse --abbrev-ref HEAD)": True,
            "git push origin $BRANCH": False,
        }
        for command, fires in cases.items():
            with self.subTest(command=command):
                got = findings(".github/workflows/d.yml", workflow("- run: %s\n" % command), rules=[branch_rule()])
                self.assertEqual(got, [(7, "protected-branches", "error")] if fires else [])

    def test_uses_lines_and_literal_domains(self):
        text = workflow("""\
            - uses: actions/checkout@v4
            - uses: peaceiris/actions-gh-pages@v4
              with:
                cname: docs.apps.example.org
            - uses: peaceiris/actions-gh-pages@v4
              with:
                cname: ${{ vars.DOCS_DOMAIN }}
            - uses: JamesIves/github-pages-deploy-action@v4
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text), [(11, "deploy-hosts", "error"), (14, "deploy-hosts", "error")])

    def test_anchors_merge_keys_and_duplicate_keys_are_read(self):
        text = workflow("""\
            - &deploy
              run: vercel --prod
            - <<: *deploy
              name: again
            - run: echo fine
              run: netlify deploy
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text),
                         [(8, "deploy-hosts", "error"), (12, "deploy-hosts", "error")])

    def test_composite_action_steps(self):
        text = textwrap.dedent("""\
            name: deploy
            runs:
              using: composite
              steps:
                - shell: bash
                  run: |
                    npm run build
                    wrangler deploy
                - uses: cloudflare/pages-action@v1
            """)
        self.assertEqual(findings(".github/actions/deploy/action.yml", text), [(8, "deploy-hosts", "error"), (9, "deploy-hosts", "error")])

    def test_an_empty_or_odd_workflow_has_nothing(self):
        for text in ("", "just a string\n", "- a\n- b\n", "jobs: 3\n", "jobs:\n  x:\n    steps: nope\n"):
            with self.subTest(text=text):
                self.assertEqual(findings(".github/workflows/d.yml", text), [])


class DeployActionTests(unittest.TestCase):
    def test_hosting_actions_deploy_under_their_own_domain(self):
        cases = {
            "peaceiris/actions-gh-pages@v4": "github.io", "actions/deploy-pages@v4": "github.io",
            "JamesIves/github-pages-deploy-action@v4.6.1": "github.io", "amondnet/vercel-action@v25": "vercel.app",
            "BetaHuhn/deploy-to-vercel-action@v1": "vercel.app", "nwtgck/actions-netlify@v3.0": "netlify.app",
            "South-Paw/action-netlify-deploy@v1.2.0": "netlify.app", "jsmrcaga/action-netlify-deploy@v2": "netlify.app",
            "cloudflare/wrangler-action@v3": "workers.dev", "cloudflare/pages-action@v1": "pages.dev",
            "FirebaseExtended/action-hosting-deploy@v0": "web.app",
            "firebaseextended/action-hosting-deploy@" + "a" * 40: "web.app",
        }
        for uses, suffix in cases.items():
            with self.subTest(uses=uses):
                self.assertEqual(targets(uses), [(SUFFIX, suffix)])

    def test_cli_actions_read_their_arguments_as_the_hook_reads_the_command(self):
        cases = [
            ("cloudflare/wrangler-action@v3", {"command": "pages deploy dist --project-name=x"}, [(SUFFIX, "pages.dev")]),
            ("cloudflare/wrangler-action@v3", {"command": "deploy --env production"}, [(SUFFIX, "workers.dev")]),
            ("cloudflare/wrangler-action@v3", {"command": "whoami"}, []),
            ("cloudflare/wrangler-action@v3", {"command": "${{ inputs.command }}"}, [(SUFFIX, "workers.dev")]),
            ("cloudflare/wrangler-action@v3", {"command": "d1 list\npages deploy dist"}, [(SUFFIX, "pages.dev")]),
            ("superfly/flyctl-actions@1.5", {"args": "deploy --remote-only"}, [(SUFFIX, "fly.dev")]),
            ("superfly/flyctl-actions@1.5", {"args": "status"}, []),
            ("superfly/flyctl-actions/setup-flyctl@master", {}, []),
            ("netlify/actions/cli@master", {"args": "deploy --dir=site --prod"}, [(SUFFIX, "netlify.app")]),
            ("netlify/actions/cli@master", {"args": "status"}, []),
            ("netlify/actions/cli@master", {}, []),
            ("netlify/actions/build@master", {}, []),
        ]
        for uses, inputs, want in cases:
            with self.subTest(uses=uses, inputs=inputs):
                self.assertEqual(targets(uses, inputs), want)

    def test_domain_inputs_count_only_as_literal_hosts(self):
        self.assertEqual(targets("peaceiris/actions-gh-pages@v4", {"cname": "Docs.Example.org"}), [(HOST, "docs.example.org")])
        self.assertEqual(targets("peaceiris/actions-gh-pages@v4", {"cname": "${{ vars.D }}"}), [(SUFFIX, "github.io")])
        self.assertEqual(targets("peaceiris/actions-gh-pages@v4", {"cname": "docs"}), [(SUFFIX, "github.io")])
        self.assertEqual(
            targets("amondnet/vercel-action@v25", {"alias-domains": "a.example.org\n{{BRANCH}}.example.org\nb.example.org"}),
            [(SUFFIX, "vercel.app"), (HOST, "a.example.org"), (HOST, "b.example.org")])
        self.assertEqual(targets("BetaHuhn/deploy-to-vercel-action@v1", {"ALIAS_DOMAINS": "x.example.org"}),
                         [(SUFFIX, "vercel.app"), (HOST, "x.example.org")])

    def test_copy_actions_name_their_host_or_an_unreadable_one(self):
        cases = [
            ("appleboy/scp-action@v0.1.7", {"host": "web1.example.org"}, [(HOST, "web1.example.org")]),
            ("appleboy/scp-action@v0.1.7", {"host": "a.example.org,b.example.org"}, [(HOST, "a.example.org"), (HOST, "b.example.org")]),
            ("appleboy/scp-action@v0.1.7", {"host": "${{ secrets.HOST }}"}, [(UNKNOWN, None)]),
            ("appleboy/scp-action@v0.1.7", {}, [(UNKNOWN, None)]),
            ("burnett01/rsync-deployments@7.0.1", {"remote_host": "mirror.example.net"}, [(HOST, "mirror.example.net")]),
            ("easingthemes/ssh-deploy@v5", {"REMOTE_HOST": "deploy.example.net"}, [(HOST, "deploy.example.net")]),
        ]
        for uses, inputs, want in cases:
            with self.subTest(uses=uses, inputs=inputs):
                self.assertEqual(targets(uses, inputs), want)

    def test_other_actions_are_not_deploys(self):
        for uses in ("actions/checkout@v4", "actions/upload-pages-artifact@v3", "./.github/actions/deploy",
                     "docker://alpine:3.20", "vercel", "patrickedqvist/wait-for-vercel-preview@v1.3.2"):
            with self.subTest(uses=uses):
                self.assertEqual(targets(uses), [])


class EnvTests(unittest.TestCase):
    """Literal env: values are read into run scripts; anything unresolved is unknown, and fires."""

    def doc(self, workflow_env="", job_env="", step_env="", run="git push --force origin $B", extra_steps=""):
        def block(env, indent):
            return ("\n" + " " * indent + "env:\n" + textwrap.indent(textwrap.dedent(env), " " * (indent + 2))) if env else ""
        return ("name: ci\non: push%s\njobs:\n  build:\n    runs-on: ubuntu-latest%s\n    steps:\n%s      - run: %s%s\n"
                % (block(workflow_env, 0), block(job_env, 4), extra_steps, run, block(step_env, 8)))

    def fired(self, text):
        return [rule for _, rule, _ in findings(".github/workflows/d.yml", text, rules=[branch_rule(), host_rule()])]

    def test_literal_values_resolve_with_step_over_job_over_workflow(self):
        self.assertEqual(self.fired(self.doc(workflow_env="B: main\n")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(workflow_env="B: feature\n")), [])
        self.assertEqual(self.fired(self.doc(workflow_env="B: main\n", job_env="B: feature\n")), [])
        self.assertEqual(self.fired(self.doc(workflow_env="B: feature\n", job_env="B: main\n")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(job_env="B: main\n", step_env="B: feature\n")), [])
        self.assertEqual(self.fired(self.doc(job_env="B: feature\n", step_env="B: main\n")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(step_env="B: feature\n", run='git push -f origin "${B}"')), [])
        self.assertEqual(self.fired(self.doc(step_env="B: feature\n", run="git push -f origin ${{ env.B }}")), [])
        self.assertEqual(self.fired(self.doc(step_env="B: main\n", run="git push -f origin ${{ env.B }}")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(step_env="H: web1.apps.example.org\n", run="rsync -a dist/ app@$H:/srv")), [])
        self.assertEqual(self.fired(self.doc(step_env="H: web1.example.org\n", run="rsync -a dist/ app@$H:/srv")), ["deploy-hosts"])

    def test_anything_unresolved_is_unknown_and_fires(self):
        cases = [
            self.doc(),  # no env at all
            self.doc(step_env="B: ${{ secrets.BRANCH }}\n"),  # not a literal
            self.doc(workflow_env="B: feature\n", step_env="B: ${{ inputs.b }}\n"),  # a later level hides the literal
            self.doc(step_env="B: \"a b\"\n"),  # not plain enough to substitute safely
            self.doc(step_env="B: \"x'\"\n"),
            self.doc(step_env="B: feature\n", run="B=main; git push --force origin $B"),  # the script sets it
            self.doc(step_env="B: feature\n", run="read B; git push --force origin $B"),
            self.doc(step_env="B: feature\n", run="git push --force origin ${B:-main}"),
            self.doc(workflow_env="B: feature\n", job_env="${{ fromJSON(vars.ENV) }}\n"),
        ]
        for text in cases:
            with self.subTest(text=text):
                self.assertEqual(self.fired(text), ["protected-branches"])

    def test_no_env_value_is_read_after_a_step_that_can_run_code(self):
        # A step can set any variable for later steps through GITHUB_ENV without naming it (review of #133).
        earlier = [
            '      - run: echo "B=main" >> "$GITHUB_ENV"\n',
            '      - run: echo "B=main" >> "$(echo github_env | tr a-z A-Z | sed s/^/$/ | xargs -I{} sh -c \'echo {}\')"\n',
            '      - run: npm run build\n',
            "      - uses: actions/github-script@v7\n        with:\n          script: core.exportVariable('B', 'main')\n",
            "      - uses: ./local-action\n",
        ]
        for step in earlier:
            with self.subTest(step=step):
                self.assertEqual(self.fired(self.doc(job_env="B: feature\n", extra_steps=step)), ["protected-branches"])
                self.assertEqual(self.fired(self.doc(step_env="B: feature\n", extra_steps=step)), ["protected-branches"])
                self.assertEqual(self.fired(self.doc(step_env="H: web1.apps.example.org\n", run="scp -r dist deploy@$H:/srv",
                                                     extra_steps=step)), ["deploy-hosts"])
        checkout = "      - uses: actions/checkout@v4\n"
        self.assertEqual(self.fired(self.doc(job_env="B: feature\n", extra_steps=checkout)), [])
        self.assertEqual(self.fired(self.doc(job_env="B: feature\n", extra_steps="      - uses: Actions/Checkout@v4\n")), [])

    def test_a_composite_action_reads_no_env_value(self):
        # The calling job's earlier steps may have set any variable through GITHUB_ENV (review of #133).
        head = "runs:\n  using: composite\n  steps:\n"
        push = "    - shell: bash\n      env:\n        B: feature\n      run: git push --force origin $B\n"
        self.assertEqual([r for _, r, _ in findings("action.yml", head + push, rules=[branch_rule()])], ["protected-branches"])

    def test_a_job_with_an_action_from_another_repository_reads_no_env_value(self):
        # Its pre: runs before the first step (review of #133).
        later = "      - uses: some-org/js-action-with-pre@v1\n"
        text = self.doc(job_env="B: feature\n") + later
        self.assertEqual(self.fired(text), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(job_env="B: feature\n") + "      - uses: ./local-action\n"), [])
        self.assertEqual(self.fired(self.doc(job_env="B: feature\n") + "      - uses: actions/checkout@v4\n"), [])
        # GitHub's own actions with no pre: (NO_PRE_ACTIONS) leave env: values readable.
        self.assertEqual(self.fired(self.doc(job_env="B: feature\n") + "      - uses: actions/setup-node@v4\n"), [])

    def test_the_branch_a_workflow_runs_on_is_unknown_even_inside_a_checkout(self):
        # check_file's directory may sit inside a git work tree (a TMPDIR under a repository): its branch is not the
        # one the workflow runs on (review of #133).
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / ".git").mkdir()
            (Path(tmp) / ".git" / "HEAD").write_text("ref: refs/heads/feature/x\n")
            for run in ('git push -f origin "$(git branch --show-current)"', "git push -f origin HEAD", "git push -f"):
                with self.subTest(run=run):
                    out = pr_check.check_file(".github/workflows/d.yml", self.doc(run=run).encode(), parsed([branch_rule()]), tmp)
                    self.assertEqual([f.rule_id for f in out], ["protected-branches"])

    def test_git_environment_from_env_names(self):
        # GIT_CONFIG_* in any env: level may make a push a mirror; GIT_DIR points git elsewhere (review of 0b0f13f).
        mirror = "GIT_CONFIG_COUNT: '1'\nGIT_CONFIG_KEY_0: remote.origin.mirror\nGIT_CONFIG_VALUE_0: 'true'\n"
        self.assertEqual(self.fired(self.doc(step_env=mirror, run="git push origin")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(job_env=mirror, run="git push origin")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(job_env="${{ fromJSON(vars.ENV) }}\n", run="git push origin")), ["protected-branches"])
        unknown = "GIT_CONFIG_COUNT: '1'\nGIT_CONFIG_KEY_0: ${{ vars.KEY }}\nGIT_CONFIG_VALUE_0: 'true'\n"
        self.assertEqual(self.fired(self.doc(step_env=unknown, run="git push origin")), ["protected-branches"])
        # A push with a refspec is never a mirror; settings that cannot make one are harmless (review of 816c933).
        self.assertEqual(self.fired(self.doc(step_env=mirror, run="git push origin feature")), [])
        safe = "GIT_CONFIG_COUNT: '1'\nGIT_CONFIG_KEY_0: safe.directory\nGIT_CONFIG_VALUE_0: /w\n"
        self.assertEqual(self.fired(self.doc(step_env=safe, run="git push origin")), [])
        self.assertEqual(self.fired(self.doc(step_env="GIT_CONFIG_GLOBAL: /dev/null\n", run="git push origin")), [])
        token = "GIT_CONFIG_COUNT: '1'\nGIT_CONFIG_KEY_0: url.https://x-access-token:${{ secrets.T }}@github.com/.insteadOf\n"
        self.assertEqual(self.fired(self.doc(step_env=token, run="git push origin")), [])
        params = "GIT_CONFIG_PARAMETERS: \"'safe.directory'='/w'\"\n"
        self.assertEqual(self.fired(self.doc(step_env=params, run="git push origin")), [])
        bad = "GIT_CONFIG_PARAMETERS: \"'remote.origin.mirror=true'\"\n"
        self.assertEqual(self.fired(self.doc(step_env=bad, run="git push origin")), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(step_env="OTHER: x\n", run="git push origin feature")), [])

    def test_an_expression_in_a_destination_is_unknown(self):
        # GitHub puts the text in before the shell runs, so it may end the word or the refspec.
        self.assertEqual(self.fired(self.doc(run='git push --force origin "fea${{ github.head_ref }}"')), ["protected-branches"])
        self.assertEqual(self.fired(self.doc(run='git push --force origin "feature/${{ github.event.pull_request.title }}"')), ["protected-branches"])
        # The workflow's own values read like shell variables (GitHub's script-injection guidance names the event and
        # head_ref as untrusted): a major-version tag move is not a protected branch (review of fe2f878).
        self.assertEqual(self.fired(self.doc(run='git push -f origin "v${{ steps.semver.outputs.major }}"')), [])
        self.assertEqual(self.fired(self.doc(run='git push -f origin "${{ inputs.branch }}"')), ["protected-branches"])
        for opaque in ("github.HEAD_REF", "GitHub.Event.pull_request.title", "github['head_ref']", "toJSON(github)"):
            self.assertEqual(self.fired(self.doc(run='git push -f origin "bot/${{ %s }}"' % opaque)), ["protected-branches"], opaque)
        self.assertEqual(self.fired(self.doc(run='git push -f origin "bot/${{ github.event.inputs.branch }}"')), [])
        # A multi-line expression keeps the line numbers.
        multi = "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo ${{\n            github.sha\n          }}\n          git push --force origin main\n"
        self.assertEqual(findings(".github/workflows/d.yml", multi, rules=[branch_rule()]), [(11, "protected-branches", "error")])
        # A tag is no branch, whatever the expression; a number or a hash cannot end the word (review of 816c933).
        self.assertEqual(self.fired(self.doc(run="git push --force origin refs/tags/${{ inputs.t }}")), [])
        self.assertEqual(self.fired(self.doc(run="git push --force origin bot/update-${{ github.run_id }}")), [])
        self.assertEqual(self.fired(self.doc(run="git push --force origin HEAD:refs/heads/preview/pr-${{ github.event.pull_request.number }}")), [])
        self.assertEqual(self.fired(self.doc(run="git push --force origin ${{ github.sha }}")), ["protected-branches"])

    def test_resolve_script_never_resolves_the_expression_placeholder(self):
        env = {"CATPILOT_EXPRESSION": "feature", "B": "feature"}
        self.assertIn("$CATPILOT_EXPRESSION", pr_check.resolve_script("git push -f origin ${{ github.head_ref }}", env))
        self.assertEqual(pr_check.resolve_script("git push -f origin $B", env), "git push -f origin feature")


class PushActionTests(unittest.TestCase):
    def pushes(self, uses, inputs=None):
        return pr_check.action_pushes(uses, {k.lower(): v for k, v in (inputs or {}).items()})

    def test_force_pushing_actions_name_their_branch(self):
        cases = [
            ("JamesIves/github-pages-deploy-action@v4", {}, ["gh-pages"]),
            ("JamesIves/github-pages-deploy-action@v4", {"branch": "main"}, ["main"]),
            ("JamesIves/github-pages-deploy-action@v4", {"branch": "refs/heads/main", "force": "true"}, ["main"]),
            ("JamesIves/github-pages-deploy-action@v4", {"branch": "main", "force": "false"}, []),
            ("JamesIves/github-pages-deploy-action@v4", {"branch": "${{ inputs.branch }}"}, [None]),
            ("peaceiris/actions-gh-pages@v4", {"publish_branch": "main"}, []),
            ("peaceiris/actions-gh-pages@v4", {"publish_branch": "main", "force_orphan": "true"}, ["main"]),
            ("peaceiris/actions-gh-pages@v4", {"force_orphan": "true"}, ["gh-pages"]),
            ("peaceiris/actions-gh-pages@v4", {"force_orphan": "${{ inputs.orphan }}"}, ["gh-pages"]),
            ("ad-m/github-push-action@v0.8.0", {"branch": "main"}, []),
            ("ad-m/github-push-action@v0.8.0", {"branch": "main", "force": "true"}, ["main"]),
            ("ad-m/github-push-action@v0.8.0", {"force_with_lease": "true"}, [None]),
            ("ad-m/github-push-action@v0.8.0", {"branch": "$B", "force": "true"}, [None]),
            ("actions/checkout@v4", {"ref": "main"}, []),
        ]
        for uses, inputs, want in cases:
            with self.subTest(uses=uses, inputs=inputs):
                self.assertEqual(self.pushes(uses, inputs), want)

    def test_push_action_findings(self):
        text = workflow("""\
            - uses: JamesIves/github-pages-deploy-action@v4
              with:
                folder: dist
            - uses: ad-m/github-push-action@v0.8.0
              with:
                force: true
            - uses: ad-m/github-push-action@v0.8.0
              with:
                branch: ${{ env.TARGET }}
                force: true
              env:
                TARGET: feature
            """)
        # JamesIves: gh-pages (not protected) and github.io (not approved); ad-m with no branch: unknown. The third
        # step's env: is not read, since actions from other repositories may run code (a pre:) that sets TARGET.
        self.assertEqual(findings(".github/workflows/d.yml", text),
                         [(7, "deploy-hosts", "error"), (10, "protected-branches", "error"), (13, "protected-branches", "error")])
        self.assertEqual(findings(".github/workflows/d.yml", text, rules=[branch_rule(values=["gh-pages"])]),
                         [(7, "protected-branches", "error"), (10, "protected-branches", "error"), (13, "protected-branches", "error")])
        first = workflow("""\
            - uses: ad-m/github-push-action@v0.8.0
              with:
                branch: ${{ env.TARGET }}
                force: true
              env:
                TARGET: feature
            """)
        self.assertEqual(findings(".github/workflows/d.yml", first), [(7, "protected-branches", "error")])


class ShellTests(unittest.TestCase):
    def test_a_run_step_in_another_shell_cannot_be_read(self):
        text = workflow("""\
            - shell: python
              run: print("hello")
            - shell: bash -e {0}
              run: echo ok
            - shell: pwsh
              run: Write-Output ok
            - shell: ${{ matrix.shell }}
              run: echo ok
            """)
        # pwsh is not read either (review of #133).
        self.assertEqual(findings(".github/workflows/d.yml", text), [(8, None, "error"), (12, None, "error"), (14, None, "error")])
        self.assertEqual(findings(".github/workflows/d.yml", text, rules=[host_rule("monitor")]),
                         [(8, None, "warning"), (12, None, "warning"), (14, None, "warning")])

    def test_runners_given_as_a_mapping_or_an_expression(self):
        def job(runs_on, run):
            return "name: ci\non: push\njobs:\n  w:\n    runs-on: %s\n    steps:\n      - run: %s\n" % (runs_on, run)
        hidden = "\"<# note #> git push --force origin main\""
        # A mapping's labels are read: a Windows label makes a step with no shell PowerShell, so unreadable.
        self.assertEqual(findings(".github/workflows/d.yml", job("{group: org, labels: [windows-latest]}", "echo ok")), [(7, None, "error")])
        self.assertEqual(findings(".github/workflows/d.yml", job("{group: org, labels: [ubuntu-latest]}", "echo ok")), [])
        # A runner the check cannot read: shell rules, unless the script holds what only PowerShell reads.
        for runs_on in ("${{ matrix.os }}", "{group: org-runners}"):
            with self.subTest(runs_on=runs_on):
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, hidden)), [(7, None, "error")])
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "iex $cmd")), [(7, None, "error")])
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "git push --force origin main")),
                                 [(7, "protected-branches", "error")])
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "echo ok")), [])
                # Bash that only looks like PowerShell to a careless match stays readable (review of #133).
                for powershell in ("'git push --force origin main' | iex", "iex -Command 'x'", "& ('gi'+'t') push --force origin main"):
                    self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "\"%s\"" % powershell)), [(7, None, "error")], powershell)
                tight = "|\n          git push origin`\n            --force main\n"
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, tight)), [(7, None, "error")])
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "\"cp .iex.exs out\"")), [])
                escaped = "|\n          Write-Host \"Pushing`n\" ; git push origin `\n            --force main\n"
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, escaped)), [(7, None, "error")])
                # A closing backtick of a pair is bash's command substitution, not a continuation (review of fe2f878).
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "|\n          SHA=`git rev-parse --short HEAD`\n")), [])
                fence = "|\n          cat > notes.md <<'EOF'\n          ```\n          ok\n          ```\n          EOF\n"
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, fence)), [])
                for bash in ("make test |& tee log", "iex -S mix", "case $x in a) echo;& b) echo;; esac"):
                    self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, "\"%s\"" % bash)), [], bash)
                continued = "|\n          git push origin main `\n            --force\n"
                self.assertEqual(findings(".github/workflows/d.yml", job(runs_on, continued)), [(7, None, "error")])

    def test_a_windows_runner_s_default_shell_is_not_read(self):
        text = "name: ci\non: push\njobs:\n  w:\n    runs-on: windows-latest\n    steps:\n      - run: git push --force origin main\n" \
               "  l:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n"
        self.assertEqual(findings(".github/workflows/d.yml", text), [(7, None, "error")])
        listed = text.replace("runs-on: windows-latest", "runs-on: [self-hosted, Windows]")
        self.assertEqual(findings(".github/workflows/d.yml", listed), [(7, None, "error")])
        bash = text.replace("      - run: git push --force origin main", "      - shell: bash\n        run: git push --force origin main")
        self.assertEqual(findings(".github/workflows/d.yml", bash), [(8, "protected-branches", "error")])

    def test_only_plain_shell_options_are_read(self):
        readable = ["bash", "bash -e {0}", "bash --noprofile --norc -eo pipefail {0}", "sh -e {0}", "/bin/bash -x {0}",
                    "bash +o posix {0}", "bash.exe {0}"]
        # PowerShell is not read: `<# ... #>` would hide a command from shell rules (review of #133).
        unreadable = ["bash -c 'exec python3 \"$1\"' _ {0}", "bash -ec 'python3 $1' _ {0}", "sh -c 'perl {0}'",
                      "pwsh -command \"& python3 '{0}'\"", "bash --rcfile x {0}", "bash -o", "bash -o 'pipe fail' {0}",
                      "bash {0} extra", "bash 'unbalanced", "pwsh -File other.ps1", "pwsh", "pwsh -command \". '{0}'\"",
                      "powershell -NoProfile -command \"& '{0}'\"", "pwsh.exe {0}"]
        for shell in readable:
            with self.subTest(shell=shell):
                self.assertTrue(pr_check._readable_shell(shell))
        for shell in unreadable:
            with self.subTest(shell=shell):
                self.assertFalse(pr_check._readable_shell(shell))

    def test_defaults_run_shell_at_job_and_workflow_level(self):
        workflow_default = "name: ci\non: push\ndefaults:\n  run:\n    shell: cmd\njobs:\n  a:\n    runs-on: windows-latest\n" \
                           "    steps:\n      - run: dir\n      - shell: bash\n        run: echo ok\n"
        self.assertEqual(findings(".github/workflows/d.yml", workflow_default), [(10, None, "error")])
        job_default = "name: ci\non: push\njobs:\n  a:\n    runs-on: x\n    defaults:\n      run:\n        shell: perl {0}\n" \
                      "    steps:\n      - run: print 1\n  b:\n    runs-on: x\n    steps:\n      - run: echo ok\n"
        self.assertEqual(findings(".github/workflows/d.yml", job_default), [(10, None, "error")])

    def test_composite_action_step_shells(self):
        text = "runs:\n  using: composite\n  steps:\n    - shell: python\n      run: print(1)\n    - shell: sh\n      run: echo\n"
        self.assertEqual(findings("action.yml", text), [(5, None, "error")])

    def test_the_annotation_has_fixed_text(self):
        with tempfile.TemporaryDirectory() as cwd:
            (finding,) = pr_check.check_file(".github/workflows/d.yml", workflow(
                "- shell: python\n  run: print('%s')\n" % CMD_HOST_MARKER).encode(), parsed(), cwd)
        self.assertIn("could not read this run step", finding.message)
        self.assertNotIn(CMD_HOST_MARKER, finding.message)


class DockerActionTests(unittest.TestCase):
    def test_a_docker_step_reads_its_entrypoint_and_args(self):
        text = workflow("""\
            - uses: docker://alpine:3.20
              with:
                entrypoint: sh
                args: -c "git push --force origin main"
            - uses: docker://node:22
              with:
                args: npx vercel --prod
            - uses: docker://alpine:3.20
            """)
        self.assertEqual(findings(".github/workflows/d.yml", text), [(7, "protected-branches", "error"), (11, "deploy-hosts", "error")])

    def test_a_docker_action_reads_its_entrypoints_and_args(self):
        text = textwrap.dedent("""\
            name: deploy
            runs:
              using: docker
              image: Dockerfile
              pre-entrypoint: git push --force origin main
              entrypoint: vercel
              args:
                - --prod
                - ${{ inputs.token }}
            """)
        self.assertEqual(findings("action.yml", text), [(6, "deploy-hosts", "error"), (5, "protected-branches", "error")])
        self.assertEqual(findings("action.yml", "runs:\n  using: docker\n  image: Dockerfile\n"), [])


class ConfigFileScanTests(unittest.TestCase):
    def test_package_json_scripts(self):
        text = textwrap.dedent("""\
            {
              "name": "web",
              "scripts": {
                "build": "next build",
                "deploy": "npm run build && vercel --prod",
                "publish:docs": "gh-pages -d out",
                "upload": "rsync -av out/ app@web1.apps.example.org:/srv",
                "release": "git push --force origin main"
              },
              "deploy": "not a script"
            }
            """)
        self.assertEqual(findings("package.json", text),
                         [(5, "deploy-hosts", "error"), (6, "deploy-hosts", "error"), (8, "protected-branches", "error")])
        self.assertEqual(findings("package.json", '{"name": "x"}'), [])

    def test_vercel_json_names_only_literal_hosts(self):
        text = textwrap.dedent("""\
            {
              "alias": ["www.apps.example.org", "shop.example.com", "preview"],
              "buildCommand": "npm run build && scp -r out deploy@web1.example.org:/srv"
            }
            """)
        self.assertEqual(findings("vercel.json", text), [(2, "deploy-hosts", "error"), (3, "deploy-hosts", "error")])
        # The file alone implies no vercel.app deploy.
        self.assertEqual(findings("vercel.json", '{"cleanUrls": true, "alias": "preview"}'), [])
        text = '{\n  "ignoreCommand": "git push --force origin main",\n  "devCommand": "vercel --prod"\n}'
        self.assertEqual(findings("vercel.json", text), [(2, "protected-branches", "error"), (3, "deploy-hosts", "error")])

    def test_netlify_toml_commands_and_no_implied_deploy(self):
        self.assertEqual(findings("netlify.toml", '[build]\n  publish = "dist"\n  command = "npm run build"\n'), [])
        text = textwrap.dedent("""\
            [build]
              command = "npm run build"

            [context.production]
              command = "npm run build && scp -r dist deploy@web1.example.org:/srv"
            """)
        self.assertEqual(findings("netlify.toml", text), [(5, "deploy-hosts", "error")])
        text = textwrap.dedent("""\
            [build]
              ignore = "git push --force origin main"

            [dev]
              command = "netlify deploy --prod"

            [context.preview]
              ignore = "scp -r dist deploy@web1.example.org:/srv"
            """)
        self.assertEqual(findings("netlify.toml", text),
                         [(2, "protected-branches", "error"), (5, "deploy-hosts", "error"), (8, "deploy-hosts", "error")])

    def test_fly_toml_app(self):
        text = '# app config\napp = "zq-app"\nprimary_region = "ams"\n'
        self.assertEqual(findings("fly.toml", text), [(2, "deploy-hosts", "error")])
        self.assertEqual(findings("fly.toml", text, rules=[host_rule(values=["*.fly.dev"])]), [])
        self.assertEqual(findings("fly.toml", text, rules=[host_rule(values=["zq-app.fly.dev"])]), [])
        self.assertEqual(findings("fly.staging.toml", text), [(2, "deploy-hosts", "error")])
        self.assertEqual(findings("fly.toml", 'primary_region = "ams"\n'), [])
        self.assertEqual(findings("fly.toml", 'app = "${APP}"\n'), [])

    def test_wrangler_routes_and_workers_dev(self):
        rules = [host_rule(values=["*.apps.example.org", "zone.example.net"])]
        text = textwrap.dedent("""\
            name = "worker"
            workers_dev = false
            routes = [
              "api.apps.example.org/*",
              "shop.example.com/*",
              { pattern = "*.apps.example.org/*", zone_name = "apps.example.org" },
              { pattern = "*apps.example.org/*", zone_name = "apps.example.org" },
              { pattern = "edge.apps.example.org", custom_domain = true },
            ]

            [env.staging]
            workers_dev = true
            route = { pattern = "$VAR/x", zone_name = "zone.example.net" }

            [env.preview]
            route = "%%%"
            """)
        # Line 4, 6 and 8 are covered; 5 is not; 7 (`*apps.example.org`) also serves apps.example.org itself; 12 is
        # workers.dev; 13 falls back to its zone_name, which is listed; 16 cannot be read.
        self.assertEqual(findings("wrangler.toml", text, rules=rules),
                         [(5, "deploy-hosts", "error"), (7, "deploy-hosts", "error"), (12, "deploy-hosts", "error"),
                          (16, "deploy-hosts", "error")])
        # No route: wrangler serves the Worker on workers.dev unless workers_dev is false. Environments inherit it.
        self.assertEqual(findings("wrangler.toml", 'name = "w"\nmain = "src/index.ts"\n', rules=rules), [(1, "deploy-hosts", "error")])
        self.assertEqual(findings("wrangler.toml", 'name = "w"\nworkers_dev = false\n[env.x]\nname = "x"\n', rules=rules), [])
        self.assertEqual(findings("wrangler.toml", 'name = "w"\nroutes = ["a.apps.example.org/*"]\n[env.x]\nname = "x"\n',
                                  rules=rules), [(1, "deploy-hosts", "error")])
        self.assertEqual(findings("wrangler.toml", 'name = "w"\n', rules=[host_rule(values=["*.workers.dev"])]), [])
        # A Pages project deploys under pages.dev.
        self.assertEqual(findings("wrangler.toml", 'name = "site"\npages_build_output_dir = "dist"\n', rules=rules),
                         [(2, "deploy-hosts", "error")])
        self.assertEqual(findings("wrangler.toml", 'pages_build_output_dir = "dist"\n', rules=[host_rule(values=["*.pages.dev"])]), [])

    def test_wrangler_jsonc_with_comments_and_trailing_commas(self):
        text = textwrap.dedent("""\
            // wrangler config
            {
              "name": "worker", /* a comment, "with quotes" */
              "routes": [
                { "pattern": "https://api.apps.example.org/*", "zone_name": "apps.example.org" },
                { "pattern": "shop.example.com/*", },
              ],
              "workers_dev": true,
            }
            """)
        self.assertEqual(findings("wrangler.jsonc", text), [(6, "deploy-hosts", "error"), (8, "deploy-hosts", "error")])
        self.assertEqual(pr_check.strip_jsonc('{"a": "x // y", "b": [1,],}'), '{"a": "x // y", "b": [1]}')

    def test_firebase_json_sites_and_deploy_hooks(self):
        text = textwrap.dedent("""\
            {
              "hosting": [
                { "site": "zq-site", "public": "dist" },
                { "target": "admin", "public": "admin" }
              ],
              "functions": { "predeploy": ["npm run build", "git push --force origin main"] }
            }
            """)
        # The second site names no site: it deploys to the project's default site under web.app.
        self.assertEqual(findings("firebase.json", text),
                         [(3, "deploy-hosts", "error"), (2, "deploy-hosts", "error"), (6, "protected-branches", "error")])
        self.assertEqual(findings("firebase.json", text, rules=[host_rule(values=["*.web.app"])]), [])
        self.assertEqual(findings("firebase.json", '{\n  "hosting": {"public": "dist"}\n}'), [(2, "deploy-hosts", "error")])
        self.assertEqual(findings("firebase.json", '{"firestore": {"rules": "firestore.rules"}}'), [])


# ----------------------------------------------------------------- modes, expiry, output


class ModeTests(RepoCase):
    def setUp(self):
        super().setUp()
        self.put("package.json", '{\n  "scripts": {\n    "deploy": "vercel --prod"\n  }\n}\n')

    def test_monitor_annotates_and_passes(self):
        self.write_policy([host_rule("monitor")])
        proc = self.run_tool("--files", "package.json")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("package.json:3: warning: Catpilot company rule `deploy-hosts`", proc.stdout)
        self.assertIn("monitor mode, so the check passes", proc.stdout)
        self.assertIn("The check passes.", proc.stdout)

    def test_ask_and_block_fail(self):
        for mode in ("ask", "block"):
            with self.subTest(mode=mode):
                self.write_policy([host_rule(mode)])
                proc = self.run_tool("--files", "package.json")
                self.assertEqual(proc.returncode, 1, proc.stderr)
                self.assertIn("package.json:3: error: Catpilot company rule `deploy-hosts`", proc.stdout)
                self.assertIn("in %s mode" % mode, proc.stdout)
                self.assertIn("Use instead: %s." % USE_INSTEAD, proc.stdout)
                self.assertIn("The check fails.", proc.stdout)

    def test_the_strictest_rule_decides_and_each_rule_is_annotated(self):
        self.write_policy([host_rule("monitor", rule_id="watch-hosts"), host_rule("block")])
        proc = self.run_tool("--files", "package.json", "--format", "github")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("::warning file=package.json,line=3,title=Catpilot company rule::Catpilot company rule `watch-hosts`", proc.stdout)
        self.assertIn("::error file=package.json,line=3,title=Catpilot company rule::Catpilot company rule `deploy-hosts`", proc.stdout)

    def test_an_expired_policy_acts_in_monitor(self):
        self.write_policy([host_rule("block"), branch_rule("ask")], expires="2001-02-03")
        self.put(".github/workflows/x.yml", workflow("- run: git push --force origin main\n"))
        proc = self.run_tool("--files", "package.json", ".github/workflows/x.yml")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertNotIn(": error:", proc.stdout)
        self.assertEqual(proc.stdout.count(": warning: Catpilot company rule"), 2)
        self.assertIn("expired on 2001-02-03", proc.stdout)

    def test_no_scanned_file_passes(self):
        self.put("README.md", "vercel --prod\n")
        proc = self.run_tool("--files", "README.md")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("0 of 1 changed file scanned; 0 errors, 0 warnings. The check passes.", proc.stdout)

    def test_github_annotations_escape_the_file_name(self):
        name = ".github/workflows/a,b:c%d.yml"
        self.put(name, workflow("- run: vercel --prod\n"))
        proc = self.run_tool("--files", name, "--format", "github")
        self.assertIn("::error file=.github/workflows/a%2Cb%3Ac%25d.yml,line=7,", proc.stdout)

    def test_a_file_name_cannot_start_a_new_output_line(self):
        name = ".github/workflows/x\n::error::forged.yml"
        try:
            self.put(name, workflow("- run: vercel --prod\n"))
        except OSError:
            self.skipTest("the file system refuses a newline in a file name")
        for fmt in ("github", "text"):
            with self.subTest(fmt=fmt):
                proc = self.run_tool("--files", name, "--format", fmt)
                self.assertEqual(proc.returncode, 1)
                self.assertFalse([line for line in proc.stdout.splitlines() if line.startswith("::error::")])
                self.assertEqual(len(proc.stdout.splitlines()), 2)

    def test_runs_isolated_from_another_directory(self):
        # The workflow template runs `python -I`, which puts neither the script's directory nor the current one on
        # the path; the tool must still find its package.
        self.write_policy([host_rule("block")])
        proc = self.run_tool("--files", "package.json", python_flags=("-I",))
        self.assertEqual(proc.returncode, 1, proc.stderr)


class PrivacyTests(RepoCase):
    """§4 and §6.1: an annotation names the rule, the file and the line, never a listed value, the command or the
    host. Values are planted in the policy and in every scanned file type."""

    def setUp(self):
        super().setUp()
        self.write_policy([branch_rule("block"), host_rule("ask"), host_rule("monitor", rule_id="watch-hosts",
                                                                              values=[HOST_MARKER])])
        scp = "scp -r dist deploy@%s:/srv" % CMD_HOST_MARKER
        push = "git push --force origin %s" % CMD_BRANCH_MARKER
        self.files = {
            ".github/workflows/deploy.yml": workflow("""\
                - run: |
                    %s
                    %s
                - uses: peaceiris/actions-gh-pages@v4
                  with:
                    cname: %s
                - uses: appleboy/scp-action@v0.1.7
                  with:
                    host: %s
                - uses: JamesIves/github-pages-deploy-action@v4
                  with:
                    branch: %s
                - run: git push --force origin $B
                  env:
                    B: %s
                - shell: python
                  run: print("%s")
                """ % (scp, push, CMD_HOST_MARKER, CMD_HOST_MARKER, CMD_BRANCH_MARKER, CMD_BRANCH_MARKER, CMD_HOST_MARKER)),
            "package.json": json.dumps({"scripts": {"a": scp, "b": push}}, indent=2),
            "vercel.json": json.dumps({"alias": [CMD_HOST_MARKER], "buildCommand": scp}),
            "netlify.toml": '[build]\ncommand = "%s"\n' % scp,
            "fly.toml": 'app = "zq-cmdmarker"\n',
            "wrangler.toml": 'routes = ["%s/*"]\n' % CMD_HOST_MARKER,
            "firebase.json": json.dumps({"hosting": {"site": "zq-cmdmarker", "predeploy": scp}}),
            ".github/workflows/broken.yml": "jobs: [%s\n" % CMD_HOST_MARKER,
        }
        for path, text in self.files.items():
            self.put(path, text)

    def test_no_value_command_or_host_reaches_the_output(self):
        for fmt in ("text", "github"):
            with self.subTest(fmt=fmt):
                proc = self.run_tool("--files", *self.files, "--format", fmt)
                self.assertEqual(proc.returncode, 1, proc.stderr)
                for path in self.files:
                    if path != ".github/workflows/broken.yml":
                        self.assertRegex(proc.stdout, re.escape(path) + r"[:,]")
                self.assertIn("could not read this file", proc.stdout)
                for marker in MARKERS + ("zq-cmdmarker",):
                    self.assertNotIn(marker, proc.stdout + proc.stderr)

    def test_a_policy_error_prints_no_value(self):
        bad = policy_dict([host_rule()])
        bad["rules"][0]["kind"] = "zq-marker-kind " + HOST_MARKER
        self.policy.write_text(json.dumps(bad), encoding="utf-8")
        proc = self.run_tool("--files", "package.json")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("malformed", proc.stderr)
        self.assertNotIn(HOST_MARKER, proc.stdout + proc.stderr)


class FailClosedTests(RepoCase):
    def test_an_unreadable_file_fails_when_a_rule_is_in_ask_or_block(self):
        self.put(".github/workflows/x.yml", "jobs:\n  a: [unclosed\n")
        for mode, code, level in (("block", 1, "error"), ("ask", 1, "error"), ("monitor", 0, "warning")):
            with self.subTest(mode=mode):
                self.write_policy([host_rule(mode)])
                proc = self.run_tool("--files", ".github/workflows/x.yml")
                self.assertEqual(proc.returncode, code)
                self.assertIn(".github/workflows/x.yml:1: %s: Catpilot pull-request check: could not read this file" % level, proc.stdout)

    def test_an_expired_policy_only_warns(self):
        self.put("package.json", "{not json")
        self.write_policy([host_rule("block")], expires="2001-01-01")
        proc = self.run_tool("--files", "package.json")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("warning: Catpilot pull-request check: could not read this file", proc.stdout)

    def test_a_rule_the_file_cannot_reveal_does_not_fail_it(self):
        self.write_policy([branch_rule("block"), host_rule("monitor")])
        self.put("fly.toml", "app = [unclosed\n")
        self.put("package.json", "{not json")
        proc = self.run_tool("--files", "fly.toml", "package.json")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("fly.toml:1: warning:", proc.stdout)
        self.assertIn("package.json:1: error:", proc.stdout)

    def test_unreadable_kinds_of_file(self):
        self.write_policy([host_rule("block")])
        outside = self.base / "outside.json"
        outside.write_text('{"scripts": {"a": "echo"}}', encoding="utf-8")
        (self.base / "package.json").write_text('{"scripts": {}}', encoding="utf-8")
        (self.repo / "linked").mkdir()
        os.symlink(outside, self.repo / "linked" / "package.json")
        os.symlink(self.base, self.repo / "dirlink")  # a directory link: dirlink/package.json is outside the repository
        self.put("big/package.json", '{"scripts": {"a": "%s"}}' % ("x" * pr_check.MAX_FILE_BYTES))
        self.put("latin/package.json", b'{"scripts": {"a": "caf\xe9"}}')
        self.put("netlify.toml", "[build\n")
        self.put("wrangler.jsonc", '{"routes": [] /* never closed')
        cases = ["linked/package.json", "dirlink/package.json", "big/package.json", "latin/package.json",
                 "netlify.toml", "wrangler.jsonc"]
        for path in cases:
            with self.subTest(path=path):
                proc = self.run_tool("--files", path)
                self.assertEqual(proc.returncode, 1, proc.stdout)
                self.assertIn("could not read this file", proc.stdout)


class PolicyAndUsageTests(RepoCase):
    def setUp(self):
        super().setUp()
        self.put("package.json", '{"scripts": {"deploy": "vercel --prod"}}')

    def test_a_symlinked_policy_is_refused(self):
        link = self.base / "link.json"
        os.symlink(self.policy, link)
        proc = self.run_tool("--files", "package.json", policy=link)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("symbolic link", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_a_policy_inside_the_repository_is_refused(self):
        inner = self.put("policy.json", self.policy.read_text(encoding="utf-8"))
        proc = self.run_tool("--files", "package.json", policy=inner)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("must never come from the repository under review", proc.stderr)

    def test_policies_that_cannot_be_used(self):
        directory = self.base / "dir.json"
        directory.mkdir()
        malformed = self.base / "bad.json"
        malformed.write_text('{"format": "catpilot-company-policy"}', encoding="utf-8")
        big = self.base / "big.json"
        big.write_text(" " * (pol.MAX_POLICY_BYTES + 10) + json.dumps(policy_dict()), encoding="utf-8")
        for path, words in ((self.base / "missing.json", "does not exist"), (directory, "not a regular file"),
                            (malformed, "malformed"), (big, "malformed")):
            with self.subTest(path=path.name):
                proc = self.run_tool("--files", "package.json", policy=path)
                self.assertEqual(proc.returncode, 2)
                self.assertIn(words, proc.stderr)

    def test_usage_errors(self):
        cases = [
            (["--files", "missing.json"], "does not exist"),
            (["--files", str(self.base / "policy.json")], "outside --repo"),
            (["--files", "../policy.json"], "outside --repo"),
            (["--base", "--output=x"], ""),
            (["--base", "-x"], ""),
            (["--base=-x"], "--base must name a commit"),
            (["--base", "no-such-ref"], "git could not list"),
            ([], ""),
        ]
        for args, words in cases:
            with self.subTest(args=args):
                proc = self.run_tool(*args)
                self.assertEqual(proc.returncode, 2, proc.stdout)
                self.assertIn(words, proc.stderr)
        proc = subprocess.run([sys.executable, str(TOOL), "--policy", str(self.policy), "--repo", str(self.base / "nope"),
                               "--files", "x"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("--repo is not a directory", proc.stderr)

    def test_an_absolute_path_inside_the_repository_is_accepted(self):
        proc = self.run_tool("--files", str(self.repo / "package.json"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("package.json:1: error:", proc.stdout)


class GitBaseTests(RepoCase):
    """--base REF scans what REF...HEAD adds or changes, in a real repository."""

    def setUp(self):
        super().setUp()
        git(self.repo, "init", "-q", "-b", "main")
        self.put("package.json", '{"scripts": {"build": "next build"}}\n')
        self.put("unchanged/package.json", '{"scripts": {"deploy": "vercel --prod"}}\n')
        self.put(".github/workflows/old.yml", workflow("- run: netlify deploy --prod\n"))
        self.put("old/fly.toml", 'app = "zq-renamed"\n')
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "base")
        git(self.repo, "checkout", "-q", "-b", "feature")
        self.put("package.json", '{\n  "scripts": {\n    "build": "next build",\n    "deploy": "vercel --prod"\n  }\n}\n')
        self.put(".github/workflows/new.yml", workflow("- run: git push --force origin main\n"))
        git(self.repo, "rm", "-q", ".github/workflows/old.yml")
        (self.repo / "new").mkdir()
        git(self.repo, "mv", "old/fly.toml", "new/fly.toml")
        self.put("notes.md", "vercel --prod\n")
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "change")
        # A commit on main after the branch point: base...HEAD diffs from the merge base, so it is not scanned.
        git(self.repo, "checkout", "-q", "main")
        self.put("later/package.json", '{"scripts": {"deploy": "surge dist"}}\n')
        git(self.repo, "add", "-A")
        git(self.repo, "commit", "-q", "-m", "later on main")
        git(self.repo, "checkout", "-q", "feature")

    def test_added_changed_and_renamed_files_are_scanned_and_deleted_ones_are_not(self):
        proc = self.run_tool("--base", "main")
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn("package.json:4: error: Catpilot company rule `deploy-hosts`", proc.stdout)
        self.assertIn(".github/workflows/new.yml:7: error: Catpilot company rule `protected-branches`", proc.stdout)
        self.assertIn("new/fly.toml:1: error: Catpilot company rule `deploy-hosts`", proc.stdout)
        for path in ("unchanged/package.json", "old.yml", "old/fly.toml", "later/package.json", "notes.md:"):
            self.assertNotIn(path, proc.stdout)
        self.assertIn("3 of 4 changed files scanned; 3 errors, 0 warnings. The check fails.", proc.stdout)

    def test_a_branch_with_nothing_to_report_passes(self):
        git(self.repo, "checkout", "-q", "-b", "clean", "main")
        self.put("package.json", '{"scripts": {"build": "next build", "test": "vitest"}}\n')
        git(self.repo, "commit", "-q", "-am", "tests")
        proc = self.run_tool("--base", "main")
        self.assertEqual(proc.returncode, 0, proc.stdout)
        self.assertIn("1 of 1 changed file scanned; 0 errors, 0 warnings. The check passes.", proc.stdout)


# ----------------------------------------------------------------- the workflow template


class WorkflowTemplateTests(unittest.TestCase):
    def setUp(self):
        self.text = TEMPLATE.read_text(encoding="utf-8")
        self.workflow = yaml.load(self.text, Loader=yaml.BaseLoader)
        (self.job,) = self.workflow["jobs"].values()
        self.steps = self.job["steps"]

    def checkout(self, path: str) -> dict:
        (step,) = [s for s in self.steps if s.get("uses", "").startswith("actions/checkout@") and s["with"]["path"] == path]
        return step["with"]

    def test_runs_on_pull_requests_read_only(self):
        # edited: retargeting a pull request's base changes what is diffed, so it must run the check again.
        self.assertEqual(self.workflow["on"], {"pull_request": {"types": ["opened", "synchronize", "reopened", "edited"]}})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertNotIn("permissions", self.job)

    def test_every_action_is_pinned_to_a_full_sha_this_repository_already_uses(self):
        ours = set()
        for path in (ROOT / ".github" / "workflows").glob("*.yml"):
            ours.update(re.findall(r"uses: (\S+@[0-9a-f]{40})", path.read_text(encoding="utf-8")))
        uses = [step["uses"] for step in self.steps if "uses" in step]
        self.assertGreaterEqual(len(uses), 3)
        for value in uses:
            with self.subTest(uses=value):
                self.assertRegex(value, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
                self.assertIn(value, ours)

    def test_the_checker_comes_from_a_pinned_checkout_never_from_the_pull_request(self):
        checker = next(s["with"] for s in self.steps if s.get("with", {}).get("repository") == "catpilotai/catpilot-ai-guardrails")
        self.assertRegex(checker["ref"], r"^[0-9a-f]{40}$")
        pull_request = self.checkout(next(s["with"]["path"] for s in self.steps
                                          if "pull_request.head.sha" in s.get("with", {}).get("ref", "")))
        self.assertNotEqual(checker["path"], pull_request["path"])
        self.assertFalse(pull_request["path"].startswith(checker["path"] + "/"))
        self.assertFalse(checker["path"].startswith(pull_request["path"] + "/"))
        self.assertEqual(pull_request["fetch-depth"], "0")
        for checkout in (checker, pull_request):
            self.assertEqual(checkout["persist-credentials"], "false")
        scripts = [step["run"] for step in self.steps if "run" in step]
        (invocation,) = [s for s in scripts if "pr_check.py" in s]
        self.assertIn("python -I %s/tools/pr_check.py" % checker["path"], invocation)
        self.assertEqual(invocation.count("pr_check.py"), 1)
        self.assertIn("--repo %s" % pull_request["path"], invocation)
        self.assertIn("--format github", invocation)
        for script in scripts:
            # Nothing from the pull request's tree runs, and no expression is interpolated into a script.
            self.assertNotRegex(script, r"(?:^|[\s\"'=])%s/" % re.escape(pull_request["path"]))
            self.assertNotIn("${{", script)

    def test_the_policy_comes_from_a_secret_and_fails_closed_without_it(self):
        first = self.steps[0]
        self.assertEqual(first["env"], {"CATPILOT_POLICY_JSON": "${{ secrets.CATPILOT_POLICY_JSON }}"})
        self.assertIn('if [ -z "${CATPILOT_POLICY_JSON}" ]', first["run"])
        self.assertIn("exit 1", first["run"])
        self.assertLess(first["run"].index("exit 1"), first["run"].index("umask 077"))
        self.assertIn('> "${RUNNER_TEMP}/catpilot-policy.json"', first["run"])
        (invocation,) = [s["run"] for s in self.steps if "pr_check.py" in s.get("run", "")]
        self.assertIn('--policy "${RUNNER_TEMP}/catpilot-policy.json"', invocation)
        self.assertNotIn("secrets.", json.dumps(self.steps[1:]))
        self.assertEqual(self.steps[-1]["if"], "always()")
        self.assertIn('rm -f "${RUNNER_TEMP}/catpilot-policy.json"', self.steps[-1]["run"])

    def test_pyyaml_is_installed_from_the_checkers_hash_pinned_list(self):
        checker = next(s["with"] for s in self.steps if s.get("with", {}).get("repository"))
        (install,) = [s["run"] for s in self.steps if "pip install" in s.get("run", "")]
        self.assertIn("--require-hashes", install)
        self.assertIn("--only-binary=:all:", install)
        self.assertIn("-r %s/deploy/ci/requirements-pr-check.txt" % checker["path"], install)

        def block(text: str) -> list:
            lines = text.splitlines()
            start = lines.index("pyyaml==6.0.3 \\")
            end = start + 1
            while end < len(lines) and lines[end].startswith("    --hash="):
                end += 1
            return lines[start:end]

        pinned = block(REQUIREMENTS.read_text(encoding="utf-8"))
        self.assertEqual(pinned, block((ROOT / "requirements-dev.txt").read_text(encoding="utf-8")))
        self.assertGreater(len(pinned), 10)
        self.assertEqual([line for line in REQUIREMENTS.read_text(encoding="utf-8").splitlines()
                          if line and not line.startswith("#")], pinned)

    def test_it_is_a_template_not_a_workflow_of_this_repository(self):
        self.assertFalse((ROOT / ".github" / "workflows" / TEMPLATE.name).exists())
        self.assertIn("TEMPLATE", self.text.splitlines()[0])


if __name__ == "__main__":
    unittest.main()
