"""deploy_host rules: what a command deploys to (catpilot_guard/deploy_targets.py), and the company-rules hook's
decision on it (docs/spec/OVERLAY_V2.md §2.2: an allow-list, so a target no value covers fires the rule)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from catpilot_guard import company_rules as cr  # noqa: E402
from catpilot_guard import policy as pol  # noqa: E402
from catpilot_guard.deploy_targets import HOST, SUFFIX, UNKNOWN, Target, deploy_targets, host_covered  # noqa: E402

MARKER = "zq-marker.apps.example.org"


def targets(command):
    return [(t.kind, t.name) for t in deploy_targets(command)]


class DeployTargetTests(unittest.TestCase):
    def test_hosting_services_deploy_under_their_own_domain(self):
        cases = {
            "vercel": "vercel.app", "vercel --prod": "vercel.app", "vc deploy --prod": "vercel.app",
            "vercel --token t deploy": "vercel.app", "vercel ./dist": "vercel.app", "vercel redeploy https://x": "vercel.app",
            "npx vercel deploy --prod": "vercel.app", "pnpm dlx vercel --prod": "vercel.app",
            "netlify deploy --prod --dir dist": "netlify.app", "ntl deploy": "netlify.app",
            "fly deploy -a myapp": "fly.dev", "flyctl deploy": "fly.dev", "fly launch": "fly.dev",
            "firebase deploy --only hosting": "web.app",
            "wrangler deploy": "workers.dev", "wrangler publish": "workers.dev", "wrangler pages deploy dist": "pages.dev",
            "surge dist": "surge.sh", "npx gh-pages -d dist": "github.io", "railway up": "up.railway.app",
            "amplify publish": "amplifyapp.com", "git push heroku main": "herokuapp.com",
            "cd app && npm run build && vercel --prod": "vercel.app", "bash -lc 'netlify deploy --prod'": "netlify.app",
            "npm run build\nnetlify deploy --prod": "netlify.app",
            # Runners with versions and package names, and options the first version misread (review of #130).
            "npx vercel@latest --prod": "vercel.app", "pnpm dlx vercel@latest": "vercel.app", "npm exec vercel -- --prod": "vercel.app",
            "npx wrangler@latest deploy": "workers.dev", "npx netlify-cli deploy --prod": "netlify.app",
            "npx firebase-tools deploy": "web.app", "npx @railway/cli up": "up.railway.app", "VERCEL --prod": "vercel.app",
            "vercel --target production": "vercel.app", "vercel -e FOO=bar --prod": "vercel.app", "vercel --build-env A=b": "vercel.app",
            "yarn vercel --prod": "vercel.app", "pnpm vercel --prod": "vercel.app", "yarn run vercel --prod": "vercel.app",
            "yarn workspace web vercel --prod": "vercel.app", "npx -c 'vercel --prod'": "vercel.app",
            "npm exec -c 'netlify deploy'": "netlify.app", "git push https://u:p@git.heroku.com/app.git": "herokuapp.com",
            "git push ssh://git@heroku.com/app.git": "herokuapp.com",
            "firebase hosting:channel:deploy preview": "web.app", "wrangler versions deploy": "workers.dev",
            "wrangler versions upload": "workers.dev", "railway redeploy": "up.railway.app", "fly machine run nginx": "fly.dev",
            "git push https://git.heroku.com/app.git main": "herokuapp.com",
        }
        for command, suffix in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), [(SUFFIX, suffix)])

    def test_named_destinations(self):
        cases = {
            "scp -r dist deploy@web1.example.org:/srv": [(HOST, "web1.example.org")],
            "scp -P 2222 -i key dist/app.tar Web1.Example.org:app.tar": [(HOST, "web1.example.org")],
            "rsync -av -e ssh dist/ app@apps.example.org:/var/www": [(HOST, "apps.example.org")],
            "rsync -av dist/ rsync://mirror.example.net/site/": [(HOST, "mirror.example.net")],
            "surge dist my-site.example.org": [(HOST, "my-site.example.org")],
            "surge --domain x.surge.sh": [(HOST, "x.surge.sh")],
            "rsync -avz dist/ $HOST:/srv": [(UNKNOWN, None)],
            "scp dist/* ${DEPLOY_HOST}:/srv": [(UNKNOWN, None)],
            "rsync dist/ web.example.org:/srv --max-delete 10": [(HOST, "web.example.org")],
            "scp f scp://deploy@web.example.org/srv": [(HOST, "web.example.org")],
            "scp f [::1]:/srv": [(UNKNOWN, None)],
            "scp f deploy@[::ffff:10.0.0.1]:/srv": [(UNKNOWN, None)],
            "scp notes.txt devbox:/tmp": [(UNKNOWN, None)],  # an SSH alias without a dot cannot be listed
        }
        for command, want in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), want)

    def test_what_is_not_a_deploy(self):
        for command in ("vercel env ls", "vercel dev", "vercel login", "netlify status", "netlify dev", "flyctl launch --no-deploy",
                        "fly logs", "firebase login", "wrangler dev", "railway logs", "git push origin main", "git push",
                        "scp deploy@web1.example.org:/srv/log.txt .", "scp file.txt ./copy", "rsync -av src/ dst/",
                        "rsync -av rsync://mirror.example.net/x ./local", "ls", "echo vercel --prod", "npm run deploy",
                        "vercel --version", "vercel -v", "vercel --help", "fly deploy --help", "gh-pages --help",
                        "surge whoami", "surge list", "surge teardown x.surge.sh", "vercel env pull", "vercel link",
                        "rsync -av host:/x ./local --max-delete 5", "vercel curl /api/hello", "vercel httpstat /",
                        "vercel rolling-release start", "vercel webhooks ls",
                        "scp web.example.org:/a web.example.org:/b .", "scp -r h1:/a h2:/b ./out"):
            with self.subTest(command=command):
                self.assertEqual(targets(command), [])

    def test_compound_commands_and_comments_are_read_as_bash_reads_them(self):
        # Independent review, 2026-11-17: the command after a leading reserved word was not read.
        cases = {
            "if [ -n \"$CI\" ]; then vercel --prod; fi": [(SUFFIX, "vercel.app")],
            "if x; then\n  netlify deploy --prod\nfi": [(SUFFIX, "netlify.app")],
            "for i in 1; do fly deploy; done": [(SUFFIX, "fly.dev")],
            "{ npm run build; vercel --prod; }": [(SUFFIX, "vercel.app")],
            "! scp dist/app.tar deploy@web1.example.org:/srv": [(HOST, "web1.example.org")],
            "echo a\\ #; vercel --prod": [(SUFFIX, "vercel.app")],
            "ls # no deploy here \\\nvercel --prod": [(SUFFIX, "vercel.app")],
            "echo then vercel --prod": [],
            "if vercel --help; then echo ok; fi": [],
        }
        for command, want in cases.items():
            with self.subTest(command=command):
                self.assertEqual(targets(command), want)
        # A carriage return is read each way a shell may read it; each target is listed once, without the carriage
        # return bash leaves in the line's last word (review of #137).
        self.assertEqual(targets("vercel --prod\r\n"), [(SUFFIX, "vercel.app")])
        self.assertEqual(targets("vercel --prod; vercel --prod"), [(SUFFIX, "vercel.app")])
        self.assertEqual(targets("surge dist my-site.surge.sh\r\n"), [(HOST, "my-site.surge.sh")])
        self.assertEqual(targets("scp dist/a sftp://apps.example.org\r\n"), [(HOST, "apps.example.org")])
        self.assertEqual(targets("2>&1 vercel --prod"), [(SUFFIX, "vercel.app")])
        self.assertEqual(targets("env -S 'netlify deploy --prod'"), [(SUFFIX, "netlify.app")])

    def test_a_vercel_directory_counts_whether_or_not_it_exists_yet(self):
        # The build before it may create it (review of #130); VERCEL_OTHER lists the words that are not deploys.
        for command in ("vercel dist --prod", "vercel my-site", "npm run build && vercel dist --prod", "vercel --cwd site dist"):
            with self.subTest(command=command):
                self.assertEqual([(t.kind, t.name) for t in deploy_targets(command)], [(SUFFIX, "vercel.app")])

    def test_a_tools_own_c_option_is_not_a_runner_call(self):
        self.assertEqual(targets("npx wrangler deploy -c wrangler.prod.toml"), [(SUFFIX, "workers.dev")])
        self.assertEqual(targets("npx firebase-tools deploy -c firebase.json"), [(SUFFIX, "web.app")])
        self.assertEqual(targets("npm exec --call='netlify deploy'"), [(SUFFIX, "netlify.app")])

    def test_remote_to_remote_copies_name_the_destination(self):
        self.assertEqual(targets("scp build.example.org:/app.tgz prod.example.org:/srv/"), [(HOST, "prod.example.org")])
        self.assertEqual(targets("scp -3 a.example.org:x b.example.org:y"), [(HOST, "b.example.org")])
        self.assertEqual(targets("scp remote.example.org:/a ./local web.example.org:/srv"), [(HOST, "web.example.org")])

    def test_coverage(self):
        cases = [
            ("*.vercel.app", Target(SUFFIX, "vercel.app"), True),
            ("vercel.app", Target(SUFFIX, "vercel.app"), False),
            ("*.railway.app", Target(SUFFIX, "up.railway.app"), True),
            ("*.example.vercel.app", Target(SUFFIX, "vercel.app"), False),
            ("*.example.org", Target(HOST, "web1.example.org"), True),
            ("*.example.org", Target(HOST, "example.org"), False),
            ("apps.example.org", Target(HOST, "apps.example.org"), True),
            ("Apps.Example.org", Target(HOST, "apps.example.org"), True),
            ("apps.example.org", Target(HOST, "web1.apps.example.org"), False),
            ("*.example.org", Target(UNKNOWN), False),
        ]
        for value, target, want in cases:
            with self.subTest(value=value, target=target):
                self.assertIs(host_covered(value, target), want)


def policy(values=("apps.example.org", "*.apps.example.org"), mode="block", use_instead=None, extra=()):
    rule = {"id": "deploy-hosts", "kind": "deploy_host", "mode": mode, "values": list(values)}
    if use_instead:
        rule["use_instead_text"] = use_instead
    return pol.parse(json.dumps({
        "format": "catpilot-company-policy", "format_version": 1, "source_sha256": "c" * 64, "expires_on": "2099-01-01",
        "rules": [rule, *extra],
    }).encode())


def bash(command):
    return {"session_id": "s1", "tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/tmp", "permission_mode": "default"}


class HookDecisionTests(unittest.TestCase):
    def setUp(self):
        self.lines = []
        patcher = mock.patch.object(cr, "record_evidence", lambda event, hook_event=None, host=None, **f: self.lines.append((event, f)))
        patcher.start()
        self.addCleanup(patcher.stop)

    def effect(self, command, **kw):
        result = cr.decide(bash(command), kw.pop("host", "claude-code"), policy(**kw))
        return result.get("hookSpecificOutput", {}).get("permissionDecision", "none")

    def test_an_unlisted_target_fires_and_a_listed_one_does_not(self):
        self.assertEqual(self.effect("vercel --prod"), "deny")
        self.assertEqual(self.effect("scp -r dist deploy@web1.example.org:/srv"), "deny")
        self.assertEqual(self.effect("rsync -av dist/ $HOST:/srv"), "deny")  # unknown: nothing covers it
        self.assertEqual(self.effect("rsync -av dist/ deploy@apps.example.org:/srv"), "none")
        self.assertEqual(self.effect("scp app.tar web2.apps.example.org:/srv"), "none")
        self.assertEqual(self.effect("vercel --prod", values=("*.vercel.app",)), "none")
        self.assertEqual(self.effect("ls && npm test"), "none")
        self.assertEqual(self.effect("vercel env ls"), "none")
        self.assertEqual(self.effect("if x; then vercel --prod; fi"), "deny")
        self.assertEqual(self.effect("for f in a; do rsync -av dist/ deploy@apps.example.org:/srv; done"), "none")
        # A host the rule lists, sent with a CR-LF line ending, is still that host (review of #137).
        self.assertEqual(self.effect("surge dist my-site.surge.sh\r\n", values=("my-site.surge.sh",)), "none")
        self.assertEqual(self.effect("rsync -av dist/ rsync://apps.example.org\r\n"), "none")
        self.assertEqual(self.effect("scp dist/a sftp://apps.example.org\r\n"), "none")
        self.assertEqual(self.effect("scp dist/a sftp://web1.example.org\r\n"), "deny")

    def test_every_target_must_be_covered(self):
        self.assertEqual(self.effect("scp a apps.example.org:/srv && vercel --prod"), "deny")

    def test_modes_and_hosts(self):
        self.assertEqual(self.effect("netlify deploy --prod", mode="monitor"), "none")
        self.assertEqual([(e, f["rule_id"], f["mode"]) for e, f in self.lines], [("would_deny", "deploy-hosts", "monitor")])
        self.assertEqual(self.effect("netlify deploy --prod", mode="ask", host="codex"), "deny")

    def test_the_reason_names_the_rule_and_alternative_never_the_host(self):
        result = cr.decide(bash("scp -r dist deploy@%s:/srv" % MARKER), "claude-code",
                           policy(values=("apps.example.org",), use_instead="Internal App Platform (company sign-in)"))
        reason = result["hookSpecificOutput"]["permissionDecisionReason"]
        self.assertIn("Catpilot company rule `deploy-hosts`: this command deploys or publishes to a host the company has not approved.", reason)
        self.assertIn("Use instead: Internal App Platform (company sign-in).", reason)
        for text in (MARKER, "apps.example.org", "scp"):
            self.assertNotIn(text, reason)
        self.assertEqual(self.lines[0][1], {"tool": "Bash", "rule_id": "deploy-hosts", "mode": "block", "policy_sha256": "c" * 64})

    def test_protected_branch_and_deploy_host_rules_together(self):
        branch = {"id": "protected-branches", "kind": "protected_branch", "mode": "block", "values": ["main"]}
        result = cr.decide(bash("git push --force origin main && vercel --prod"), "claude-code", policy(mode="monitor", extra=(branch,)))
        self.assertEqual(result["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(sorted((e, f["rule_id"]) for e, f in self.lines), [("deny", "protected-branches"), ("would_deny", "deploy-hosts")])


if __name__ == "__main__":
    unittest.main()
