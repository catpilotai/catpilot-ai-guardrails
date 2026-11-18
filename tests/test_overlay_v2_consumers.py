"""Every consumer of the company rules file, on version 1 and version 2. Offline, synthetic only.

- The privacy invariant (docs/spec/OVERLAY_V2.md §6.1, invariant 1): canary values planted in
  every enforcement field of a version 2 file appear in no private-build file (zip members
  included), company-checklist block, benchmark prompt or scanner evidence, sidecar,
  session-start output or evidence line, MCP tool response or server evidence line.
- The server cannot be probed: a check_plan call naming a listed host answers exactly as one
  naming an unlisted host. The file's hash, which a model sees, cannot confirm a guess either:
  the salt makes the file's bytes unguessable (§6.3 rule 10).
- A migrated file renders the same bundle body and paste blocks as its source, and check_plan
  gives the same outcome for the same call (§2.4).
- Version 1 files reach every consumer unchanged.
"""

import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import re
import secrets
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "mcp-server"))

from catpilot_guard import evidence, session_start  # noqa: E402
from catpilot_guardrails_mcp import content, policy  # noqa: E402
from catpilot_guardrails_mcp import tools as mcp_tools  # noqa: E402
from tools import bundle, company_checklist, eval as evaltool, validate_overlay  # noqa: E402
from tools.bench import hosts as bench_hosts, sandbox, scanners  # noqa: E402

SPEC = ROOT / "docs" / "spec"
EXAMPLE_V1 = SPEC / "overlay.example.yaml"
EXAMPLE_V2 = SPEC / "overlay.v2.example.yaml"
V1_DAY = dt.date(2026, 9, 13)
TODAY = dt.date.today()

# One distinctive value per enforcement field a file can choose freely. kind, mode and
# default_mode come from closed lists; STRUCTURE checks that their names do not leak either.
CANARIES = (
    "canary-rule-branches-5d1e",  # a rule id
    "canary-rule-hosts-9b7c",  # a rule id
    "canary-branch-1a2b",  # a protected branch
    "release-canary-3c4d",  # a protected branch prefix, as release-canary-3c4d/*
    "canary-host-7e8f",  # a deploy host, canary-host-7e8f.example.net
    "canary-wild-0a1b",  # a wildcard deploy host, *.canary-wild-0a1b.example.net
    "canary-alias-2f4e",  # use_instead, an alias only enforcement refers to
    "canary-rule-registries-6a2c",  # a rule id
    "canary-rule-accounts-1c9e",  # a rule id
    "canary-registry-5b3d",  # a package registry host, canary-registry-5b3d.example.net/canary-path-8e4f
    "canary-path-8e4f",  # that registry's path
    "canary-project-4d7a",  # a GCP project, gcp:canary-project-4d7a
    "730194628517",  # an AWS account, aws:730194628517
    "c4a7e1d2-9b3f-4e8a-b6c5-2d1f0e9a8b7c",  # an Azure subscription
    "ca7a1b9e3d5f0c8264e1f7b2d9a0c3e5",  # the salt
)
STRUCTURE = ("protected_branch", "deploy_host", "package_registry", "cloud_account", "default_mode", "use_instead")

try:
    from starlette.testclient import TestClient
    HAVE_SERVER = True
except ImportError:  # pragma: no cover
    HAVE_SERVER = False


def canary_overlay() -> dict:
    """The version 2 example with canaries in every enforcement field, current as of today."""
    data, _ = validate_overlay.load_overlay_file(EXAMPLE_V2)
    data["reviewed_on"] = TODAY - dt.timedelta(days=1)
    data["expires_on"] = TODAY + dt.timedelta(days=30)
    data["hosting"]["approved"][0]["aliases"].append("canary-alias-2f4e")
    data["salt"] = "ca7a1b9e3d5f0c8264e1f7b2d9a0c3e5"
    data["enforcement"] = {
        "default_mode": "monitor",
        "rules": [
            {"id": "canary-rule-branches-5d1e", "kind": "protected_branch", "mode": "block",
             "values": ["canary-branch-1a2b", "release-canary-3c4d/*"]},
            {"id": "canary-rule-hosts-9b7c", "kind": "deploy_host", "mode": "ask", "use_instead": "canary-alias-2f4e",
             "values": ["canary-host-7e8f.example.net", "*.canary-wild-0a1b.example.net"]},
            {"id": "canary-rule-registries-6a2c", "kind": "package_registry", "mode": "block", "use_instead": "canary-alias-2f4e",
             "values": ["canary-registry-5b3d.example.net/canary-path-8e4f"]},
            {"id": "canary-rule-accounts-1c9e", "kind": "cloud_account", "mode": "monitor",
             "values": ["gcp:canary-project-4d7a", "aws:730194628517", "azure:c4a7e1d2-9b3f-4e8a-b6c5-2d1f0e9a8b7c"]},
        ],
    }
    return data


def write_yaml(path: Path, data: dict) -> Path:
    path.write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def pinned(day: dt.date):
    real = validate_overlay.validate_expiry
    return mock.patch.object(validate_overlay, "validate_expiry", lambda overlay, today=None: real(overlay, day))


def private_build(source: Path, out: Path, day: dt.date | None = None) -> Path:
    with pinned(day or TODAY), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as err:
        code = bundle.cmd_private(source, out, [], None)
    if code != 0:
        raise AssertionError(err.getvalue())
    return out


def output_texts(root: Path) -> dict[str, str]:
    """Every file under root as text, keyed by relative path; zip members are read decompressed."""
    texts = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if path.suffix == ".zip":
            with zipfile.ZipFile(path) as archive:
                for name in archive.namelist():
                    texts[f"{rel}!{name}"] = archive.read(name).decode("utf-8")
        else:
            texts[rel] = path.read_bytes().decode("utf-8")
    return texts


def run_session_start(hosts_dir: Path, log: Path) -> str:
    stdin = io.TextIOWrapper(io.BytesIO(b'{"session_id": "s-1", "source": "startup"}'), encoding="utf-8")
    out = io.StringIO()
    with mock.patch.dict(os.environ, {evidence.EVIDENCE_ENV: str(log)}), mock.patch.object(sys, "stdin", stdin), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        session_start.main(["--host", "codex", "--dir", str(hosts_dir)], today=TODAY)
    return out.getvalue()


class CanaryCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.source = write_yaml(self.root / "rules.yaml", canary_overlay())
        self.raw = self.source.read_bytes()

    def assertNoCanary(self, label: str, text: str):
        folded = text.casefold()
        for canary in CANARIES + STRUCTURE:
            self.assertNotIn(canary, folded, f"{label} carries {canary}")

    def test_the_canary_file_is_valid_and_carries_every_canary(self):
        data, raw = validate_overlay.load_overlay_file(self.source)
        overlay, errors = validate_overlay.validate_overlay(data)
        self.assertEqual(errors, [])
        for canary in CANARIES:
            self.assertIn(canary.encode(), raw)
        for view in (validate_overlay.model_facing(overlay), validate_overlay.v1_projection(overlay)):
            self.assertNotIn("enforcement", view)
            self.assertNoCanary("a view", repr(view))


class PrivacyCanaryTests(CanaryCase):
    def test_private_build_checklist_and_sidecar(self):
        out = private_build(self.source, self.root / "private")
        texts = output_texts(out)
        self.assertTrue(any(name.endswith(".zip!catpilot-safe-building-example-org/SKILL.md") for name in texts), sorted(texts))
        for name, text in texts.items():
            with self.subTest(file=name):
                self.assertNoCanary(name, text)
        (hosts,) = out.glob("*-hosts")
        # The sidecar keeps the hash of the whole source file, enforcement included (see company_checklist.sidecar).
        sidecar = json.loads((hosts / "company-checklist.json").read_text(encoding="utf-8"))
        self.assertEqual(sidecar["policy_sha256"], hashlib.sha256(self.raw).hexdigest())
        # The block shows the model-facing parts: ids and text, no aliases, no enforcement.
        block = (hosts / "company-checklist.md").read_text(encoding="utf-8")
        policy_yaml = yaml.safe_load(block.split("```yaml\n", 1)[1].rsplit("```", 1)[0])
        overlay, _ = validate_overlay.validate_overlay(yaml.safe_load(self.raw))
        self.assertEqual(policy_yaml, validate_overlay.model_facing(overlay))
        self.assertEqual(policy_yaml["hosting"]["approved"][0], {"id": "hosting-app-platform", "text": "Internal App Platform (company sign-in)"})
        self.assertNotIn("aliases", block)

    def test_session_start_output_and_evidence_line(self):
        hosts = next(private_build(self.source, self.root / "private").glob("*-hosts"))
        log = self.root / "evidence.jsonl"
        output = run_session_start(hosts, log)
        self.assertIn("additionalContext", output)
        self.assertNoCanary("session-start output", output)
        line = json.loads(log.read_text(encoding="utf-8"))
        self.assertEqual(line["event"], "rules_delivered")
        self.assertEqual(line["policy_sha256"], hashlib.sha256(self.raw).hexdigest())
        self.assertNoCanary("session-start evidence", log.read_text(encoding="utf-8"))

    def test_benchmark_prompts_and_scanner_evidence(self):
        self.assertNoCanary("condition F", company_checklist.company_checklist_instruction(self.source))
        overlay, _ = company_checklist.validated_company_overlay(self.source)
        self.assertNotIn("enforcement", overlay)
        skill_source = self.root / "skill-source"
        skill_source.mkdir()
        for arm in ("D", "F"):
            box = sandbox.build_sandbox({"id": "synthetic", "sandbox": []}, arm, self.root / f"project-{arm}", host="codex",
                                        skill_source=skill_source, server_script=self.root / "server.py", python="python3",
                                        overlay_file=self.source)
            for path in box.project.rglob("*"):
                if path.is_file():
                    self.assertNoCanary(f"arm {arm} {path.name}", path.read_text(encoding="utf-8"))
            self.assertNoCanary(f"arm {arm} MCP config", json.dumps(box.mcp_config))
        loaded = sandbox.load_overlay(self.source)
        self.assertEqual(loaded["hosting"]["approved"][0], "Internal App Platform (company sign-in)")
        self.assertNoCanary("load_overlay", repr(loaded))
        transcript = bench_hosts.Transcript(host="codex", assistant_texts=[
            "Deploy it on the Internal App Platform. Do not use canary-host-7e8f.example.net or canary-branch-1a2b."])
        values = scanners.scan_values_cited(scanners.ScanContext(scenario={}, transcript=transcript), loaded)
        self.assertEqual(values["cites_approved_hosting"], {"cited": True, "evidence": "Internal App Platform (company sign-in)"})
        self.assertNoCanary("scanner evidence", json.dumps(values))
        # The scanners read a version 2 item's text if they are ever handed one directly.
        raw = yaml.safe_load(self.raw)
        self.assertEqual(scanners.cites_approved_hosting(scanners.ScanContext(scenario={}, transcript=transcript), raw)[1],
                         "Internal App Platform (company sign-in)")

    def test_eval_checks_read_text_only(self):
        overlay, _ = validate_overlay.validate_overlay(yaml.safe_load(self.raw))
        checks = evaltool.overlay_checks(overlay)
        self.assertTrue(checks["cites_approved_hosting"]("Use the Internal App Platform (company sign-in)."))
        self.assertFalse(checks["cites_company_value"]("canary-host-7e8f.example.net hosting-app-platform canary-alias-2f4e"))

    def test_policy_state_never_holds_enforcement(self):
        state = policy.load_policy(str(self.source), set())
        self.assertEqual(state.status, "approved")
        self.assertNotIn("enforcement", state.overlay)
        self.assertNoCanary("PolicyState", repr(state))
        self.assertEqual(state.source["sha256"], hashlib.sha256(self.raw).hexdigest())
        # A host's policy_provider that builds a PolicyState from the full validated file gets the projection too.
        overlay, _ = validate_overlay.validate_overlay(yaml.safe_load(self.raw))
        hosted = policy.PolicyState("approved", "hosted", overlay, {"organization": "Example Org", "reviewed_on": "x"})
        self.assertEqual(hosted.overlay, validate_overlay.v1_projection(overlay))
        self.assertNoCanary("hosted PolicyState", repr(hosted))


def load_server():
    import importlib.util

    spec = importlib.util.spec_from_file_location("catpilot_mcp_server_v2_canary", ROOT / "mcp-server" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}


@unittest.skipUnless(HAVE_SERVER, "the mcp SDK or starlette is not installed; pip install --require-hashes -r requirements-dev.txt")
class ServerCanaryTests(CanaryCase):
    """Every tool of the reference server, over HTTP in this process, with the canary file configured."""

    CALLS = (
        *[("get_guidance", {"topic": t}) for t in sorted(content.TOPICS)],
        *[("list_approved", {"category": c}) for c in content.CATEGORIES],
        *[("get_template", {"kind": k}) for k in content.TEMPLATE_KINDS],
        ("check_plan", {"description": "An internal dashboard for the ops team, deployed to our app platform from the main branch."}),
        ("check_plan", {"description": "Upload the customer export to my personal Replit, share a public link, take payments.",
                        "data_classes": ["customer names", "health records"], "audience": "anyone with the link",
                        "hosting": "free-tier hosting", "services": ["a new model endpoint"], "write_access": True}),
        ("check_plan", {"description": "A lookup tool.", "audience": "our ops team", "hosting": "Internal App Platform",
                        "data_classes": ["made-up records with example.com addresses"], "services": ["the company LLM gateway"],
                        "write_access": False, "data_provenance": "synthetic"}),
    )

    def test_no_tool_response_or_evidence_line_carries_a_canary(self):
        server = load_server()
        log = self.root / "evidence.jsonl"
        env = {"CATPILOT_OVERLAY_FILE": str(self.source), "CATPILOT_TEMPLATE_HOSTS": "", evidence.EVIDENCE_ENV: str(log)}
        responses = []
        with mock.patch.dict(os.environ, env):
            app = server.build_http_app(host="0.0.0.0", stateless=True, allowed_hosts=["testserver"])
            with TestClient(app) as client:
                client.post("/mcp", headers=HEADERS, json=INITIALIZE)
                for n, (name, arguments) in enumerate(self.CALLS, start=2):
                    body = {"jsonrpc": "2.0", "id": n, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
                    response = client.post("/mcp", headers=HEADERS, json=body)
                    self.assertEqual(response.status_code, 200, response.text)
                    responses.append((name, response.text, response.json()["result"]))
                responses.append(("health", client.get("/health").text, None))
        for name, text, result in responses:
            with self.subTest(tool=name):
                self.assertNoCanary(name, text)
                if result is not None:
                    self.assertEqual(result["structuredContent"]["policy_status"], "approved")
        listed = next(r for n, _, r in responses if n == "list_approved" and r["structuredContent"]["category"] == "hosting")
        self.assertIn("Internal App Platform (company sign-in)", listed["structuredContent"]["items"]["approved"])
        lines = log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(lines), len(self.CALLS))
        self.assertNoCanary("server evidence", "\n".join(lines))
        self.assertEqual({json.loads(line)["policy_sha256"] for line in lines}, {hashlib.sha256(self.raw).hexdigest()})


class SaltedHashTests(unittest.TestCase):
    """The whole-file SHA-256 reaches a model, so it must not confirm a guess (§6.3 rule 10).

    The guesser here knows every byte of the file except the salt: the shipped example's text,
    every enforcement value, the layout. Rebuilding the bytes with the true salt reproduces the
    hash, which shows the rebuild is exact; with any other salt it does not match.
    """

    def test_every_value_known_but_the_salt_does_not_match_the_hash(self):
        template = EXAMPLE_V2.read_text(encoding="utf-8")
        published = f'salt: "{validate_overlay.EXAMPLE_SALT}"'
        self.assertEqual(template.count(published), 1)

        def rebuild(salt: str) -> bytes:
            return template.replace(published, f'salt: "{salt}"').encode("utf-8")

        secret = validate_overlay.new_salt()
        target = hashlib.sha256(rebuild(secret)).hexdigest()  # what the block, the sidecar and the server show
        data = validate_overlay.parse_yaml(rebuild(secret).decode("utf-8"))
        _, errors = validate_overlay.validate_overlay(data, today=dt.date(2026, 11, 17))
        self.assertEqual(errors, [])
        self.assertEqual(hashlib.sha256(rebuild(secret)).hexdigest(), target)
        guesses = [validate_overlay.EXAMPLE_SALT, "0" * 32, "f" * 32, secret[:-1] + ("0" if secret[-1] != "0" else "1")]
        guesses += [secrets.token_hex(16) for _ in range(1000)]
        for guess in guesses:
            rebuilt = validate_overlay.parse_yaml(rebuild(guess).decode("utf-8"))
            # Every enforcement value and every other field is right; only the salt differs.
            self.assertEqual({k: v for k, v in rebuilt.items() if k != "salt"}, {k: v for k, v in data.items() if k != "salt"})
            self.assertNotEqual(hashlib.sha256(rebuild(guess)).hexdigest(), target)


class ProbeTests(CanaryCase):
    """check_plan never reads enforcement, so naming a listed value changes nothing (§2.2)."""

    def answer(self, state, **fields):
        guidance = content.load_guidance()
        return mcp_tools.check_plan(fields.pop("description", "A small internal tool."), guidance, state, **fields)

    def test_a_listed_value_answers_exactly_as_an_unlisted_one(self):
        state = policy.load_policy(str(self.source), set())
        self.assertEqual(state.status, "approved")
        # Each control differs from the listed value in one token, its last hex group, so the
        # answers can differ only where check_plan echoes the caller's own words as evidence.
        listed_values = (
            "canary-host-7e8f.example.net", "x.canary-wild-0a1b.example.net", "canary-branch-1a2b",
            "release-canary-3c4d/hotfix", "canary-rule-hosts-9b7c", "canary-alias-2f4e",
            "canary-registry-5b3d.example.net", "canary-project-4d7a", "canary-rule-accounts-1c9e",
        )
        for listed in listed_values:
            token = re.search(r"[0-9a-f]{4}(?=[^0-9a-f]|$)", listed).group(0)
            unlisted = listed.replace(token, "kkkk")
            for field in ("hosting", "services", "data_classes", "audience", "description"):
                value = [listed] if field in ("services", "data_classes") else listed
                control = [unlisted] if field in ("services", "data_classes") else unlisted
                with self.subTest(value=listed, field=field):
                    probe = json.dumps(self.answer(state, **{field: value}), sort_keys=True)
                    baseline = json.dumps(self.answer(state, **{field: control}), sort_keys=True)
                    self.assertEqual(probe.replace(token, "kkkk"), baseline.replace(token, "kkkk"))


class MigratedFileTests(unittest.TestCase):
    """A migrated file renders the same bundle body and paste blocks as its source, and the
    server answers the same (OVERLAY_V2.md §2.4)."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        data, _ = validate_overlay.load_overlay_file(EXAMPLE_V1)
        self.migrated = self.root / "rules.v2.yaml"
        self.migrated.write_text(validate_overlay.migrate_text(data), encoding="utf-8")

    @staticmethod
    def masked(text: str, raw: bytes) -> str:
        digest = hashlib.sha256(raw).hexdigest()
        return text.replace(digest, "SOURCE-SHA256").replace(digest[:12], "SOURCE-SHA")

    def test_every_output_but_the_checklist_block_is_the_same(self):
        v1 = output_texts(private_build(EXAMPLE_V1, self.root / "v1", V1_DAY))
        v2 = output_texts(private_build(self.migrated, self.root / "v2", V1_DAY))
        self.assertEqual(sorted(v1), sorted(v2))
        compared = 0
        for name in v1:
            if Path(name).name.startswith("company-checklist."):
                continue
            with self.subTest(file=name):
                self.assertEqual(self.masked(v2[name], self.migrated.read_bytes()), self.masked(v1[name], EXAMPLE_V1.read_bytes()))
                compared += 1
        self.assertGreater(compared, 10)
        # The SKILL.md body and the paste blocks are byte-identical, hash or not.
        skill = "catpilot-safe-building-example-org/SKILL.md"
        self.assertEqual(v2[skill].split("\n---\n", 1)[1], v1[skill].split("\n---\n", 1)[1])
        for paste in ("catpilot-safe-building-example-org-hosts/CLAUDE.md", "catpilot-safe-building-example-org-hosts/chatgpt-project-instructions.md"):
            self.assertEqual(v2[paste], v1[paste])
        # The checklist block shows the migrated ids, and its sidecar the migrated file's own hash.
        block = v2["catpilot-safe-building-example-org-hosts/company-checklist.md"]
        self.assertIn("id: hosting-internal-app-platform-company-sign-in", block)
        self.assertIn(hashlib.sha256(self.migrated.read_bytes()).hexdigest(), block)

    def test_the_server_answers_the_same(self):
        day = dt.date(2026, 9, 14)
        guidance, templates = content.load_guidance(), content.load_templates()
        states = [policy.load_policy(str(path), set(), now=day) for path in (EXAMPLE_V1, self.migrated)]
        self.assertEqual([s.status for s in states], ["approved", "approved"])
        self.assertEqual(states[0].overlay, states[1].overlay)

        def answers(state):
            out = [mcp_tools.get_guidance(t, guidance, state) for t in sorted(content.TOPICS)]
            out += [mcp_tools.list_approved(c, guidance, state) for c in content.CATEGORIES]
            out += [mcp_tools.get_template(k, templates, guidance, state) for k in content.TEMPLATE_KINDS]
            for _name, arguments in ServerCanaryTests.CALLS:
                if _name == "check_plan":
                    arguments = dict(arguments)
                    out.append(mcp_tools.check_plan(arguments.pop("description"), guidance, state, **arguments))
            for answer in out:
                answer.pop("policy_source")  # the source file's hash differs; nothing else may
            return out

        self.assertEqual(answers(states[1]), answers(states[0]))


class Version1UnchangedTests(unittest.TestCase):
    """A version 1 file reaches every consumer exactly as before: the views are the identity."""

    def setUp(self):
        self.data, self.raw = validate_overlay.load_overlay_file(EXAMPLE_V1)
        self.overlay, errors = validate_overlay.validate_overlay(self.data, today=V1_DAY)
        self.assertEqual(errors, [])

    def test_the_views_return_the_version_1_overlay_itself(self):
        self.assertIs(validate_overlay.model_facing(self.overlay), self.overlay)
        self.assertIs(validate_overlay.v1_projection(self.overlay), self.overlay)

    def test_the_checklist_block_is_the_pre_version_2_rendering(self):
        expected = (
            company_checklist.CHECKLIST_INSTRUCTION
            + "\n\n## Company policy\n\n"
            + "Apply the checklist using the reviewed company policy below. Listed approvals supply company confirmation; "
            "for decisions the policy does not cover, ask its named owner. Respect the review and expiry dates. "
            "This is a static snapshot validated when the run started.\n\n"
            + f"Overlay SHA-256: {hashlib.sha256(self.raw).hexdigest()}\n\n```yaml\n"
            + yaml.safe_dump(validate_overlay.validate_structure(self.data), sort_keys=False, allow_unicode=True).rstrip("\n")
            + "\n```"
        )
        self.assertEqual(company_checklist.render(self.overlay, self.raw), expected)

    def test_the_server_bench_and_eval_see_the_version_1_shape(self):
        state = policy.load_policy(str(EXAMPLE_V1), set(), now=dt.date(2026, 9, 14))
        self.assertEqual(state.overlay, self.overlay)
        self.assertEqual(sandbox.load_overlay(EXAMPLE_V1), yaml.safe_load(self.raw))
        defaults = bundle.load_bundle_cfg(ROOT / "src" / "skills" / "safe-building")["slots"]
        self.assertEqual(bundle.overlay_slot_values(self.overlay, defaults)["approved_hosting"], self.overlay["hosting"]["approved"])
        self.assertIn("Approved hosting: Internal App Platform (company sign-in);", bundle.overlay_values_block(self.overlay))
        self.assertTrue(evaltool.overlay_checks(self.overlay)["cites_owner"]("ask security-review@example.org"))

    def test_the_example_block_and_its_v2_counterpart_fit_the_line_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            v2 = Path(tmp) / "rules.yaml"
            v2.write_text(EXAMPLE_V2.read_text(encoding="utf-8").replace(validate_overlay.EXAMPLE_SALT, validate_overlay.new_salt()), encoding="utf-8")
            for path, day in ((EXAMPLE_V1, V1_DAY), (v2, dt.date(2026, 11, 17))):
                with self.subTest(example=path.name), pinned(day):
                    lines = company_checklist.company_checklist_instruction(path).splitlines()
                    self.assertLessEqual(len(lines), 200)


class ServerPolicyErrorTests(unittest.TestCase):
    """A file the server cannot parse is the normal policy error state, never an exception out of a tool."""

    def test_deep_nesting_and_impossible_dates_are_invalid_policies(self):
        cases = {
            "nested too deeply": "[" * 5000 + "]" * 5000 + "\n",
            "impossible date": EXAMPLE_V1.read_text(encoding="utf-8").replace("reviewed_on: 2026-09-13", "reviewed_on: 2026-13-45"),
            "duplicate key": EXAMPLE_V1.read_text(encoding="utf-8") + 'owner: "someone-else@example.org"\n',
        }
        guidance = content.load_guidance()
        with tempfile.TemporaryDirectory() as tmp:
            for label, text in cases.items():
                path = Path(tmp) / f"{label.replace(' ', '-')}.yaml"
                path.write_text(text, encoding="utf-8")
                with self.subTest(case=label):
                    state = policy.load_policy(str(path), set(), now=dt.date(2026, 9, 14))
                    self.assertEqual(state.status, "invalid")
                    self.assertTrue(state.unknown_policy)
                    self.assertEqual(state.reason, "The configured overlay did not validate: OverlayError.")
                    self.assertTrue(mcp_tools.list_approved("hosting", guidance, state)["unknown_policy"])
                    self.assertIsNone(sandbox.load_overlay(path))


if __name__ == "__main__":
    unittest.main()
