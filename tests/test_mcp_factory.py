"""create_server: the same four tools with the rules and evidence chosen per call by the host.

A host that serves several organizations builds the server with a policy provider that reads the
HTTP request, and its own evidence sink. These tests serve two organizations from one app, one with
the example overlay and one without, and check that the tools, their schemas, and the reference
server's defaults do not change.
"""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"

try:
    from starlette.testclient import TestClient
    HAVE_DEPS = True
except ImportError:  # pragma: no cover
    HAVE_DEPS = False

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}


def load_server():
    spec = importlib.util.spec_from_file_location("catpilot_mcp_server_factory", ROOT / "mcp-server" / "server.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "mcp-server"))
    spec.loader.exec_module(module)
    return module


def call(client, name, arguments, org=None, request_id=2):
    headers = {**HEADERS, **({"X-Test-Org": org} if org else {})}
    body = {"jsonrpc": "2.0", "id": request_id, "method": "tools/call", "params": {"name": name, "arguments": arguments}}
    response = client.post("/mcp", headers=headers, json=body)
    assert response.status_code == 200, response.text
    return response.json()["result"]


@unittest.skipUnless(HAVE_DEPS, "starlette test client not installed")
class FactoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()

    def build(self, **kwargs):
        mcp = self.server.create_server(**kwargs)
        app = self.server.build_http_app(host="0.0.0.0", stateless=True, allowed_hosts=["testserver"], mcp_server=mcp)
        return mcp, app

    def test_the_policy_provider_picks_the_rules_for_each_request(self):
        seen = []

        def rules_for(ctx):
            request = ctx.request_context.request
            org = request.headers.get("x-test-org") if request is not None else None
            seen.append(org)
            return self.server.policy.load_policy(str(EXAMPLE) if org == "acme" else None, set())

        _, app = self.build(policy_provider=rules_for)
        with TestClient(app) as client:
            client.post("/mcp", headers=HEADERS, json=INITIALIZE)
            acme = call(client, "list_approved", {"category": "hosting"}, org="acme")["structuredContent"]
            self.assertFalse(acme["unknown_policy"])
            self.assertIn("Internal App Platform (company sign-in)", acme["items"]["approved"])
            other = call(client, "list_approved", {"category": "hosting"}, org="other")["structuredContent"]
            self.assertTrue(other["unknown_policy"])
            plan = call(client, "check_plan", {"description": "A dashboard.", "hosting": "Personal cloud accounts"}, org="acme")
            hosting = next(d for d in plan["structuredContent"]["decisions"] if d["field"] == "hosting")
            self.assertEqual((hosting["rule"], hosting["source"]), ("Personal cloud accounts", "company overlay"))
        self.assertEqual(seen, ["acme", "other", "acme"])

    def test_the_evidence_sink_gets_enumerated_fields_and_the_request(self):
        records = []

        def sink(tool, result, fields, ctx):
            records.append((tool, dict(fields), ctx.request_context.request is not None))

        _, app = self.build(evidence=sink)
        with TestClient(app) as client:
            client.post("/mcp", headers=HEADERS, json=INITIALIZE)
            call(client, "get_guidance", {"topic": "not-a-topic"})
            call(client, "check_plan", {"description": "Upload the customer export and share it publicly.", "audience": "anyone with the link"})
        self.assertEqual(records[0], ("get_guidance", {"topic": "invalid"}, True))
        tool, fields, has_request = records[1]
        self.assertEqual((tool, has_request, fields["fields"]), ("check_plan", True, ["audience"]))
        self.assertIn(fields["outcome"], {"requires_review", "prohibited", "unknown"})
        self.assertNotIn("description", fields)  # the plan text never reaches the sink

    def test_the_tools_and_their_inputs_match_the_reference_server(self):
        _, custom_app = self.build(policy_provider=lambda ctx: self.server._policy(), instructions="Hosted for Example Org.")
        reference_app = self.server.build_http_app(host="0.0.0.0", stateless=True, allowed_hosts=["testserver"])
        listings = []
        for app in (reference_app, custom_app):
            with TestClient(app) as client:
                init = client.post("/mcp", headers=HEADERS, json=INITIALIZE).json()["result"]
                tools = client.post("/mcp", headers=HEADERS, json={"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).json()["result"]["tools"]
                listings.append((init.get("instructions"), {t["name"]: (t["description"], t["inputSchema"], t.get("annotations")) for t in tools}))
        (reference_instructions, reference_tools), (custom_instructions, custom_tools) = listings
        self.assertEqual(reference_tools, custom_tools)
        self.assertEqual(set(reference_tools), {"get_guidance", "check_plan", "get_template", "list_approved"})
        for _description, schema, _annotations in reference_tools.values():
            self.assertNotIn("ctx", schema.get("properties", {}))  # the context is injected, never an input
        self.assertEqual(reference_instructions, self.server.INSTRUCTIONS)
        self.assertEqual(custom_instructions, "Hosted for Example Org.")


if __name__ == "__main__":
    unittest.main()
