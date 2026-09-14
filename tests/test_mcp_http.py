"""The streamable HTTP app in stateless mode: health, root statement, and an MCP initialize over JSON."""

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

try:
    from starlette.testclient import TestClient
    HAVE_DEPS = True
except ImportError:  # pragma: no cover
    HAVE_DEPS = False


def load_server():
    spec = importlib.util.spec_from_file_location("catpilot_mcp_server", ROOT / "mcp-server" / "server.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "mcp-server"))
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAVE_DEPS, "starlette test client not installed")
class HttpAppTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()

    def setUp(self):
        # The SDK's session manager starts once per app instance, so each test gets a fresh app.
        self.app = self.server.build_http_app(host="0.0.0.0", stateless=True, allowed_hosts=["mcp.example.test", "testserver"])

    def test_health_and_root(self):
        with TestClient(self.app) as client:
            resp = client.get("/health")
            self.assertEqual(resp.headers.get("cache-control"), "no-store")
            health = resp.json()
            self.assertEqual(health["status"], "ok")
            self.assertEqual(health["policy_status"], "none")
            root = client.get("/").json()
            self.assertIn("stores nothing", root["data_statement"])
            self.assertEqual(root["mcp_endpoint"], "/mcp")

    def test_stateless_initialize_and_tool_call(self):
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
        with TestClient(self.app) as client:
            init = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}})
            self.assertEqual(init.status_code, 200, init.text)
            self.assertEqual(init.json()["result"]["serverInfo"]["name"], "catpilot-guardrails")
            call = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_approved", "arguments": {"category": "contacts"}}})
            self.assertEqual(call.status_code, 200, call.text)
            self.assertTrue(call.json()["result"]["structuredContent"]["unknown_policy"])

    def test_disallowed_host_is_rejected(self):
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json", "Host": "evil.example"}
        with TestClient(self.app) as client:
            resp = client.post("/mcp", headers=headers, json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}}})
            self.assertIn(resp.status_code, (400, 403, 421))


if __name__ == "__main__":
    unittest.main()
