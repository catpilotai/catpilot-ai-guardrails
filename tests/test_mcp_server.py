"""Contract tests over a real stdio session with the MCP SDK client. No model, no network."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "mcp-server" / "server.py"
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    HAVE_MCP = True
except ImportError:  # pragma: no cover
    HAVE_MCP = False


@unittest.skipUnless(HAVE_MCP, "the mcp SDK is not installed; pip install --require-hashes -r requirements-dev.txt")
class ServerContractTests(unittest.IsolatedAsyncioTestCase):
    async def _session(self, env: dict):
        params = StdioServerParameters(command=sys.executable, args=[str(SERVER)], env={"PATH": "/usr/bin:/bin", **env})
        return stdio_client(params)

    async def test_handshake_tools_and_lookups(self):
        with tempfile.TemporaryDirectory() as tmp:
            overlay = Path(tmp) / "overlay.yaml"
            shutil.copyfile(EXAMPLE, overlay)
            env = {"CATPILOT_OVERLAY_FILE": str(overlay), "CATPILOT_TEMPLATE_HOSTS": "intranet.example.org"}
            async with await self._session(env) as (read, write):
                async with ClientSession(read, write, read_timeout_seconds=20) as client:
                    init = await client.initialize()
                    self.assertEqual(init.server_info.name, "catpilot-guardrails")
                    listing = await client.list_tools()
                    self.assertEqual({t.name for t in listing.tools}, {"get_guidance", "check_plan", "get_template", "list_approved"})
                    for tool in listing.tools:
                        self.assertTrue(tool.annotations.read_only_hint)
                        self.assertFalse(tool.annotations.destructive_hint)
                    result = await client.call_tool("list_approved", {"category": "hosting"})
                    self.assertFalse(result.is_error)
                    self.assertFalse(result.structured_content["unknown_policy"])
                    self.assertIn("Internal App Platform (company sign-in)", result.structured_content["items"]["approved"])
                    result = await client.call_tool("check_plan", {"description": "Load last month's customer export with card digits into a lookup tool."})
                    self.assertTrue(result.structured_content["risks"])
                    self.assertEqual(result.structured_content["risks"][0]["component"], "data-in-prompts")
                    # The fields a model has to pass are on the tool's schema, and they decide the outcome.
                    check_plan = next(t for t in listing.tools if t.name == "check_plan")
                    properties = check_plan.input_schema["properties"]
                    for field in ("description", "data_classes", "data_provenance", "audience", "hosting", "services", "write_access", "data_types", "credential_references"):
                        self.assertIn(field, properties)
                    result = await client.call_tool("check_plan", {
                        "description": "An internal dashboard. No external users or public links.",
                        "audience": "our ops team", "hosting": "Internal App Platform",
                        "data_classes": ["made-up records with example.com addresses"],
                        "services": ["the company LLM gateway"], "write_access": False,
                    })
                    self.assertEqual(result.structured_content["outcome"], "permitted")
                    self.assertEqual(result.structured_content["risks"], [])
                    self.assertFalse(result.structured_content["ask_a_human"])
                    result = await client.call_tool("check_plan", {
                        "description": "A local helper that names an environment variable without reading its value.",
                        "audience": "our team", "hosting": "not deployed", "data_classes": ["made-up records"],
                        "data_provenance": "synthetic", "services": ["none"], "write_access": False,
                        "credential_references": [{"name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": False, "value_in_generated_artifacts": False}],
                    })
                    self.assertEqual(result.structured_content["outcome"], "permitted")
                    reference = next(d for d in result.structured_content["decisions"] if d["field"] == "credential_references")
                    self.assertEqual(reference["outcome"], "permitted")
                    result = await client.call_tool("check_plan", {"description": "A dashboard.", "hosting": "my personal Replit account", "write_access": True})
                    self.assertEqual(result.structured_content["outcome"], "prohibited")
                    hosting = next(d for d in result.structured_content["decisions"] if d["field"] == "hosting")
                    self.assertEqual(hosting["rule"], "Personal cloud accounts")
                    result = await client.call_tool("get_template", {"kind": "dashboard"})
                    self.assertTrue(result.structured_content["starting_point"].startswith("## Dashboard"))
                    # Expiry is live: rewrite the file and the next call reports it.
                    text = overlay.read_text().replace("reviewed_on: 2026-09-13", "reviewed_on: 2026-01-01").replace("expires_on: 2027-03-13", "expires_on: 2026-02-01")
                    overlay.write_text(text)
                    result = await client.call_tool("get_guidance", {"topic": "hosting"})
                    self.assertTrue(result.structured_content["unknown_policy"])
                    self.assertEqual(result.structured_content["policy_status"], "expired")

    async def test_no_overlay_means_unknown_policy(self):
        async with await self._session({}) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=20) as client:
                await client.initialize()
                result = await client.call_tool("list_approved", {"category": "contacts"})
                self.assertTrue(result.structured_content["unknown_policy"])
                self.assertIn("generic defaults", result.structured_content["source"])
                result = await client.call_tool("get_guidance", {"topic": "nope"})
                self.assertEqual(result.structured_content["error"], "unknown-topic")


if __name__ == "__main__":
    unittest.main()
