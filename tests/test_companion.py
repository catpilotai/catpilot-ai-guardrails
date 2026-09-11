"""Synthetic private-policy, hook, and real SDK stdio tests; no LLM calls."""
from copy import deepcopy
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins/catpilot-companion'
NOW = datetime(2026, 9, 11, tzinfo=timezone.utc)


def load(name):
    spec = importlib.util.spec_from_file_location(name, PLUGIN / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


policy = load('policy')
hook = load('check_patch')


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / 'private-policy.json'
        self.data = json.loads((ROOT / 'examples/company-policy.synthetic.json').read_text())
        self.store = policy.PolicyStore(self.file, 'fictional-company')
        self.write()

    def write(self):
        self.file.write_text(json.dumps(self.data))

    def result(self, **kwargs):
        return self.store.guidance('sharing', 'fictional-pilot', 'demo', now=NOW, **kwargs)

    def test_current_policy_has_provenance_and_one_next_step(self):
        result = self.result()
        self.assertEqual(result['status'], 'approved-local')
        self.assertEqual(result['enforcement'], 'none')
        self.assertEqual(len(result['sha256']), 64)
        self.assertEqual(result['paved_road']['id'], 'employee-demo')
        self.assertIn('not a cryptographic signature', result['approval_verified_by'])

    def test_no_policy_or_wrong_organization_is_never_approved(self):
        self.file.unlink()
        self.assertEqual(self.result()['status'], 'missing')
        self.write()
        self.store.organization_id = 'another-company'
        self.assertEqual(self.result()['status'], 'organization-mismatch')
        self.assertNotIn('requirement', self.result())

    def test_scope_and_topics_cannot_route_to_other_policy_files(self):
        for topic, project, env, expected in [('sharing', 'other-project', 'demo', 'out-of-scope'), ('secrets', '../escape', 'demo', 'invalid-scope'), ('arbitrary', 'fictional-pilot', 'demo', 'unknown-topic'), ('authentication', 'fictional-pilot', 'demo', 'missing-topic')]:
            self.assertEqual(self.store.guidance(topic, project, env, now=NOW)['status'], expected)

    def test_expiry_revocation_and_not_yet_valid(self):
        for field, value, expected in [('expires_at', '2026-09-10T00:00:00Z', 'expired'), ('valid_from', '2026-10-01T00:00:00Z', 'not-yet-valid')]:
            original = self.data[field]
            self.data[field] = value
            self.write()
            self.assertEqual(self.result()['status'], expected)
            self.data[field] = original
        for status in ('draft', 'revoked'):
            self.data['approval']['status'] = status
            self.write()
            self.assertEqual(self.result()['status'], status)

    def test_every_call_reloads_revocation_and_digest(self):
        first = self.result()
        self.data['rules'][1]['why'] = 'Changed approved rationale.'
        self.write()
        self.assertNotEqual(self.result()['sha256'], first['sha256'])
        self.data['approval']['status'] = 'revoked'
        self.write()
        self.assertEqual(self.result()['status'], 'revoked')

    def test_duplicate_conflicting_and_invalid_fields_rejected(self):
        for mutate in [lambda d: d['rules'].append(deepcopy(d['rules'][0])), lambda d: d.update(unknown=True), lambda d: d['paved_roads'][0].update(url='https://user:password@example.com/'), lambda d: d['rules'][0].update(paved_road_id='unknown'), lambda d: d.update(schema_version=True), lambda d: d.update(expires_at='2026-12-01')]:
            data = deepcopy(self.data)
            mutate(data)
            with self.assertRaises(policy.PolicyError):
                policy.validate_policy(data)
        self.file.write_text('{"a":1,"a":2}')
        self.assertEqual(self.result()['status'], 'invalid')

    def test_symlink_oversized_and_corrupt_files_do_not_leak_details(self):
        self.file.unlink()
        self.file.symlink_to(ROOT / 'examples/company-policy.synthetic.json')
        self.assertEqual(self.result()['status'], 'invalid')
        self.file.unlink()
        for payload in ('sensitive-synthetic-content', 'x' * (policy.LIMIT + 1)):
            self.file.write_text(payload)
            self.assertEqual(self.result()['status'], 'invalid')
            self.assertNotIn(payload[:20], json.dumps(self.result()))


class HookTests(unittest.TestCase):
    def test_private_key_blocks_supported_added_content_without_echo(self):
        marker = '-----BEGIN PRIVATE KEY-----'
        for name, args in [('Write', {'content': marker}), ('Edit', {'new_string': marker}), ('MultiEdit', {'edits': [{'new_string': marker}]}), ('apply_patch', {'command': '*** Begin Patch\n+' + marker})]:
            result = hook.inspect_event({'tool_name': name, 'tool_input': args})
            self.assertEqual(result['hookSpecificOutput']['permissionDecision'], 'deny')
            self.assertNotIn(marker, json.dumps(result))

    def test_safe_and_unsupported_paths_are_not_claimed_as_enforced(self):
        for event in [{'tool_name': 'Write', 'tool_input': {'content': 'pk_test_synthetic_publishable'}}, {'tool_name': 'apply_patch', 'tool_input': {'command': '-\u002d----BEGIN PRIVATE KEY-----\n+<PRIVATE_KEY_PLACEHOLDER>'}}, {'tool_name': 'Bash', 'tool_input': {'command': 'synthetic unsupported command'}}]:
            self.assertEqual(hook.inspect_event(event), {})

    def test_malformed_hook_input_exits_two_without_leaking_payload(self):
        result = subprocess.run([sys.executable, str(PLUGIN / 'scripts/check_patch.py')], input='sensitive-synthetic-input', text=True, capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn('sensitive-synthetic-input', result.stderr + result.stdout)


class MCPTests(unittest.IsolatedAsyncioTestCase):
    async def test_initialize_discover_and_read_via_real_stdio(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        # Use a missing policy so the protocol test does not depend on wall clock.
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        policy_file = Path(temporary) / 'private.json'
        params = StdioServerParameters(command=sys.executable, args=[str(PLUGIN / 'scripts/server.py')], env={'CATPILOT_ORGANIZATION_ID': 'fictional-company', 'CATPILOT_POLICY_FILE': str(policy_file)})
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write, read_timeout_seconds=15) as client:
                initialized = await client.initialize()
                self.assertEqual(initialized.server_info.name, 'catpilot-companion')
                manifest = json.loads((PLUGIN / '.codex-plugin/plugin.json').read_text())
                self.assertEqual(initialized.server_info.version, manifest['version'])
                listing = await client.list_tools()
                self.assertEqual({tool.name for tool in listing.tools}, {'get_company_guidance', 'get_approved_starting_point', 'explain_security_decision'})
                for tool in listing.tools:
                    self.assertTrue(tool.annotations.read_only_hint)
                    self.assertNotIn('organization_id', tool.input_schema['properties'])
                    result = await client.call_tool(tool.name, {'topic': 'sharing', 'project': 'fictional-pilot', 'environment': 'demo'})
                    self.assertFalse(result.is_error)
                    self.assertEqual(result.structured_content['status'], 'missing')
                data = json.loads((ROOT / 'examples/company-policy.synthetic.json').read_text())
                data['approval']['approved_at'] = '1999-01-01T00:00:00Z'
                data['valid_from'], data['expires_at'] = '2000-01-01T00:00:00Z', '2999-01-01T00:00:00Z'
                policy_file.write_text(json.dumps(data))
                result = await client.call_tool('get_company_guidance', {'topic': 'sharing', 'project': 'fictional-pilot', 'environment': 'demo'})
                self.assertEqual(result.structured_content['status'], 'approved-local')
                data['approval']['status'] = 'revoked'
                policy_file.write_text(json.dumps(data))
                result = await client.call_tool('get_company_guidance', {'topic': 'sharing', 'project': 'fictional-pilot', 'environment': 'demo'})
                self.assertEqual(result.structured_content['status'], 'revoked')

    def test_manifests_agree_and_reference_real_entrypoints(self):
        codex = json.loads((PLUGIN / '.codex-plugin/plugin.json').read_text())
        claude = json.loads((PLUGIN / '.claude-plugin/plugin.json').read_text())
        self.assertEqual(codex['name'], claude['name'])
        self.assertEqual(codex['version'], claude['version'])
        mcp = json.loads((PLUGIN / codex['mcpServers']).read_text())['mcpServers']['catpilot-companion']
        self.assertEqual(mcp['command'], 'python3')
        self.assertEqual(mcp['args'], ['${CLAUDE_PLUGIN_ROOT}/scripts/server.py'])
        self.assertTrue((PLUGIN / 'scripts/server.py').is_file())
        hooks = json.loads((PLUGIN / 'hooks/hooks.json').read_text())
        self.assertEqual(hooks['hooks']['PreToolUse'][0]['matcher'], 'Write|Edit|MultiEdit|apply_patch')
        self.assertTrue((PLUGIN / 'scripts/check_patch.py').is_file())
