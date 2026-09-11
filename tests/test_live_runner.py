import json
from pathlib import Path
import unittest
from tools import run_live_evals as runner


class RunnerTests(unittest.TestCase):
    def test_safe_commands_disable_tools_and_personal_customizations(self):
        codex = runner.command_for('codex', '/trusted/codex', 'explicit-model', 'medium', '/tmp/synthetic', 0.5)
        self.assertIn('--ignore-user-config', codex)
        self.assertIn('read-only', codex)
        self.assertIn('skip_host_skill_discovery', codex)
        self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', codex)
        claude = runner.command_for('claude', '/trusted/claude', 'explicit-model', 'medium', '/tmp/synthetic', 0.5)
        self.assertIn('--safe-mode', claude)
        self.assertEqual(claude[claude.index('--tools') + 1], '')

    def test_prompt_has_no_answer_key_and_advisory_is_explicit(self):
        case = json.loads((runner.ROOT / 'evals/cases.json').read_text())['cases'][0]
        for condition in ('baseline', 'advisory'):
            prompt = runner.prompt_for(case, condition, runner.ROOT / 'skills/catpilot-security-core')
            self.assertNotIn('required_concepts', prompt)
            self.assertNotIn(case['expected']['forbidden_behaviors'][1], prompt)
            self.assertEqual('injected explicitly' in prompt, condition == 'advisory')

    def test_parser_requires_actual_host_response(self):
        self.assertTrue(runner.parse_output('codex', '{"type":"turn.failed"}')['host_error'])
        self.assertTrue(runner.parse_output('claude', 'not-json')['host_error'])
        result = runner.parse_output('codex', '{"type":"item.completed","item":{"type":"agent_message","text":"Synthetic answer"}}')
        self.assertEqual(result['response'], 'Synthetic answer')
