"""Exceptions on package_registry and cloud_account rules relax only their own rule, in the hook and in verify's probe
picker (review of the merge of #134 into #135)."""
import datetime as dt, json, tempfile, unittest
from pathlib import Path
from unittest import mock
from test_overlay_v2_exceptions import cr, bash, effect, parsed, policy_dict, policy_exception, load_helper, TODAY

TWO_REGISTRY_RULES = [
    {"id": "package-registries", "kind": "package_registry", "mode": "monitor", "values": ["npm.example.org"]},
    {"id": "registries-strict", "kind": "package_registry", "mode": "block", "values": ["npm.example.org"]},
]
TWO_ACCOUNT_RULES = [
    {"id": "cloud-accounts", "kind": "cloud_account", "mode": "monitor", "values": ["aws:111122223333"]},
    {"id": "accounts-strict", "kind": "cloud_account", "mode": "block", "values": ["aws:111122223333"]},
]


class ScopingTests(unittest.TestCase):
    def run_hook(self, command, rules, exceptions):
        lines = []
        with mock.patch.object(cr, "record_evidence", lambda e, h=None, host=None, **f: lines.append((e, f["rule_id"], f.get("exception_id")))):
            result = effect(cr.decide(bash(command), "claude-code", parsed(exceptions, rules), today=TODAY))
        return result, lines

    def test_an_exception_relaxes_only_its_own_rule(self):
        for rules, exception, command, strict in (
            (TWO_REGISTRY_RULES, policy_exception(id="exception-mirror", rule="package-registries", allows=["mirror.example.net"]),
             "pip install -i https://mirror.example.net/simple x", "registries-strict"),
            (TWO_ACCOUNT_RULES, policy_exception(id="exception-sandbox", rule="cloud-accounts", allows=["aws:999988887777"]),
             "aws organizations describe-account --account-id 999988887777", "accounts-strict"),
        ):
            with self.subTest(rule=strict):
                result, lines = self.run_hook(command, rules, [exception])
                self.assertEqual(result, "deny")
                self.assertEqual(lines, [("would_deny", rules[0]["id"], exception["id"]), ("deny", strict, None)])

    def test_the_picker_reads_each_rule_s_own_exceptions(self):
        helper = load_helper()
        for picker, probes, rules, rule_id in ((helper.first_registry_probe, helper.REGISTRY_PROBES, TWO_REGISTRY_RULES, "registries-strict"),
                                               (helper.first_cloud_probe, helper.CLOUD_PROBES, TWO_ACCOUNT_RULES, "accounts-strict")):
            with self.subTest(rule=rule_id), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "p.json"
                # The second (block) rule's exception allows the first probe target: the first rule is still probed on it,
                # and the expected decision is the first rule's (monitor), as the hook decides.
                exceptions = [policy_exception(id="exception-probe", rule=rule_id, allows=[probes[0][1]])]
                path.write_text(json.dumps(policy_dict(rules, exceptions)), encoding="utf-8")
                _, _, command, _, modes = picker(path, today=TODAY)
                self.assertEqual(command, probes[0][0])
                expected = helper.expected_effect("claude-code", modes, ask_enabled=False)
                result, _ = self.run_hook(command, rules, exceptions)
                self.assertEqual((expected, result), ("none", "none"))


if __name__ == "__main__":
    unittest.main()
