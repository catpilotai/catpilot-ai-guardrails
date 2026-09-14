"""Overlay validator: schema, expiry, and content scans. Offline, synthetic only."""

import copy
import datetime as dt
import unittest
from pathlib import Path

from tools import validate_overlay as vo

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
TODAY = dt.date(2026, 9, 13)
HOSTS = {"intranet.example.org"}


class OverlayValidatorTests(unittest.TestCase):
    def setUp(self):
        self.data, _ = vo.load_overlay_file(EXAMPLE)

    def errors(self, data, hosts=HOSTS):
        _, errors = vo.validate_overlay(data, hosts, today=TODAY)
        return errors

    def test_example_passes(self):
        self.assertEqual(self.errors(self.data), [])

    def test_structural_rejections(self):
        cases = [
            lambda d: d.update(notes="extra field"),
            lambda d: d.pop("owner"),
            lambda d: d.update(schema_version=2),
            lambda d: d.update(schema_version=True),
            lambda d: d.update(expires_on=d["reviewed_on"]),
            lambda d: d["data_classes"].pop("ok"),
            lambda d: d["hosting"].update(extra=["x"]),
            lambda d: d["identity"].update(default=["not a string"]),
            lambda d: d.update(review_triggers=[]),
            lambda d: d.update(review_triggers=["dup", "dup"]),
            lambda d: d.update(templates=[{"kind": "Bad Kind"}]),
            lambda d: d.update(organization="x" * 81),
            lambda d: d["services"].update(approved=["x" * 201]),
        ]
        for mutate in cases:
            data = copy.deepcopy(self.data)
            mutate(data)
            with self.subTest(mutate=mutate), self.assertRaises(vo.OverlayError):
                vo.validate_structure(data)

    def test_content_rejections(self):
        cases = {
            "secret": lambda d: d["services"]["approved"].append("api_key=abcdefghijklmnopqrstuvwxyz123456"),
            "aws": lambda d: d["hosting"]["approved"].append("Bucket AKIAIOSFODNN7EXAMPLE"),
            "url in list": lambda d: d["hosting"]["approved"].append("See https://wiki.example.org/hosting"),
            "email in list": lambda d: d["review_triggers"].append("Ask alice@example.org"),
            "ip": lambda d: d["hosting"]["approved"].append("Server 10.1.2.3"),
            "narrative": lambda d: d["review_triggers"].append("After last year's breach we require review"),
            "http template": lambda d: d["templates"][0].update(location="http://intranet.example.org/t"),
            "template query": lambda d: d["templates"][0].update(location="https://intranet.example.org/t?x=1"),
            "template credentials": lambda d: d["templates"][0].update(location="https://user:pw@intranet.example.org/t"),
        }
        for label, mutate in cases.items():
            data = copy.deepcopy(self.data)
            mutate(data)
            with self.subTest(case=label):
                self.assertTrue(self.errors(data), label)

    def test_template_host_must_be_allowlisted(self):
        self.assertTrue(any("allowlist" in e for e in self.errors(self.data, hosts=set())))

    def test_expiry_window(self):
        data = copy.deepcopy(self.data)
        _, errors = vo.validate_overlay(data, HOSTS, today=dt.date(2027, 4, 1))
        self.assertTrue(any("has passed" in e for e in errors))
        _, errors = vo.validate_overlay(data, HOSTS, today=dt.date(2026, 1, 1))
        self.assertTrue(any("in the future" in e for e in errors))

    def test_cli_on_example(self):
        self.assertEqual(vo.main([str(EXAMPLE), "--allow-host", "intranet.example.org"]), 0)
        self.assertEqual(vo.main([str(EXAMPLE)]), 1)


if __name__ == "__main__":
    unittest.main()
