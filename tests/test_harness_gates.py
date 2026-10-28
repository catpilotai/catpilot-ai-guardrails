"""Tests for hooks/harness/network_gate.py and hooks/harness/path_gate.py."""

import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hooks.harness.network_gate import gate_url_fetch, gate_url_tool_call
from hooks.harness.path_gate import gate_file_path, gate_path_tool_call


class NetworkGateTests(unittest.TestCase):
    def test_blocks_non_http_schemes_and_credentials(self):
        for bad in (
            "file:///etc/passwd",
            "ftp://example.com/file.txt",
            "gopher://127.0.0.1:70/",
            "javascript:alert(1)",
            "https://user:secret@example.com/api",
            "",
        ):
            with self.subTest(url=bad):
                reason = gate_url_fetch(bad, resolve_dns=False)
                self.assertIsNotNone(reason)
                self.assertIn("Blocked URL fetch", reason)

    def test_blocks_metadata_and_loopback_hosts(self):
        for bad in (
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://localhost:8080/admin",
            "http://127.0.0.1:18789/hooks/agent",
            "http://[::1]:8000/",
            "http://10.0.0.42/internal",
            "http://172.16.5.4/secret",
            "http://192.168.1.1/router",
            "http://0.0.0.0:5000/",
            "http://service.internal/api",
        ):
            with self.subTest(url=bad):
                reason = gate_url_fetch(bad, resolve_dns=False)
                self.assertIsNotNone(reason)

    def test_dns_resolution_blocks_rebind_to_private_ip_and_allows_public_ip(self):
        fake_private = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.24.0.8", 443))]
        with mock.patch("socket.getaddrinfo", return_value=fake_private):
            reason = gate_url_fetch("https://rebind.example.com/data", resolve_dns=True)
            self.assertIsNotNone(reason)
            self.assertIn("private network address", reason)

        fake_public = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        with mock.patch("socket.getaddrinfo", return_value=fake_public):
            self.assertIsNone(gate_url_fetch("https://example.com/docs", resolve_dns=True))

        with mock.patch("socket.getaddrinfo", side_effect=socket.gaierror("DNS failure")):
            reason = gate_url_fetch("https://unresolvable.example.invalid/x", resolve_dns=True)
            self.assertIsNotNone(reason)
            self.assertIn("failing closed", reason)

    def test_blocks_numeric_ipv4_forms_without_dns(self):
        for bad in (
            "http://2130706433/",
            "http://0x7f000001/",
            "http://0177.0.0.1/",
            "http://127.1/",
            "http://0xa9fea9fe/latest/meta-data/",
            "http://999999999999/",
        ):
            with self.subTest(url=bad):
                self.assertIsNotNone(gate_url_fetch(bad, resolve_dns=False))
        # The same numeric form of a public address is not blocked for being numeric.
        self.assertIsNone(gate_url_fetch("http://1572395042/", resolve_dns=False))

    def test_invalid_port_is_a_denial_not_an_exception(self):
        reason = gate_url_fetch("http://example.com:99999/", resolve_dns=False)
        self.assertIsNotNone(reason)
        self.assertIn("port", reason)

    def test_allowed_hosts_restriction(self):
        self.assertIsNone(
            gate_url_fetch("https://api.example.com/v1", allowed_hosts={"api.example.com"}, resolve_dns=False)
        )
        reason = gate_url_fetch("https://other.example.com/v1", allowed_hosts={"api.example.com"}, resolve_dns=False)
        self.assertIsNotNone(reason)
        self.assertIn("allowed_hosts", reason)

    def test_fails_closed_on_bad_input_and_tool_call_wrapper(self):
        with self.assertRaises(ValueError):
            gate_url_fetch(None)  # type: ignore[arg-type]
        self.assertIsNotNone(gate_url_tool_call("web_fetch", {}, field="url", resolve_dns=False))
        self.assertIsNotNone(gate_url_tool_call("web_fetch", {"url": 123}, field="url", resolve_dns=False))
        self.assertIsNone(
            gate_url_tool_call("web_fetch", {"url": "https://93.184.216.34/ok"}, field="url", resolve_dns=False)
        )


class PathGateTests(unittest.TestCase):
    def test_allows_files_inside_workspace_and_blocks_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp).resolve()
            (workspace / "sub").mkdir()
            safe_file = workspace / "sub" / "notes.txt"
            safe_file.write_text("ok", encoding="utf-8")

            self.assertIsNone(gate_file_path(str(safe_file), allowed_dirs=[workspace]))
            self.assertIsNone(gate_file_path("sub/notes.txt", allowed_dirs=[workspace], base_dir=workspace))

            # Path traversal outside workspace
            traversal = str(workspace / ".." / "outside.txt")
            reason = gate_file_path(traversal, allowed_dirs=[workspace])
            self.assertIsNotNone(reason)
            self.assertIn("outside the allowed workspace", reason)

    def test_blocks_symlink_escape(self):
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            workspace = Path(tmp1).resolve()
            outside = Path(tmp2).resolve() / "secret.txt"
            outside.write_text("top-secret", encoding="utf-8")

            escape_link = workspace / "leak.txt"
            escape_link.symlink_to(outside)

            reason = gate_file_path(str(escape_link), allowed_dirs=[workspace])
            self.assertIsNotNone(reason)
            self.assertIn("outside the allowed workspace", reason)

    def test_blocks_credential_and_system_paths_even_if_home_allowed(self):
        home = Path.home().resolve()
        for cred in ("~/.ssh/id_rsa", "~/.aws/credentials", "~/.gnupg/secring.gpg", "/etc/passwd"):
            with self.subTest(path=cred):
                reason = gate_file_path(cred, allowed_dirs=[home, Path("/")])
                self.assertIsNotNone(reason)
                self.assertIn("Blocked file path", reason)

    def test_credential_paths_match_without_regard_to_case(self):
        # macOS and Windows file systems ignore case by default, so ~/.SSH opens ~/.ssh.
        home = Path.home().resolve()
        for cred in ("~/.SSH/config", "~/.Aws/credentials", "~/.Config/GH/hosts.yml", "/ETC/passwd"):
            with self.subTest(path=cred):
                reason = gate_file_path(cred, allowed_dirs=[home, Path("/")])
                self.assertIsNotNone(reason)
                self.assertIn("Blocked file path", reason)

    def test_fails_closed_on_bad_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                gate_file_path(None, allowed_dirs=[tmp])  # type: ignore[arg-type]
            with self.assertRaises(ValueError):
                gate_file_path("file.txt", allowed_dirs=[])
            self.assertIsNotNone(gate_path_tool_call("read_file", {}, allowed_dirs=[tmp]))
            self.assertIsNotNone(gate_path_tool_call("read_file", {"file_path": "/etc/shadow"}, allowed_dirs=[tmp]))


if __name__ == "__main__":
    unittest.main()
