"""Execute shipped helpers with synthetic data, never cloud or public calls."""

import json
from pathlib import Path
import runpy
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / 'src/skills/core/language-baseline/scripts'
IO = runpy.run_path(str(SCRIPTS / 'safe_io.py'))
ENV = runpy.run_path(str(ROOT / 'src/skills/core/cloud-cli-safety/scripts/env_patch.py'))


class SecurityExampleTests(unittest.TestCase):
    def test_azure_patch_preserves_secret_refs_and_unrelated_entries(self):
        current = [{'name': 'DB_URL', 'secretRef': 'old-db'}, {'name': 'OTHER', 'value': 'unchanged'}]
        plan = ENV['plan_patch'](current, [{'name': 'DB_URL', 'secretRef': 'new-db'}, {'name': 'LABEL', 'value': 'hello world=$value'}])
        self.assertEqual(plan['set_env_vars'], ['DB_URL=secretref:new-db', 'LABEL=hello world=$value'])
        self.assertEqual(plan['rollback'], {'set_env_vars': ['DB_URL=secretref:old-db'], 'remove_env_vars': ['LABEL']})
        self.assertNotIn('new-db', json.dumps(ENV['summarize_patch'](plan)))
        self.assertEqual(current[0]['secretRef'], 'old-db')

    def test_azure_rejects_ambiguous_values_duplicates_and_bad_names(self):
        for entries in ([{'name': 'KEY', 'value': 'x', 'secretRef': 's'}], [{'name': 'KEY', 'secretRef': None}], [{'name': 'KEY', 'value': 'secretref:s'}], [{'name': 'BAD NAME', 'value': 'x'}], [{'name': 'KEY', 'value': 'x'}] * 2):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                ENV['plan_patch']([], entries)

    def test_azure_no_op_needs_no_rollback(self):
        current = [{'name': 'EMPTY', 'value': ''}]
        self.assertEqual(ENV['plan_patch'](current, current), {'set_env_vars': [], 'rollback': {'set_env_vars': [], 'remove_env_vars': []}})

    def dns(self, address):
        return [(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 443))]

    def test_nonpublic_and_mapped_dns_addresses_rejected(self):
        for address in ('127.0.0.1', '10.1.2.3', '169.254.169.254', '::1', '::ffff:127.0.0.1', 'fe80::1', 'fc00::1', '100.64.0.1', '224.0.0.1'):
            with self.subTest(address=address), patch.object(socket, 'getaddrinfo', return_value=self.dns(address)), self.assertRaises(ValueError):
                IO['resolve_public_https']('https://api.example.com/a', {'api.example.com'})

    def test_mixed_dns_response_is_rejected(self):
        with patch.object(socket, 'getaddrinfo', return_value=self.dns('1.1.1.1') + self.dns('127.0.0.1')), self.assertRaises(ValueError):
            IO['resolve_public_https']('https://api.example.com/a', {'api.example.com'})

    def test_bad_urls_fail_before_dns(self):
        for url in ('http://api.example.com', 'https://evil.example', 'https://user:pass@api.example.com', 'https://api.example.com:444', 'https://api.example.com/#x', 'https://api.example.com/\nabc'):
            with self.subTest(url=url), patch.object(socket, 'getaddrinfo') as dns, self.assertRaises(ValueError):
                IO['resolve_public_https'](url, {'api.example.com'})
            dns.assert_not_called()

    def test_https_pins_ip_and_preserves_tls_hostname(self):
        response = MagicMock(status=200)
        response.read.return_value = b'{"ok":true}'
        connection = MagicMock()
        connection.getresponse.return_value = response
        tls = MagicMock()
        with patch.object(socket, 'getaddrinfo', return_value=self.dns('1.1.1.1')) as dns, patch.object(socket, 'create_connection') as connect, patch.object(IO['ssl'], 'create_default_context', return_value=tls), patch.object(IO['http'].client, 'HTTPSConnection', return_value=connection):
            self.assertEqual(IO['request_public_json']('https://api.example.com/a?b=c', {'api.example.com'}), {'ok': True})
            connect.assert_called_once_with(('1.1.1.1', 443), timeout=10)
            tls.wrap_socket.assert_called_once_with(connect.return_value, server_hostname='api.example.com')
            self.assertEqual(dns.call_count, 1)
            connection.request.assert_called_once_with('GET', '/a?b=c', headers={'Accept': 'application/json'})

    def test_redirect_and_oversized_response_fail(self):
        for status, body in ((302, b''), (200, b'x' * 11)):
            response = MagicMock(status=status)
            response.read.return_value = body
            connection = MagicMock()
            connection.getresponse.return_value = response
            with patch.object(socket, 'getaddrinfo', return_value=self.dns('1.1.1.1')), patch.object(socket, 'create_connection'), patch.object(IO['ssl'], 'create_default_context'), patch.object(IO['http'].client, 'HTTPSConnection', return_value=connection), self.assertRaises(ValueError):
                IO['request_public_json']('https://api.example.com/', {'api.example.com'}, max_bytes=10)
            self.assertEqual(connection.request.call_count, 1)
            connection.close.assert_called_once()

    def test_file_reader_rejects_symlink_traversal_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / 'uploads'
            allowed.mkdir()
            (allowed / 'safe.txt').write_text('synthetic')
            (root / 'outside.txt').write_text('outside sentinel')
            (allowed / 'link.txt').symlink_to(root / 'outside.txt')
            self.assertEqual(IO['read_file_in_directory'](allowed, 'safe.txt'), b'synthetic')
            for name in ('../outside.txt', 'a/b', '..', 'link.txt'):
                with self.subTest(name=name), self.assertRaises((ValueError, OSError)):
                    IO['read_file_in_directory'](allowed, name)
            with self.assertRaises(ValueError):
                IO['read_file_in_directory'](allowed, 'safe.txt', max_bytes=2)

    @unittest.skipUnless(shutil.which('node'), 'Node is required for the shipped JavaScript example')
    def test_node_file_reader_rejects_real_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / 'uploads'
            allowed.mkdir()
            (allowed / 'safe.txt').write_text('synthetic')
            (root / 'outside.txt').write_text('outside sentinel')
            (allowed / 'link.txt').symlink_to(root / 'outside.txt')
            code = "const {safeRead}=require(process.argv[1]); (async()=>{if((await safeRead(process.argv[2],'safe.txt')).toString()!=='synthetic')throw Error('bad read'); for(const name of ['../outside.txt','link.txt']) { let blocked=false; try {await safeRead(process.argv[2],name);}catch{blocked=true;}if(!blocked)throw Error('escape');} })().catch(e=>{console.error(e.message);process.exit(1);});"
            result = subprocess.run(['node', '-e', code, str(SCRIPTS / 'safe_files.cjs'), str(allowed)], capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
