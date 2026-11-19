"""The opt-in OIDC resource-server mode and the startup guard (docs/spec/SERVER_AUTH.md).

Keys are generated here; nothing touches the network. Every refusal must be a 401 before any tool runs,
and a valid token must get the rules file its group selects.
"""

import base64
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, rsa
    from starlette.testclient import TestClient
    HAVE_DEPS = True
except ImportError:  # pragma: no cover
    HAVE_DEPS = False

ISSUER = "https://idp.example.test/"
RESOURCE = "https://guardrails.example.test/mcp"
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "test", "version": "0"}}}
CALL = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "list_approved", "arguments": {"category": "contacts"}}}


def load_server():
    spec = importlib.util.spec_from_file_location("catpilot_mcp_server_auth", ROOT / "mcp-server" / "server.py")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT / "mcp-server"))
    spec.loader.exec_module(module)
    return module


@unittest.skipUnless(HAVE_DEPS, "PyJWT, cryptography or starlette not installed")
class OIDCAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()
        from catpilot_guardrails_mcp import auth

        cls.auth = auth
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.tmp = tempfile.TemporaryDirectory()
        tmp = Path(cls.tmp.name)
        cls.rules = tmp / "groups.json"
        cls.rules.write_text(json.dumps({"pilot-eng": str(EXAMPLE), "pilot-fin": str(tmp / "finance.yaml")}))
        cls.env = {
            "CATPILOT_OIDC_ISSUER": ISSUER, "CATPILOT_RESOURCE_URL": RESOURCE,
            "CATPILOT_GROUP_RULES_FILE": str(cls.rules), "CATPILOT_TEMPLATE_HOSTS": "intranet.example.org",
        }
        cls.config = auth.load_config(cls.env)
        public = cls.key.public_key()
        cls.verifier = auth.OIDCTokenVerifier(cls.config, lambda token: public)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def token(self, key=None, alg="RS256", **overrides):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": RESOURCE, "sub": "user-1", "azp": "claude", "iat": now, "exp": now + 300, "groups": ["pilot-eng"]}
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, key or self.key, algorithm=alg, headers={"kid": "k1"})

    # -- the verifier ---------------------------------------------------------------------------------

    def test_valid_token(self):
        claims = self.verifier.verify(self.token())
        self.assertEqual(claims["sub"], "user-1")
        self.assertEqual(self.config.rules_file_for(claims), str(EXAMPLE))

    def test_refusals(self):
        now = int(time.time())
        cases = {
            "wrong audience": self.token(aud="https://other.example.test/mcp"),
            "client id as audience (an ID token)": self.token(aud="claude"),
            "wrong issuer": self.token(iss="https://evil.example.test/"),
            "expired beyond leeway": self.token(exp=now - 120, iat=now - 600),
            "bad signature": self.token(key=self.other_key),
            "missing group claim": self.token(groups=None),
            "unknown group": self.token(groups=["everyone"]),
            "groups mapping to two different files": self.token(groups=["pilot-eng", "pilot-fin"]),
            "missing exp": self.token(exp=None),
            "missing sub": self.token(sub=None),
            "not a JWT": "not-a-token",
        }
        for name, token in cases.items():
            with self.subTest(name), self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
                self.assertIsNone(self.verifier.verify(token))

    def test_alg_none_is_refused(self):
        def b64(obj):
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
        now = int(time.time())
        unsigned = f'{b64({"alg": "none", "typ": "JWT", "kid": "k1"})}.{b64({"iss": ISSUER, "aud": RESOURCE, "sub": "u", "exp": now + 300, "groups": ["pilot-eng"]})}.'
        with self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
            self.assertIsNone(self.verifier.verify(unsigned))

    def test_hmac_with_the_public_key_is_refused(self):
        pem = self.key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        now = int(time.time())
        forged = jwt.encode({"iss": ISSUER, "aud": RESOURCE, "sub": "u", "exp": now + 300, "groups": ["pilot-eng"]},
                            base64.b64encode(pem).decode(), algorithm="HS256", headers={"kid": "k1"})
        with self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
            self.assertIsNone(self.verifier.verify(forged))

    def test_key_type_mismatch_is_refused(self):
        es = ec.generate_private_key(ec.SECP256R1())
        with self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
            self.assertIsNone(self.verifier.verify(self.token(key=es, alg="ES256")))

    def test_clock_skew_within_leeway_is_accepted(self):
        now = int(time.time())
        self.assertIsNotNone(self.verifier.verify(self.token(exp=now - 30, iat=now - 600)))

    def test_a_resolver_failure_is_a_refusal(self):
        def broken(token):
            raise jwt.PyJWKClientError("JWKS unreachable")
        verifier = self.auth.OIDCTokenVerifier(self.config, broken)
        with self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
            self.assertIsNone(verifier.verify(self.token()))

    def jwks(self, *keys):
        out = []
        for kid, key in keys:
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
            out.append({**jwk, "kid": kid, "use": "sig"})
        return {"keys": out}

    def test_jwks_fetch_attempts_are_rate_limited_while_the_idp_is_down(self):
        now = [1000.0]
        calls = []
        up = [True]

        def fetch(url):
            calls.append(url)
            if not up[0]:
                raise OSError("JWKS endpoint down")
            return self.jwks(("k1", self.key))

        cache = self.auth.JWKSCache("https://idp.example.test/jwks", fetch, clock=lambda: now[0])
        verifier = self.auth.OIDCTokenVerifier(self.config, cache)
        self.assertIsNotNone(verifier.verify(self.token()))  # first fetch
        self.assertEqual(len(calls), 1)
        up[0] = False
        now[0] += 31
        forged = jwt.encode({"iss": ISSUER, "aud": RESOURCE, "sub": "u", "exp": int(time.time()) + 300},
                            self.other_key, algorithm="RS256", headers={"kid": "attacker-1"})
        with self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
            self.assertIsNone(verifier.verify(forged))  # one failed attempt
            self.assertEqual(len(calls), 2)
            for i in range(20):  # within the cooldown: refused without a network call
                self.assertIsNone(verifier.verify(forged.replace("attacker-1", f"attacker-{i}")))
        self.assertEqual(len(calls), 2)
        self.assertIsNotNone(verifier.verify(self.token()))  # the known kid still verifies, off the network
        self.assertEqual(len(calls), 2)
        now[0] += 400  # cache expired and the IdP still down: one attempt, then the stale known key
        self.assertIsNotNone(verifier.verify(self.token()))
        self.assertEqual(len(calls), 3)
        self.assertIsNotNone(verifier.verify(self.token()))
        self.assertEqual(len(calls), 3)

    def test_jwks_rotation_picks_up_a_new_key(self):
        now = [1000.0]
        published = [("k1", self.key)]
        cache = self.auth.JWKSCache("https://idp.example.test/jwks", lambda url: self.jwks(*published), clock=lambda: now[0])
        verifier = self.auth.OIDCTokenVerifier(self.config, cache)
        self.assertIsNotNone(verifier.verify(self.token()))
        published.append(("k2", self.other_key))
        rotated = jwt.encode({"iss": ISSUER, "aud": RESOURCE, "sub": "u", "exp": int(time.time()) + 300, "groups": ["pilot-eng"]},
                             self.other_key, algorithm="RS256", headers={"kid": "k2"})
        now[0] += 31
        self.assertIsNotNone(verifier.verify(rotated))

    # -- configuration --------------------------------------------------------------------------------

    def test_unsafe_configuration_is_refused(self):
        bad = {
            "alg none": {"CATPILOT_OIDC_ALGORITHMS": "none"},
            "hmac": {"CATPILOT_OIDC_ALGORITHMS": "RS256,HS256"},
            "leeway too large": {"CATPILOT_OIDC_LEEWAY": "3600"},
            "http resource": {"CATPILOT_RESOURCE_URL": "http://guardrails.example.test/mcp"},
            "http jwks": {"CATPILOT_OIDC_JWKS_URL": "http://idp.example.test/jwks"},
            "no issuer": {"CATPILOT_OIDC_ISSUER": ""},
            "overlay file also set": {"CATPILOT_OVERLAY_FILE": str(EXAMPLE)},
            "no group map": {"CATPILOT_GROUP_RULES_FILE": ""},
        }
        for name, change in bad.items():
            with self.subTest(name), self.assertRaises(self.auth.AuthConfigError):
                self.auth.load_config({**self.env, **change})

    def test_relative_rules_path_is_refused(self):
        rel = Path(self.tmp.name) / "rel.json"
        rel.write_text(json.dumps({"g": "rules.yaml"}))
        with self.assertRaises(self.auth.AuthConfigError):
            self.auth.load_config({**self.env, "CATPILOT_GROUP_RULES_FILE": str(rel)})

    def test_discovery_checks_the_issuer(self):
        good = {"issuer": ISSUER, "jwks_uri": "https://idp.example.test/jwks"}
        self.assertEqual(self.auth.discover_jwks_url(ISSUER, lambda url: good), "https://idp.example.test/jwks")
        for doc in ({**good, "issuer": "https://evil.example.test/"}, {**good, "jwks_uri": "http://idp.example.test/jwks"}, {"issuer": ISSUER}):
            with self.subTest(doc), self.assertRaises(self.auth.AuthConfigError):
                self.auth.discover_jwks_url(ISSUER, lambda url: doc)

    # -- over HTTP ------------------------------------------------------------------------------------

    def app(self):
        public = self.key.public_key()
        mcp = self.server.build_oidc_server(self.fail, env=self.env, key_resolver=lambda token: public)
        return self.server.build_http_app(host="0.0.0.0", stateless=True, allowed_hosts=["testserver"], mcp_server=mcp)

    def test_http_refusals_are_401_with_resource_metadata(self):
        with TestClient(self.app()) as client, self.assertLogs("catpilot_guardrails_mcp.auth", "WARNING"):
            for name, headers in {
                "no token": HEADERS,
                "expired": {**HEADERS, "Authorization": "Bearer " + self.token(exp=int(time.time()) - 600)},
                "unknown group": {**HEADERS, "Authorization": "Bearer " + self.token(groups=["everyone"])},
            }.items():
                with self.subTest(name):
                    resp = client.post("/mcp", headers=headers, json=CALL)
                    self.assertEqual(resp.status_code, 401)
                    www = resp.headers["www-authenticate"]
                    self.assertTrue(www.startswith("Bearer "))
                    self.assertIn('resource_metadata="https://guardrails.example.test/.well-known/oauth-protected-resource/mcp"', www)
                    self.assertNotIn("result", resp.text)

    def test_http_valid_token_gets_its_groups_rules(self):
        headers = {**HEADERS, "Authorization": "Bearer " + self.token()}
        with TestClient(self.app()) as client:
            self.assertEqual(client.post("/mcp", headers=headers, json=INITIALIZE).status_code, 200)
            resp = client.post("/mcp", headers=headers, json=CALL)
            self.assertEqual(resp.status_code, 200, resp.text)
            result = resp.json()["result"]["structuredContent"]
            self.assertFalse(result["unknown_policy"])

    def test_protected_resource_metadata_and_health(self):
        with TestClient(self.app()) as client:
            meta = client.get("/.well-known/oauth-protected-resource/mcp").json()
            self.assertEqual(meta["resource"], RESOURCE)
            self.assertEqual(meta["authorization_servers"], [ISSUER])
            health = client.get("/health").json()
            self.assertEqual(health["auth"], "oidc")
            self.assertEqual(health["policy_status"], "per-group")

    def test_the_policy_provider_refuses_without_a_verified_token(self):
        provider = self.auth.group_policy_provider(self.config)
        ctx = mock.Mock()
        ctx.request_context.request.scope = {}
        with self.assertRaises(PermissionError):
            provider(ctx)
        ctx.request_context = None
        with self.assertRaises(PermissionError):
            provider(ctx)


@unittest.skipUnless(HAVE_DEPS, "starlette not installed")
class StartupGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = load_server()

    def run_main(self, argv, env):
        clean = {k: v for k, v in os.environ.items() if not k.startswith("CATPILOT_")}
        with mock.patch.dict(os.environ, {**clean, **env}, clear=True), mock.patch("uvicorn.run") as run, \
                mock.patch("sys.stderr"):
            try:
                self.server.main(argv)
            except SystemExit as exc:
                return exc.code, run.called
            return 0, run.called

    HTTP = ["--transport", "streamable-http", "--allowed-host", "guardrails.example.test"]

    def test_rules_file_on_a_public_bind_without_auth_is_refused(self):
        code, served = self.run_main(self.HTTP + ["--host", "0.0.0.0"], {"CATPILOT_OVERLAY_FILE": str(EXAMPLE)})
        self.assertEqual(code, 2)
        self.assertFalse(served)

    def test_the_gateway_flag_lifts_the_guard(self):
        for argv, env in (
            (self.HTTP + ["--host", "0.0.0.0", "--behind-auth-gateway"], {"CATPILOT_OVERLAY_FILE": str(EXAMPLE)}),
            (self.HTTP + ["--host", "0.0.0.0"], {"CATPILOT_OVERLAY_FILE": str(EXAMPLE), "CATPILOT_BEHIND_AUTH_GATEWAY": "1"}),
        ):
            with self.subTest(argv=argv, env=env):
                self.assertEqual(self.run_main(argv, env), (0, True))

    def test_localhost_and_generic_defaults_are_unaffected(self):
        self.assertEqual(self.run_main(self.HTTP + ["--host", "127.0.0.1"], {"CATPILOT_OVERLAY_FILE": str(EXAMPLE)}), (0, True))
        self.assertEqual(self.run_main(self.HTTP + ["--host", "::1"], {"CATPILOT_OVERLAY_FILE": str(EXAMPLE)}), (0, True))
        self.assertEqual(self.run_main(self.HTTP + ["--host", "0.0.0.0"], {}), (0, True))

    def test_auth_on_stdio_is_refused(self):
        code, served = self.run_main(["--auth", "oidc"], {})
        self.assertEqual(code, 2)

    def test_incomplete_auth_config_does_not_start(self):
        code, served = self.run_main(self.HTTP + ["--host", "0.0.0.0", "--auth", "oidc"], {"CATPILOT_OIDC_ISSUER": ISSUER})
        self.assertEqual(code, 2)
        self.assertFalse(served)


if __name__ == "__main__":
    unittest.main()
