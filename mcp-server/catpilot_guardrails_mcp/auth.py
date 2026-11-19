"""Opt-in OIDC resource-server mode for the reference server (docs/spec/SERVER_AUTH.md).

The server only checks tokens the company's identity provider issued; it never issues one. The MCP SDK
supplies the bearer middleware, the 401 with WWW-Authenticate, and the protected-resource metadata route;
this module supplies the JWT verification (PyJWT) and the group claim to rules file mapping. Every
failure returns None, which the SDK turns into a 401 before any tool runs.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

import jwt

from . import policy

log = logging.getLogger("catpilot_guardrails_mcp.auth")

DEFAULT_ALGORITHMS = ("RS256", "ES256")
# Asymmetric only: `none` and HMAC would let a published key, or nothing at all, sign a token.
ALLOWED_ALGORITHMS = frozenset({"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA"})
MAX_LEEWAY = 300
LOOPBACK_NAMES = ("localhost",)


class AuthConfigError(ValueError):
    """The auth configuration is incomplete or unsafe; the server must not start."""


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


@dataclass(frozen=True)
class OIDCConfig:
    issuer: str
    resource_url: str
    group_rules: Mapping[str, str]
    audience: str = ""
    jwks_url: str | None = None
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    leeway: int = 60
    group_claim: str = "groups"
    required_scopes: tuple[str, ...] = ()
    template_hosts: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.issuer:
            raise AuthConfigError("CATPILOT_OIDC_ISSUER is required in auth mode")
        if not self.resource_url.startswith("https://"):
            raise AuthConfigError("CATPILOT_RESOURCE_URL must be the public https:// URL of /mcp")
        if not self.audience:
            object.__setattr__(self, "audience", self.resource_url)
        if self.jwks_url is not None and not self.jwks_url.startswith("https://"):
            raise AuthConfigError("the JWKS URL must be https://")
        bad = [a for a in self.algorithms if a not in ALLOWED_ALGORITHMS]
        if bad or not self.algorithms:
            raise AuthConfigError(f"unsupported or unsafe algorithms {bad}; asymmetric algorithms only")
        if not 0 <= self.leeway <= MAX_LEEWAY:
            raise AuthConfigError(f"CATPILOT_OIDC_LEEWAY must be between 0 and {MAX_LEEWAY} seconds")
        if not self.group_rules:
            raise AuthConfigError("CATPILOT_GROUP_RULES_FILE must map at least one group to a rules file")
        for group, path in self.group_rules.items():
            if not isinstance(group, str) or not group or not isinstance(path, str) or not Path(path).is_absolute():
                raise AuthConfigError("CATPILOT_GROUP_RULES_FILE must map group names to absolute paths")

    def rules_file_for(self, claims: Mapping[str, Any]) -> str | None:
        """The one rules file the token's group claim selects; None if it names none, or two different ones."""
        value = claims.get(self.group_claim)
        groups = [value] if isinstance(value, str) else value
        if not isinstance(groups, list):
            return None
        files = {self.group_rules[g] for g in groups if isinstance(g, str) and g in self.group_rules}
        return files.pop() if len(files) == 1 else None


def load_config(env: Mapping[str, str] | None = None) -> OIDCConfig:
    env = os.environ if env is None else env
    if env.get("CATPILOT_OVERLAY_FILE"):
        raise AuthConfigError("CATPILOT_OVERLAY_FILE does not apply in auth mode; the group map chooses the rules file")
    rules_path = env.get("CATPILOT_GROUP_RULES_FILE", "")
    if not rules_path:
        raise AuthConfigError("CATPILOT_GROUP_RULES_FILE is required in auth mode")
    try:
        group_rules = json.loads(Path(rules_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise AuthConfigError(f"cannot read CATPILOT_GROUP_RULES_FILE: {exc.__class__.__name__}") from None
    if not isinstance(group_rules, dict):
        raise AuthConfigError("CATPILOT_GROUP_RULES_FILE must be a JSON object")

    def csv(name: str, default: tuple[str, ...] = ()) -> tuple[str, ...]:
        items = tuple(s.strip() for s in env.get(name, "").split(",") if s.strip())
        return items or default

    try:
        leeway = int(env.get("CATPILOT_OIDC_LEEWAY", "60"))
    except ValueError:
        raise AuthConfigError("CATPILOT_OIDC_LEEWAY must be an integer") from None
    return OIDCConfig(
        issuer=env.get("CATPILOT_OIDC_ISSUER", ""),
        resource_url=env.get("CATPILOT_RESOURCE_URL", ""),
        audience=env.get("CATPILOT_OIDC_AUDIENCE", ""),
        jwks_url=env.get("CATPILOT_OIDC_JWKS_URL") or None,
        algorithms=csv("CATPILOT_OIDC_ALGORITHMS", DEFAULT_ALGORITHMS),
        leeway=leeway,
        group_claim=env.get("CATPILOT_OIDC_GROUP_CLAIM", "groups") or "groups",
        required_scopes=csv("CATPILOT_OIDC_REQUIRED_SCOPES"),
        group_rules=group_rules,
        template_hosts=frozenset(csv("CATPILOT_TEMPLATE_HOSTS")),
    )


def discover_jwks_url(issuer: str, fetch: Callable[[str], dict[str, Any]] | None = None) -> str:
    """OpenID Connect Discovery: the issuer's jwks_uri, after checking the document names the same issuer."""
    url = issuer.rstrip("/") + "/.well-known/openid-configuration"
    document = (fetch or _fetch_json)(url)
    if document.get("issuer") != issuer:
        raise AuthConfigError("the discovery document's issuer does not match CATPILOT_OIDC_ISSUER")
    jwks = document.get("jwks_uri")
    if not isinstance(jwks, str) or not jwks.startswith("https://"):
        raise AuthConfigError("the discovery document has no https:// jwks_uri")
    return jwks


def _fetch_json(url: str) -> dict[str, Any]:
    if not url.startswith("https://"):
        raise AuthConfigError("discovery must use https://")
    with urllib.request.urlopen(url, timeout=10) as resp:  # noqa: S310 - https only, checked above
        data = json.load(resp)
    if not isinstance(data, dict):
        raise AuthConfigError("the discovery document is not a JSON object")
    return data


# Given the raw token, the key that should have signed it (raises when there is none).
KeyResolver = Callable[[str], Any]


def jwks_key_resolver(jwks_url: str) -> KeyResolver:
    """Keys from the issuer's JWKS: cached 5 minutes; an unknown `kid` forces one refetch per 30 s cooldown."""
    client = jwt.PyJWKClient(jwks_url, cache_jwk_set=True, lifespan=300, timeout=10, cooldown_duration=30)

    def resolve(token: str) -> Any:
        if not jwt.get_unverified_header(token).get("kid"):
            raise jwt.InvalidTokenError("token has no kid")
        return client.get_signing_key_from_jwt(token).key

    return resolve


class OIDCTokenVerifier:
    """An MCP SDK `TokenVerifier`: a JWT from the configured issuer, for the configured audience, in one mapped group."""

    def __init__(self, config: OIDCConfig, key_resolver: KeyResolver):
        self.config = config
        self.key_resolver = key_resolver

    def verify(self, token: str) -> dict[str, Any] | None:
        """The verified claims, or None. Synchronous; the JWKS fetch may block."""
        cfg = self.config
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") not in cfg.algorithms:
                raise jwt.InvalidAlgorithmError("algorithm not allowed")
            claims = jwt.decode(
                token,
                self.key_resolver(token),
                algorithms=list(cfg.algorithms),
                audience=cfg.audience,
                issuer=cfg.issuer,
                leeway=cfg.leeway,
                options={"require": ["exp", "iss", "aud", "sub"], "verify_signature": True},
            )
        except jwt.ExpiredSignatureError:
            return self._refuse("expired")
        except jwt.InvalidAudienceError:
            return self._refuse("audience")
        except jwt.InvalidIssuerError:
            return self._refuse("issuer")
        except jwt.InvalidAlgorithmError:
            return self._refuse("algorithm")
        except jwt.InvalidSignatureError:
            return self._refuse("signature")
        except jwt.PyJWKClientError:
            return self._refuse("keys")
        except Exception:  # fail closed on anything else: malformed token, missing claim, key type mismatch
            return self._refuse("invalid")
        if cfg.rules_file_for(claims) is None:
            return self._refuse("group")
        return claims

    async def verify_token(self, token: str):
        import anyio
        from mcp.server.auth.provider import AccessToken

        claims = await anyio.to_thread.run_sync(self.verify, token)
        if claims is None:
            return None
        scope = claims.get("scope", claims.get("scp", ""))
        scopes = scope.split() if isinstance(scope, str) else [s for s in scope if isinstance(s, str)] if isinstance(scope, list) else []
        client_id = claims.get("azp") or claims.get("client_id") or claims.get("appid") or claims["sub"]
        return AccessToken(
            token=token, client_id=str(client_id), scopes=scopes, expires_at=int(claims["exp"]),
            resource=self.config.resource_url, subject=str(claims["sub"]), claims=claims,
        )

    @staticmethod
    def _refuse(reason: str) -> None:
        log.warning("bearer token refused: %s", reason)
        return None


def group_policy_provider(config: OIDCConfig) -> Callable[[Any], policy.PolicyState]:
    """A `create_server(policy_provider=...)` that reads the rules file the verified token's group selects.

    Raises when the request carries no verified token or no mapped group, so rules are never read without one.
    """

    def provide(ctx: Any) -> policy.PolicyState:
        request = getattr(getattr(ctx, "request_context", None), "request", None)
        user = request.scope.get("user") if request is not None else None
        token = getattr(user, "access_token", None)
        claims = getattr(token, "claims", None)
        path = config.rules_file_for(claims) if isinstance(claims, dict) else None
        if path is None:
            raise PermissionError("no verified token with a configured group on this request")
        return policy.load_policy(path, set(config.template_hosts))

    return provide


def auth_settings(config: OIDCConfig):
    from mcp.server.auth.settings import AuthSettings

    return AuthSettings(
        issuer_url=config.issuer,
        resource_server_url=config.resource_url,
        required_scopes=list(config.required_scopes) or None,
        # The verifier checks `aud` itself, against CATPILOT_OIDC_AUDIENCE (SERVER_AUTH.md §3).
        validate_token_resource=False,
    )
