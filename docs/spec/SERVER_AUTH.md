# Server authentication — design note

**Status:** Implemented (decision in issue #94, option 2). Tested with locally generated keys only. **Not verified with Claude.ai or ChatGPT on a host.**
**Scope:** the reference MCP server (`mcp-server/server.py`) over streamable HTTP, for one company. Stdio and the localhost quickstart are unchanged and unauthenticated. Multi-tenant hosting is out of scope.

## 1. What it is, and what it is not

The server is an OAuth 2.0 **resource server only**. It validates bearer tokens (JWTs) that the company's own identity provider issued, and it uses a group claim in the token to choose which rules file answers the call. It never issues tokens, never runs a login page, never registers clients, and never stores a credential. Claude.ai and ChatGPT obtain the token from the company's identity provider, which is the authorization server; this server only checks it.

The MCP SDK supplies the HTTP plumbing: `TokenVerifier`, the bearer middleware, the 401 response with `WWW-Authenticate`, and the protected-resource metadata route (RFC 9728). The SDK does not verify JWTs, so verification uses PyJWT (`jwt.decode`, `PyJWKClient`), which `mcp` already depends on and `requirements-dev.txt` already pins with hashes, together with `cryptography`. No new package is added; PyJWT becomes a direct, named dependency.

## 2. Threat model

| Threat | Answer |
|---|---|
| Anyone on the network reads the company's rules by calling the tools | With auth on, `/mcp` answers only to a valid token. With auth off, the startup guard (§8) refuses to serve a rules file on any non-loopback address unless the operator states that a gateway authenticates. |
| A token issued for a different application at the same identity provider (including an ID token, whose `aud` is a client id) | Audience binding (§3): `aud` must contain the configured audience. |
| A token from a different identity provider, or a look-alike issuer | `iss` must equal the configured issuer exactly; keys come only from that issuer's JWKS. |
| A forged or altered token | Signature checked against the issuer's published keys. Only asymmetric algorithms are accepted; `none` and every HMAC algorithm are refused at configuration time and at verification, so a public key can never be used as an HMAC secret. |
| A replayed old token | `exp` is required and checked with bounded leeway (§5). A token stolen while still valid is accepted until it expires: keep token lifetimes short at the identity provider. |
| A signed-in employee outside the pilot reads a group's rules | The group claim must name exactly one configured group (§7); otherwise no rules are served. |
| An attacker floods the server with unknown key ids to make it hammer the identity provider | `PyJWKClient` caches the key set and forces at most one refetch per cooldown (30 s) for an unknown `kid`. |
| A verification error is mistaken for "no rules configured" and generic defaults are served as if authorized | Fail closed: every verification error is a 401 before any tool runs. The tool-level rules provider also refuses (raises) when no verified, mapped token is on the request, so rules are never read without one. |

Out of scope: the identity provider's own security, token theft from the client, TLS termination (run behind HTTPS; the server speaks plain HTTP to its proxy), denial of service in general, and tenant isolation.

## 3. Audience binding

`CATPILOT_RESOURCE_URL` is the public HTTPS URL of the `/mcp` endpoint, for example `https://guardrails.example.com/mcp`. It is the `resource` advertised in the protected-resource metadata, which is what the MCP authorization spec tells clients to send as the RFC 8707 `resource` parameter.

`CATPILOT_OIDC_AUDIENCE` is the value the token's `aud` must contain. It defaults to the resource URL. Some identity providers put their own identifier in `aud` (Entra ID: `api://<app id>`), so it can be set separately. The verifier checks it itself (`jwt.decode(audience=...)`), so the SDK's `validate_token_resource` is off; the check is not skipped, it is done once, here. Never set the audience to a client id: that would accept ID tokens.

## 4. Issuer, discovery, and key rotation

`CATPILOT_OIDC_ISSUER` is the issuer exactly as the identity provider writes it in `iss` (trailing slash included or not, as the provider does).

At startup, unless `CATPILOT_OIDC_JWKS_URL` is set, the server fetches `<issuer>/.well-known/openid-configuration`, requires its `issuer` to equal the configured issuer (OpenID Connect Discovery §4.3), and takes `jwks_uri` from it. The JWKS URL must be HTTPS. A failed discovery stops the server from starting; it does not start unauthenticated.

Keys are fetched lazily by `PyJWKClient`: the key set is cached for 5 minutes, and a token whose `kid` is not in the cache forces one refetch (no more than once per 30 s). An identity provider that publishes the next key before signing with it (the normal practice) rotates with no restart. A key removed from the JWKS stops verifying within the cache lifetime. A token without a `kid`, or whose `kid` is unknown after the refetch, is refused. A JWKS fetch failure refuses the token (401); it never falls back to accepting it.

## 5. Clock skew

`exp` is required; `nbf` and `iat` are checked when present. Leeway is `CATPILOT_OIDC_LEEWAY` seconds (default 60, at most 300; a larger value is a configuration error). Keep the host clock synchronized.

## 6. Failure responses

Every failure is the SDK's response from `RequireAuthMiddleware`, before any tool runs:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer error="invalid_token", error_description="Authentication required",
                  resource_metadata="https://guardrails.example.com/.well-known/oauth-protected-resource/mcp"
```

The `resource_metadata` URL is the RFC 9728 document the MCP authorization spec tells clients to read; it names the issuer in `authorization_servers`. The body never says which check failed (no oracle); the server logs one line with the reason class (`expired`, `audience`, `issuer`, `signature`, `group`, …) and never the token or its claims.

A valid token whose user is in no configured group, or in two groups that map to different files, also gets a 401 rather than a 403. That keeps one answer for every refusal; the cost is that a client may offer to sign in again, which will not help. Restrict who can obtain a token for this application at the identity provider (app assignment), so non-members never get one.

`required_scopes` (`CATPILOT_OIDC_REQUIRED_SCOPES`) is optional; a token missing one gets the SDK's 403 `insufficient_scope`.

`/health`, `/`, and the protected-resource metadata stay unauthenticated. They carry no rules: `/health` reports `"auth": "oidc"` and `"policy_status": "per-group"`, never a group or a file.

## 7. Group claim to rules file

`CATPILOT_GROUP_RULES_FILE` names a JSON file owned by the policy administrator:

```json
{"pilot-engineering": "/etc/catpilot/rules/engineering.yaml",
 "pilot-finance":     "/etc/catpilot/rules/finance.yaml"}
```

Keys are group values exactly as they appear in the token (names on Okta, object ids on Entra ID); values are absolute paths to overlays. `CATPILOT_OIDC_GROUP_CLAIM` names the claim (default `groups`; a string or a list of strings). The verifier accepts the token only when the claim's values that appear in the map all point at the same file. The tools get their rules through `create_server(policy_provider=...)`: the provider reads the verified token from the HTTP request (`ctx.request_context.request.user`), resolves the file again, and loads it with `policy.load_policy` on every call, so expiry and revocation take effect at once, as with `CATPILOT_OVERLAY_FILE`. `CATPILOT_OVERLAY_FILE` must not be set in auth mode; the server refuses to start if it is, so nobody believes it applies.

## 8. Startup guard

Over streamable HTTP, on an address that is not loopback (`127.0.0.1`, `::1`, `localhost`), with auth off and `CATPILOT_OVERLAY_FILE` set, the server refuses to start unless `--behind-auth-gateway` (or `CATPILOT_BEHIND_AUTH_GATEWAY=1`) says a gateway in front authenticates every request. Generic defaults with no rules file (the public endpoint's case) are not affected. Stdio and localhost are not affected.

## 9. Configuration summary

| Variable / flag | Meaning |
|---|---|
| `--auth oidc` / `CATPILOT_AUTH=oidc` | Turn on the resource-server mode. Streamable HTTP only. |
| `CATPILOT_OIDC_ISSUER` | Required. Exact `iss`. |
| `CATPILOT_RESOURCE_URL` | Required. Public HTTPS URL of `/mcp`. |
| `CATPILOT_OIDC_AUDIENCE` | Optional; defaults to the resource URL. |
| `CATPILOT_OIDC_JWKS_URL` | Optional; skips discovery. HTTPS. |
| `CATPILOT_OIDC_ALGORITHMS` | Optional; default `RS256,ES256`. Asymmetric only. |
| `CATPILOT_OIDC_LEEWAY` | Optional; default 60, at most 300. |
| `CATPILOT_OIDC_GROUP_CLAIM` | Optional; default `groups`. |
| `CATPILOT_GROUP_RULES_FILE` | Required. JSON map of group to overlay path. |
| `CATPILOT_OIDC_REQUIRED_SCOPES` | Optional; comma-separated. |
| `--behind-auth-gateway` / `CATPILOT_BEHIND_AUTH_GATEWAY=1` | Auth off, a gateway authenticates; lifts the startup guard. |

## 10. Not done

- No verification on a host: whether Claude.ai and ChatGPT complete sign-in against a given identity provider (dynamic client registration or a pre-registered client, the scopes they request, whether they send `resource`) has not been tried.
- No token introspection (opaque tokens) and no RFC 9068 `typ: at+jwt` requirement, since not every identity provider sets it.
- No per-user evidence: the evidence line stays content-free and carries no subject or group.
