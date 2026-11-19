#!/usr/bin/env python3
"""Catpilot guardrails reference MCP server.

Read-only guidance lookups for safe AI-assisted building: the eight
checkpoints of `catpilot-safe-building`, plus a company's approved values
when an overlay is configured. Four tools, deterministic, no model calls,
no network, no logging unless CATPILOT_EVIDENCE_LOG names a local file or
CATPILOT_EVIDENCE_SYSLOG is set (then one content-free line per call).

Run from a checkout of catpilotai/catpilot-ai-guardrails:

    python mcp-server/server.py                          # stdio (Claude Code, Codex, Cursor)
    python mcp-server/server.py --transport streamable-http --host 127.0.0.1 --port 8765

Configuration is environment only, never tool arguments:

    CATPILOT_OVERLAY_FILE   absolute path to a validated overlay.yaml (optional)
    CATPILOT_TEMPLATE_HOSTS comma-separated hosts allowed in overlay templates (optional)

What this is: advice a host can ask for at the moment it matters. What it
is not: tenant isolation, monitoring, or enforcement. Bind it to localhost,
or expose it only with `--auth oidc` (it then checks tokens from your own
identity provider and a group claim picks the rules file; see
docs/spec/SERVER_AUTH.md) or behind a gateway that authenticates
(`--behind-auth-gateway`). It refuses to serve a rules file on a
non-loopback address with neither. An
answer with `unknown_policy: true` means no current approved company values
were available; generic defaults are never the company's policy.

A host that serves several organizations can build the same four tools with
`create_server(policy_provider=..., evidence=...)`: the provider picks the
overlay for each request (the tool's `ctx.request_context.request` is the HTTP
request), and the tools, their descriptions, and their answers stay the same.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parent))
# The repository root, for catpilot_guard's shared evidence writer. Appended, so it shadows nothing installed.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(REPO_ROOT))

from catpilot_guardrails_mcp import content, policy, tools  # noqa: E402
from catpilot_guardrails_mcp.content import CATEGORIES, TEMPLATE_KINDS, TOPICS  # noqa: E402
from mcp.server import MCPServer  # noqa: E402
from mcp.server.mcpserver import Context  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

GUIDANCE = content.load_guidance()
TEMPLATES = content.load_templates()

INSTRUCTIONS = (
    "Read-only guidance lookups for safe AI-assisted building. Advisory: nothing here blocks an action. "
    "When an answer carries unknown_policy: true, no current approved company values were available; "
    "say so to the person and do not present generic defaults as their company's policy. "
    "Call check_plan before you ask the person about a plan, with what you already know: a field left out comes "
    "back as an open question, so a missing answer is not a reason to wait. "
    "When check_plan says ask_a_human, or whenever you suggest checking with someone, tell the person to contact "
    "who_to_ask, by the name or address it gives, and offer to draft the message."
)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)

# The rules for one tool call: given the call's context, the policy state to answer with.
PolicyProvider = Callable[[Context], policy.PolicyState]
# Where one tool call's evidence goes: the tool, its result, the content-free fields (the enumerated
# argument, check_plan's outcome and field names, and `policy_sha256`), and the context.
EvidenceSink = Callable[[str, dict[str, Any], dict[str, Any], Context], None]


# Optional evidence log, written by catpilot_guard/evidence.py (schema in docs/spec/EVIDENCE.md). When
# CATPILOT_EVIDENCE_LOG names a file, every tool call appends one `lookup` line: the time, the release,
# the tool, the enumerated argument (topic, category, kind), the SHA-256 of the overlay whenever one was
# read, and for check_plan the outcome, whether it asked for a human, and the names of the fields the
# caller supplied. When CATPILOT_EVIDENCE_SYSLOG is set, the same content-free JSON line is sent to
# syslog. Never the description, the data classes, a value from the overlay, or any other free text.
# Off unless set; the public endpoint does not set it. A logging failure never changes an answer.
SHA256 = re.compile(r"[0-9a-f]{64}")


def _evidence(tool: str, result: dict[str, Any], fields: dict[str, Any], ctx: Context | None = None) -> None:
    try:
        # Imported here: a missing or broken writer is a logging failure, not a failed answer.
        from catpilot_guard import evidence

        line: dict[str, Any] = {
            "release": GUIDANCE["release"],
            "tool": tool,
            "error": result.get("error"),
            "policy_status": result.get("policy_status"),
            "unknown_policy": result.get("unknown_policy"),
        }
        line.update({k: v for k, v in fields.items() if v is not None})
        evidence.record("lookup", evidence.SERVER_SOURCE, line)
    except Exception:
        pass


def _policy_sha256(state: object) -> str | None:
    """The SHA-256 of the overlay file behind a call, whenever one was read and parsed; None otherwise."""
    source = getattr(state, "source", None)
    digest = source.get("sha256") if isinstance(source, dict) else None
    return digest if isinstance(digest, str) and SHA256.fullmatch(digest) else None


def _enumerated(value: str, allowed) -> str:
    return value if value in allowed else "invalid"


def _policy(ctx: Context | None = None) -> policy.PolicyState:
    """The reference server's rules: the overlay named by CATPILOT_OVERLAY_FILE, read on every call."""
    hosts = {h.strip() for h in os.environ.get("CATPILOT_TEMPLATE_HOSTS", "").split(",") if h.strip()}
    return policy.load_policy(os.environ.get("CATPILOT_OVERLAY_FILE"), hosts)


def create_server(
    *,
    policy_provider: PolicyProvider | None = None,
    evidence: EvidenceSink | None = None,
    instructions: str | None = None,
    auth: Any = None,
    token_verifier: Any = None,
) -> MCPServer:
    """The four tools on a new server.

    With no arguments this is the reference server: the overlay from CATPILOT_OVERLAY_FILE and the
    optional evidence file. A host serving several organizations passes `policy_provider`, which
    picks the overlay for each call from its context, and its own `evidence` sink. `instructions`
    replaces the server instructions; a host that adds to them should start from `INSTRUCTIONS`.
    `auth` (the SDK's `AuthSettings`) and `token_verifier` turn on bearer-token checking over HTTP; see
    `catpilot_guardrails_mcp.auth` and docs/spec/SERVER_AUTH.md.
    """
    rules = policy_provider or _policy
    record = evidence or _evidence
    server = MCPServer("catpilot-guardrails", version=GUIDANCE["release"], instructions=instructions or INSTRUCTIONS, auth=auth, token_verifier=token_verifier)

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def get_guidance(topic: str, ctx: Context) -> dict[str, Any]:
        """Guidance for one checkpoint while a person builds with an AI assistant.

        topic: data-in-prompts | access | hosting | sharing | credentials | third-party | untrusted-input | review.
        Returns what to ask, how to name the risk, the safe alternative, when to stop and ask a human,
        and the relevant company values when a current approved overlay is configured.
        """
        state = rules(ctx)
        result = tools.get_guidance(topic, GUIDANCE, state)
        record("get_guidance", result, {"topic": _enumerated(topic, TOPICS), "policy_sha256": _policy_sha256(state)}, ctx)
        return result

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def check_plan(
        ctx: Context,
        description: str,
        data_classes: list[str] | None = None,
        data_provenance: str | None = None,
        audience: str | None = None,
        hosting: str | None = None,
        services: list[str] | None = None,
        write_access: bool | None = None,
        data_types: list[str] | None = None,
        credential_references: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Deterministic check of a building plan against the eight checkpoints and, when configured, the company overlay.

        Call it before you ask the person about the plan, with what you already know: a field left out comes
        back as an open question in `checklist`, so a missing answer is not a reason to wait.

        The fields decide; the description is only read for hints, because free text names a risk as often to
        rule it out ("no external users", "synthetic records only") as to choose it. Pass every field you know:

        - description: what is being built, in plain words. Required.
        - data_classes: what data the app will touch, one item per class, in the person's own words
          ("customer names and emails", "synthetic patient records", "an API key"). `data_types` is the old
          name for this field and is merged into it.
        - data_provenance: where the data_classes items actually come from, when you know it for certain:
          "synthetic" (made up, shaped like the real thing), "real", "mixed", or "unknown". Overrides the
          words in data_classes for every item, so "sample" or "synthetic" in the text no longer makes an
          item that is actually real data read as safe. "unknown" is treated as "real". Leave unset to let
          the words in each item decide, with "not synthetic", "real", and similar cues read correctly.
        - audience: who can open it ("our ops team", "customers", "anyone with the link").
        - hosting: where it will run ("Internal App Platform", "my personal Replit account", "not
          deployed; runs locally on my laptop"). A value that says it is never deployed, hosted, or
          published anywhere is permitted on its own; naming a machine other people rely on ("my
          laptop", "workstation") alongside an audience beyond the builder is a review question.
        - services: software services it will connect to, one per item ("the approved transactional email
          service", "a new enrichment API"). Use [] or ["none"] when it connects to no external
          services; names such as "NoneCloud" are still service names.
        - credential_references: identifier-only environment-variable metadata, one object per reference,
          for example {"name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": false,
          "value_in_generated_artifacts": false}. The name must be an uppercase environment-variable
          identifier. This form accepts no secret value. Both boolean flags are required: true is
          prohibited, while a local runtime environment lookup alone is neither model context nor a
          generated artifact. Describe actual secret material as a data_classes item so the
          conservative credential checks apply.
        - write_access: true if it writes to a system of record (CRM, ERP, HR, finance, tickets, the
          production database), false if it only reads or writes to its own store.

        Returns `outcome` (permitted, requires_review, prohibited, or unknown, the worst across the fields),
        `decisions` (one per field, each with the rule that decided it and whether that rule came from the
        company overlay or a generic default), `hints` from the description that are questions rather than
        findings, risks ranked by severity with a safer alternative each, one next step (it names who to
        check with first when a human has to look and nothing is prohibited), whether to ask a human, who to
        ask, `escalation_draft` (pre-filled subject, body, and optional mailto_url / intake_url when
        `ask_a_human` is true), and a checklist. When `ask_a_human` is true, name `who_to_ask` to the person as
        given (the company's contact when it publishes one; with topic contacts, the contact for the one field
        that decided the outcome, named in `contact_topic`, else the owner) and offer to draft the message. Advisory: a
        missing field returns `unknown`, not a pass, and no outcome here approves or blocks anything.
        """
        state = rules(ctx)
        result = tools.check_plan(
            description, GUIDANCE, state, data_classes, data_provenance, audience, hosting,
            services, write_access, data_types, credential_references,
        )
        supplied = {
            "data_classes": data_classes, "data_provenance": data_provenance, "audience": audience, "hosting": hosting,
            "services": services, "write_access": write_access, "data_types": data_types, "credential_references": credential_references,
        }
        record("check_plan", result, {
            "outcome": result.get("outcome"), "ask_a_human": result.get("ask_a_human"),
            "fields": sorted(name for name, value in supplied.items() if value is not None),
            "policy_sha256": _policy_sha256(state),
        }, ctx)
        return result

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def get_template(kind: str, ctx: Context) -> dict[str, Any]:
        """A safe starting point for a common kind of app.

        kind: internal-lookup-tool | form-to-spreadsheet | dashboard | document-summarizer | chatbot-over-docs.
        Returns a generic starting point and constraints, and the company's approved starting point as a
        reference when its overlay names one. Never downloads or executes anything.
        """
        state = rules(ctx)
        result = tools.get_template(kind, TEMPLATES, GUIDANCE, state)
        record("get_template", result, {"kind": _enumerated(kind, TEMPLATE_KINDS), "policy_sha256": _policy_sha256(state)}, ctx)
        return result

    @server.tool(annotations=READ_ONLY, structured_output=True)
    def list_approved(category: str, ctx: Context) -> dict[str, Any]:
        """What the company has approved, or generic defaults labeled as such.

        category: hosting | services | data-classes | contacts. With a current approved overlay, unknown_policy is
        false and the items are the company's; contacts gives the owner and, when the company names them, who to
        ask about data, hosting, services and identity. Otherwise unknown_policy is true and the items are generic
        defaults that must not be presented as the company's policy.
        """
        state = rules(ctx)
        result = tools.list_approved(category, GUIDANCE, state)
        record("list_approved", result, {"category": _enumerated(category, CATEGORIES), "policy_sha256": _policy_sha256(state)}, ctx)
        return result

    return server


server = create_server()


DATA_STATEMENT = (
    "This endpoint answers read-only guidance lookups. It receives the topic, plan description, template kind, or "
    "category a client sends, answers from generic defaults, stores nothing, logs no request content, and calls "
    "nothing else. Do not send confidential plans to a public endpoint; run the server yourself behind your own "
    "gateway instead (github.com/catpilotai/catpilot-ai-guardrails, mcp-server/)."
)


def build_http_app(*, host: str = "127.0.0.1", stateless: bool = False, allowed_hosts: list[str] | None = None, dns_rebinding_protection: bool = True, mcp_server: MCPServer | None = None):
    """The Starlette app: /mcp (streamable HTTP), /health, and / (a plain data statement).

    `mcp_server` defaults to this module's reference server; pass one from `create_server` to serve it instead.
    """
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    security = None
    if allowed_hosts:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=list(allowed_hosts), allowed_origins=[f"https://{h.split(':')[0]}" for h in allowed_hosts])
    elif not dns_rebinding_protection:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    mcp_server = mcp_server or server
    auth_on = mcp_server.settings.auth is not None
    app = mcp_server.streamable_http_app(streamable_http_path="/mcp", json_response=stateless, stateless_http=stateless, transport_security=security, host=host)

    async def health(request):
        # With auth on, the rules depend on the caller's group; the unauthenticated health check names none.
        status = "per-group" if auth_on else _policy().status
        return JSONResponse({"status": "ok", "server": "catpilot-guardrails", "release": GUIDANCE["release"], "policy_status": status, "auth": "oidc" if auth_on else "none", "stateless": stateless})

    async def root(request):
        return JSONResponse({"server": "catpilot-guardrails", "release": GUIDANCE["release"], "mcp_endpoint": "/mcp", "health": "/health", "tools": ["get_guidance", "check_plan", "get_template", "list_approved"], "data_statement": DATA_STATEMENT})

    app.router.routes.insert(0, Route("/health", health, methods=["GET"]))
    app.router.routes.insert(0, Route("/", root, methods=["GET"]))
    app.add_middleware(_NoStore)
    return app


class _NoStore:
    """Mark every response uncacheable at the origin, so a CDN in front cannot serve stale guidance."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        from starlette.datastructures import MutableHeaders

        async def send_no_store(message):
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_no_store)


def build_oidc_server(fail: Callable[[str], Any], env: dict[str, str] | None = None, key_resolver: Any = None) -> MCPServer:
    """The four tools behind OIDC bearer-token checking, configured from the environment; `fail` on any config error."""
    from catpilot_guardrails_mcp import auth

    try:
        config = auth.load_config(env)
        if key_resolver is None:
            key_resolver = auth.jwks_key_resolver(config.jwks_url or auth.discover_jwks_url(config.issuer))
    except auth.AuthConfigError as exc:
        fail(f"auth configuration: {exc}")
        raise
    except Exception as exc:  # discovery failed: never start unauthenticated
        fail(f"auth configuration: OIDC discovery failed ({exc.__class__.__name__})")
        raise
    return create_server(
        policy_provider=auth.group_policy_provider(config),
        auth=auth.auth_settings(config),
        token_verifier=auth.OIDCTokenVerifier(config, key_resolver),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1", help="streamable-http bind address; keep it local unless a gateway fronts it")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--stateless", action="store_true", help="streamable-http without sessions, JSON responses; required behind a load balancer with several replicas")
    parser.add_argument("--allowed-host", action="append", default=None, help="Host header values to accept (repeatable); also CATPILOT_MCP_ALLOWED_HOSTS, comma-separated. Required when binding beyond localhost.")
    parser.add_argument("--no-dns-rebinding-protection", action="store_true", help="accept any Host header; only behind a gateway that already validates hosts")
    parser.add_argument("--auth", choices=["none", "oidc"], default=os.environ.get("CATPILOT_AUTH") or "none", help="oidc: check bearer tokens from your identity provider and pick the rules file by group claim (docs/spec/SERVER_AUTH.md); also CATPILOT_AUTH")
    parser.add_argument("--behind-auth-gateway", action="store_true", default=os.environ.get("CATPILOT_BEHIND_AUTH_GATEWAY") == "1", help="auth off because a gateway in front authenticates every request; lets a rules file be served beyond localhost; also CATPILOT_BEHIND_AUTH_GATEWAY=1")
    args = parser.parse_args(argv)
    if args.auth not in ("none", "oidc"):
        parser.error("--auth (CATPILOT_AUTH) must be none or oidc")
    if args.transport == "stdio":
        if args.auth != "none":
            parser.error("--auth applies to streamable-http only; stdio has no network caller to authenticate")
        server.run(transport="stdio")
        return 0
    from catpilot_guardrails_mcp.auth import is_loopback

    allowed = args.allowed_host or [h.strip() for h in os.environ.get("CATPILOT_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if not is_loopback(args.host) and not allowed and not args.no_dns_rebinding_protection:
        parser.error("binding beyond localhost requires --allowed-host (or CATPILOT_MCP_ALLOWED_HOSTS), or --no-dns-rebinding-protection behind a gateway that validates hosts")
    # The startup guard (SERVER_AUTH.md §8): company rules never go to an unauthenticated network caller.
    if args.auth == "none" and not is_loopback(args.host) and os.environ.get("CATPILOT_OVERLAY_FILE") and not args.behind_auth_gateway:
        parser.error("refusing to serve CATPILOT_OVERLAY_FILE on a non-loopback address without authentication: use --auth oidc, or --behind-auth-gateway when a gateway in front authenticates every request")
    mcp_server = None
    if args.auth == "oidc":
        mcp_server = build_oidc_server(parser.error)
    import uvicorn

    app = build_http_app(host=args.host, stateless=args.stateless, allowed_hosts=allowed, dns_rebinding_protection=not args.no_dns_rebinding_protection, mcp_server=mcp_server)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
