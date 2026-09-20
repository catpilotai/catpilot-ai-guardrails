#!/usr/bin/env python3
"""Catpilot guardrails reference MCP server.

Read-only guidance lookups for safe AI-assisted building: the eight
checkpoints of `catpilot-safe-building`, plus a company's approved values
when an overlay is configured. Four tools, deterministic, no model calls,
no network, no logging unless CATPILOT_EVIDENCE_LOG names a local file (then one content-free line per call).

Run from a checkout of catpilotai/catpilot-ai-guardrails:

    python mcp-server/server.py                          # stdio (Claude Code, Codex, Cursor)
    python mcp-server/server.py --transport streamable-http --host 127.0.0.1 --port 8765

Configuration is environment only, never tool arguments:

    CATPILOT_OVERLAY_FILE   absolute path to a validated overlay.yaml (optional)
    CATPILOT_TEMPLATE_HOSTS comma-separated hosts allowed in overlay templates (optional)

What this is: advice a host can ask for at the moment it matters. What it
is not: authentication, tenant isolation, monitoring, or enforcement. Bind
it to localhost and put it behind your own gateway if you expose it. An
answer with `unknown_policy: true` means no current approved company values
were available; generic defaults are never the company's policy.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catpilot_guardrails_mcp import content, policy, tools  # noqa: E402
from catpilot_guardrails_mcp.content import CATEGORIES, TEMPLATE_KINDS, TOPICS  # noqa: E402
from mcp.server import MCPServer  # noqa: E402
from mcp.types import ToolAnnotations  # noqa: E402

GUIDANCE = content.load_guidance()
TEMPLATES = content.load_templates()

server = MCPServer(
    "catpilot-guardrails",
    version=GUIDANCE["release"],
    instructions=(
        "Read-only guidance lookups for safe AI-assisted building. Advisory: nothing here blocks an action. "
        "When an answer carries unknown_policy: true, no current approved company values were available; "
        "say so to the person and do not present generic defaults as their company's policy."
    ),
)
READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


# Optional evidence log. When CATPILOT_EVIDENCE_LOG names a file, every tool call appends one JSON
# line: the time, the release, the tool, the enumerated argument (topic, category, kind), and for
# check_plan the outcome, whether it asked for a human, and the names of the fields the caller
# supplied. Never the description, the data classes, or any other free text. Off unless the
# variable is set; the public endpoint does not set it. A logging failure never changes an answer.
EVIDENCE_ENV = "CATPILOT_EVIDENCE_LOG"


def _evidence(tool: str, result: dict[str, Any], **fields: Any) -> None:
    path = os.environ.get(EVIDENCE_ENV, "").strip()
    if not path:
        return
    try:
        line: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "source": "mcp-server",
            "release": GUIDANCE["release"],
            "tool": tool,
            "error": result.get("error"),
            "policy_status": result.get("policy_status"),
            "unknown_policy": result.get("unknown_policy"),
        }
        line.update({k: v for k, v in fields.items() if v is not None})
        target = Path(os.path.expanduser(path))
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, sort_keys=True) + "\n")
    except Exception:
        return


def _enumerated(value: str, allowed) -> str:
    return value if value in allowed else "invalid"


def _policy() -> policy.PolicyState:
    hosts = {h.strip() for h in os.environ.get("CATPILOT_TEMPLATE_HOSTS", "").split(",") if h.strip()}
    return policy.load_policy(os.environ.get("CATPILOT_OVERLAY_FILE"), hosts)


@server.tool(annotations=READ_ONLY, structured_output=True)
def get_guidance(topic: str) -> dict[str, Any]:
    """Guidance for one checkpoint while a person builds with an AI assistant.

    topic: data-in-prompts | access | hosting | sharing | credentials | third-party | untrusted-input | review.
    Returns what to ask, how to name the risk, the safe alternative, when to stop and ask a human,
    and the relevant company values when a current approved overlay is configured.
    """
    result = tools.get_guidance(topic, GUIDANCE, _policy())
    _evidence("get_guidance", result, topic=_enumerated(topic, TOPICS))
    return result


@server.tool(annotations=READ_ONLY, structured_output=True)
def check_plan(
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
    findings, risks ranked by severity with a safer alternative each, one next step, whether to ask a
    human, and a checklist. Advisory: a missing field returns `unknown`, not a pass, and no outcome here
    approves or blocks anything.
    """
    result = tools.check_plan(
        description, GUIDANCE, _policy(), data_classes, data_provenance, audience, hosting,
        services, write_access, data_types, credential_references,
    )
    supplied = {
        "data_classes": data_classes, "data_provenance": data_provenance, "audience": audience, "hosting": hosting,
        "services": services, "write_access": write_access, "data_types": data_types, "credential_references": credential_references,
    }
    _evidence(
        "check_plan", result, outcome=result.get("outcome"), ask_a_human=result.get("ask_a_human"),
        fields=sorted(name for name, value in supplied.items() if value is not None),
    )
    return result


@server.tool(annotations=READ_ONLY, structured_output=True)
def get_template(kind: str) -> dict[str, Any]:
    """A safe starting point for a common kind of app.

    kind: internal-lookup-tool | form-to-spreadsheet | dashboard | document-summarizer | chatbot-over-docs.
    Returns a generic starting point and constraints, and the company's approved starting point as a
    reference when its overlay names one. Never downloads or executes anything.
    """
    result = tools.get_template(kind, TEMPLATES, GUIDANCE, _policy())
    _evidence("get_template", result, kind=_enumerated(kind, TEMPLATE_KINDS))
    return result


@server.tool(annotations=READ_ONLY, structured_output=True)
def list_approved(category: str) -> dict[str, Any]:
    """What the company has approved, or generic defaults labeled as such.

    category: hosting | services | data-classes | contacts. With a current approved overlay, unknown_policy is
    false and the items are the company's. Otherwise unknown_policy is true and the items are generic defaults
    that must not be presented as the company's policy.
    """
    result = tools.list_approved(category, GUIDANCE, _policy())
    _evidence("list_approved", result, category=_enumerated(category, CATEGORIES))
    return result


DATA_STATEMENT = (
    "This endpoint answers read-only guidance lookups. It receives the topic, plan description, template kind, or "
    "category a client sends, answers from generic defaults, stores nothing, logs no request content, and calls "
    "nothing else. Do not send confidential plans to a public endpoint; run the server yourself behind your own "
    "gateway instead (github.com/catpilotai/catpilot-ai-guardrails, mcp-server/)."
)


def build_http_app(*, host: str = "127.0.0.1", stateless: bool = False, allowed_hosts: list[str] | None = None, dns_rebinding_protection: bool = True):
    """The Starlette app: /mcp (streamable HTTP), /health, and / (a plain data statement)."""
    from mcp.server.transport_security import TransportSecuritySettings
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    security = None
    if allowed_hosts:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=True, allowed_hosts=list(allowed_hosts), allowed_origins=[f"https://{h.split(':')[0]}" for h in allowed_hosts])
    elif not dns_rebinding_protection:
        security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
    app = server.streamable_http_app(streamable_http_path="/mcp", json_response=stateless, stateless_http=stateless, transport_security=security, host=host)

    async def health(request):
        return JSONResponse({"status": "ok", "server": "catpilot-guardrails", "release": GUIDANCE["release"], "policy_status": _policy().status, "stateless": stateless})

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1", help="streamable-http bind address; keep it local unless a gateway fronts it")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--stateless", action="store_true", help="streamable-http without sessions, JSON responses; required behind a load balancer with several replicas")
    parser.add_argument("--allowed-host", action="append", default=None, help="Host header values to accept (repeatable); also CATPILOT_MCP_ALLOWED_HOSTS, comma-separated. Required when binding beyond localhost.")
    parser.add_argument("--no-dns-rebinding-protection", action="store_true", help="accept any Host header; only behind a gateway that already validates hosts")
    args = parser.parse_args(argv)
    if args.transport == "stdio":
        server.run(transport="stdio")
        return 0
    allowed = args.allowed_host or [h.strip() for h in os.environ.get("CATPILOT_MCP_ALLOWED_HOSTS", "").split(",") if h.strip()]
    if args.host not in ("127.0.0.1", "localhost", "::1") and not allowed and not args.no_dns_rebinding_protection:
        parser.error("binding beyond localhost requires --allowed-host (or CATPILOT_MCP_ALLOWED_HOSTS), or --no-dns-rebinding-protection behind a gateway that validates hosts")
    import uvicorn

    app = build_http_app(host=args.host, stateless=args.stateless, allowed_hosts=allowed, dns_rebinding_protection=not args.no_dns_rebinding_protection)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning", access_log=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
