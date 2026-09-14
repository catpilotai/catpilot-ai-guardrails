#!/usr/bin/env python3
"""Catpilot guardrails reference MCP server.

Read-only guidance lookups for safe AI-assisted building: the eight
checkpoints of `catpilot-safe-building`, plus a company's approved values
when an overlay is configured. Four tools, deterministic, no model calls,
no network, no logging.

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
import inspect
import os
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from catpilot_guardrails_mcp import content, policy, tools  # noqa: E402
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
    return tools.get_guidance(topic, GUIDANCE, _policy())


@server.tool(annotations=READ_ONLY, structured_output=True)
def check_plan(description: str, data_types: list[str] | None = None, audience: str | None = None, hosting: str | None = None) -> dict[str, Any]:
    """Deterministic check of a building plan against the eight checkpoints and, when configured, the company overlay.

    Describe what is being built in plain words; optionally list the data types involved, who will use it,
    and where it will run. Returns risks ranked by severity with a safer alternative each, one next step,
    whether to ask a human, and a short checklist. Keyword matching, not judgment; a clean result is not approval.
    """
    return tools.check_plan(description, GUIDANCE, _policy(), data_types, audience, hosting)


@server.tool(annotations=READ_ONLY, structured_output=True)
def get_template(kind: str) -> dict[str, Any]:
    """A safe starting point for a common kind of app.

    kind: internal-lookup-tool | form-to-spreadsheet | dashboard | document-summarizer | chatbot-over-docs.
    Returns a generic starting point and constraints, and the company's approved starting point as a
    reference when its overlay names one. Never downloads or executes anything.
    """
    return tools.get_template(kind, TEMPLATES, GUIDANCE, _policy())


@server.tool(annotations=READ_ONLY, structured_output=True)
def list_approved(category: str) -> dict[str, Any]:
    """What the company has approved, or generic defaults labeled as such.

    category: hosting | services | data-classes | contacts. With a current approved overlay, unknown_policy is
    false and the items are the company's. Otherwise unknown_policy is true and the items are generic defaults
    that must not be presented as the company's policy.
    """
    return tools.list_approved(category, GUIDANCE, _policy())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--transport", choices=["stdio", "streamable-http"], default="stdio")
    parser.add_argument("--host", default="127.0.0.1", help="streamable-http bind address; keep it local unless a gateway fronts it")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args(argv)
    if args.transport == "stdio":
        server.run(transport="stdio")
        return 0
    accepted = inspect.signature(server.run_streamable_http_async).parameters
    kwargs = {k: v for k, v in {"host": args.host, "port": args.port}.items() if k in accepted}
    if not kwargs:
        os.environ.setdefault("FASTMCP_HOST", args.host)
        os.environ.setdefault("FASTMCP_PORT", str(args.port))
    server.run(transport="streamable-http", **kwargs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
