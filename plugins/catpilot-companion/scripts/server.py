"""Read-only stdio MCP adapter; uses the official MCP SDK, no custom transport."""
import os
from typing import Any
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from policy import PolicyStore

server = MCPServer('catpilot-companion', version='0.2.0-dev.1', instructions='Read-only local policy reference, not an enforcement or compliance service. Missing or expired policy is not approval. Explain one next step in plain language.')
store = PolicyStore(os.environ.get('CATPILOT_POLICY_FILE'), os.environ.get('CATPILOT_ORGANIZATION_ID'))
read_only = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)


@server.tool(annotations=read_only, structured_output=True)
def get_company_guidance(topic: str, project: str, environment: str) -> dict[str, Any]:
    """Look up one topic: test-data, authentication, sharing, secrets, dependencies, deployment.

    Project/environment are exact approved scope IDs. Does not accept a company,
    file path, employee identity, raw code, credentials, or arbitrary prompt.
    """
    return store.guidance(topic, project, environment)


@server.tool(annotations=read_only, structured_output=True)
def get_approved_starting_point(topic: str, project: str, environment: str) -> dict[str, Any]:
    """Return a current, scoped paved-road reference; never download or execute it."""
    result = store.guidance(topic, project, environment)
    if result['status'] == 'approved-local' and result['paved_road'] is None:
        return {'status': 'missing-starting-point', 'enforcement': 'none', 'next_step': 'Ask the policy owner to nominate an approved starting point.'}
    return result


@server.tool(annotations=read_only, structured_output=True)
def explain_security_decision(topic: str, project: str, environment: str) -> dict[str, Any]:
    """Return the approved rationale and one next step, without grading or claiming course completion."""
    return store.guidance(topic, project, environment)


if __name__ == '__main__':
    server.run(transport='stdio')
