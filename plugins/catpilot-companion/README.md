# CATpilot Companion — evaluation preview

Includes portable core guidance, a company-security coach, a read-only local
policy MCP server, and a narrow private-key write hook. No production tenant
integration, telemetry, automatic installation, or general enforcement claim.

Read [the repository preview guide](../../docs/COMPANION_PREVIEW.md)
in the **same reviewed checkout** as this package. This preview is evaluated
from the repository; the guide and locked development dependencies are at
the repository root, not downloaded automatically by the plugin.

Runtime: Python 3.11+ and MCP 2.2.0 in the selected Python environment. The
hook itself uses only the standard library. The host must review/trust the
command and supply `CLAUDE_PLUGIN_ROOT` (supported by both target manifests).

`CATPILOT_POLICY_FILE` is an absolute administrator-owned private JSON path;
`CATPILOT_ORGANIZATION_ID` is that organization's exact ID. No file is selected
by default. Policies returned through MCP enter the model provider's context.
Do not include real policies or customer data in this public package.
