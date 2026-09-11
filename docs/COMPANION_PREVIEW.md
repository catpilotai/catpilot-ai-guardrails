# Company companion: local evaluation preview

This is the opt-in `2026.09.11-hardening.1` preview, not a hosted CATpilot
connector or a managed security product. The stable `2026.09.11` release and
default branch are unchanged.

## What works locally

- One shared core skill plus a plain-language company coach, with thin Codex
  and Claude Code manifests. No customer policies are included.
- Read-only stdio MCP tools: `get_company_guidance`,
  `get_approved_starting_point`, and `explain_security_decision`.
- An administrator-selected private JSON policy, validated on every request.
  Responses carry scope, policy/version, owner, expiry, and a content digest.
- Explicit unavailable states: missing, invalid (including duplicate/conflicting
  definitions), draft, revoked, expired, not yet valid, wrong organization,
  out-of-scope, or missing topic. None returns approved content.
- An optional plugin `PreToolUse` hook for literal private-key headers in
  `Write`, `Edit`, `MultiEdit`, and `apply_patch` additions.

The policy loader performs no network requests. It never accepts a policy
path or organization ID from the model. Paved-road URLs are references, not
downloads or execution requests. It does not store conversations or learning
records, and it sends no CATpilot telemetry.

## Trust and limitations

Local filesystem/process ownership is the prototype's trust boundary.
The administrator must own the policy file, all parent directories, and host
configuration. The builder and agent must not be able to rewrite them. The
`approval` object is an assertion from that trusted file, **not a signature**.
Do not use this as a multi-tenant server or expose it over HTTP.

Policy excerpts returned to Codex or Claude are provided to that host/model
provider. Local storage does not mean retrieved material stays on-device.
Approve that data flow before loading real company policy. Keep private
policy outside this public repository and review host retention settings.

The SDK stdio handshake and tools are tested independently of a model, and
both target hosts successfully made a real read-only synthetic MCP lookup.
Those were MCP-only sessions, not proof of installed skill/plugin activation.
Plugin manifest validation is not live host activation. Command-hook unit tests
verify response/exit semantics, not trusted execution inside every host.
Host trust review and actual blocked-action traces remain gates for a stable
release or any enforcement claim, not a reason to label this preview protected.

The hook is deliberately narrow. It does not catch all credential formats,
secrets in prompts, shell-written files, indirect writes, or subsequent stdin
commands. An exact private-key header in an example is also blocked; use an
unmistakable placeholder. It never returns an overriding `allow`. Invalid
supported input exits 2; host timeouts, disabled hooks, bypasses, and alternate
paths still need host-specific testing. Never equate an MCP lookup with a gate.

## Evaluate without installing into personal configuration

Requires Python 3.11+ and a reviewed virtual environment with MCP 2.2.0.
From this checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt
.venv/bin/python tools/bundle.py --check
.venv/bin/python tools/package_plugin.py --check
.venv/bin/python -m unittest discover -s tests -v
```

For a local Claude session, put the reviewed environment's `bin` directory on
the session's PATH, set `CATPILOT_POLICY_FILE` to an **absolute** private-file
path and `CATPILOT_ORGANIZATION_ID` to the approved organization ID, then run
`claude --plugin-dir /absolute/path/to/plugins/catpilot-companion`. This is
session-scoped; do not install into personal/team settings automatically.
Review the hook command and host trust prompt before enabling it.

For Codex, the package supplies `.codex-plugin/plugin.json`. Use the host's
reviewed local plugin flow. A manual MCP-only configuration can instead point
`mcp_servers.catpilot-companion.command` at the virtual environment's Python
and `args` at `scripts/server.py`, with the same two environment variables.
MCP-only configuration does **not** install skills or the hook. Pin the checkout
and record the host configuration actually used; this document does not
claim a completed Codex installation.

For an entirely synthetic trial only, use
[`company-policy.synthetic.json`](../examples/company-policy.synthetic.json),
organization `fictional-company`, project `fictional-pilot`, environment
`demo`. Its template URL is illustrative and its approval expires. Never
silently renew or substitute this fixture for a customer's approved policy.

## Customer and stable-release gates

1. Name a policy owner and approve the data sent to each model provider.
2. Supply 3–5 current rules and one real approved starting template privately.
3. Establish non-agent-writable policy/config ownership (or implement signed,
   authenticated managed delivery before claiming a stronger trust boundary).
4. Test installation, activation, freshness/revocation, errors, timeouts,
   alternate write paths, and a demonstrably blocked action in each host.
5. Run held-out builder scenarios; score correct decisions, usable next steps,
   false blocks, and successful safe task completion, not just refusals.
6. Only then promote beyond this evaluation preview and start a customer
   bake-off using approved private policy and explicitly verified coverage.

Do not connect CATpilot tenant APIs until server-side identity, authorization,
policy approval, audit-log redaction, and revocation have dedicated tests.
Do not mark a course or checkpoint complete from companion dialogue.

Protocol references: [official MCP server guide](https://modelcontextprotocol.io/docs/develop/build-server),
[Codex hooks](https://developers.openai.com/codex/hooks),
[Claude plugin reference](https://code.claude.com/docs/en/plugins-reference).
