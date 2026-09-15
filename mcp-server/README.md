# Catpilot guardrails reference MCP server

A skill is text the model reads. This server is a tool the model calls: at the
moment a person is about to paste data, pick hosting, connect a service, or
share something, the assistant can ask for the relevant checkpoint, check a
plan, get a safe starting point, or look up what the company has approved.

It is the seam between the open baseline and a company's own values. With no
overlay configured it answers from generic defaults and says so on every
answer (`unknown_policy: true`). With a validated, unexpired overlay it
answers with the company's reviewed values and cites them. Nothing here
observes a conversation, blocks an action, sends data anywhere, or logs by
default.

## Tools

| Tool | Input | Returns |
| --- | --- | --- |
| `get_guidance(topic)` | `data-in-prompts`, `access`, `hosting`, `sharing`, `credentials`, `third-party`, `untrusted-input`, `review` | what to ask, how to name the risk, the safe alternative, when to stop and ask a human, and the relevant company values with their source |
| `check_plan(description, data_types?, audience?, hosting?)` | a plain-language plan | risks ranked by severity with a safer alternative each, one next step, `ask_a_human`, `who_to_ask`, a checklist, and the labels that fired |
| `get_template(kind)` | `internal-lookup-tool`, `form-to-spreadsheet`, `dashboard`, `document-summarizer`, `chatbot-over-docs` | a generic starting point with constraints, and the company's approved starting point as a reference when its overlay names one |
| `list_approved(category)` | `hosting`, `services`, `data-classes`, `contacts` | the company's items when an approved overlay exists, otherwise generic defaults labeled as such |

Every answer carries `unknown_policy`, `policy_status`, `policy_source`
(organization, owner, review and expiry dates, overlay hash), the release the
guidance came from, and `enforcement: "none"`.

`check_plan` is keyword matching against the eight checkpoints and the
overlay. It is deterministic and readable, and it is not judgment: a clean
result means no keyword fired, not that the plan is safe. An overlay item
fires when its content words (lowercased, singular, stop words dropped) all
appear in the plan in any order, or when a hosting or service synonym such as
"unmanaged" or "unapproved" appears with one of them; every risk carries the
`rule` that fired and the `evidence` words from the plan. When `hosting` or
`audience` is not supplied, the labels say `unknown` and the checklist asks
for it. An optional model pass is a possible future addition, never a
requirement.

## Run it

From a checkout of this repository, with the locked dependencies installed:

```bash
python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt

# stdio, for Claude Code, Codex, Cursor
python mcp-server/server.py

# streamable HTTP, bound to localhost; put your own gateway in front before exposing it
python mcp-server/server.py --transport streamable-http --host 127.0.0.1 --port 8765
```

Configuration is by environment variable only. A tool argument can never
choose the policy file.

| Variable | Meaning |
| --- | --- |
| `CATPILOT_OVERLAY_FILE` | Absolute path to a company overlay (`docs/spec/OVERLAY.md`). Optional. Re-read and re-validated on every call, so expiry and revocation take effect immediately. |
| `CATPILOT_TEMPLATE_HOSTS` | Comma-separated hosts allowed in the overlay's template locations. Required if the overlay names templates. |

Host configuration snippets are in `host-configs/`: a `.mcp.json` for Claude
Code and a `config.toml` fragment for Codex. Replace the absolute paths.

## Hosted instance

A hosted instance is live at `https://mcp.catpilot.ai/mcp` (streamable HTTP). It serves generic defaults only: no company overlay is loaded, and none ever will be on this public endpoint. Host config examples that point at it: `host-configs/claude-code.http.mcp.json` and `host-configs/codex.http.config.toml`. Deployment steps and the protections in front of it: [`deploy/README.md`](../deploy/README.md).

## What it is not

- **Not authentication or tenant isolation.** Whoever can reach the process
  gets the overlay's values. The file, its directory, and the process
  configuration must be owned by the policy administrator. The tenant-scoped,
  authenticated version of this server is Catpilot Plus.
- **Not enforcement.** A lookup the model never made protects nothing. A
  refusal in a conversation is not a blocked action.
- **Not telemetry.** No logging by default, no outbound calls.
- **Not a place for policy prose or incident details.** The overlay validator
  rejects secrets, URLs outside the allowlist, and narratives before the
  server will use a file.

## Where the content comes from

`defaults/guidance.json` is generated from `src/skills/safe-building/` by
`tools/bundle.py` and checked for drift in CI, so the server and the skill
cannot disagree. `defaults/templates.json` is authored. Edit the source
components and rebuild; do not edit the JSON.

## Verification

Contract tests in `tests/test_mcp_server.py` open a real stdio session with
the SDK client: handshake, tool listing, read-only annotations, lookups with
and without an overlay, and live expiry. They call no model. Per-host live
lookups are recorded in `evals/HOST_VERIFICATION.md` with dates; a host not
listed there has not been verified.
