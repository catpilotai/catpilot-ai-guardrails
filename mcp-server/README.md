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
| `check_plan(description, data_classes?, data_provenance?, audience?, hosting?, services?, write_access?)` | a plain-language plan, plus the fields that decide it | `outcome`, one `decision` per field with the rule that decided it, `hints` from the description, risks ranked by severity with a safer alternative each, one next step, `ask_a_human`, `who_to_ask`, a checklist, and the labels that fired |
| `get_template(kind)` | `internal-lookup-tool`, `form-to-spreadsheet`, `dashboard`, `document-summarizer`, `chatbot-over-docs` | a generic starting point with constraints, and the company's approved starting point as a reference when its overlay names one |
| `list_approved(category)` | `hosting`, `services`, `data-classes`, `contacts` | the company's items when an approved overlay exists, otherwise generic defaults labeled as such |

Every answer carries `unknown_policy`, `policy_status`, `policy_source`
(organization, owner, review and expiry dates, overlay hash), the release the
guidance came from, and `enforcement: "none"`.

### `check_plan`: the fields decide, the description only hints

Free text names a risk as often to rule it out as to choose it. "No external
users or public links" and "synthetic patient records only" are safe plans
that say the dangerous words, so the description alone can never produce an
outcome. The explicit fields do:

| Field | Type | Values | Outcome |
| --- | --- | --- | --- |
| `hosting` | string | where it will run | a value that says the thing is never deployed, hosted, or published anywhere -- it only runs locally, on the builder's own machine or laptop, or by hand as a one-off -- is the `not_deployed` category (below), unless it also names an approved or not-approved entry, a personal cloud account, or a free tier. Otherwise: the value equal to, or naming only the words of, one of the overlay's approved entries: `permitted`. On its not-approved list: `prohibited`. Naming an approved entry together with other words, or negating one ("not", "instead of", "rather than", ...): `requires_review`. Anything else, with an overlay: `requires_review`. A personal account, free tier, trial workspace, home server, or laptop, with no overlay: `requires_review`. Not given, or no overlay to check it against: `unknown` |
| `audience` | string | normalized to `internal`, `external`, `public`, `unknown` | `internal`: `permitted`. `external` or `public`: `requires_review`. `unknown`: `unknown` |
| `data_classes` | list of strings | what data the app touches, one class per item | one decision per item, against the overlay's `never_in_prompts` (`prohibited`), `ok_with_approval` (`requires_review`), and `ok` (`permitted`); with no overlay, payment, government, health, and credential data are `prohibited`, employee and customer records `requires_review`, synthetic or made-up data `permitted`, anything else `unknown`. A word like "sample" or "synthetic" only takes the made-up-data branch when it is not negated ("not synthetic", "non-synthetic") and no real-data cue ("real", "actual", "production", "customer records", ...) is also present; a mixed or negated cue is decided under the real-data rules instead, with a note saying so |
| `data_provenance` | string, optional | `synthetic`, `real`, `mixed`, or `unknown` | overrides the inference above for every `data_classes` item, regardless of its wording: `synthetic` always takes the made-up-data branch, `real` and `mixed` always take the real-data rules, and `unknown` is treated as `real` with a note on each decision. Any other value comes back as an `error` in the response, not a crash |
| `services` | list of strings | software services it will connect to | the value equal to, or naming only the words of, one of the overlay's approved entries: `permitted`. Naming an approved entry together with other words, or negating one: `requires_review`. Everything else: `requires_review` |
| `write_access` | bool | does it write to a system of record (CRM, ERP, HR, finance, tickets, the production database) | `true`: `requires_review`. `false`: `permitted`. Not given: `unknown` |

`data_types` is the old name for `data_classes`; it still works and is merged
into it. `outcome` is the worst of the decisions, ordered `prohibited` >
`requires_review` > `unknown` > `permitted`. A missing field is `unknown` and
adds its question to the checklist, never a pass. Every decision names the
`rule` that decided it and whether that rule came from the `company overlay`
or a `generic default`. Naming an approved hosting or service value alongside
something else ("Internal App Platform and a personal VPS"), or negating one
("a new model endpoint instead of the company LLM gateway"), is
`requires_review`, not `permitted`; only the value itself, or nothing more
than its own words, is.

A `not_deployed` hosting value ("not deployed", "not hosted", "not published",
"local"/"locally", "localhost", "my machine", "my laptop", "own laptop", "own
machine", "workstation", "workspace", "run by hand", "one-off", "run
manually", "no hosting", "no new hosting") is `permitted`, not `requires_review`
for missing the approved list -- there is nothing to approve when it is never
hosted. It is `requires_review` only for a machine-only phrase ("my laptop",
"my machine", "own machine", "workstation", "localhost") named together with
an audience of other people (internal, a named team, external, or public);
the same phrase with the audience unset, unknown, or naming only the builder
("just me", "only me", "myself", "the builder", "personal use", ...) is
`permitted`, as are the plain "not deployed"-style phrases regardless of
audience, since a script that never leaves the builder's machine is not
hosting even when its output is for others. `labels.hosting` reports
`not_deployed`, and the hosting question is not added to the checklist when
this category already answered it.

`hints` are the findings from the description, each labelled as a hint. A hint
adds a question and a risk, never an outcome, and a hint under a negation
("no external users", "synthetic records only", "instead of the real export",
"the approved email service") does not fire at all. A hint can set
`ask_a_human` only for the three cases that were always review triggers: real
sensitive data, credentials, and an external audience. Each risk carries
`basis: "decision"` or `basis: "hint"` so a caller can tell the two apart.

Matching is deterministic keyword work, and it is not judgment: a clean result
means no rule fired, not that the plan is safe. An overlay item fires when its
content words (lowercased, singular, stop words dropped) all appear in the
value or the plan in any order, or when a hosting or service synonym such as
"unmanaged" or "unapproved" appears with one of them; every decision and risk
carries the `rule` that fired and the `evidence` words. An optional model pass
is a possible future addition, never a requirement.

```jsonc
// check_plan("A lookup tool for the ops team over last month's CRM export.",
//            data_classes=["customer names and business email addresses"],
//            audience="our ops team", hosting="my personal Replit account",
//            services=["a new enrichment API"], write_access=true)
{
  "outcome": "prohibited",
  "decisions": [
    {"field": "hosting", "value": "my personal Replit account", "outcome": "prohibited",
     "rule": "Personal cloud accounts", "source": "company overlay",
     "evidence": ["personal", "account"], "note": "on the company's not-approved hosting list"},
    {"field": "audience", "value": "internal", "outcome": "permitted",
     "rule": "Company sign-in, smallest named group that needs access",
     "source": "company overlay", "evidence": ["ops", "team"], "note": null},
    {"field": "data_classes", "value": "customer names and business email addresses",
     "outcome": "requires_review", "rule": "Customer names and business email addresses",
     "source": "company overlay", "evidence": ["customer", "name"], "note": null},
    {"field": "services", "value": "a new enrichment API", "outcome": "requires_review",
     "rule": "any new software service needs review", "source": "generic default",
     "evidence": ["new", "enrichment", "api"],
     "note": "named services are reviewed by default; nothing here says this one is approved"},
    {"field": "write_access", "value": true, "outcome": "requires_review",
     "rule": "Writes to a system of record", "source": "company overlay",
     "evidence": ["system of record"], "note": null}
  ],
  "hints": [
    {"component": "data-in-prompts", "evidence": "crm export",
     "note": "the description mentions customer records; a hint only, pass data_classes to decide"}
  ],
  "risks": [
    {"component": "hosting-and-where-it-runs", "severity": "high", "basis": "decision",
     "why": "Company hosting rule, not approved: Personal cloud accounts.",
     "rule": "Personal cloud accounts", "overlay_list": "hosting.not_approved",
     "evidence": ["personal", "account"], "safer_alternative": "...", "ask": "...", "title": "..."}
  ],
  "ask_a_human": true,
  "who_to_ask": "security-review@example.org",
  "next_step": "Build in the company's approved place from the start, even for a first version. ...",
  "checklist": ["Where will the finished thing live, and who looks after that place?", "..."],
  "labels": {"hosting": "not_approved", "audience": "internal", "...": "..."},
  "enforcement": "none"
}
```

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
| `CATPILOT_EVIDENCE_LOG` | Path of a local JSON-lines file. When set, every tool call appends one line: time, release, tool, `policy_status`, `unknown_policy`, the enumerated argument, and for `check_plan` the outcome, `ask_a_human`, and the names of the fields supplied. Never the description or any other free text. Optional; the public endpoint does not set it. A logging failure never changes an answer. |

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
