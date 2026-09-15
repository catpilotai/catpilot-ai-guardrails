# Organization overlay

**Status:** Active. Schema: [`overlay.schema.json`](./overlay.schema.json). Example: [`overlay.example.yaml`](./overlay.example.yaml).
**Companion to:** [`SKILL_FORMAT.md`](./SKILL_FORMAT.md) (slots) and [`PACKAGING.md`](./PACKAGING.md) (private builds).

---

## 1. What an overlay is

The public `catpilot-safe-building` skill is generic. It tells an assistant
to steer a builder to "your company's approved hosting" without knowing what
that is. An **overlay** is the short, reviewed list of what it is for one
organization: approved hosting, approved services, data classes, the default
identity rule, review triggers, who to ask, and optional approved starting
templates.

The overlay is where a company's specifics live. The schema is open so any
organization can write one and merge it locally. Generating an overlay from a
company's actual policies, having a named reviewer approve it, versioning it,
serving it to tools, and recording the evidence trail is the Catpilot Plus
product. That is the seam, stated plainly:

| Open source | Catpilot Plus |
| --- | --- |
| Schema, validator, local merge into a private bundle, generic defaults | Authoring from the company's policies, named-reviewer approval, versioning, tenant-scoped serving, per-person coaching, evidence trail |

## 2. Rules that the tooling enforces

1. **Never in the public tree.** `tools/bundle.py` refuses to build any public
   bundle if a file shaped like an overlay exists under `src/`, `skills/`, or
   `dist/`. `.gitignore` also excludes `overlay.yaml` and `*.overlay.yaml`.
2. **Private output only.** `--overlay` requires `--private-out`, and the
   output directory must be outside this repository. The default is
   `../private-skills/` next to the checkout.
3. **Additive only.** Overlay values fill designated `{{slot}}` markers in the
   components. They never replace baseline text and cannot remove a rule.
4. **Expiry is real.** A private bundle cannot be built from an overlay whose
   `expires_on` has passed. The rendered bundle states the review and expiry
   dates so an assistant can say when values are stale.
5. **Lists, not stories.** The validator rejects anything that looks like a
   secret, a URL outside the allowlist, an email address other than `owner`,
   an IP address, or an incident narrative. Overlay values are short phrases.

## 3. Schema

```yaml
# overlay.yaml — organization-specific values merged into catpilot-safe-building
# Never commit this file to a public repository.
schema_version: 1
organization: "Example Org"              # display name only; no internal identifiers
owner: "security-review@example.org"      # where "ask a human" points
reviewed_on: 2026-09-13
expires_on: 2027-03-13                    # values are unknown after this date

data_classes:
  never_in_prompts: ["Cardholder data", "Government identifiers", "Health records", "Employee HR records", "Credentials"]
  ok_with_approval: ["Customer names and business emails"]
  ok: ["Synthetic data", "Public product information"]

hosting:
  approved: ["Internal App Platform (company sign-in)", "Power Apps (tenant)", "Approved cloud subscription"]
  not_approved: ["Personal cloud accounts", "Free-tier hosting", "Unmanaged VMs"]

services:
  approved: ["Company LLM gateway", "Approved email service", "Internal object storage"]
  needs_review: ["Any new software service", "Any new model endpoint", "Browser extensions"]

identity:
  default: "Company sign-in, smallest group that needs access"
  never: ["Shared passwords", "Public links for internal tools"]

review_triggers:                           # appended to the when-to-ask-a-human checkpoint
  - "External users"
  - "Payments or refunds"
  - "Writes to a system of record"

templates:                                 # optional: approved starting points
  - kind: internal-lookup-tool
    location: "https://intranet.example.org/templates/lookup"   # only if reachable by the tool; otherwise omit
```

Field limits are in the JSON Schema. Every list item is one phrase of at most
200 characters. `templates[].location` must be HTTPS with a hostname, carry no
credentials, query string, or fragment, and its host must be on the caller's
allowlist: `--allow-host` (repeatable) for `tools/validate_overlay.py` and
`tools/bundle.py`, or the `CATPILOT_TEMPLATE_HOSTS` environment variable
(comma-separated) for the reference MCP server (`mcp-server/README.md`). A
location whose host is not allowed fails validation; that is why the shipped
[`overlay.example.yaml`](./overlay.example.yaml) has no `templates` entry.

## 4. Slots

Each overlay field maps to one or more slots in the source components of
`src/skills/safe-building/`:

| Overlay field | Slot | Rendered in |
| --- | --- | --- |
| `owner` | `{{owner}}` | data-in-prompts, sharing-and-publishing, when-to-ask-a-human |
| `organization`, `reviewed_on`, `expires_on` | `{{overlay_notice}}` | bundle preamble |
| `data_classes.never_in_prompts` | `{{data_never_in_prompts}}` | data-in-prompts |
| `data_classes.ok_with_approval` | `{{data_ok_with_approval}}` | data-in-prompts |
| `data_classes.ok` | `{{data_ok}}` | data-in-prompts |
| `hosting.approved` | `{{approved_hosting}}` | hosting-and-where-it-runs |
| `hosting.not_approved` | `{{not_approved_hosting}}` | hosting-and-where-it-runs |
| `templates` | `{{templates}}` | hosting-and-where-it-runs |
| `services.approved` | `{{approved_services}}` | keys-and-credentials, third-party-services |
| `services.needs_review` | `{{services_needs_review}}` | third-party-services |
| `identity.default` | `{{identity_default}}` | access-and-identity |
| `identity.never` | `{{identity_never}}` | access-and-identity, sharing-and-publishing |
| `review_triggers` | `{{review_triggers}}` | when-to-ask-a-human |

A list value renders as a bulleted list; a string renders inline. The public
bundle renders every slot from the generic defaults in the tier's
`bundle.toml` (`[bundle.slots]`), so the public output never contains a
`{{...}}` marker.

## 5. Building a private bundle

```bash
# Validate first. --allow-host is required for each template host.
python tools/validate_overlay.py /private/path/overlay.yaml --allow-host intranet.example.org

# Build. The output name is catpilot-safe-building-<organization slug>.
python tools/bundle.py --overlay /private/path/overlay.yaml --private-out /private/path/private-skills --allow-host intranet.example.org
```

The private bundle's `catpilot.json` records an `overlay` block with the
organization, `reviewed_on`, `expires_on`, the SHA-256 of the overlay file, and
the SHA-256 of the rendered body. Its frontmatter carries the same facts as two
strings, `metadata.catpilot-overlay` and `metadata.catpilot-content-sha256`,
because the Agent Skills specification allows only string values under
`metadata` (`SKILL_FORMAT.md` §3.5). Its `name` is the public name plus the
organization slug, because the Agent Skills name grammar allows only lowercase
letters, digits, and hyphens (`+ACME` is not a valid skill name).

Install a private bundle the same way as a public one, from private storage.
A fork of a public repository is not private storage.

## 6. What the overlay is not

- Not a policy document. It holds lists of approved things, not the reasons,
  exceptions, or history behind them.
- Not authorization. Nothing in the overlay grants access, approves a
  request, or proves a review happened. The `owner` field is where to ask.
- Not a hosted service. The open-source tooling reads a local file. The
  tenant-scoped, authenticated serving of overlay values through an MCP
  server is planned for the design-partnership stage that names the host.
