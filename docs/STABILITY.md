# Stability

What you can rely on between releases, and how much notice you get before it changes. Decided in [issue #101](https://github.com/catpilotai/catpilot-ai-guardrails/issues/101).

## Tiers

| Tier | Meaning |
|---|---|
| **Stable** | Changes are backward compatible. A removal or breaking change is announced in the changelog at least two stable releases before it lands, and the old form keeps working until then. |
| **Beta** | Works and is tested, but the shape may change in any stable release. Changes are listed in the changelog; there is no two-release notice. |
| **Experimental** | May change or disappear in any release. Marked experimental where you use it. Do not build a production dependency on it. |

## What is in each tier

| Surface | Tier | Where it is defined |
|---|---|---|
| Hooks (command-line options, what each one denies, asks or logs, and their escape hatches) | Stable | [`hooks/README.md`](../hooks/README.md) |
| Company rules file (the overlay: `schema_version` 1 and 2, rule kinds, modes, exceptions) | Stable | [`spec/OVERLAY.md`](spec/OVERLAY.md), [`spec/OVERLAY_V2.md`](spec/OVERLAY_V2.md) |
| Evidence events (schema version 1, the closed list of events and fields) | Stable | [`spec/EVIDENCE.md`](spec/EVIDENCE.md) |
| Reference MCP server and its tools | Beta | [`mcp-server/`](../mcp-server/) |
| `check_plan` (inputs, outputs, decision wording) | Beta | [`mcp-server/`](../mcp-server/) |
| Exports, including the allow/deny list export | Experimental | [`spec/policy-export.schema.json`](spec/policy-export.schema.json) |

Anything not listed here (internal modules under `catpilot_guard/`, the bundler's internals, benchmark scripts) is not an interface: it may change at any time.

## What "stable" covers

- A rules file or evidence line that is valid today stays valid. New optional fields may appear in a new `schema_version` or `format_version`; the specs say which readers refuse unknown fields.
- A hook's documented deny and ask behavior does not get weaker, and a new deny is announced in the changelog.
- A schema's `schema_version` or `format_version` changes only with a migration path or a documented reader that accepts both.

## Notice before removal

A stable surface is deprecated in one release and removed no sooner than two stable releases later. The changelog entry names the replacement. Security fixes may break this rule when the old behavior is itself the vulnerability; the advisory says so.
