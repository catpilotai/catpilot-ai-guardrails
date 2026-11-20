# Roadmap

Updated 2026-11-19. This page lists what is shipped, what we are building next, and what is parked until someone asks for it. "Shipped" means merged and tested in CI. Where something has not yet been run on a real host, identity provider or SIEM, the entry says so; [`CHANGELOG.md`](../CHANGELOG.md) has the detail, and the [verification status](DEPLOY_ORG.md#verification-status) table has dates and notes for each host check.

To ask for a parked item, comment on its issue. That is how parked work gets picked up.

## Shipped

| Area | What | Run on a real host? |
|---|---|---|
| Baseline content | `catpilot-security-core` (nine components) and `catpilot-safe-building`, with per-host targets | yes |
| Hooks | Destructive-operation, credential and private-key checks on Claude Code, Codex and GitHub Copilot CLI; they block when they cannot run; commands inside `if`, loops, `{ }`, functions and comments are read (#137) | Claude Code and Codex yes (2026-11-16/17), before the #137 reader and the single-file layout; Copilot CLI not yet |
| Company rules v2 | Schema, validator, `migrate`, topic contacts, and expiring exceptions | n/a (offline tools) |
| Company enforcement | Company-rules hook for `protected_branch`, `deploy_host`, `package_registry` and `cloud_account`, in `monitor`, `ask` or `block`, plus a pull-request check | not yet |
| Session-start rules | The company rules reach the model at every session start on Claude Code and Codex | yes |
| Windows | The hooks run on Windows, with a PowerShell reader | not yet |
| Install | One command per OS (`deploy/org/install.sh`, `install.ps1`), which proves and records the hooks' Python and, on macOS and Linux, places the hooks as one file with a recorded SHA-256 (#158); `verify` and `uninstall` | macOS and Linux in CI; Windows not yet |
| Reference MCP server | `get_guidance`, `check_plan`, `get_template`, `list_approved`; Claude.ai and ChatGPT connectors | yes (2026-09-28) |
| Server sign-in | Opt-in OIDC mode (`--auth oidc`) for Claude.ai and ChatGPT | not yet, needs an identity provider |
| Gateway export | Company rules as generic JSON (`validate_overlay.py export`) | experimental |
| Evidence | Versioned evidence schema, OCSF and ECS export, an opt-in hash chain, and HTTPS forwarding | not yet against a real SIEM |
| Project policy | [Stability](STABILITY.md), [support](../SUPPORT.md), governance, monthly stable releases | n/a |

## Next

| Item | Issue |
|---|---|
| Sign-in mode tested against a real identity provider | #94 |
| First monthly stable release | #101 |

## Parked until requested

| Item | Why parked | Issue |
|---|---|---|
| Windows company rules in the installer (`-Overlay`), the Windows host check and PowerShell hardening | Waiting for a Windows customer | #156, #141–#143 |
| Admin-settings guides for Lovable, Replit, Bolt and v0 | Each needs an admin account on that tool to check against | #154 |
| Hook hardening: crafted shell spellings the parser misreads | Fixed when a real case shows up | #144–#148, #160 |
| Evidence loaded into a real SIEM | Waiting for a customer's SIEM to test against | n/a |
| Framework bundles (`catpilot-<framework>-security`) and agentic-loop packaging | Content is kept in `frameworks/`; no bundle is promised | n/a |
| `catpilot-security-advanced`, `tools/recommend.py`, HIPAA and GDPR mappings | No current demand | n/a |

## Open decisions

#93, #95, #96, #98, #99 and #102 are labelled `question`.
