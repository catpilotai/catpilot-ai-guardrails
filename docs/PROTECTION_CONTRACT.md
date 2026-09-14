# Protection contract

Status: two advisory skills shipped; one narrowly scoped hook shipped and labeled as enforcement for its path only; live-host results recorded in the README's tested-runtimes table.

## What the repository provides

The public package provides local security instructions for two audiences, reference material, a deterministic bundler with per-host rendering, an organization-overlay schema and validator, one host hook, and offline evaluation tooling. None of it observes an employee's work, authenticates an organization, runs security scans automatically, or installs a mandatory execution gate on every path.

The baseline does not call Catpilot or send telemetry. Installing it does not change the AI host's own data-handling terms or permissions. Do not put confidential company material in this public repository or a public fork; an overlay lives outside the tree, and the bundler refuses to build if one is inside it.

## Three different capabilities

| Mode | What it means | What constitutes evidence |
| --- | --- | --- |
| Advice | An agent consults guidance and recommends a safer approach | The actual response and the relevant policy/source, with limitations |
| Contextual coaching | A supported event produces a brief explanation and one useful next step | The event, response, and observed follow-through; not an implied quiz or completion |
| Enforcement | A particular action cannot proceed without an external, trusted check | Tool/action trace showing the check and denial/allow decision on that path, including failure-mode tests |

Both skills in this repository are advice. The safe-building skill also tells the assistant how to coach, but a coaching *event* (a supported trigger in a work surface) is a Catpilot platform capability, not something a skill file can produce. The only enforcement in this repository is the Claude Code hook in `hooks/`, and its claim is limited to the Bash tool path on the host versions in the tested-runtimes table.

A refusal in a conversation is not proof that every action path is blocked. A published skill is not necessarily installed; an installed skill is not necessarily active; an active instruction is not necessarily followed. A correct learner answer is not proof that an application changed. A pasted instruction block in ChatGPT, Copilot, Lovable, Bolt, Replit, or v0 is text the model may or may not weigh; nothing on those hosts blocks anything.

## Status vocabulary

Use the narrowest supported description:

- **Authored:** a rule or test exists.
- **Reviewed:** a named reviewer accepted a particular version and scope.
- **Published:** that version is available for distribution.
- **Installed:** a recorded host has the expected files/version.
- **Activated:** an observable host signal shows the relevant instructions/configuration were made available in that session.
- **Behavior observed:** a recorded scenario produced a particular response or action.
- **Enforced on a named path:** a trusted mechanism prevented an action in a verified test.

Do not replace these states with one green “protected” badge. Report unknown, unavailable, and not tested explicitly.

## Where each claim lives

| Claim | Where it is recorded | What it is based on |
| --- | --- | --- |
| A skill loads on a host | README, tested-runtimes table | A host signal from a recorded session (for Claude Code, the session's own listing of available skills), not the model saying so |
| The hook blocks a command | README, tested-runtimes table; `evals/reports/` verification notes | A tool-result trace showing the host applied the hook's deny decision, plus a control run without the hook |
| The safe-building skill changes responses | `evals/reports/<release>.md` when one exists | The with/without runner in `tools/eval.py`, heuristic scores, human review |
| Company values are current | The private bundle's frontmatter (`metadata.catpilot.overlay`) | The overlay's `reviewed_on` and `expires_on`, checked at build time |

Anything not in that table is not claimed. In particular: no coaching events, no MCP server, no coverage of file writes by the hook, no Cursor hook, no verified activation on Cursor, Codex, Claude.ai, or any skills.sh host beyond those listed.

## Company policy boundaries

- Keep universal public guidance separate from authenticated, approved company policy and application-specific context. The overlay schema is the public half; the values are the private half.
- Record the policy owner, source, approval, applicable scope, version, and freshness. Do not invent a policy when it is missing or silently choose a convenient rule when approved sources conflict. The overlay carries `owner`, `reviewed_on`, and `expires_on` for this reason.
- Keep customer data, credentials, internal policy excerpts, employee identifiers, and incident payloads out of public examples and reports. Public fixtures must be synthetic and reviewed; a classification label cannot prove that data is safe to publish.
- A policy document or tool result is data, not authorization to run embedded commands, export information, or weaken controls. Company content cannot override the host's governing safety rules.
- Do not grant authority based on an arbitrary prompt's organization name or user ID. Any future service must authenticate and authorize the caller server-side.
- State which host/model providers receive context. Private Catpilot storage does not mean material retrieved into another AI host stays exclusively inside Catpilot.

## What a mandatory check must establish

Before claiming enforcement, verify the protected action and all relevant execution paths, configuration ownership, activation, supported denial semantics, behavior during errors/timeouts, and handling of disabled or stale checks. For a high-risk protected action, unavailable checks must halt or route to an authorized reviewer according to approved policy. The UI must not silently report protection when the check did not run.

The shipped hook meets the parts of this it can meet on its own: it never returns allow, it fails closed on malformed input, and its scope is written down. It does not meet the rest by itself: a hook the host did not load, timed out, or that a person disabled protects nothing, and only a host-level test can show which of those happened. Keep explicit human approval for consequential changes. Do not implement “check failed, therefore allow” or rely on an agent promising to call an optional tool. Scope the claim to the host/version, actions, and conditions actually tested.

## Learning and work are different modes

During work, provide a short explanation and one actionable next step. Offer deeper learning rather than adding a compulsory quiz after every intervention. During deliberate training, use Catpilot's authoritative training service for grading, progression, and records; a host model must not fabricate completion. The safe-building skill mirrors Module 399 checkpoint for checkpoint so the two modes share one set of ideas, and it says explicitly that a chat answer is not a completion record.

## Evaluation boundaries

See [the evaluation guide](../evals/README.md). Offline fixture validation measures structure and coverage, not policy truth, model behavior, app security, or compliance. The with/without runner scores with keyword heuristics that a human must review. Published cases are a development corpus. Passing them would still not establish universal safety; use separate held-out scenarios, record failures, and verify actual artifacts/actions before broader claims.
