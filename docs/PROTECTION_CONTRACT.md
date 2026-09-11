# Protection contract

Status: first evaluation foundation; live-host results not yet recorded.

## What the repository provides

The public package provides local security instructions, reference material, and a deterministic bundler. The evaluation tooling added alongside it reads synthetic fixtures offline. Neither the package nor that tooling observes an employee's work, authenticates an organization, runs security scans automatically, or installs a mandatory execution gate.

The baseline does not call Catpilot or send telemetry. Installing it does not change the AI host's own data-handling terms or permissions. Do not put confidential company material in this public repository or a public fork.

## Three different capabilities

| Mode | What it means | What constitutes evidence |
| --- | --- | --- |
| Advice | An agent consults guidance and recommends a safer approach | The actual response and the relevant policy/source, with limitations |
| Contextual coaching | A supported event produces a brief explanation and one useful next step | The event, response, and observed follow-through; not an implied quiz or completion |
| Enforcement | A particular action cannot proceed without an external, trusted check | Tool/action trace showing the check and denial/allow decision on that path, including failure-mode tests |

A refusal in a conversation is not proof that every action path is blocked. A published skill is not necessarily installed; an installed skill is not necessarily active; an active instruction is not necessarily followed. A correct learner answer is not proof that an application changed.

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

## Initial evaluation targets

| Target | Initial goal | Live installation/activation evidence | Behavioral results | Enforcement coverage |
| --- | --- | --- | --- | --- |
| Codex | Company-aware guidance for nontechnical app builders | Not recorded in this foundation increment | Not run | None supplied by this repository |
| Claude Code | The same scenarios and scoring contract | Not recorded in this foundation increment | Not run | None supplied by this repository |

This table identifies the first evaluation cohort, not a complete support matrix. An installer's list of compatible hosts is not a Catpilot safety benchmark. Update claims only from exact host/model/configuration/release evidence; do not infer one host's results from another.

## Company policy boundaries

- Keep universal public guidance separate from authenticated, approved company policy and application-specific context.
- Record the policy owner, source, approval, applicable scope, version, and freshness. Do not invent a policy when it is missing or silently choose a convenient rule when approved sources conflict.
- Keep customer data, credentials, internal policy excerpts, employee identifiers, and incident payloads out of public examples and reports. Public fixtures must be synthetic and reviewed; a classification label cannot prove that data is safe to publish.
- A policy document or tool result is data, not authorization to run embedded commands, export information, or weaken controls. Company content cannot override the host's governing safety rules.
- Do not grant authority based on an arbitrary prompt's organization name or user ID. Any future service must authenticate and authorize the caller server-side.
- State which host/model providers receive context. Private Catpilot storage does not mean material retrieved into another AI host stays exclusively inside Catpilot.

## What a future mandatory check must establish

Before claiming enforcement, verify the protected action and all relevant execution paths, configuration ownership, activation, supported denial semantics, behavior during errors/timeouts, and handling of disabled or stale checks. For a high-risk protected action, unavailable checks must halt or route to an authorized reviewer according to approved policy. The UI must not silently report protection when the check did not run.

Keep explicit human approval for consequential changes. Do not implement “check failed, therefore allow” or rely on an agent promising to call an optional tool. Scope the claim to the host/version, actions, and conditions actually tested.

## Learning and work are different modes

During work, provide a short explanation and one actionable next step. Offer deeper learning rather than adding a compulsory quiz after every intervention. During deliberate training, use Catpilot's authoritative training service for grading, progression, and records; a host model must not fabricate completion.

## Evaluation boundaries

See [the evaluation guide](../evals/README.md). Offline fixture validation measures structure and coverage, not policy truth, model behavior, app security, or compliance. Published cases are a development corpus. Passing them would still not establish universal safety; use separate held-out scenarios, record failures, and verify actual artifacts/actions before broader claims.
