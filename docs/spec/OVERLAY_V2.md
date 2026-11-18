# Overlay version 2: design note

**Status:** Approved on 2026-11-17 in [issue #92](https://github.com/catpilotai/catpilot-ai-guardrails/issues/92), with the decisions in §7. The first build's file format is implemented: every reader accepts `schema_version: 1` and `2`, `tools/validate_overlay.py` checks every rule in §6.3 and has `migrate`, and no bundle, paste block, company-checklist block, benchmark prompt or server answer carries `enforcement`. `tools/validate_overlay.py compile` writes the `enforcement` section as the JSON policy the company-rules hook (`hooks/claude-code/pretooluse-company-rules.py`, `catpilot_guard/company_rules.py`) reads, and prints each rule's effect per tool (§2.3). The hook acts on `protected_branch` rules in `monitor`, `ask` and `block` on Claude Code and Codex (`ask` acts as `block` unless an administrator adds `--ask` to the hook's command line: the hook cannot tell a person from a program that approves, see decision 2), writes `deny`, `ask` and `would_deny` evidence with `rule_id` and `mode`, and `deploy/org/install.sh --overlay` places and registers it; not yet run on a host. Topic contacts (§3.1) are implemented: the validator checks `contacts`, `check_plan` takes `who_to_ask` and the escalation draft's recipient from the contact for the field that decided the outcome, `list_approved("contacts")` returns them, and the session-start rules block lists them. The hook also acts on `deploy_host` rules (`catpilot_guard/deploy_targets.py` reads what a command deploys to; not yet run on a host). Not yet implemented: the pull-request check, `check_plan` deciding by id or alias with `rule_id` and `matched_by`, ids in `list_approved` (§2.1), expiring exceptions (§3.1) and everything in §3.2.
**Companion to:** [`OVERLAY.md`](./OVERLAY.md) (version 1), [`overlay.schema.json`](./overlay.schema.json), [`overlay.example.yaml`](./overlay.example.yaml). Version 2: [`overlay.v2.schema.json`](./overlay.v2.schema.json), [`overlay.v2.example.yaml`](./overlay.v2.example.yaml).

The overlay is the company rules file. Version 1 is written to advise a model.
Version 2 would let hooks, a pull-request check and `check_plan` match the
same rules exactly, without putting machine values in front of a model. This
note proposes a first build, a next increment, and what waits. The maintainer
approved it on 2026-11-17 with the decisions in §7, which this text already
reflects.

---

## 1. The problem

Version 1 is one flat file of model-facing phrases: lists of at most 30
items, each at most 200 characters, one `owner`, no identifiers and no modes.
That is enough to advise a model. It is not enough for anything that must
match exactly.

**No exact matching.**

- **Hooks** do not read the overlay. In
  `hooks/claude-code/pretooluse-destructive-ops.py` the protected branches are
  a hardcoded regex, `PROTECTED_BRANCH` (`main`, `master`, `trunk`,
  `production`, `prod`, `staging`, `develop`, `release/*`). A company that also
  protects `hotfix/*` has no place to say so.
- **A pull-request check** does not exist yet. When it does, it needs host
  names and account ids to compare a deployment file against. Version 1 has no
  field for them, and its content scan (`validate_content()` in
  `tools/validate_overlay.py`) rejects every IP address and every URL outside
  `templates` and `intake_url`.
- **`check_plan`** matches free text against phrases. `_overlay_hits()` and
  `_approved_mention()` in `mcp-server/catpilot_guardrails_mcp/tools.py`
  compare normalized content words and synonym lists ("unmanaged", "free
  tier"), so the outcome depends on wording. `mcp-server/README.md` says so:
  "Matching is deterministic keyword work, and it is not judgment."

**No stable ids.** A decision's `rule` is the phrase itself
(`"rule": "Personal cloud accounts"`). Edit the phrase and every reference to
it breaks: an evidence query, a CI configuration, a future exception.

**One owner.** `owner` is one string. `check_plan` puts it in `who_to_ask` and
the escalation draft, whatever the question is about: data, hosting, a
service or sign-in.

**No modes.** A hook denies or returns nothing. A company cannot roll a rule
out in monitor mode first, or have a person confirm instead of a hard deny.

**Why not add the values to version 1 lists.** Every list is rendered for a
model: into private bundles by `overlay_slot_values()` and paste-size targets
by `overlay_values_block()` (both in `tools/bundle.py`), and returned as it
stands by `list_approved`. The benchmark's `company_checklist_instruction()`
in `tools/bench/sandbox.py` puts the whole validated file into a prompt. A
branch name, internal host or account id in a list would reach the model
everywhere. Machine values need a section that no renderer reads.

## 2. Proposal

This is issue #92's recommendation, option 2: stable ids with aliases, a
machine-only `enforcement` section, a mode per enforcement rule, and version 1
files valid unchanged with a `migrate` path. Every field has a named consumer
(§4).

### 2.1 Stable ids, with aliases

Every model-facing list item becomes an object: an `id`, and its version 1
phrase as `text`.

```yaml
hosting:
  approved:
    - id: hosting-app-platform
      text: "Internal App Platform (company sign-in)"
      aliases: [hosting-internal-app-platform-company-sign-in]
```

- This applies to every list under `data_classes`, `hosting`, `services`,
  `identity.never` and `review_triggers`, and to `identity.default`, which
  becomes one item. `templates` keep `kind` as their id. `owner`,
  `organization`, `intake_url` and the dates stay plain values.
- An id is lowercase letters, digits and single hyphens, at most 64
  characters: the grammar `templates[].kind` already uses. It is unique across
  the file, aliases and enforcement rule ids included, so a `rule_id` names one
  thing.
- `aliases` are former ids. A renamed item keeps its old id as an alias, so
  existing references keep working. Aliases match exactly; they are not
  synonyms for the keyword matcher. An id is never reused for a different
  thing.

`check_plan` accepts an id or alias in `hosting`, `services` and
`data_classes` and decides it without the keyword matcher. Each decision gains
`rule_id` and `matched_by` (`id`, `alias`, `text` or `none`). Free text still
goes through today's matcher, labeled as the weaker basis. `list_approved` and
the session-start rules block show ids so a model can pass them back. Evidence
lines carry `rule_id`. Bundle slots render `text` only, so skill text does not
change.

### 2.2 A machine-only `enforcement` section

```yaml
enforcement:
  default_mode: monitor
  rules:
    - id: protected-branches
      kind: protected_branch
      mode: block
      values: ["main", "release/*", "hotfix/*"]
    - id: deploy-hosts
      kind: deploy_host
      use_instead: hosting-app-platform
      values: ["apps.example.org", "*.apps.example.org"]
```

A rule has an `id`, a `kind`, an optional `mode` (§2.3), its `values`, and an
optional `use_instead`: the id of an approved item whose `text` a deny reason
offers as the alternative. The section has no free text. The kind fixes what
the values mean and when the rule fires; a file cannot change that.

| Kind | Values | Fires on | First consumer |
| --- | --- | --- | --- |
| `protected_branch` | Branch names; a trailing `/*` covers the prefix, as `release/*` does today | A force push or deletion aimed at a listed branch, or a bare force push while one is checked out | The destructive-operation hook, alongside `PROTECTED_BRANCH` |
| `deploy_host` | Approved host names; a leading `*.` covers subdomains | A deploy or publish command, or deployment file, targeting an unlisted host | A hook; the pull-request check |
| `package_registry` | Approved registries: a host name, optional path | An install, publish or registry setting naming an unlisted registry | A hook; the pull-request check |
| `cloud_account` | `aws:<12 digits>`, `azure:<subscription id>`, `gcp:<project id>` | A cloud command or deployment file naming an unlisted account | A hook; the pull-request check |

- `protected_branch` is a protect-list: a listed value fires the rule. The
  other three are allow-lists: an unlisted value fires it. The difference
  matters for exceptions and inheritance (§3).
- Which commands and files a consumer recognizes, and whether it reads a
  target as a host or an account, is that consumer's design, written up in an
  "Exact coverage" section like those in `hooks/README.md`.
- A kind enters the schema in the same pull request as its first consumer.
  The first build carries `protected_branch` and `deploy_host`.

**Never rendered, never returned.** `values` never leave the hooks and the
pull-request check (§6.1). The server and every renderer get the file with
`enforcement` removed right after validation. A rule's `id`, `mode` and
resolved `use_instead` text may appear in a deny reason and in evidence.
`check_plan` does not read `enforcement` even internally: if its answer
depended on the listed hosts, a caller could learn the list one guess at a
time.

**How hooks get it.** Hooks are standard library only and cannot parse YAML.
A `compile` step, designed with the hook work, writes a JSON policy with the
enforcement rules, `expires_on` and the source file's SHA-256. A hook reads it
only from a path on its own command line, root-owned like the hook scripts,
never from the project, the home directory or an environment variable.

A deny reason would read, for example: "Catpilot company rule `deploy-hosts`:
this deploy targets a host the company has not approved. Use instead: Internal
App Platform (company sign-in). If this exact command is intentional, run it
yourself in your own terminal." It names no host and repeats no command.

### 2.3 Modes: `monitor`, `ask`, `block`

**What a hook can express.** A Claude Code `PreToolUse` hook can deny the call,
ask the person to confirm it, allow it, or return nothing so the host's own
permission rules apply. This repository's hooks never return allow. Codex runs
the same hooks as managed hooks (`docs/DEPLOY_ORG.md`) and reads the same deny
shape, but its documentation says `permissionDecision: "ask"` is not supported:
the hook run fails and the call continues. On Codex a hook must therefore turn
`ask` into a deny itself; `--host codex` tells it which host it is on. That
leaves three effects: deny, ask, nothing.

| Mode | Claude Code hook | Where no prompt is possible | Pull-request check | Evidence event |
| --- | --- | --- | --- | --- |
| `monitor` | No decision | No decision | Annotation; the check passes | `would_deny` |
| `ask` | `ask`: the host asks the person, who decides | Deny | Fails | `ask`, or `deny` where it fell back |
| `block` | Deny | Deny | Fails | `deny` |

When several rules match one action, the strictest mode wins, and evidence
records each rule.

**Why `ask`, not `warn`.** Issue #92 sketched `monitor` / `warn` / `block`.
This note proposes `ask` in place of `warn`:

- Each word says what the person sees, and the three map one to one onto the
  three effects a hook has.
- In other policy tools, "warn" usually means the action runs and the person
  sees a message. Claude Code documents a message field for hooks, but this
  repository has not checked when a person sees it, and this note assumes
  nothing about Codex. Until a host check shows the message is seen before the
  action runs, `warn` would be `monitor` with a note nobody is sure was read,
  or `ask` under a misleading name.
- The agent cannot answer a host permission prompt, so `ask` adds no bypass
  an agent can use.

**Fallback.** Where no prompt is possible (Codex as documented, the
pull-request check, and possibly a non-interactive Claude Code run), `ask`
acts as `block`. `ask` means a person decides before the action runs, and a
deny keeps that true: the reason tells the person to run the command
themselves, as the hooks do today. Falling back to `monitor` would let the
action run with nobody asked. Lint prints each rule's effective mode per host
before rollout.

**Defaults.** `default_mode` applies to rules with no `mode`, and is `monitor`
when omitted. New rule kinds should start in `monitor`: a false block costs
more trust than a missed one.

**The built-in checks are not modes.** Today's hardcoded checks stay `block`,
and no file can change that. A company `protected_branch` list adds to
`PROTECTED_BRANCH`; it cannot remove `main`, and a company rule in `monitor`
does not soften a built-in deny.

**Not checked on a host.** How Claude Code handles `ask` in each permission
mode, and in a run with nobody to answer, needs a host check before `ask` is
documented as working. That includes the modes in which Claude Code approves
actions without asking a person, such as auto mode and bypass permissions: if
an `ask` is approved there with no person involved, `ask` must act as `block`
in those modes. An `ask` evidence line records that the person was
asked, not what they chose: a `PreToolUse` hook does not see the answer.

### 2.4 Version 1 stays valid; `migrate`

- Every reader dispatches on `schema_version`. `1` gets the version 1 rules,
  unchanged. `2` gets version 2. Anything else is rejected.
- `docs/spec/overlay.example.yaml` stays a version 1 file and keeps validating
  unchanged.
- `migrate` converts a version 1 file to version 2. It sets
  `schema_version: 2`, turns each phrase into `{id, text}`, copies everything
  else, and adds no `enforcement` section, and so no `salt` (§6.3 rule 10).
  `reviewed_on` and `expires_on` stay, because no value changed. Adding enforcement rules afterwards is a change a
  reviewer approves, with new dates.
- Ids come from the text: a prefix for the list (`data`, `hosting`,
  `service`, `identity`, `trigger`), a hyphen, then the text lowercased with
  each run of other characters turned into one hyphen, cut at a hyphen to at
  most 48 characters; a repeat gets `-2`, `-3`. The output is deterministic.
  Comments are not carried over. A company can shorten an id later and keep
  the generated one as an alias. A phrase with no ASCII letter or digit gets
  the bare prefix as its id (`data`, then `data-2`), so a company writing in
  another script should replace those ids by hand.
- A migrated file must render the same bundle body and paste block as its
  source, and `check_plan` must give the same outcome for the same free-text
  call. The build adds tests for both on the example.
- A version 1 reader rejects a version 2 file: `validate_structure()` raises
  `schema_version: expected 1`. An older server therefore answers with
  `unknown_policy` instead of misreading the file. Upgrade readers before
  files.

### 2.5 Alternatives not chosen

- **Option 1: keep version 1 and put enforcement data in a separate file.**
  Two files carry two review dates and two hashes and can drift apart, and a
  rule in one cannot point at an item in the other (`use_instead`). Its one
  advantage, machine values kept out of the model-facing file, the proposal
  gets by removing `enforcement` at load and testing that (§6.1).
- **Option 3: option 2 plus exceptions, topic contacts, `extends` and a
  signature from the start.** Four more features, each with its own
  validation and merge rules, before anything reads them. §3 sequences them.
- **Nesting the model-facing lists under a `rules` key.** It would change
  every version 1 path for no consumer's benefit.

## 3. Later work

### 3.1 Next increment: topic contacts and expiring exceptions

Designed here, not in the first build. Topic contacts are implemented; expiring
exceptions are not.

**Topic contacts.** *Implemented.*

```yaml
contacts:
  data: {name: "privacy-office@example.org"}
  hosting: {name: "Platform team, #platform-help", intake_url: "https://intake.example.org/hosting"}
  services: {name: "vendor-review@example.org"}
  identity: {name: "identity-team@example.org"}
```

- The topics are a closed list matching `check_plan`'s fields: `data`
  (`data_classes`), `hosting`, `services`, and `identity` (`audience`).
  `owner` stays required and remains the default.
- `check_plan` takes `who_to_ask` and the escalation draft's recipient from
  the contact for the field that decided the outcome. A tie between topics,
  or `write_access`, which has no topic, uses `owner`.
  `list_approved("contacts")` returns the contacts, and the session-start
  rules block lists them.
- `name` follows the `owner` rules, so an email address is allowed.
  `intake_url` follows the version 1 `intake_url` rules.

*How it was built:*

- `contacts` is optional and holds one or more of the four topics; any other
  key is an error that names it. A contact is `{name, intake_url?}`: `name` is
  3 to 160 characters, and the content scan accepts an email address in a
  contact's `name` as it does in `owner`, and still nowhere else. `intake_url`
  is https with its host on the `--allow-host` allowlist, no credentials,
  query string or fragment. A contact's `name` counts as model-facing text for
  §6.3 rule 7; its `intake_url` is exempt, as `intake_url` is, so a host on the
  `--allow-host` allowlist that is also an enforcement value reaches a model
  through it: keep enforcement hosts off the allowlist. `null` is
  refused, as elsewhere in version 2. A version 1 file with `contacts` is
  rejected as an unknown field, as before.
- Contacts are model-facing: `model_facing()` keeps them, so the rules block
  shows them, and its sentence on whom to ask names them. `v1_projection()`
  drops them, so bundle slots and paste blocks, which render the projection,
  keep naming `owner` and render as before.
- **The field that decided.** `check_plan`'s `outcome` is the worst outcome
  across its decisions. When that outcome is `prohibited` or
  `requires_review`, the fields that decided it are the fields of the
  decisions whose outcome equals it. If they are one field with a topic, and
  the file has a contact for that topic, `who_to_ask`, the escalation draft's
  `to` (and its `mailto_url`) and the person `next_step` names are that
  contact's `name`, and the draft's `intake_url` is the contact's when it has
  one, else the file's own. Several decisions from one field (two data
  classes, say) are one field. Everything else uses `owner`: decisions at the
  outcome from two or more fields, a deciding `write_access` or
  `credential_references` decision (no topic), another field with a decision
  that also needs a person (`prohibited` or `requires_review` below the
  outcome), since the escalation draft lists every such item and one topic's
  contact should not receive another topic's questions, a topic with no
  contact, and
  an outcome of `permitted` (every field decided it) or `unknown` (it waits on
  the caller's answers, so a person is asked then only because of a hint,
  which names no field). The decision is by field, not by component: a
  credential named in `data_classes` goes to the `data` contact.
- `check_plan` adds `contact_topic`, the topic whose contact `who_to_ask`
  names, or `null` when it is `owner`, only when the file has contacts;
  answers from a version 1 file, or a version 2 file without contacts, keep
  their exact shape. `list_approved("contacts")` returns `owner` as before
  and adds `contacts` when the file has them.

**Expiring exceptions.**

```yaml
enforcement:
  exceptions:
    - id: exception-analytics-preview
      rule: deploy-hosts
      allows: ["preview.analytics.example.org"]
      approver_role: "Platform security lead"
      expires_on: 2027-02-01
```

- An exception relaxes one company rule, named by id or alias. It never
  relaxes a built-in check.
- It lives next to the rule it relaxes. For an enforcement rule it sits in
  `enforcement.exceptions`, is machine-only, and its `allows` are values of
  that rule's kind. For a model-facing rule it sits in a top-level
  `exceptions` list, its `allows` are item ids, and `check_plan` names it and
  its expiry in the decision's note.
- `approver_role` is a role, not a person's name. `expires_on` is required and
  no later than the file's own. An expired exception is ignored, and the rule
  applies as written.
- An optional `where: {repositories: [...]}` limits an exception to named
  repositories. Only the pull-request check reads it, because it takes the
  repository from the CI platform. Hooks apply only exceptions without
  `where`: a repository name read from a working tree is something the agent
  can change. To scope an exception to a group of machines, deploy a different
  file to them.
- When an exception changes a decision, evidence records its
  `exception_id`.

### 3.2 Deferred until a pilot needs them

**`extends` inheritance.** A file would name one parent file, and `compile`
would merge the two.

- Rules, written down now so a later build is sound: a child adds approvals
  and prohibitions and never removes a parent's prohibition. For an
  allow-list kind the parent's list is the outer bound, so a child can only
  narrow it. Protect-lists combine. A child cannot carry an exception against
  a parent's rule. The result expires at the earliest `expires_on` in the
  chain. Merging happens at compile time, never at run time.
- Why wait: deploying a different file to each group of machines already
  gives scopes, with no merge rules. Inheritance adds a resolution step every
  consumer must perform identically, and "never remove a prohibition" is easy
  to get wrong for allow-lists.
- Trigger: an organization that keeps two or more files with mostly shared
  content, approved by different reviewers (a central security team and a
  business unit, say), and has seen them drift.

**A detached signature.** A signature file over the exact bytes, checked at
compile or install time, where dependencies are allowed. Hooks would not
check it: they stay standard library only, trust the compiled file because it
is root-owned, and record its hash.

- Why wait: on a managed machine the trust boundary is who can write the
  root-owned file. A signature adds nothing there that a hook could check
  without a dependency, and the hash in each evidence line already ties a
  decision to one version.
- Trigger: a file that travels through a channel the administrator does not
  control end to end (a shared drive, another party's CI, a hosted service),
  or an auditor who needs proof of which reviewer approved which bytes beyond
  the review record and the hash. Signing is a person's act; no tool signs
  for a reviewer.

## 4. Field by consumer

**Hook** is the hooks, reading the compiled policy. **PR check** is the
planned pull-request check. **Server** is `check_plan`, `list_approved` and
`get_guidance`. **Rules block** is the planned session-start rules block plus
today's bundle slots and paste blocks. **Evidence** is the local evidence log.

| Field | Read by | Never sent to | Ships |
| --- | --- | --- | --- |
| `schema_version: 2` | Every reader | — | First build |
| Item `id` | Server (decides by it, returns it), Rules block, Evidence (`rule_id`); Hook and PR check through `use_instead` | — (model-facing) | First build |
| Item `text` | Server, Rules block (slots render it unchanged); Hook and PR check as the `use_instead` label | — (model-facing) | First build (the version 1 phrase) |
| Item `aliases` | Server (exact match), validator | Rules block and bundles: no consumer there | First build |
| `enforcement.default_mode` | Hook, PR check | Server, Rules block | First build |
| `enforcement.rules[].id`, `kind`, `mode` | Hook, PR check; deny reasons and Evidence carry `id` and `mode` | Server, Rules block | First build |
| `enforcement.rules[].values` | Hook, PR check | Server, Rules block, Evidence, deny reasons, PR annotations | First build for `protected_branch` and `deploy_host`; other kinds with their first consumer |
| `enforcement.rules[].use_instead` | Hook, PR check (resolved to the item's `text`) | Server, Rules block | First build |
| `salt` | Validator only; it changes the file's SHA-256, which the Rules block, the Server and Evidence carry | Server, Rules block, Evidence, deny reasons | First build (§6.3 rule 10) |
| `contacts.<topic>` | Server (`who_to_ask`, escalation draft, `list_approved`), Rules block (the session-start block; bundle slots and paste blocks keep `owner`) | Hook, PR check (not needed) | Next increment; implemented |
| `exceptions[]` (model-facing rules) | Server (decision note) | Hook, PR check (not needed) | Next increment |
| `enforcement.exceptions[]` | Hook (only without `where`), PR check; Evidence carries `exception_id` | Server, Rules block | Next increment |
| `extends` | `compile` only | Every run-time consumer: it is resolved before them | Deferred |
| Detached signature (a separate file) | `compile` or install | Hook: it trusts ownership and records the hash | Deferred |

A PR annotation points at the line in the diff. It never prints the listed
values.

## 5. Examples

Every value is synthetic Example Org data. Never commit a real rules file to
a public repository.

### 5.1 A complete version 2 file

First-build fields and topic contacts (§3.1). It is the file from §5.2 after
a reviewer approved shorter ids (the generated ones kept as aliases where
something already referred to them), one new service, topic contacts, and an
`enforcement` section, with new review dates. It is
[`overlay.v2.example.yaml`](./overlay.v2.example.yaml), and the tests check
that the two match and that it validates once its published salt is replaced.

*Corrected when the first build was implemented, to follow §6.3:* the
approved version of this example also had a `package_registry` rule and a
`cloud_account` rule, which rule 4 rejects until their consumers ship, and
review dates (2026-12-01 to 2027-06-01) that the expiry-window check rejects
before 2026-12-01. They are shown after the example instead, and the dates are
the approval date and six months later, the span the version 1 example uses.
The example also gained a `salt` after approval (§6.3 rule 10). Its value is
published here, so the validator rejects it: replace it with `python tools/validate_overlay.py salt FILE`.
It gained `contacts` when topic contacts were implemented. Its hosting contact
has no `intake_url`, unlike the one in §3.1, so the example validates without
`--allow-host`.

```yaml
schema_version: 2
organization: "Example Org"
owner: "security-review@example.org"
reviewed_on: 2026-11-17
expires_on: 2027-05-17

contacts:
  data: {name: "privacy-office@example.org"}
  hosting: {name: "Platform team, #platform-help"}
  services: {name: "vendor-review@example.org"}
  identity: {name: "identity-team@example.org"}

data_classes:
  never_in_prompts:
    - {id: data-cardholder, text: "Cardholder data and bank details", aliases: [data-cardholder-data-and-bank-details]}
    - {id: data-government-ids, text: "Government identifiers", aliases: [data-government-identifiers]}
    - {id: data-health-records, text: "Health records"}
    - {id: data-employee-hr-records, text: "Employee HR records"}
    - {id: data-credentials, text: "Passwords, keys, tokens, and sign-in codes", aliases: [data-passwords-keys-tokens-and-sign-in-codes]}
  ok_with_approval:
    - {id: data-customer-contacts, text: "Customer names and business email addresses"}
  ok:
    - {id: data-synthetic, text: "Made-up records with example.com addresses"}
    - {id: data-published-product-info, text: "Published product information"}

hosting:
  approved:
    - {id: hosting-app-platform, text: "Internal App Platform (company sign-in)", aliases: [hosting-internal-app-platform-company-sign-in]}
    - {id: hosting-power-apps, text: "Power Apps in the company tenant"}
    - {id: hosting-cloud-subscription, text: "The approved cloud subscription managed by IT"}
  not_approved:
    - {id: hosting-personal-cloud, text: "Personal cloud accounts"}
    - {id: hosting-free-tier, text: "Free-tier hosting"}
    - {id: hosting-unmanaged-vms, text: "Unmanaged virtual machines"}

services:
  approved:
    - {id: service-llm-gateway, text: "The company LLM gateway"}
    - {id: service-email, text: "The approved transactional email service"}
    - {id: service-object-storage, text: "Internal object storage"}
    - {id: service-package-mirror, text: "The internal package mirror"}
  needs_review:
    - {id: service-new-software, text: "Any new software service"}
    - {id: service-new-model-endpoint, text: "Any new model endpoint"}
    - {id: service-browser-extensions, text: "Browser extensions"}

identity:
  default: {id: identity-default, text: "Company sign-in, smallest named group that needs access"}
  never:
    - {id: identity-shared-passwords, text: "Shared passwords"}
    - {id: identity-public-links, text: "Public links for internal tools"}

review_triggers:
  - {id: trigger-external-users, text: "External users"}
  - {id: trigger-payments, text: "Payments or refunds"}
  - {id: trigger-system-of-record-writes, text: "Writes to a system of record"}

# Machine-only. Required with enforcement; set your own with
#   python tools/validate_overlay.py salt FILE
# This published value is rejected.
salt: "0123456789abcdef0123456789abcdef"

# Machine-only: never rendered into a prompt, never returned by the server.
enforcement:
  default_mode: monitor
  rules:
    - id: protected-branches
      kind: protected_branch
      mode: block
      values: ["main", "release/*", "hotfix/*"]
    - id: deploy-hosts              # default_mode applies: monitor
      kind: deploy_host
      use_instead: hosting-app-platform
      values: ["apps.example.org", "*.apps.example.org"]
```

When the `package_registry` and `cloud_account` kinds ship with their first
consumers, the same file could add these two rules:

```yaml
    - id: package-registries
      kind: package_registry
      use_instead: service-package-mirror
      values: ["npm.example.org", "pypi.example.org/simple"]
    - id: cloud-accounts
      kind: cloud_account
      mode: ask
      use_instead: hosting-cloud-subscription
      values: ["aws:111122223333", "azure:00000000-0000-0000-0000-000000000000", "gcp:example-org-apps"]
```

### 5.2 The version 1 example, migrated

What `migrate` prints for
[`overlay.example.yaml`](./overlay.example.yaml)
(`python tools/validate_overlay.py migrate docs/spec/overlay.example.yaml`),
byte for byte; a test checks it. Only `schema_version` and the shape of each
item change. The dates stay, and there is no `enforcement` section.

```yaml
schema_version: 2
organization: "Example Org"
owner: "security-review@example.org"
reviewed_on: 2026-09-13
expires_on: 2027-03-13

data_classes:
  never_in_prompts:
    - {id: data-cardholder-data-and-bank-details, text: "Cardholder data and bank details"}
    - {id: data-government-identifiers, text: "Government identifiers"}
    - {id: data-health-records, text: "Health records"}
    - {id: data-employee-hr-records, text: "Employee HR records"}
    - {id: data-passwords-keys-tokens-and-sign-in-codes, text: "Passwords, keys, tokens, and sign-in codes"}
  ok_with_approval:
    - {id: data-customer-names-and-business-email-addresses, text: "Customer names and business email addresses"}
  ok:
    - {id: data-made-up-records-with-example-com-addresses, text: "Made-up records with example.com addresses"}
    - {id: data-published-product-information, text: "Published product information"}

hosting:
  approved:
    - {id: hosting-internal-app-platform-company-sign-in, text: "Internal App Platform (company sign-in)"}
    - {id: hosting-power-apps-in-the-company-tenant, text: "Power Apps in the company tenant"}
    - {id: hosting-the-approved-cloud-subscription-managed, text: "The approved cloud subscription managed by IT"}
  not_approved:
    - {id: hosting-personal-cloud-accounts, text: "Personal cloud accounts"}
    - {id: hosting-free-tier-hosting, text: "Free-tier hosting"}
    - {id: hosting-unmanaged-virtual-machines, text: "Unmanaged virtual machines"}

services:
  approved:
    - {id: service-the-company-llm-gateway, text: "The company LLM gateway"}
    - {id: service-the-approved-transactional-email-service, text: "The approved transactional email service"}
    - {id: service-internal-object-storage, text: "Internal object storage"}
  needs_review:
    - {id: service-any-new-software-service, text: "Any new software service"}
    - {id: service-any-new-model-endpoint, text: "Any new model endpoint"}
    - {id: service-browser-extensions, text: "Browser extensions"}

identity:
  default: {id: identity-company-sign-in-smallest-named-group, text: "Company sign-in, smallest named group that needs access"}
  never:
    - {id: identity-shared-passwords, text: "Shared passwords"}
    - {id: identity-public-links-for-internal-tools, text: "Public links for internal tools"}

review_triggers:
  - {id: trigger-external-users, text: "External users"}
  - {id: trigger-payments-or-refunds, text: "Payments or refunds"}
  - {id: trigger-writes-to-a-system-of-record, text: "Writes to a system of record"}
```

## 6. Invariants and rules

### 6.1 Privacy and safety invariants

1. **Enforcement data never reaches a model.** `enforcement` is removed at
   load for the server and every renderer, and no deny reason or annotation
   prints a listed value. Test: plant a marker in every enforcement value and
   exception; assert it appears in no bundle, paste block, rules block,
   benchmark prompt, MCP response, deny reason or evidence line. The file's
   SHA-256 does reach a model (the rules block's `Overlay SHA-256` line, the
   server's `policy_source`, the bundle manifest), and a file made by
   `migrate` or copied from §5.1 is predictable enough that the hash would
   confirm guessed enforcement values offline. A file with `enforcement`
   therefore carries a random `salt` (§6.3 rule 10), which is machine-only
   like `enforcement` and never appears in a message.
2. **Evidence stays content-free.** A line carries the event, `rule_id`,
   `mode`, `exception_id`, the policy hash and the session id. Never a
   command, a file path, a prompt, a description or a value from
   `enforcement`. Each new field gets a row in the recorded and never-recorded
   table in `docs/DEPLOY_ORG.md` when it ships.
3. **Hooks never resolve identity at run time.** No hook looks up who the
   person is (a directory, a token, `git config user.email`) to choose rules,
   modes or exceptions. The scope is which compiled file a machine receives.
4. **A narrower scope can add prohibitions but never remove one.** No file
   lowers the built-in checks. A company protect-list adds to the built-in
   one. An exception relaxes only a company rule, in the file that holds that
   rule, until a date. A child file (§3.2) cannot remove a parent's
   prohibition and can only narrow a parent's allow-list.
5. **A file is never less careful than no file.** An invalid, unreadable or
   wrongly owned file means the built-in checks in `block`, generic defaults on
   the server, and a `policy_error` evidence line. An expired file's company
   enforcement rules act in `monitor` until it is renewed: nothing is blocked on
   stale values, each match still writes a `would_deny` line, and the built-in
   checks stay in `block` (decision 3, §7). Never allow. An unlisted data class
   still gets the generic outcome.
6. **No switch the agent can reach.** No mode, exception or policy path comes
   from a project file, the home directory, an environment variable or a tool
   argument. A person answers `ask`.

### 6.2 Compatibility and versioning

- Version 1 files stay valid and render as they do today for as long as
  version 2 is supported.
- A reader rejects an unknown `schema_version`. The result is the built-in
  checks and `unknown_policy`, never a guess.
- Within version 2, changes are additive: new optional fields only. Readers
  reject unknown fields, as version 1 does today (`additionalProperties:
  false`), so a file that uses a newer field fails closed on an older reader.
  Deploy readers before files.
- Removing or renaming a field, or changing what one means, needs
  `schema_version: 3`.
- An id is never reused. A rename keeps the old id as an alias.
- `check_plan` and `list_approved` responses only gain keys: `rule_id`,
  `matched_by`, and ids in a new key beside today's lists. Existing keys keep
  their meaning.
- `migrate` is one-way. `compile` is deterministic: the same input gives
  byte-identical output, and each output records the source SHA-256.

### 6.3 Validation rules

Version 1's checks stay for every model-facing value: phrase and list
limits, the content scan, the expiry window, the 128 KiB size limit and the
refusal of symlinks. Version 2 adds:

1. `schema_version` is `1` or `2`, and a file is checked only against its own
   version's rules.
2. Every list item is an object with `id` and `text`, and optional `aliases`.
   A plain string is a version 1 item and is rejected in a version 2 file.
3. Ids and aliases match `^[a-z0-9]+(?:-[a-z0-9]+)*$`, are at most 64
   characters, and are unique together across the file: item ids, aliases,
   enforcement rule ids and exception ids. An item has at most 5 aliases.
4. `enforcement` is optional. `default_mode` and every `mode` are `monitor`,
   `ask` or `block`. A file has 1 to 50 rules. `kind` comes from the closed
   list in §2.2, limited to kinds whose consumer has shipped.
5. A rule has 1 to 100 values, unique after normalization, each matching its
   kind:
   - `protected_branch`: a valid Git branch name (no spaces, `..`, `~`, `^`,
     `:`, `?`, `[`, `\` or leading `-`), with at most one `*`, and only as a
     trailing `/*`.
   - `deploy_host`: a lowercase host name with at least one dot, optionally
     starting with `*.`; no scheme, port, path, credentials or IP address.
   - `package_registry`: such a host name, optionally followed by a path of
     letters, digits, `.`, `_`, `-` and `/`; no scheme, query or credentials.
   - `cloud_account`: `aws:` and 12 digits; `azure:` and a lowercase GUID; or
     `gcp:` and a project id (6 to 30 lowercase letters, digits and hyphens,
     starting with a letter).
6. `use_instead` resolves to an id or alias of an item in `hosting.approved`
   or `services.approved`.
7. No `deploy_host`, `package_registry` or `cloud_account` value appears,
   ignoring case and a leading `*.`, in any model-facing phrase, id or alias,
   or in `organization`, `owner` or a contact's `name`. URLs in `templates`,
   `intake_url` and a contact's `intake_url` are exempt: their hosts are
   already on the operator's allowlist.
8. The secret scan runs over the whole file, `enforcement` included.
9. Lint warnings, which do not fail validation: a rule whose effective mode
   differs by host (`ask` where no prompt is possible); a rule in `block` for
   a kind with no host verification note yet; and, in the next increment, an
   exception within 14 days of expiry.
10. A file with `enforcement` has a top-level `salt`: a quoted string of 32 to
    128 lowercase hex characters, chosen at random. Without it, the whole-file
    hash a model sees would let anyone with the rules block test guesses at
    enforcement values offline (§6.1). `python tools/validate_overlay.py salt FILE` is the way to set one: it
    writes a 64-character salt from `secrets.token_hex(32)` and changes no
    other line, keeping an existing salt line's ending and trailing comment.
    The validator rejects a salt that is, or starts with, a well-known
    published value (test vectors such as `000102…0f` and `2b7e1516…`, the
    MD5 and SHA-256 of nothing, hex words); one within a Hamming distance of
    half its length of the published example's (over the shorter length); one
    that repeats a pattern (a period of at most half its length, as digits or
    as bytes); one with fewer than 8 different hex digits; one with a run of 8
    or more consecutive ascending or descending hex digits (`01234567`,
    `fedcba98`); one with 6 or more bytes in a row that step evenly
    (`00 01 02 …`, `00 11 22 …`); and one whose digit-to-digit steps repeat
    with a period of at most 4 (`a1b2c3…`). These checks catch common
    mistakes; they do not measure randomness. A random salt is rejected about
    once in 10^7 at 32 characters and once in 4 × 10^6 at 64, almost all of
    it from the run-of-8 check; none of 1,200,000 random salts was.
    `salt` is machine-only: never rendered, never returned, never in an error
    message.

*Added after approval:* rule 10, and two readings of the rules as written.
Rule 3 also counts template kinds, since templates keep `kind` as their id
(§2.1). A key that appears twice in one mapping is refused in both versions,
since YAML would otherwise keep only the last one, and so is a YAML merge key
(`<<`), which would change values just as quietly.

*How the first build reads two of these rules:* rule 4 accepts the first
build's two kinds, `protected_branch` and `deploy_host` (§2.2), although their
hook consumer lands in a later pull request; until then those rules are
validated only. Rule 7 checks an id, alias or template kind for the value with
each run of other characters as one hyphen (`apps.example.org` as
`apps-example-org`), since an id cannot hold a dot. Rule 7 matches substrings,
so a `deploy_host` value `*.example.org` also rejects an `owner` such as
`security-review@example.org`.

## 7. Decisions (2026-11-17)

The maintainer approved this note in #92 with these answers to its open
questions:

1. **Mode names:** `monitor` / `ask` / `block`. Each says what the person sees,
   and "warn" would promise a message nobody has shown is read before the
   action runs.
2. **`ask` with no prompt** acts as `block`: on Codex, in the pull-request
   check (which fails), in a run with nobody to answer, and in Claude Code
   modes that approve without asking a person. `ask` means a person decides
   first; falling back to `monitor` would let the action run with nobody asked.
3. **Expiry and the hooks:** when the file expires, its company enforcement
   rules act in `monitor` until it is renewed. Nothing is blocked on stale
   values, each match still writes a `would_deny` line, and the built-in checks
   stay in `block`. This matches the session-start script, which tells the model
   and the person that expired rules are not in force.
4. **Plain strings in a version 2 list** are rejected. `migrate` turns a
   version 1 file's strings into items with ids, so every rule has an id that
   evidence and exceptions can name.
5. **Hosts in phrases:** rule 7 in §6.3 is an error, not a lint warning. The
   `enforcement` section stays out of prompts and server answers, so its values
   cannot reach a model through a phrase either.
6. **No rollout window for the built-in checks** in the first build: they stay
   in `block`. Revisit if a pilot asks ([#93](https://github.com/catpilotai/catpilot-ai-guardrails/issues/93)).
7. **Catpilot Plus:** settled with the maintainer; nothing in this note depends
   on it.
