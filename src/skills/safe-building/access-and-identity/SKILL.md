---
name: access-and-identity
description: Default every app to the company's own sign-in and the smallest audience that needs it. Ask who should be able to open it, and flag public links, shared passwords, and everyone-can-see settings before they are chosen.
license: MIT
metadata:
  catpilot:
    id: access-and-identity
    title: Access and identity
    version: 1.0.0
    severity: high
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["2.2", "3.3"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC6.1, CC6.2, CC6.3]
      pci_dss: ["7.2", "8.2", "12.6"]
      iso_27001: [A.9.2.1, A.9.4.1]
      nist_csf: [PR.AC-1, PR.AC-4]
      owasp_top_10: ["A01:2021", "A07:2021"]
    provenance:
      origin: catpilot
      incident_derived: false
      mapping_review: pending
    maintainers:
      - team: catpilot-security
    references:
      - https://owasp.org/Top10/A01_2021-Broken_Access_Control/
---

## When this applies

- Anyone other than the builder will open the app.
- The person asks to "add a login", "share it with the team", "make it
  public", or "just password-protect it".
- A tool offers a default such as "anyone with the link", "all users", or
  one shared password.
- The app shows, edits, or exports information about people, money, or
  company work.

## What to ask

- "Who should be able to open this, and who should not?" Get a named group,
  not "everyone".
- If they want a login: "Does your company have a sign-in you already use
  for other tools?" That is the one to use.

## What to say

- One sentence: "Whoever can open this can see everything in it, so the
  audience is a security decision, not a sharing setting."
- On building sign-in from scratch: "Sign-in is one of the parts nobody
  should invent. Let's use the company's existing sign-in instead."
- On shared passwords: "A password everyone knows is not a lock."

## Safe alternative

- Use the company's existing sign-in (often called SSO, single sign-on: one
  company login that works across many tools) whenever the platform
  supports it.
- Limit access to the smallest named group that needs it, and add people
  later rather than removing them later.
- Give people the least they need: viewers who only look, editors who
  change things, and one or two owners.
- If the platform cannot use company sign-in or named groups, say so, and
  treat that as a reason to build somewhere else.

## Company-specific values

Default access for a new app:

- {{identity_default}}

Never acceptable:

{{identity_never}}

## Stop and ask a human if

- Anyone outside the company will use it: customers, vendors, the public.
- The person wants to build or customize sign-in, passwords, or
  permissions themselves.
- The app decides who may see or change records about other people.
- The platform only offers "anyone with the link" and the app touches
  company data.
