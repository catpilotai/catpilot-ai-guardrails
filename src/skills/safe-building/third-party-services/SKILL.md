---
name: third-party-services
description: Treat any new software service, plugin, connector, extension, or AI model endpoint as an approval question, not a convenience. Check the company's approved list first, and explain in one sentence what a new service would receive.
license: MIT
metadata:
  catpilot:
    id: third-party-services
    title: Third-party services
    version: 1.0.1
    severity: medium
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["3.3"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC6.8, CC9.2]
      pci_dss: ["12.8.1", "12.8.3", "12.6"]
      iso_27001: [A.15.1.1, A.15.1.2]
      nist_csf: [ID.SC-1, ID.SC-2]
      owasp_top_10: ["A06:2021", "A08:2021"]
    provenance:
      origin: catpilot
      incident_derived: false
      mapping_review: pending
    maintainers:
      - team: catpilot-security
    references:
      - https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/
---

## When this applies

- The person wants to connect the app to a service the company has not
  clearly approved: a free API, a plugin, a browser extension, a new AI
  provider, a marketplace connector, an automation platform.
- A tool suggests installing something to make a task easier.
- The person is signing up for a new account "just to try it".

## What to ask

- "Is this service on your company's approved list, or is it new?"
- If it is new: "What would it receive, and where does that information
  go?"

## What to say

- One sentence: "Every new service is a new place your company's
  information lives, and someone has to be responsible for it."
- On free services: "Free usually means the service keeps or uses what you
  send it. That may be fine for pretend data and not fine for real data."
- On plugins and extensions: "A plugin can read everything the app can
  read. Installing one is like giving someone a key."

## Safe alternative

- Prefer services the company has already approved; the approved option is
  usually already connected somewhere.
- Build and test with pretend data while approval is pending, so the work
  keeps moving.
- Write the two-sentence request the person can send: what the service is,
  what it will receive, and why it is needed.
- Do not suggest workarounds such as personal accounts, personal payment
  cards, or exporting data to make an unapproved service work.
- Until the service is approved, leave the connection as a clearly marked
  stub that sends nothing, and say so in your reply. Wiring the real endpoint
  and calling it a draft is the same as wiring it.

## Company-specific values

Approved services:

{{approved_services}}

Needs review before use:

{{services_needs_review}}

## Stop and ask a human if

- The service would receive customer, employee, payment, or health data.
- The service needs a payment method, a contract, or company credentials.
- The person wants to install a plugin, extension, or connector in a tool
  many people use.
- The service is a new AI provider or model endpoint.
