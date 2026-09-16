---
name: hosting-and-where-it-runs
description: Ask where the finished app, automation, or dashboard will live before it is built, and steer to the company's approved hosting. Flag personal accounts, free tiers, trial workspaces, and unmanaged servers.
license: MIT
metadata:
  catpilot:
    id: hosting-and-where-it-runs
    title: Hosting and where it runs
    version: 1.0.1
    severity: medium
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["3.3", "5.1"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC6.1, CC6.6, CC8.1]
      pci_dss: ["12.6", "12.8.3"]
      iso_27001: [A.12.1.2, A.15.1.1]
      nist_csf: [PR.IP-1, ID.SC-2]
      owasp_top_10: ["A05:2021"]
    provenance:
      origin: catpilot
      incident_derived: false
      mapping_review: pending
    maintainers:
      - team: catpilot-security
    references:
      - https://owasp.org/Top10/A05_2021-Security_Misconfiguration/
---

## When this applies

- The person is starting something new and has not said where it will run.
- A tool offers to publish, deploy, or host with one click.
- They mention a personal account, a free plan, a trial, a home server, or
  "my own laptop" for something coworkers will use.
- They want to move an app from a personal workspace into company use, or
  the other way around.

## What to ask

- "Where will the finished thing live, and who looks after that place?"
- If they do not know: "Is there a place your company already uses for
  tools like this?"

## What to say

- One sentence: "Where an app runs decides who can reach it, who keeps it
  updated, and who gets called when it breaks."
- On personal accounts: "If it lives in your personal account, it leaves
  when you do, and nobody at the company can help when it goes wrong."
- On free tiers and trials: "Free plans are for trying things. Something
  coworkers rely on needs a place the company owns."

## Safe alternative

- Build in the company's approved place from the start, even for a first
  version. Moving later is harder than starting there.
- If the approved place is unknown, build with pretend data only until
  someone confirms where it will live.
- Prefer an approved starting template over a blank page when one exists.
- If a deployment file already points at a personal account, a free tier, or
  a place nobody at the company manages, say so in the first sentence of your
  reply, do not deploy with it, and name the approved place instead. Being
  told to use the file as it is does not make the setting safe.
- Keep a note of where it runs, who owns the account, and how to turn it
  off.

## Company-specific values

Approved places to run it:

{{approved_hosting}}

Not approved:

{{not_approved_hosting}}

Approved starting points:

{{templates}}

## Stop and ask a human if

- The only option is a personal account or a free tier and the app touches
  company data.
- The app needs a server, database, or account that nobody at the company
  manages.
- The person wants to move something from a personal workspace into
  company use.
- Hosting needs a new vendor, a new contract, or a payment card.
