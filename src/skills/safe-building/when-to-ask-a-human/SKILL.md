---
name: when-to-ask-a-human
description: Explicit triggers to stop and ask for a security review, including real customer or employee data, external users, payments, health data, anything that writes to a system of record, and anything the person cannot explain. Give the person a two-sentence summary to send.
license: MIT
metadata:
  catpilot:
    id: when-to-ask-a-human
    title: When to ask a human
    version: 1.0.0
    severity: medium
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["1.4", "3.4"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC2.2, CC7.2]
      pci_dss: ["12.6"]
      iso_27001: [A.7.2.2, A.16.1.2]
      nist_csf: [PR.AT-1, RS.CO-2]
    provenance:
      origin: catpilot
      incident_derived: false
      mapping_review: pending
    maintainers:
      - team: catpilot-security
    references:
      - https://www.nist.gov/cyberframework
---

## When this applies

- Any trigger in the list below appears, in any conversation about
  building, connecting, deploying, or sharing.
- The person is unsure whether something is okay. Unsure is a trigger.
- The pace of the work is making a risky choice feel normal.

## What to ask

- "Can you explain, in one sentence, what this change will do and who it
  affects?" If they cannot, that is the signal.

## What to say

- One sentence: "This is the point to ask security. It costs an hour now
  and saves a bad week later."
- Then give them the message to send, in two sentences: what they are
  building and for whom, and the specific thing that needs a decision.
- Keep building the parts that do not depend on the answer, with pretend
  data.

## Safe alternative

- Draft the request for them: who they are, what the app does, the data
  involved, the audience, and the one decision needed.
- Point them to the right person or channel.
- Suggest they keep a note of what was asked and what was decided, so the
  next builder does not have to ask again.
- Never present a chat answer as a review, an approval, or proof that the
  app is safe.

## Company-specific values

Who to ask:

- {{owner}}

Always ask before continuing when:

{{review_triggers}}

## Stop and ask a human if

- Real customer, employee, payment, or health data is involved, or people
  outside the company will use it.
- It takes payments, moves money, or writes to a system of record (the
  official source for orders, employees, finances, or tickets).
- The person cannot explain what a change will do, or a tool suggests
  turning off a protection to make something work.
- It signs people in, or decides who may see or change records.
- A mistake could harm a person, a customer relationship, or an obligation
  the company has.
