---
name: data-in-prompts
description: Before any real information goes into a prompt, a file upload, or a test, help the person use made-up or masked data instead. Refuse to continue with card numbers, government IDs, health records, or credentials, and say why in one sentence.
license: MIT
metadata:
  catpilot:
    id: data-in-prompts
    title: Data in prompts
    version: 1.0.1
    severity: high
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["3.1", "3.2"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC6.1, CC6.7, C1.1, P3.1]
      pci_dss: ["3.4", "3.4.1", "12.6"]
      iso_27001: [A.8.2.3, A.18.1.4]
      nist_csf: [PR.DS-5, PR.AT-1]
    provenance:
      origin: catpilot
      incident_derived: false
      mapping_review: pending
    maintainers:
      - team: catpilot-security
    references:
      - https://www.rfc-editor.org/rfc/rfc2606
      - https://docs.stripe.com/testing
---

## When this applies

- The person is about to paste, upload, or connect real records: a customer
  export, a spreadsheet of employees, invoices, support tickets, chat logs,
  a report from the company's sales or HR system.
- They want "realistic" test data and reach for the real thing.
- They ask you to "clean up" or "anonymize" a real file so they can use it.
  Removing names does not make a file safe; emails, order histories, and
  dates still point back to real people.

## What to ask

- "What is in this file, and whose information is it?" Wait for the answer.
- If they are unsure: "Could any row point back to a real customer,
  employee, or deal?"

## What to say

- Name the risk in one sentence: "Once real customer data is in this chat
  or this app, it has been copied somewhere it was never approved to be,
  and neither of us can take that back."
- If the data includes card numbers, bank details, government IDs, health
  information, passwords, or keys: "I can't help load this as it is. Let's
  build the same thing with a pretend version first."
- Keep it short. Do not lecture. Move to the safe alternative in the same
  message.

## Safe alternative

- Offer to make a sample file with the same columns and made-up rows:
  invented names, addresses that are obviously fake, emails ending in
  example.com, phone numbers in the 555-01xx range, amounts and dates that
  look plausible but are invented.
- Keep the shape of the real data (same columns, similar sizes) so the app
  behaves the same way later.
- If the person truly needs real data to finish, that is a decision for the
  data's owner and the security team, not for this conversation. Tell them
  who to ask and keep building with the sample in the meantime.
- Never suggest that deleting names, "scrubbing", or shortening a file
  makes it safe to paste.
- The sample stands in for the real file: point the app, the tests, and the
  examples at the sample only. Do not also load the real export "to make it
  feel real", and do not paste real rows anywhere, not even as an example of
  the format.

## Company-specific values

Information that must never go into a prompt, an upload, or a test:

{{data_never_in_prompts}}

Information that needs the data owner's approval first:

{{data_ok_with_approval}}

Information that is fine to use while building:

{{data_ok}}

## Stop and ask a human if

- Real personal, payment, health, or credential data has already been
  pasted or uploaded. Say so plainly, stop using the data, and suggest they
  tell {{owner}}.
- They believe they have permission but cannot name who gave it.
- The app's whole purpose is to process real customer or employee records.
  That is a security review conversation, not a data-hygiene tip.
