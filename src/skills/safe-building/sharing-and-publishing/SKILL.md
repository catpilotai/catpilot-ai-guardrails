---
name: sharing-and-publishing
description: Before anything is published, shared, embedded, or sent, check for company data in the output, public link settings, and screenshots that leak. Start with a small private preview and keep a way back to the last working version.
license: MIT
metadata:
  catpilot:
    id: sharing-and-publishing
    title: Sharing and publishing
    version: 1.0.1
    severity: medium
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["5.1", "5.2", "5.3"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC6.1, CC6.7, CC8.1]
      pci_dss: ["7.2", "12.6"]
      iso_27001: [A.9.4.1, A.13.2.1]
      nist_csf: [PR.DS-5, PR.AC-4]
      owasp_top_10: ["A01:2021", "A05:2021"]
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

- The person is about to share a link, publish, embed, export, send a
  screenshot or recording, or post a result in a chat or document.
- They ask "can I send this to them?" about a vendor, a customer, a wide
  channel, or the public.
- The app or its output includes names, emails, amounts, internal names, or
  anything pulled from company systems.

## What to ask

- "Who will see this, and is there anything in it they should not see?"
- Before a wider release: "Who tried it first, and what happened?"

## What to say

- One sentence: "Sharing is the moment a private draft becomes a public
  fact, so check the audience and the contents before the click."
- On screenshots: "A screenshot carries everything on the screen, including
  the rows you were not thinking about."
- On public links: "A link nobody has posted yet is still public. Being
  hard to find is not a lock."

## Safe alternative

- Start with a private preview: a few named people, one real task for them
  to try, and a way to report problems.
- Before sharing, read the output as the recipient would. Remove real
  names, amounts, and internal details unless the recipient is entitled to
  them.
- Use the platform's audience settings (named people or groups) instead of
  public links.
- If a settings file already grants public or anyone-with-the-link access,
  say so in the first sentence of your reply and name who can change it,
  before the link goes anywhere. If the person asked you to leave the file
  alone, leave it alone and still say it.
- Keep the last working version, and decide in advance what would make you
  turn the new one off.
- After sharing, watch a few simple signs: a save fails, a number is wrong,
  someone sees more than they should.

## Company-specific values

Never acceptable when sharing:

{{identity_never}}

## Stop and ask a human if

- The recipient is outside the company and the content came from company
  systems.
- The output includes customer, employee, payment, or health information.
- The person wants to make something public, embed it on a website, or post
  it in a large channel.
- Something has already been shared too widely. Say so, suggest reporting
  it to {{owner}}, and help unshare it first.
