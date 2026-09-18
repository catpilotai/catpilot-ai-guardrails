---
name: keys-and-credentials
description: Never let a password, API key, token, or connection string be pasted into a prompt, a file, or generated code. Use the company's approved way to connect, use obvious placeholders in examples, and treat anything already pasted as exposed.
license: MIT
metadata:
  catpilot:
    id: keys-and-credentials
    title: Keys and credentials
    version: 1.0.0
    severity: high
    category: safe-ai-building
    mode: advisory
    training_module: "399"
    training_checkpoints: ["3.2"]
    applies_to:
      surfaces: [chat, app-builder, coding-agent]
      languages: [any]
      frameworks: [any]
      runtimes: [claude-ai, chatgpt, microsoft-copilot, copilot-studio, lovable, bolt, replit, v0, claude-code, cursor, codex-cli, copilot, cline, aider, openclaw]
    control_mappings:
      soc2: [CC6.1, CC6.6]
      pci_dss: ["8.2.1", "12.6"]
      iso_27001: [A.9.4.3, A.10.1.2]
      nist_csf: [PR.AC-1, PR.DS-5]
      owasp_top_10: ["A02:2021", "A07:2021"]
    provenance:
      origin: catpilot
      incident_derived: false
      mapping_review: pending
    maintainers:
      - team: catpilot-security
    references:
      - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
---

## When this applies

- The tool or app needs to connect to another system: email, a database, a
  payment provider, a calendar, a sales or HR system, a file store.
- The person offers, or is asked for, a password, key, token, secret, or
  connection string.
- Generated code or settings contain a real-looking secret.
- A temporary sign-in code or one-time password comes up.

## What to ask

- "Does your company have an approved way to connect to this, or a person
  who sets up connections?"
- If a secret has appeared in the conversation: "Is this the real value?"
  If yes, treat it as exposed.

## What to say

- One sentence: "Anything pasted into a chat or saved in an app can be
  copied, so a real key here is a key that is already out."
- On being asked for a password: "Don't give it to me or to the app. Let's
  use the approved connection instead."
- On placeholders: "In examples we write SAMPLE-KEY, not a real one, so
  nobody mistakes the example for the real thing."

## Safe alternative

- Use the platform's built-in connection feature or the company's secret
  store (a place that holds keys so the app can use them without anyone
  typing them into a chat). If neither exists, that is a reason to pause.
- In examples and code, use unmistakable placeholders such as SAMPLE-KEY or
  REPLACE-ME. Never a realistic-looking value.
- If a real secret was pasted: say so, stop using it, and help the person
  get it replaced ("rotated") by whoever manages it. Deleting the message
  does not undo the exposure.
- Publishable or public keys are a different class. When unsure which kind
  a value is, treat it as secret.

## Company-specific values

Approved services and connection methods:

{{approved_services}}

## Stop and ask a human if

- A real password, key, or token has been pasted or saved anywhere.
- The app needs access to payments, banking, HR, or health systems.
- The person plans to share their own login with the app or with others.
- A tool asks the person to lower a security setting to make a connection
  work.
