---
name: memory-and-identity
description: Isolate agent memory per user and session, redact secrets and PII before persisting to memory or logs, delineate untrusted RAG/tool context from instructions, and verify SHA-256 hashes of agent identity files at session start.
license: MIT
metadata:
  catpilot:
    id: memory-and-identity
    version: 1.0.0
    severity: high
    category: agentic-security
    applies_to:
      languages:
      - any
      frameworks:
      - any
      runtimes:
      - claude-code
      - cursor
      - openclaw
      - cline
      - aider
      - copilot
      - codex-cli
    control_mappings:
      soc2:
      - CC6.1
      - CC6.7
      - CC7.2
      pci_dss:
      - '3.4'
      - '10.2'
      iso_27001:
      - A.12.4.1
      - A.14.1.2
      nist_csf:
      - PR.DS-1
      - DE.CM-1
      owasp_top_10:
      - A01:2021
      - A08:2021
      - A09:2021
    provenance:
      origin: catpilot
      incident_derived: true
    maintainers:
    - team: catpilot-security
    references:
    - https://genai.owasp.org/llmrisk/llm01-prompt-injection/
---

## Baseline

**Applies when:** Persisting or retrieving agent memory, RAG context, or audit logs, injecting retrieved documents or tool output into model prompts, or managing agent behavioral/identity files (`SOUL.md`, `AGENTS.md`, `IDENTITY.md`, `CLAUDE.md`).

**Always:**
- Scope persistent agent memory by `(user_id, session_id)` and redact secrets and PII before writing to memory, logs, or agent outputs.
- Separate untrusted RAG/tool output from system instructions using explicit structural delimiters and a system rule stating that instructions inside retrieved context must be ignored.
- Hash behavioral and identity files (`SOUL.md`, `AGENTS.md`, `IDENTITY.md`, `CLAUDE.md`) with SHA-256 at session start, alert the human when a hash changes unexpectedly, and keep behavioral files separate from mutable `memory/*.md` notes.
- Log every tool invocation to an append-only audit trail with timestamp, agent ID, tool name, sanitized args, truncated sanitized result, and duration.
- Inject runtime credentials via environment variables or short-lived vault tokens scoped to minimum permissions (read-only where possible), never as tool arguments.

**Never:**
- Share a single global memory store across different users or trust boundaries, or store unredacted API keys, passwords, or connection strings in memory or logs.
- Concatenate retrieved RAG documents or tool outputs directly into the system prompt as trusted instructions.
- Allow an agent to silently rewrite its own behavioral or identity files without human diff review and approval.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

Persistent memory and behavioral instruction files (`SOUL.md`, `AGENTS.md`) outlive a single turn. If a prompt injection in a retrieved web page or ticket is saved into memory or edits an identity file, a one-turn exploit becomes a permanent backdoor across future sessions. Similarly, storing raw tool outputs in memory or logs without secret redaction turns the memory store into a credential dump.

## When to apply

Apply this component whenever building or reviewing RAG pipelines, session memory stores, output filters, audit loggers, or self-updating agent workspaces.

## Rules

### Rule 1 — Scope memory per user and session, and scrub secrets on write

Never use a global shared memory pool across users. Pass every memory write and log entry through secret and PII redaction before storage.

### Rule 2 — Delineate retrieved context as untrusted data

Keep system prompts free of raw RAG/tool text. Place retrieved text in a clearly delimited user/context block and instruct the model to ignore any directives found inside that block.

### Rule 3 — Hash identity files at session start and require human review for edits

Behavioral files (`SOUL.md`, `AGENTS.md`, `IDENTITY.md`) must be version-controlled and hash-checked at session start. Agents may write to `memory/*.md`, never silently to their own instruction files.

## Negative examples

```python
# ❌ Global unredacted memory and silent self-modification of instructions
shared_memory.save("db_setup", f"Connected with {db_password}")
Path("SOUL.md").write_text(new_instructions)
```

## Remediation

```python
import hashlib, json, re
from pathlib import Path

SECRET_RE = re.compile(r"(sk-[A-Za-z0-9]{20,}|AKIA[A-Z0-9]{16}|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")

def sanitize_for_memory(text: str) -> str:
    return SECRET_RE.sub("[REDACTED]", text)

def verify_identity_hashes(files: list[str], hash_log: Path) -> list[str]:
    current = {f: hashlib.sha256(Path(f).read_bytes()).hexdigest() for f in files if Path(f).exists()}
    drifted = []
    if hash_log.exists():
        previous = json.loads(hash_log.read_text(encoding="utf-8"))
        drifted = [f for f, h in current.items() if f in previous and previous[f] != h]
    hash_log.write_text(json.dumps(current, sort_keys=True), encoding="utf-8")
    return drifted
```

## References

- OWASP Top 10 for LLM Applications: LLM01 Prompt Injection — https://genai.owasp.org/llmrisk/llm01-prompt-injection/
