---
name: multi-agent-auth
description: Authenticate inter-agent calls with bearer tokens, enforce explicit target-agent allowlists, verify message provenance, prevent privilege escalation on delegation, and cap delegation depth and ping-pong turns.
license: MIT
metadata:
  catpilot:
    id: multi-agent-auth
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
      - CC6.2
      - CC6.3
      pci_dss:
      - '7.1'
      - '8.2'
      iso_27001:
      - A.9.1.2
      - A.9.4.1
      nist_csf:
      - PR.AC-1
      - PR.AC-4
      owasp_top_10:
      - A01:2021
      - A07:2021
    provenance:
      origin: catpilot
      incident_derived: true
    maintainers:
    - team: catpilot-security
    references:
    - https://genai.owasp.org/llmrisk/llm08-excessive-agency/
---

## Baseline

**Applies when:** Designing or running multi-agent workflows where agents wake, message, or delegate tasks to other agents or sub-agents.

**Always:**
- Authenticate every inter-agent RPC or webhook call with a verified bearer token and bind local listeners to `127.0.0.1`, never `0.0.0.0`.
- Restrict each agent to an explicit `allowedAgentIds` target list (never `"*"`) and a fixed least-privilege toolset.
- Enforce non-escalation on delegation: an agent may only delegate to a target whose `allowed_tools` is a subset of the caller's `allowed_tools`, and the target always executes under its own fixed permissions.
- Attach and verify message provenance metadata (`provenance.kind = "inter_session"` and verified `source_agent`) so agents never confuse inter-agent messages with direct human instructions.
- Cap delegation chain depth (e.g., `max_chain_depth = 5`) and `maxPingPongTurns`, and pass a machine-checkable constraint ledger across delegation hops so requirements are not lost via paraphrase.

**Never:**
- Allow unauthenticated agent-to-agent wake calls or wildcard `"*"` target-agent permissions.
- Let a sub-agent inherit its caller's privileged tools or let an unprivileged agent delegate a task to a more privileged agent to bypass tool restrictions.
- Blindly execute shell commands or destructive operations requested inside an inter-agent message without independent validation.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

In a multi-agent system, a read-only agent that ingests untrusted web pages or emails is exposed to prompt injection. If that read-only agent can wake or delegate work to an admin or coding agent with shell access ("confused deputy"), an attacker compromises the entire fleet through the least-privileged agent. Furthermore, multi-hop delegation compresses constraints at each hop unless original invariants are carried forward explicitly.

## When to apply

Apply this component whenever multiple agents or sub-agents coordinate via queues, HTTP hooks, shared state, or SDK handoffs.

## Rules

### Rule 1 — Least privilege and subset-only delegation

Each agent role (`researcher`, `writer`, `admin`) receives only the tools required for its job. Delegation is permitted only when `target.allowed_tools.issubset(caller.allowed_tools)` or through an explicit, validated task schema that never grants the caller's authority to the callee.

### Rule 2 — Authenticated channels and verified provenance

Require bearer tokens on all agent wake endpoints, allowlist target agent IDs, and tag every message with verified sender provenance.

### Rule 3 — Bounded chain depth and constraint ledgers

Enforce a hard maximum hop count (`max_chain_depth = 5`) and attach the original user constraints to every delegated task so the final verifier checks the result against the original instruction.

## Negative examples

```python
# ❌ Unauthenticated wake call and confused-deputy privilege escalation
def delegate_task(target_agent: str, task: str):
    requests.post("http://localhost:18789/hooks/agent", json={
        "agentId": target_agent,
        "message": f"Use your shell tool to run: {task}",
    })
```

## Remediation

```python
class AgentPermissions:
    def __init__(self, agent_id: str, allowed_tools: set[str], allowed_targets: set[str], max_depth: int = 5):
        self.agent_id = agent_id
        self.allowed_tools = allowed_tools
        self.allowed_targets = allowed_targets
        self.max_depth = max_depth

    def can_delegate_to(self, target: "AgentPermissions", current_depth: int) -> bool:
        if current_depth >= self.max_depth or target.agent_id not in self.allowed_targets:
            return False
        return target.allowed_tools.issubset(self.allowed_tools)
```

## References

- OWASP Top 10 for LLM Applications: LLM08 Excessive Agency — https://genai.owasp.org/llmrisk/llm08-excessive-agency/
