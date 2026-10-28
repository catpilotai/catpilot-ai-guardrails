---
name: tool-sandboxing
description: Constrain agent shell, file, and network tools with explicit command allowlists, symlink-resolved workspace path confinement, DNS-resolved SSRF and metadata-endpoint blocking, and human-in-the-loop approval for destructive actions.
license: MIT
metadata:
  catpilot:
    id: tool-sandboxing
    version: 1.0.0
    severity: critical
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
      - CC6.6
      - CC7.2
      pci_dss:
      - '6.2'
      - '7.1'
      iso_27001:
      - A.9.4.1
      - A.13.1.3
      nist_csf:
      - PR.AC-4
      - PR.PT-3
      owasp_top_10:
      - A01:2021
      - A03:2021
      - A10:2021
    provenance:
      origin: catpilot
      incident_derived: true
    maintainers:
    - team: catpilot-security
    references:
    - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
---

## Baseline

**Applies when:** Defining, wrapping, or invoking agent tools for shell execution, filesystem reads/writes/deletes, outbound HTTP fetches, or external state changes (deployments, outbound messages, database writes).

**Always:**
- Restrict shell tools to an explicit command allowlist with `shell=False` and an argv list; exclude commands with exec/eval flags (`find -exec`, `awk`, `python -c`).
- Resolve every file path and non-flag shell argument with `Path.resolve()` and verify it lies inside an explicit workspace `ALLOWED_DIRS` set before reading or writing.
- Block access to credential and system paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`, `/etc/passwd`, `/etc/shadow`) even when a parent directory is allowed.
- Resolve outbound HTTP hostnames via `socket.getaddrinfo` before connecting, reject private, loopback, link-local, reserved, and cloud metadata IPs (`169.254.169.254`, `metadata.google.internal`), and disable redirects (`allow_redirects=False`).
- Require explicit human approval (`"yes"`) showing the exact action and parameters before any destructive, external-communication, or deployment tool call.
- Wire deterministic runtime gates (`hooks/harness/secret_gate.py`, `destructive_gate.py`, `network_gate.py`, `path_gate.py`) at the tool boundary of Python harnesses.

**Never:**
- Expose `subprocess.run(cmd, shell=True)` or unrestricted `open(path)` directly as an agent tool.
- Rely on hostname prefix strings alone to block SSRF (`127.0.0.1`, `::1`, `0.0.0.0`, and DNS rebinding bypass string checks), or follow HTTP redirects on agent URL fetches.
- Allow an agent tool to delete files, deploy services, or send external emails/messages without an explicit human confirmation gate.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

An agent harness that hands the model raw `subprocess.run(..., shell=True)`, `open(path)`, or `requests.get(url)` gives any prompt injection or reasoning mistake the full privileges of the host process. String-prefix checks on paths or URLs routinely fail: symlinks and `..` escape the working directory, DNS names resolve to internal RFC 1918 or link-local metadata addresses (`169.254.169.254`), and HTTP `302` redirects pivot a public URL into an internal service after the initial check.

## When to apply

Apply this component whenever you write, review, or wire a tool function in LangGraph, CrewAI, OpenAI Agents SDK, Claude Agent SDK, an MCP server, or a custom Python agent loop.

## Rules

### Rule 1 — Shell tools use an allowlist, `shell=False`, and argument path confinement

Never pass a model-supplied string to `shell=True`. Allowlist only read-only or narrowly scoped binaries, exclude binaries that can spawn commands (`find`, `xargs`, interpreters), and validate every non-flag path argument against `ALLOWED_DIRS`.

### Rule 2 — Filesystem tools resolve symlinks and block credential paths

Resolve every target path via `Path(os.path.expanduser(path)).resolve()` and verify `.is_relative_to(allowed_dir)`. Explicitly deny `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gcloud`, `~/.docker`, `~/.openclaw`, and `/etc/passwd` / `/etc/shadow` even if a caller misconfigures `allowed_dirs` to include `$HOME`.

### Rule 3 — Outbound HTTP tools validate resolved IPs and disable redirects

Parse the URL, allow only `http` and `https`, reject embedded credentials, resolve all records with `socket.getaddrinfo`, reject any IP that is private, loopback, link-local, multicast, unspecified, reserved, or cloud metadata, and set `allow_redirects=False`.

### Rule 4 — Gate destructive and external-effect tools on human approval

Actions that delete state, deploy infrastructure, or send messages outside the session must pause and show the structured action details to a human before executing.

## Negative examples

```python
# ❌ Unrestricted shell, file read, and SSRF-vulnerable HTTP fetch
def shell_tool(command: str) -> str:
    return subprocess.run(command, shell=True, capture_output=True, text=True).stdout

def read_file(path: str) -> str:
    return open(path).read()

def fetch_url(url: str) -> str:
    return requests.get(url).text
```

## Remediation

```python
from pathlib import Path
import requests
from hooks.harness.secret_gate import gate_shell_command, gate_file_write
from hooks.harness.destructive_gate import gate_destructive_command
from hooks.harness.network_gate import gate_url_fetch
from hooks.harness.path_gate import gate_file_path

WORKSPACE = Path("/app/workspace").resolve()

def safe_read(path: str) -> str:
    reason = gate_file_path(path, allowed_dirs=[WORKSPACE], base_dir=WORKSPACE)
    if reason:
        raise PermissionError(reason)
    return (WORKSPACE / path).resolve().read_text(encoding="utf-8")

def safe_fetch(url: str) -> str:
    reason = gate_url_fetch(url)
    if reason:
        raise PermissionError(reason)
    return requests.get(url, timeout=10, allow_redirects=False).text
```

## References

- OWASP Server-Side Request Forgery Prevention Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
