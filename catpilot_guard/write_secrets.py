"""PreToolUse hook for Claude Code and Codex: deny a file write or edit that adds a literal credential or private-key block.

hooks/claude-code/pretooluse-write-secrets.py runs this module's main(); hooks/harness/secret_gate.py
calls inspect_event(). The credential patterns come from the sibling secrets module.

Covers Claude Code's Write, Edit, MultiEdit, and NotebookEdit tools and Codex's
apply_patch, whose tool_input.command is a patch: the lines it adds are the
lines that start with "+". It checks the content being added against the literal credential patterns documented in the
secret-blocking component of catpilot-security-core (PEM private-key headers,
API keys, tokens, database URLs with embedded passwords, and literal
password/secret/token assignments) and returns a deny decision with a
plain-language reason that never echoes the content. It never returns allow, so
every other host rule still applies.

Allowed on purpose: environment references ($VAR, ${VAR}), obvious placeholders
and local-development default passwords, and database URLs on a loopback host.
There is no in-content allowlist marker: an agent told about one adds it and
retries. A deliberate example in documentation is written by a person.

Fails closed: malformed or oversized input, a missing sibling secrets
module, or any unexpected error exits 2, which the host treats as
a block. Not a general secret scanner: it does not inspect shell commands (see
secrets.py), file reads, prompts, or other tools. Standard library
only; no network, no logging unless CATPILOT_EVIDENCE_LOG or
CATPILOT_EVIDENCE_SYSLOG is set. The hook file was formerly
pretooluse-write-private-key.py, which remains as a compatibility entry point.
"""

from __future__ import annotations

import json
import re
import sys

from . import decision_for_host, event_for_host, hook_host, write_decision, write_reason

PRIVATE_KEY = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")
MAX_INPUT = 1_048_576

PRIVATE_KEY_REASON = (
    "A literal private-key block was found in the content being written. Keep key "
    "material out of files the agent writes: reference it from a secret store or use an "
    "unmistakable placeholder such as SAMPLE-KEY. No key material is included in this message."
)

_SECRETS_MODULE = None


def secrets_module():
    """The sibling secrets module, imported on first use. An import failure raises, and main() fails closed."""
    global _SECRETS_MODULE
    if _SECRETS_MODULE is None:
        from . import secrets as module

        _SECRETS_MODULE = module
    return _SECRETS_MODULE


# Optional evidence log, written by catpilot_guard/evidence.py when CATPILOT_EVIDENCE_LOG or
# CATPILOT_EVIDENCE_SYSLOG is set: one content-free line per deny or input error, with the hook, the
# tool, the credential type and the session id. Never the file path, never the content.
HOOK_NAME = "pretooluse-write-secrets"
HOST = "claude-code"  # main()'s host with no --host (hook_host); inspect_event() called from a harness passes no host


def record_evidence(event: str, hook_event: object = None, host: str | None = None, **fields) -> None:
    """One evidence line through the shared writer, imported here so that a missing or broken writer is a
    logging failure: it never changes the decision, and nothing here raises."""
    try:
        from . import evidence

        evidence.record_hook_event(HOOK_NAME, event, hook_event, host, **fields)
    except Exception:
        pass


# Codex's file-edit tool. Its hook input reports tool_name "apply_patch" whichever of
# apply_patch, Edit or Write the matcher named, with the patch in tool_input.command.
APPLY_PATCH = "apply_patch"
PATCH_FILE_HEADER = re.compile(r"\*\*\* (?:Add|Update|Delete) File: ")


def patch_added_text(patch: str) -> list[str]:
    """The text a Codex patch adds, one string per file.

    In Codex's patch format (*** Begin Patch, *** Add File: / *** Update File: /
    *** Delete File:, @@ hunks, *** End Patch) every added line starts with "+",
    in a new file and in a hunk alike; removed lines start with "-" and context
    lines with a space. Every "+" line counts wherever it sits, so a wrapper
    around the patch (a heredoc, or missing Begin and End markers) hides nothing.
    Removed and context lines are not added text: deleting a key is not a write
    of one.

    Lines are split the way Codex's own parser splits them, on "\n" only, with
    a "\r" before it dropped. Python's str.splitlines() would also split on
    "\r", form feed, U+2028 and other separators that Codex writes into the file
    as ordinary characters, so text after one of them would be checked as a line
    of its own, without its "+", and skipped.

    All the lines a patch adds to one file are checked together, in order, as
    one text. Removed lines, blank context lines and separate hunks can leave
    added lines next to each other in the file, so a value split across them
    (password: on one added line, the value on the next) is still one match.
    The cost is a rare false positive when two added fragments that a kept
    line separates happen to form a credential; a person resolves it.
    """
    sections: list[list[str]] = [[]]
    for line in patch.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        if PATCH_FILE_HEADER.match(line):
            sections.append([])
        elif line.startswith("+"):
            sections[-1].append(line[1:])
    return ["\n".join(lines) + "\n" for lines in sections if lines]


def added_text(tool_name: str, tool_input: object) -> list[str] | None:
    """The strings a supported tool would add to a file, or None for tools this hook does not cover."""
    if not isinstance(tool_input, dict):
        raise ValueError("invalid tool input")
    if tool_name == "Write":
        parts = [tool_input.get("content")]
    elif tool_name == "Edit":
        parts = [tool_input.get("new_string")]
    elif tool_name == "MultiEdit":
        edits = tool_input.get("edits")
        if not isinstance(edits, list) or not all(isinstance(e, dict) for e in edits):
            raise ValueError("invalid edits")
        parts = [e.get("new_string") for e in edits]
    elif tool_name == "NotebookEdit":
        parts = [tool_input.get("new_source")]
    elif tool_name == APPLY_PATCH:
        command = tool_input.get("command")
        if not isinstance(command, str):
            raise ValueError("missing patch")
        parts = patch_added_text(command)
    else:
        return None
    if not all(isinstance(p, str) for p in parts):
        raise ValueError("missing write content")
    return parts


def find_write_credential(parts: list[str]) -> tuple[str, str] | None:
    """Return (evidence_label, reason) for the first literal credential in parts, or None."""
    find_credential = secrets_module().find_credential
    for part in parts:
        if PRIVATE_KEY.search(part):
            return "private-key-block", PRIVATE_KEY_REASON
        label = find_credential(part)
        if label is not None:
            if label == "private key block":
                return "private-key-block", PRIVATE_KEY_REASON
            reason = (
                f"Catpilot secret check: the content being written appears to contain a literal credential ({label}). "
                "Keep secret values out of files the agent writes: read them from an environment variable or secret "
                "store at runtime (for example process.env.STRIPE_API_KEY or os.environ['STRIPE_API_KEY']), or use "
                "an unmistakable placeholder such as REPLACE_ME. The matched text is not included in this message."
            )
            return label, reason
    return None


def inspect_event(event: object, host: str | None = None) -> dict:
    if not isinstance(event, dict):
        raise ValueError("invalid hook event")
    parts = added_text(str(event.get("tool_name")), event.get("tool_input"))
    if parts is None:
        return {}
    found = find_write_credential(parts)
    if found is not None:
        label, reason = found
        record_evidence("deny", event, host, tool=str(event.get("tool_name")), label=label)
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
    return {}


def main() -> int:
    host = hook_host()  # from --host: the evidence label, and Copilot CLI's event shape; never the decision
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(payload) > MAX_INPUT:
            raise ValueError("hook input too large")
        result = inspect_event(event_for_host(json.loads(payload), host), host)
    except Exception:
        # Any failure (malformed input, a missing sibling module, an unexpected error)
        # blocks: an ordinary non-zero exit would let the host perform the write.
        record_evidence("input_error", host=host)
        write_reason("Catpilot write check unavailable: invalid input or an internal error. Review the write before retrying.")
        return 2
    return write_decision(decision_for_host(result, host))


if __name__ == "__main__":
    sys.exit(main())
