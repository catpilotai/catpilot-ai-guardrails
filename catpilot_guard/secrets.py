"""Catpilot PreToolUse hook for Claude Code: block shell commands that carry a literal credential.

hooks/claude-code/pretooluse-secrets.py runs this module's main(); hooks/harness/secret_gate.py
calls decide(), and write_secrets.py uses find_credential().

Scope, stated exactly:
  - Runs only for the Bash tool (the matcher in settings selects it).
  - Scans the proposed command text for the credential patterns documented in
    the secret-blocking component of catpilot-security-core.
  - On a match, returns a PreToolUse "deny" decision with a plain-language
    reason. The matched text is never included in the reason.
  - On anything else, returns an empty decision so the host's own permission
    rules apply unchanged. It never returns "allow".
  - Malformed or oversized input exits 2 (the host treats that as a blocking
    error), so a broken hook fails closed rather than silently allowing.

What it does not do: it does not inspect file writes, edits, prompts, other
tools, commands the host runs outside the Bash tool, or commands typed by a
person in their own terminal. It is not a secret scanner for a repository.
Coverage claims for this hook are limited to the Bash tool path on the host
versions listed in the repository README's tested-runtimes table.

Escape hatch for false positives: reference the value from an environment
variable or secret store instead of pasting it (the hook never matches
$VAR or ${VAR} references), or run the command yourself in your own
terminal. There is no bypass flag, on purpose.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import json
import re
import sys

from . import decision_for_host, event_for_host, hook_host, write_decision, write_reason

MAX_INPUT_BYTES = 1_048_576

# (label, compiled pattern). Patterns are conservative on length and charset
# to keep false positives low; they mirror the secret-blocking table.
#
# A pattern that needs to tell a credential's actual value apart from a
# surrounding key name, URL scheme, or quotes captures that value into a
# named group "val" (the four "literal ... assignment" patterns, the two
# database-URL patterns, and the unquoted CLI/env forms below); find_credential
# checks only the captured value against the placeholder/env-reference/
# short-value allowances in _is_placeholder_value. A pattern with no "val"
# group (the token-shaped patterns, where the whole match is the credential)
# is checked the same way against its whole match, so the one allowance
# applies uniformly everywhere.
PATTERNS = [
    ("Stripe secret or restricted key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("AWS secret access key", re.compile(r"aws_secret_access_key\s*=\s*[\"']?(?P<val>[A-Za-z0-9/+=]{40})[\"']?", re.IGNORECASE)),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("GitHub fine-grained personal access token", re.compile(r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b")),
    ("GitLab personal token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-(?:api|admin)\d+-[A-Za-z0-9_\-]{80,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Google OAuth access token", re.compile(r"\bya29\.[A-Za-z0-9_\-]+\b")),
    ("Square token", re.compile(r"\bsq0[a-z]{3}-[A-Za-z0-9_\-]{20,}\b")),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("npm access token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b")),
    ("private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("database URL with an embedded password", re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://[^:\s/]*:(?P<val>[^@\s]+)@(?P<host>\[[^\]\s]*\]|[^:/\s?#\"'@]*)", re.IGNORECASE)),
    ("bearer token", re.compile(r"\bbearer\s+[A-Za-z0-9_\-\.=]{16,}\b", re.IGNORECASE)),
    ("literal API key assignment", re.compile(r"\b(?:api[_-]?key|apikey)\s*[:=]\s*[\"']?(?P<val>[A-Za-z0-9_\-]{16,})[\"']?", re.IGNORECASE)),
    ("literal password assignment", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[\"'](?P<val>[^\"'$]{6,})[\"']", re.IGNORECASE)),
    ("literal client secret", re.compile(r"\b(?:secret|client_secret)\s*[:=]\s*[\"'](?P<val>[A-Za-z0-9_\-]{16,})[\"']", re.IGNORECASE)),
    ("literal auth token assignment", re.compile(r"\b(?:token|auth_token|access_token)\s*[:=]\s*[\"'](?P<val>[A-Za-z0-9_\-\.]{16,})[\"']", re.IGNORECASE)),
    ("literal DATABASE_URL", re.compile(r"\bDATABASE_URL\s*=\s*[\"']?(?:mongodb|postgres|mysql|redis|amqp)[^\s\"']*://[^\s\"']*:(?P<val>[^\s\"'@]+)@(?P<host>\[[^\]\s]*\]|[^:/\s?#\"'@]*)", re.IGNORECASE)),
    # Unquoted CLI/env forms: same literal-credential shape as above, but without the
    # quotes that the four "literal ... assignment" patterns require. Each captures the
    # bare value into the named group "val" so find_credential can apply the same
    # placeholder/short-value/env-reference allowances as the quoted forms get for free
    # from their own character classes (see _is_placeholder_value).
    ("literal --password flag", re.compile(r"--password=(?P<val>[^\s\"'$]+)", re.IGNORECASE)),
    ("literal mysql -p<password> flag", re.compile(r"\b(?:mysql|mysqldump|mariadb)\b.*?\s-p(?P<val>[^\s\"'$=][^\s\"']*)", re.IGNORECASE)),
    ("literal PGPASSWORD assignment", re.compile(r"\bPGPASSWORD=[\"']?(?P<val>[^\s\"'$]+)")),
    # Generic quoted-JSON credential property: the existing "literal ... assignment"
    # patterns above require the key bare (key=value or key: value); they do not match
    # a JSON-style key that is itself quoted ("password": "value"), because the closing
    # quote of the key sits between the key and the colon.
    (
        "literal credential in a JSON-style property",
        re.compile(
            r'"(?:api[_-]?key|apikey|password|passwd|pwd|token|auth_token|access_token|secret|client_secret)"'
            r'\s*:\s*"(?P<val>[^"$]+)"',
            re.IGNORECASE,
        ),
    ),
]

# A value that is only an environment reference is never a literal credential.
ENV_REFERENCE = re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?")

# Obvious placeholder tokens used in documentation and test fixtures, and the default
# passwords local development stacks ship with (postgres, password, admin, ...), never a
# real credential. Kept narrow and explicit on purpose: this is an allowance, not a filter.
PLACEHOLDER_VALUE = re.compile(
    r"^(?:REPLACE[_-]?ME|SAMPLE[_-]?KEY|YOUR[_-]?(?:API[_-]?)?KEY|CHANGE[_-]?ME|EXAMPLE|PLACEHOLDER|DUMMY|FAKE|TODO|FIXME|X{3,}|\*{3,}"
    r"|PASSWORD|PASSW0RD|POSTGRES|MYSQL|ADMIN|SECRET)$",
    re.IGNORECASE,
)

# A database URL whose host is the local machine (or Docker's alias for it) points at a
# development database; its password is a local default, not a credential to protect.
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"})

# There is deliberately no in-content allowlist marker (such as detect-secrets'
# "pragma: allowlist secret"): an agent that is told about one adds it and retries,
# which a host test showed. False positives are resolved by a person, not in-band.

MIN_CREDENTIAL_LENGTH = 6


# Optional evidence log, written by catpilot_guard/evidence.py when CATPILOT_EVIDENCE_LOG or
# CATPILOT_EVIDENCE_SYSLOG is set: one content-free line per deny or input error, with the hook, the
# tool, the credential type and the session id. Never the command, never the matched text.
HOOK_NAME = "pretooluse-secrets"
HOST = "claude-code"  # main()'s host with no --host (hook_host); decide() called from a harness passes no host


def record_evidence(event: str, hook_event: object = None, host: str | None = None, **fields) -> None:
    """One evidence line through the shared writer, imported here so that a missing or broken writer is a
    logging failure: it never changes the decision, and nothing here raises."""
    try:
        from . import evidence

        evidence.record_hook_event(HOOK_NAME, event, hook_event, host, **fields)
    except Exception:
        pass


def _is_placeholder_value(value: str) -> bool:
    """True if a captured unquoted/JSON value is an env reference, a known placeholder, or too short to be real."""
    value = value.strip("'\"")
    if len(value) < MIN_CREDENTIAL_LENGTH:
        return True
    if ENV_REFERENCE.fullmatch(value):
        return True
    return PLACEHOLDER_VALUE.fullmatch(value) is not None


def find_credential(command: str):
    """Return the label of the first credential-shaped literal in the text, or None.

    The same placeholder/env-reference/short-value allowance applies whether or not the
    pattern captured a separate "val" group, so a quoted assignment such as
    password="REPLACE_ME" is allowed exactly like the unquoted --password=REPLACE_ME.
    A database URL pointing at a loopback host is allowed.
    """
    if not command:
        return None
    for label, pattern in PATTERNS:
        for match in pattern.finditer(command):
            value = match.group("val") if "val" in pattern.groupindex else match.group(0)
            if _is_placeholder_value(value):
                continue
            if "host" in pattern.groupindex and (match.group("host") or "").strip("[]").lower() in LOOPBACK_HOSTS:
                continue
            return label
    return None


def decide(event: dict, host: str | None = None) -> dict:
    if not isinstance(event, dict):
        raise ValueError("hook event must be an object")
    if event.get("tool_name") != "Bash":
        return {}
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    label = find_credential(command)
    if label is None:
        return {}
    record_evidence("deny", event, host, tool="Bash", label=label)
    reason = (
        f"Catpilot secret check: this command appears to contain a literal credential ({label}). "
        "Keep the value out of the command: reference it from an environment variable or a secret "
        "store (for example $STRIPE_API_KEY), or run the command yourself in your own terminal if "
        "the value is a known-fake fixture. The matched text is not included in this message."
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> int:
    host = hook_host()  # from --host: the evidence label, and Copilot CLI's event shape; never the decision
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("hook input too large")
        result = decide(event_for_host(json.loads(payload), host), host)
    except Exception:
        # Any failure, not only malformed input, blocks: a hook that crashes with an
        # ordinary non-zero exit would let the host run the command.
        record_evidence("input_error", host=host)
        write_reason(
            "Catpilot secret check could not read the hook input, so the command was not allowed. "
            "Review the command and retry.")
        return 2
    return write_decision(decision_for_host(result, host))


if __name__ == "__main__":
    sys.exit(main())
