#!/usr/bin/env python3
"""Catpilot PreToolUse hook for Claude Code: block shell commands that carry a literal credential.

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
    ("database URL with an embedded password", re.compile(r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqps?)://[^:\s/]*:(?P<val>[^@\s]+)@", re.IGNORECASE)),
    ("bearer token", re.compile(r"\bbearer\s+[A-Za-z0-9_\-\.=]{16,}\b", re.IGNORECASE)),
    ("literal API key assignment", re.compile(r"\b(?:api[_-]?key|apikey)\s*[:=]\s*[\"']?(?P<val>[A-Za-z0-9_\-]{16,})[\"']?", re.IGNORECASE)),
    ("literal password assignment", re.compile(r"\b(?:password|passwd|pwd)\s*[:=]\s*[\"'](?P<val>[^\"'$]{6,})[\"']", re.IGNORECASE)),
    ("literal client secret", re.compile(r"\b(?:secret|client_secret)\s*[:=]\s*[\"'](?P<val>[A-Za-z0-9_\-]{16,})[\"']", re.IGNORECASE)),
    ("literal auth token assignment", re.compile(r"\b(?:token|auth_token|access_token)\s*[:=]\s*[\"'](?P<val>[A-Za-z0-9_\-\.]{16,})[\"']", re.IGNORECASE)),
    ("literal DATABASE_URL", re.compile(r"\bDATABASE_URL\s*=\s*[\"']?(?:mongodb|postgres|mysql|redis|amqp)[^\s\"']*://[^\s\"']*:(?P<val>[^\s\"'@]+)@", re.IGNORECASE)),
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

# Obvious placeholder tokens used in documentation and test fixtures, never a real
# credential. Kept narrow and explicit on purpose: this is an allowance, not a filter.
PLACEHOLDER_VALUE = re.compile(
    r"^(?:REPLACE[_-]?ME|SAMPLE[_-]?KEY|YOUR[_-]?(?:API[_-]?)?KEY|CHANGE[_-]?ME|EXAMPLE|PLACEHOLDER|DUMMY|FAKE|TODO|FIXME|X{3,}|\*{3,})$",
    re.IGNORECASE,
)

MIN_CREDENTIAL_LENGTH = 6


def _is_placeholder_value(value: str) -> bool:
    """True if a captured unquoted/JSON value is an env reference, a known placeholder, or too short to be real."""
    value = value.strip("'\"")
    if len(value) < MIN_CREDENTIAL_LENGTH:
        return True
    if ENV_REFERENCE.fullmatch(value):
        return True
    return PLACEHOLDER_VALUE.fullmatch(value) is not None


def find_credential(command: str):
    """Return the label of the first credential-shaped literal in the command, or None.

    The same placeholder/env-reference/short-value allowance applies whether or not the
    pattern captured a separate "val" group, so a quoted assignment such as
    password="REPLACE_ME" is allowed exactly like the unquoted --password=REPLACE_ME.
    """
    if not command:
        return None
    for label, pattern in PATTERNS:
        for match in pattern.finditer(command):
            value = match.group("val") if "val" in pattern.groupindex else match.group(0)
            if _is_placeholder_value(value):
                continue
            return label
    return None


def decide(event: dict) -> dict:
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
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("hook input too large")
        result = decide(json.loads(payload))
    except (ValueError, TypeError, RecursionError):
        print(
            "Catpilot secret check could not read the hook input, so the command was not allowed. "
            "Review the command and retry.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
