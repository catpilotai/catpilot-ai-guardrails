"""The compiled company policy: what the company-rules hook reads instead of the YAML rules file.

`python tools/validate_overlay.py compile FILE --out POLICY` turns the `enforcement` section of a validated
version 2 rules file into this JSON (docs/spec/OVERLAY_V2.md §2.2). Hooks are standard library only and cannot
parse YAML, so they read this instead. The file holds, and only holds:

  format, format_version   "catpilot-company-policy", 1
  source_sha256            the SHA-256 of the rules file's bytes, written into evidence lines
  expires_on               the rules file's expiry date; after it the rules act in monitor (decision 3)
  rules                    each with id, kind, mode (resolved: the rule's own or default_mode), values, and
                           use_instead_text when the rule names an approved alternative

Where it may come from (§2.2, §6.1 invariant 6): only an absolute path on the hook's own command line, never
the project, the home directory or an environment variable. The file must be a regular file, not a symlink, with
the same owner as the catpilot_guard package the hook runs from, and neither it nor its directory may be
writable by group or others. install.sh places both as root, so a person, and an agent acting as them, can
change neither. Anything else is a PolicyError with a fixed label, and the hook applies no company rule: the
built-in checks, which run as their own hooks, are unchanged (invariant 5: never less careful than no file).

Nothing here prints or returns a value from the policy in an error. Standard library only. Python 3.8+.
"""
from __future__ import annotations

import datetime as dt
import errno
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

FORMAT = "catpilot-company-policy"
FORMAT_VERSION = 1
MODES = ("monitor", "ask", "block")
# The kinds a compiled policy may carry: those the validator accepts (tools/validate_overlay.py ACCEPTED_KINDS).
# ENFORCED_KINDS are the ones the company-rules hook acts on; a rule of another known kind is carried and skipped.
KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
ENFORCED_KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
RULES_MAX = 50
VALUES_MAX = 100
VALUE_MAX_CHARS = 255
USE_INSTEAD_MAX_CHARS = 200
MAX_POLICY_BYTES = 262_144

# Why a policy could not be used: the only values a policy_error line from the hook carries in `label`.
ERROR_LABELS = ("bad-arguments", "missing", "unreadable", "wrong-owner", "malformed", "internal-error")

RULE_ID = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SHA256 = re.compile(r"[0-9a-f]{64}")
ISO_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
CONTROL = re.compile("[\x00-\x1f\x7f]")
TOP_KEYS = {"format", "format_version", "source_sha256", "expires_on", "rules"}
RULE_KEYS = {"id", "kind", "mode", "values"}
RULE_OPTIONAL = {"use_instead_text"}


class PolicyError(Exception):
    """The policy could not be used. Its one argument is a label from ERROR_LABELS, never content."""


@dataclass(frozen=True)
class Rule:
    id: str
    kind: str
    mode: str
    values: tuple
    use_instead_text: str | None


@dataclass(frozen=True)
class Policy:
    source_sha256: str
    expires_on: dt.date
    rules: tuple

    def expired(self, today: dt.date | None = None) -> bool:
        """True after expires_on, by the machine's local date; the expiry day itself is current."""
        return self.expires_on < (today or dt.date.today())


def package_owner() -> int:
    """The owner of the catpilot_guard directory this module runs from: root for an install.sh install."""
    return os.stat(Path(__file__).resolve().parent).st_uid


def _writable_by_others(mode: int) -> bool:
    return bool(mode & (stat.S_IWGRP | stat.S_IWOTH))


def read_checked(path: Path, owner: int | None = None) -> bytes:
    """The policy file's bytes, read from the same open file whose type, owner and mode were checked.

    The final path component is opened without following a symlink, and the checks run on the open descriptor,
    so the file cannot be swapped between the check and the read. Its directory must also have the expected owner
    and be writable by no one else. Raises PolicyError for anything anyone but the package's owner could have changed.
    """
    if not path.is_absolute():
        raise PolicyError("bad-arguments")
    try:
        expected = package_owner() if owner is None else owner
        parent = os.stat(path.parent)
    except FileNotFoundError:
        raise PolicyError("missing") from None
    except OSError:
        raise PolicyError("unreadable") from None
    if parent.st_uid != expected or _writable_by_others(parent.st_mode):
        raise PolicyError("wrong-owner")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        raise PolicyError("missing") from None
    except OSError as exc:
        # ELOOP: the final component is a symlink, which O_NOFOLLOW refuses.
        raise PolicyError("wrong-owner" if exc.errno == errno.ELOOP else "unreadable") from None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):  # a directory, a device, a FIFO
            raise PolicyError("wrong-owner")
        if info.st_uid != expected or _writable_by_others(info.st_mode):
            raise PolicyError("wrong-owner")
        chunks, size = [], 0
        while size <= MAX_POLICY_BYTES:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks)
    except OSError:
        raise PolicyError("unreadable") from None
    finally:
        os.close(fd)


def _string(value: object, longest: int) -> str:
    if not isinstance(value, str) or not value or len(value) > longest or CONTROL.search(value):
        raise PolicyError("malformed")
    return value


def _rule(value: object, seen: set) -> Rule:
    if not isinstance(value, dict):
        raise PolicyError("malformed")
    keys = set(value)
    if not RULE_KEYS <= keys or keys - RULE_KEYS - RULE_OPTIONAL:
        raise PolicyError("malformed")
    rule_id = value["id"]
    if not isinstance(rule_id, str) or len(rule_id) > 64 or not RULE_ID.fullmatch(rule_id) or rule_id in seen:
        raise PolicyError("malformed")
    seen.add(rule_id)
    if value["kind"] not in KINDS or value["mode"] not in MODES:
        raise PolicyError("malformed")
    values = value["values"]
    if not isinstance(values, list) or not 1 <= len(values) <= VALUES_MAX:
        raise PolicyError("malformed")
    use_instead = value.get("use_instead_text")
    return Rule(
        id=rule_id,
        kind=value["kind"],
        mode=value["mode"],
        values=tuple(_string(v, VALUE_MAX_CHARS) for v in values),
        use_instead_text=None if use_instead is None else _string(use_instead, USE_INSTEAD_MAX_CHARS),
    )


def parse(raw: bytes) -> Policy:
    """A policy from its bytes. Raises PolicyError("malformed") for anything but the format compile writes."""
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError("malformed")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise PolicyError("malformed") from None
    if not isinstance(data, dict) or set(data) != TOP_KEYS:
        raise PolicyError("malformed")
    if data["format"] != FORMAT or data["format_version"] != FORMAT_VERSION or isinstance(data["format_version"], bool):
        raise PolicyError("malformed")
    sha = data["source_sha256"]
    if not isinstance(sha, str) or not SHA256.fullmatch(sha):
        raise PolicyError("malformed")
    expires = data["expires_on"]
    if not isinstance(expires, str) or not ISO_DATE.fullmatch(expires):
        raise PolicyError("malformed")
    try:
        expires_on = dt.date.fromisoformat(expires)
    except ValueError:
        raise PolicyError("malformed") from None
    rules = data["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= RULES_MAX:
        raise PolicyError("malformed")
    seen: set = set()
    return Policy(source_sha256=sha, expires_on=expires_on, rules=tuple(_rule(rule, seen) for rule in rules))


def load(path: str | Path, owner: int | None = None) -> Policy:
    """The policy at path, after the location checks. Raises PolicyError with a label from ERROR_LABELS."""
    return parse(read_checked(Path(path), owner))


def branch_matches(value: str, branch: str) -> bool:
    """Whether a protected_branch value covers a branch name, ignoring case as the built-in check does.

    A trailing `/*` covers every branch under the prefix (`release/*` covers `release/2026.11` and
    `release/a/b`), as the built-in `release/*` does; anything else must match the whole name.
    """
    if not branch:
        return False
    if value.startswith("refs/heads/"):  # the validator refuses this form; a push destination is read without it
        value = value[len("refs/heads/"):]
    if value.endswith("/*"):
        prefix = value[:-1].casefold()
        name = branch.casefold()
        return name.startswith(prefix) and len(name) > len(prefix)
    return value.casefold() == branch.casefold()
