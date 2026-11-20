"""Validate an organization overlay (the company rules file) offline. Standard library plus PyYAML.

Two versions, dispatched on `schema_version`, and a file is checked only
against its own version's rules:

- version 1, docs/spec/overlay.schema.json and docs/spec/OVERLAY.md;
- version 2, docs/spec/overlay.v2.schema.json and docs/spec/OVERLAY_V2.md:
  every list item is an object with a stable `id` and its phrase as `text`,
  an optional machine-only `enforcement` section holds rules with a mode, and
  optional topic `contacts` name who to ask about data, hosting, services or
  identity, with `owner` as the default (§3.1).

Checks, in order: the schema (implemented here without a jsonschema
dependency), the expiry window, and a content scan for anything that looks
like a secret, a URL outside the allowlist, an email address other than
owner (and, in version 2, a contact's name), an IP address, or an incident
narrative. In version 2 the secret scan also covers `enforcement`, no deploy
host, registry or account an enforcement rule lists may appear in a model-facing
value, and a file with `enforcement` carries
a random `salt`, so the file's SHA-256, which a model sees, cannot confirm a
guessed enforcement value. A key that
appears twice in one mapping, and a YAML merge key (`<<`), are refused in
both versions. `enforcement.exceptions` relax one enforcement rule until a date
(§3.1): an exception never outlives the file and never touches a built-in check.

A passing overlay is structurally valid. The validator does not know whether
the listed hosting or services are actually approved; a named reviewer does.

`python tools/validate_overlay.py migrate FILE` prints a version 1 file as
version 2 (OVERLAY_V2.md §2.4). `python tools/validate_overlay.py salt FILE`
sets a new random `salt` in a version 2 file, changing no other line.
`python tools/validate_overlay.py compile FILE --out POLICY` validates the file
and writes `enforcement` as the JSON policy the company-rules hook reads
(catpilot_guard/company_rules.py), with each rule's mode resolved and the
exceptions copied. The hook acts on `protected_branch`, `deploy_host`,
`package_registry` and `cloud_account` rules, and applies the exceptions that
have no `where`. `export FILE --out JSON` (experimental) writes a generic allow/deny list instead
(docs/spec/policy-export.schema.json).
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent

ITEM_MAX = 200
LIST_MAX = 30
KIND_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s\"'<>]+", re.IGNORECASE)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
NARRATIVE_RE = re.compile(
    r"\b(?:incident|breach|breached|leak(?:ed)?|compromis(?:e|ed)|postmortem|post-mortem|"
    r"root cause|CVE-\d{4}-\d+|ticket #?\d+|last (?:week|month|year) we|we discovered|"
    r"attacker|exfiltrat)\b",
    re.IGNORECASE,
)
SECRET_PATTERNS = [
    re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"\bsk-(?:ant-)?(?:api|admin|proj)?[A-Za-z0-9_\-]{30,}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[:=]\s*\S{6,}", re.IGNORECASE),
    re.compile(r"://[^\s/:@]+:[^\s@]+@"),
]

TOP_REQUIRED = (
    "schema_version",
    "organization",
    "owner",
    "reviewed_on",
    "expires_on",
    "data_classes",
    "hosting",
    "services",
    "identity",
    "review_triggers",
)
TOP_ALLOWED = TOP_REQUIRED + ("templates", "intake_url")

# ----------------------------------------------------------------- version 2 (OVERLAY_V2.md)

SCHEMA_VERSIONS = (1, 2)
TOP_ALLOWED_V2 = TOP_ALLOWED + ("salt", "enforcement", "contacts")
# Topic contacts (§3.1): a closed list of topics, one per check_plan field that has one
# (data: data_classes, hosting, services, identity: audience). Model-facing, like owner.
CONTACT_TOPICS = ("data", "hosting", "services", "identity")
CONTACT_FIELDS = ("name", "intake_url")
# Ids and aliases share the grammar templates[].kind already uses (§2.1, §6.3 rule 3).
ID_RE = KIND_RE
ID_MAX = 64
ALIASES_MAX = 5
# The model-facing lists, in file order, with the prefix `migrate` gives their ids (§2.4).
# identity.default is one item, between identity's prefix and identity.never.
LISTS = (
    ("data_classes", "never_in_prompts", "data"),
    ("data_classes", "ok_with_approval", "data"),
    ("data_classes", "ok", "data"),
    ("hosting", "approved", "hosting"),
    ("hosting", "not_approved", "hosting"),
    ("services", "approved", "service"),
    ("services", "needs_review", "service"),
)
MIGRATED_ID_MAX = 48

MODES = ("monitor", "ask", "block")
DEFAULT_MODE = "monitor"
RULES_MAX = 50
VALUES_MAX = 100
# The closed list of rule kinds (§2.2). A kind enters the schema in the same pull
# request as its first consumer (§6.3 rule 4): the first build carried protected_branch
# and deploy_host; package_registry and cloud_account came with their hook consumer
# (catpilot_guard/registry_targets.py, catpilot_guard/cloud_targets.py).
RULE_KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
ACCEPTED_KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
# Allow-list kinds whose values must not appear in model-facing text (§6.3 rule 7).
HOST_KINDS = ("deploy_host", "package_registry", "cloud_account")
# Kinds a hook acts on in this release, through the compiled policy (`compile`) and the
# company-rules hook (catpilot_guard/company_rules.py). A rule of another accepted kind is
# validated and compiled, and nothing acts on it yet.
ENFORCED_KINDS = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
# Kinds with a host verification note for their consumer, so `block` on them draws no lint
# warning (§6.3 rule 9): protected_branch, denied on Claude Code, Codex and Copilot CLI
# (evals/reports/2026.11.17-host-check-company-rules.md); deploy_host, package_registry and
# cloud_account, denied on the same three tools
# (evals/reports/2026.11.19-host-check-zipapp-reader.md).
HOST_VERIFIED_KINDS: tuple[str, ...] = ("protected_branch", "deploy_host", "package_registry", "cloud_account")
# The compiled policy's format (catpilot_guard/policy.py reads it). Still 1 with exceptions: the policy gains an optional
# `exceptions` key, written only when the file has exceptions, so a file without them compiles byte for byte as before.
# A hook from before exceptions refuses a policy with the key as malformed (policy_error), as it refuses any unknown key.
POLICY_FORMAT = "catpilot-company-policy"
POLICY_FORMAT_VERSION = 1
# Expiring exceptions to enforcement rules (§3.1).
EXCEPTIONS_MAX = 50
EXCEPTION_FIELDS = ("id", "rule", "allows", "approver_role", "expires_on", "where")
APPROVER_ROLE_MAX = 80
# Lint warns about an exception this many days or fewer before its expires_on (§6.3 rule 9).
EXCEPTION_WARN_DAYS = 14
# `where.repositories`: owner/repo, as a CI platform names a repository. Only the pull-request check reads it.
REPOSITORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}/(?!\.\.?$)[A-Za-z0-9._-]{1,100}")
# The approved lists `use_instead` may name (§6.3 rule 6).
USE_INSTEAD_LISTS = (("hosting", "approved"), ("services", "approved"))

_HOST_LABEL_RE = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
_REGISTRY_PATH_RE = re.compile(r"[A-Za-z0-9._\-/]+")
_CLOUD_ACCOUNT_RE = re.compile(
    r"aws:[0-9]{12}"
    r"|azure:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    r"|gcp:[a-z][a-z0-9-]{5,29}"
)
_BRANCH_FORBIDDEN = set(" ~^:?*[\\")

# §6.3 rule 10. The file's SHA-256 reaches a model (the block's "Overlay SHA-256" line,
# the server's policy_source, the bundle manifest). A file made by `migrate` or copied
# from the example is predictable, so without a random salt that hash would confirm
# guessed enforcement values offline. The salt is machine-only and never in a message.
SALT_RE = re.compile(r"[0-9a-f]{32,128}")
# The salt in docs/spec/overlay.v2.example.yaml and OVERLAY_V2.md §5.1: published, so never valid.
EXAMPLE_SALT = "0123456789abcdef0123456789abcdef"
SALT_HOW = "set a new one with: python tools/validate_overlay.py salt FILE"
# Checks that catch a hand-made salt. They do not measure randomness. The thresholds are
# set so a salt from `secrets.token_hex(16)` or longer is essentially never rejected. Worked
# out per salt: a run of 8 digits about 1e-7 at 32 characters and 2.4e-7 at 64; fewer than
# 8 different digits 4e-8 at 32; six evenly stepping bytes under 1e-8; the rest far less.
# None of 600,000 token_hex(16) and 600,000 token_hex(32) salts was rejected. (Fewer than
# 10 digits, or a run of 6, would reject about 1 in 10^4 and 1 in 3 x 10^4 random salts.)
SALT_MIN_DISTINCT = 8
SALT_MAX_RUN = 7
# Read as bytes (pairs of hex digits), a run of this many bytes whose values step evenly
# (00 01 02 ..., 00 11 22 ...) is refused.
SALT_BYTE_RUN = 6
# Digit-to-digit steps (mod 16) that repeat with a period this short over the whole salt (a1b2c3...).
SALT_STEP_PERIOD = 4
# Published values someone might paste: test vectors, well-known digests, hex words. Compared on
# the full value and on the leading 32 digits.
SALT_DENYLIST = (
    "000102030405060708090a0b0c0d0e0f",
    "00112233445566778899aabbccddeeff",
    "2b7e151628aed2a6abf7158809cf4f3c",
    "d41d8cd98f00b204e9800998ecf8427e",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "deadbeefcafebabe8badf00d1337c0de",
)
_SALT_DENIED = frozenset(SALT_DENYLIST) | frozenset(value[:32] for value in SALT_DENYLIST)
_HEX = "0123456789abcdef"
# Every field name the schemas define. A duplicate-key error names a key only when it is
# one of these, so an arbitrary key (inside enforcement, say) is never repeated back.
FIELD_NAMES = frozenset(
    TOP_ALLOWED_V2
    + ("never_in_prompts", "ok_with_approval", "ok", "approved", "not_approved", "needs_review", "default", "never")
    + ("id", "text", "aliases", "kind", "location", "default_mode", "rules", "mode", "values", "use_instead")
    + ("exceptions",) + EXCEPTION_FIELDS + ("repositories",)
    + CONTACT_TOPICS
    + CONTACT_FIELDS
)


class OverlayError(ValueError):
    pass


def _date(value: object, label: str) -> dt.date:
    if isinstance(value, dt.datetime):
        raise OverlayError(f"{label}: expected a date (YYYY-MM-DD), not a datetime")
    if isinstance(value, dt.date):
        return value
    if isinstance(value, str):
        try:
            return dt.date.fromisoformat(value)
        except ValueError:
            pass
    raise OverlayError(f"{label}: expected a date (YYYY-MM-DD)")


def _item(value: object, label: str, max_len: int = ITEM_MAX) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OverlayError(f"{label}: expected a nonempty phrase")
    if len(value) > max_len:
        raise OverlayError(f"{label}: longer than {max_len} characters; overlay values are short phrases")
    if any(ord(c) < 32 or ord(c) == 127 or c in INVISIBLE_LAYOUT for c in value):
        raise OverlayError(f"{label}: control characters are not allowed")
    return value


# Characters that break or reorder a line where a model or a person reads the phrase: next line, the line and
# paragraph separators, and the bidirectional embedding, override and isolate controls.
INVISIBLE_LAYOUT = frozenset("\u0085\u2028\u2029\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def _items(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or not value:
        raise OverlayError(f"{label}: expected a nonempty list of phrases")
    if len(value) > LIST_MAX:
        raise OverlayError(f"{label}: more than {LIST_MAX} items")
    items = [_item(v, f"{label}[{i}]") for i, v in enumerate(value)]
    if len(set(items)) != len(items):
        raise OverlayError(f"{label}: duplicate items")
    return items


def _object(value: object, label: str, required: tuple[str, ...]) -> dict:
    if not isinstance(value, dict):
        raise OverlayError(f"{label}: expected an object with {sorted(required)}")
    extra = set(value) - set(required)
    missing = set(required) - set(value)
    if extra:
        raise OverlayError(f"{label}: unknown fields {sorted(extra)}")
    if missing:
        raise OverlayError(f"{label}: missing fields {sorted(missing)}")
    return value


def _is_version(value: object, version: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == version


def _top_fields(data: dict, allowed: tuple[str, ...]) -> None:
    extra = set(data) - set(allowed)
    missing = set(TOP_REQUIRED) - set(data)
    if extra:
        raise OverlayError(f"overlay: unknown fields {sorted(extra)}; the schema allows nothing else")
    if missing:
        raise OverlayError(f"overlay: missing fields {sorted(missing)}")


def _owner(value: object, label: str) -> str:
    """owner, and a contact's name, which follows the owner rules (§3.1)."""
    owner = _item(value, label)
    if len(owner) < 3 or len(owner) > 160:
        raise OverlayError(f"{label}: expected 3 to 160 characters")
    return owner


def _header(data: dict, out: dict, allow_null: bool = True) -> None:
    """organization, owner, intake_url and the dates: plain values in both versions.

    Version 1 reads `intake_url: null` as absent, as it always has; version 2 refuses it."""
    org = _item(data["organization"], "organization")
    if len(org) > 80:
        raise OverlayError("organization: longer than 80 characters; display name only")
    out["organization"] = org
    out["owner"] = _owner(data["owner"], "owner")
    if "intake_url" in data and (data["intake_url"] is not None or not allow_null):
        out["intake_url"] = _item(data["intake_url"], "intake_url", max_len=500)
    out["reviewed_on"] = _date(data["reviewed_on"], "reviewed_on")
    out["expires_on"] = _date(data["expires_on"], "expires_on")
    if out["expires_on"] <= out["reviewed_on"]:
        raise OverlayError("expires_on: must be after reviewed_on")


def _templates(data: dict, allow_null: bool = True) -> list[dict]:
    templates = data.get("templates", [])
    if templates is None:
        if not allow_null:
            raise OverlayError("templates: expected a list of at most 20 entries, not null")
        templates = []
    if not isinstance(templates, list) or len(templates) > 20:
        raise OverlayError("templates: expected a list of at most 20 entries")
    out = []
    for i, entry in enumerate(templates):
        label = f"templates[{i}]"
        if not isinstance(entry, dict) or "kind" not in entry or set(entry) - {"kind", "location"}:
            raise OverlayError(f"{label}: expected an object with kind and optional location")
        kind = entry["kind"]
        if not isinstance(kind, str) or not KIND_RE.fullmatch(kind) or len(kind) > 64:
            raise OverlayError(f"{label}.kind: expected a lowercase-hyphen identifier")
        normalized = {"kind": kind}
        if "location" in entry:
            location = _item(entry["location"], f"{label}.location", max_len=500)
            normalized["location"] = location
        out.append(normalized)
    return out


def validate_structure(data: object) -> dict:
    """Schema-equivalent structural checks. Returns a normalized copy.

    Dispatches on `schema_version`: 1 gets the version 1 rules, unchanged; 2
    gets the version 2 rules; anything else is rejected.
    """
    if not isinstance(data, dict):
        raise OverlayError("overlay: expected a YAML object")
    version = data.get("schema_version")
    if _is_version(version, 2):
        return _validate_structure_v2(data)
    # Checked before any other field, so "2" or 2.0 reads as a version error.
    if "schema_version" in data and (isinstance(version, bool) or version != 1):
        raise OverlayError("schema_version: expected 1 or 2")
    return _validate_structure_v1(data)


def _validate_structure_v1(data: dict) -> dict:
    _top_fields(data, TOP_ALLOWED)
    schema_version = data["schema_version"]
    if isinstance(schema_version, bool) or schema_version != 1:
        raise OverlayError("schema_version: expected 1 or 2")
    out: dict = {"schema_version": 1}
    _header(data, out)
    dc = _object(data["data_classes"], "data_classes", ("never_in_prompts", "ok_with_approval", "ok"))
    out["data_classes"] = {k: _items(dc[k], f"data_classes.{k}") for k in ("never_in_prompts", "ok_with_approval", "ok")}
    hosting = _object(data["hosting"], "hosting", ("approved", "not_approved"))
    out["hosting"] = {k: _items(hosting[k], f"hosting.{k}") for k in ("approved", "not_approved")}
    services = _object(data["services"], "services", ("approved", "needs_review"))
    out["services"] = {k: _items(services[k], f"services.{k}") for k in ("approved", "needs_review")}
    identity = _object(data["identity"], "identity", ("default", "never"))
    out["identity"] = {"default": _item(identity["default"], "identity.default"), "never": _items(identity["never"], "identity.never")}
    out["review_triggers"] = _items(data["review_triggers"], "review_triggers")
    out["templates"] = _templates(data)
    return out


# ----------------------------------------------------------------- version 2 structure


class _Ids:
    """Every id and alias in one file, with where it was defined (§6.3 rule 3)."""

    def __init__(self) -> None:
        self.where: dict[str, str] = {}

    def add(self, value: object, label: str) -> str:
        if not isinstance(value, str) or not ID_RE.fullmatch(value) or len(value) > ID_MAX:
            raise OverlayError(
                f"{label}: expected an id of lowercase letters, digits and single hyphens, at most {ID_MAX} characters"
            )
        if value in self.where:
            raise OverlayError(f"{label}: already used at {self.where[value]}; ids, aliases and template kinds are unique across the file")
        self.where[value] = label
        return value


def _item_v2(value: object, label: str, ids: _Ids) -> dict:
    if isinstance(value, str):
        raise OverlayError(
            f"{label}: a plain string is a version 1 item; in a version 2 file every item is an object with id and "
            "text (convert a version 1 file with `validate_overlay.py migrate`)"
        )
    if not isinstance(value, dict):
        raise OverlayError(f"{label}: expected an object with id, text and optional aliases")
    extra = set(value) - {"id", "text", "aliases"}
    missing = {"id", "text"} - set(value)
    if extra:
        raise OverlayError(f"{label}: unknown fields {sorted(extra)}")
    if missing:
        raise OverlayError(f"{label}: missing fields {sorted(missing)}")
    out = {"id": ids.add(value["id"], f"{label}.id"), "text": _item(value["text"], f"{label}.text")}
    if "aliases" in value:
        aliases = value["aliases"]
        if not isinstance(aliases, list) or len(aliases) > ALIASES_MAX:
            raise OverlayError(f"{label}.aliases: expected a list of at most {ALIASES_MAX} former ids")
        normalized = [ids.add(a, f"{label}.aliases[{i}]") for i, a in enumerate(aliases)]
        if normalized:
            out["aliases"] = normalized
    return out


def _items_v2(value: object, label: str, ids: _Ids) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise OverlayError(f"{label}: expected a nonempty list of items")
    if len(value) > LIST_MAX:
        raise OverlayError(f"{label}: more than {LIST_MAX} items")
    items = [_item_v2(v, f"{label}[{i}]", ids) for i, v in enumerate(value)]
    texts = [item["text"] for item in items]
    if len(set(texts)) != len(texts):
        raise OverlayError(f"{label}: duplicate items")
    return items


def _validate_structure_v2(data: dict) -> dict:
    _top_fields(data, TOP_ALLOWED_V2)
    out: dict = {"schema_version": 2}
    _header(data, out, allow_null=False)
    if "contacts" in data:
        out["contacts"] = _contacts(data["contacts"])
    ids = _Ids()
    dc = _object(data["data_classes"], "data_classes", ("never_in_prompts", "ok_with_approval", "ok"))
    out["data_classes"] = {k: _items_v2(dc[k], f"data_classes.{k}", ids) for k in ("never_in_prompts", "ok_with_approval", "ok")}
    hosting = _object(data["hosting"], "hosting", ("approved", "not_approved"))
    out["hosting"] = {k: _items_v2(hosting[k], f"hosting.{k}", ids) for k in ("approved", "not_approved")}
    services = _object(data["services"], "services", ("approved", "needs_review"))
    out["services"] = {k: _items_v2(services[k], f"services.{k}", ids) for k in ("approved", "needs_review")}
    identity = _object(data["identity"], "identity", ("default", "never"))
    out["identity"] = {
        "default": _item_v2(identity["default"], "identity.default", ids),
        "never": _items_v2(identity["never"], "identity.never", ids),
    }
    out["review_triggers"] = _items_v2(data["review_triggers"], "review_triggers", ids)
    out["templates"] = _templates(data, allow_null=False)
    # Templates keep kind as their id (§2.1), so a kind is unique against every other id.
    for i, template in enumerate(out["templates"]):
        ids.add(template["kind"], f"templates[{i}].kind")
    if "salt" in data:
        out["salt"] = _salt(data["salt"])
    if "enforcement" in data:
        if "salt" not in out:
            raise OverlayError(
                "salt: required when enforcement is present, so the file's SHA-256, which a model sees, cannot confirm a "
                f"guessed enforcement value; {SALT_HOW}"
            )
        out["enforcement"] = _enforcement(data["enforcement"], out, ids)
    return out


def _contacts(value: object) -> dict:
    """Topic contacts (§3.1): one or more of the closed topics, each {name, optional intake_url}.

    `name` follows the owner rules and `intake_url` the intake_url rules; the content scan
    checks both (validate_content). Returned in the order of CONTACT_TOPICS."""
    topics = ", ".join(CONTACT_TOPICS)
    if not isinstance(value, dict) or not value:
        raise OverlayError(f"contacts: expected an object with one or more of {topics}")
    extra = set(value) - set(CONTACT_TOPICS)
    if extra:
        raise OverlayError(f"contacts: unknown topics {sorted(str(k) for k in extra)}; the topics are {topics}")
    out = {}
    for topic in CONTACT_TOPICS:
        if topic not in value:
            continue
        label = f"contacts.{topic}"
        contact = value[topic]
        if not isinstance(contact, dict):
            raise OverlayError(f"{label}: expected an object with name and optional intake_url")
        unknown = set(contact) - set(CONTACT_FIELDS)
        if unknown:
            raise OverlayError(f"{label}: unknown fields {sorted(str(k) for k in unknown)}; a contact has name and optional intake_url")
        if "name" not in contact:
            raise OverlayError(f"{label}: missing fields ['name']")
        normalized = {"name": _owner(contact["name"], f"{label}.name")}
        if "intake_url" in contact:
            normalized["intake_url"] = _item(contact["intake_url"], f"{label}.intake_url", max_len=500)
        out[topic] = normalized
    return out


def _salt(value: object) -> str:
    """§6.3 rule 10. Messages never repeat the value."""
    if not isinstance(value, str) or not SALT_RE.fullmatch(value):
        raise OverlayError(f"salt: expected a quoted string of 32 to 128 lowercase hex characters; {SALT_HOW}")
    problem = salt_problem(value)
    if problem:
        raise OverlayError(f"salt: {problem}, so it may not hide the enforcement values; {SALT_HOW}")
    return value


def _periodic(sequence, max_period: int) -> bool:
    """True when the whole sequence repeats with some period from 1 to max_period."""
    n = len(sequence)
    return any(all(sequence[i] == sequence[i + period] for i in range(n - period)) for period in range(1, max_period + 1))


def _even_run(numbers: list[int], length: int) -> bool:
    """True when `length` or more numbers in a row step by one constant amount."""
    count, previous = 1, None
    for a, b in zip(numbers, numbers[1:]):
        count = count + 1 if b - a == previous else 2
        previous = b - a
        if count >= length:
            return True
    return False


def salt_problem(value: str) -> str | None:
    """Why a well-formed salt looks hand-made, or None. Catches common mistakes; does not measure randomness."""
    value = value.lower()
    if value in _SALT_DENIED or value[:32] in _SALT_DENIED:
        return "it is a well-known published value"
    shorter = min(len(value), len(EXAMPLE_SALT))
    if sum(a != b for a, b in zip(value, EXAMPLE_SALT)) <= shorter / 2:
        return "it is the published example's salt or close to it"
    octets = [int(value[i:i + 2], 16) for i in range(0, len(value) - 1, 2)]
    if _periodic(value, len(value) // 2) or _periodic(octets, len(octets) // 2):
        return "it repeats a pattern"
    if len(set(value)) < SALT_MIN_DISTINCT:
        return f"it uses fewer than {SALT_MIN_DISTINCT} different hex digits"
    up = down = 1
    for a, b in zip(value, value[1:]):
        step = _HEX.index(b) - _HEX.index(a)
        up = up + 1 if step == 1 else 1
        down = down + 1 if step == -1 else 1
        if max(up, down) > SALT_MAX_RUN:
            return f"it has a run of {SALT_MAX_RUN + 1} or more consecutive hex digits"
    if _even_run(octets, SALT_BYTE_RUN):
        return f"it has {SALT_BYTE_RUN} or more bytes in a row that step evenly"
    steps = [(_HEX.index(b) - _HEX.index(a)) % 16 for a, b in zip(value, value[1:])]
    if _periodic(steps, SALT_STEP_PERIOD):
        return "its digits step in a repeating pattern"
    return None


def new_salt() -> str:
    """A salt from `secrets.token_hex(32)` that passes `salt_problem`, which it all but always does first time."""
    while True:
        value = secrets.token_hex(32)
        if salt_problem(value) is None:
            return value


def _mode(value: object, label: str) -> str:
    if value not in MODES or not isinstance(value, str):
        raise OverlayError(f"{label}: expected one of {', '.join(MODES)}")
    return value


def _enforcement(value: object, overlay: dict, ids: _Ids) -> dict:
    """The machine-only section (§2.2, §3.1, §6.3 rules 4 to 6). Error messages name a value's
    position, never the value: a listed host or branch is not echoed anywhere."""
    if not isinstance(value, dict):
        raise OverlayError("enforcement: expected an object with rules, and optional default_mode and exceptions")
    extra = set(value) - {"default_mode", "rules", "exceptions"}
    if extra:
        raise OverlayError(f"enforcement: {_count(extra, 'unknown field')}; it has rules, and optional default_mode and exceptions")
    if "rules" not in value:
        raise OverlayError("enforcement: missing fields ['rules']")
    out = {"default_mode": _mode(value["default_mode"], "enforcement.default_mode") if "default_mode" in value else DEFAULT_MODE}
    rules = value["rules"]
    if not isinstance(rules, list) or not 1 <= len(rules) <= RULES_MAX:
        raise OverlayError(f"enforcement.rules: expected a list of 1 to {RULES_MAX} rules")
    targets = set()
    for group, key in USE_INSTEAD_LISTS:
        for item in overlay[group][key]:
            targets.add(item["id"])
            targets.update(item.get("aliases", []))
    out["rules"] = [_rule(rule, f"enforcement.rules[{i}]", ids, targets) for i, rule in enumerate(rules)]
    if "exceptions" in value:
        exceptions = value["exceptions"]
        if not isinstance(exceptions, list) or not 1 <= len(exceptions) <= EXCEPTIONS_MAX:
            raise OverlayError(f"enforcement.exceptions: expected a list of 1 to {EXCEPTIONS_MAX} exceptions")
        rules_by_id = {rule["id"]: rule for rule in out["rules"]}
        out["exceptions"] = [
            _exception(entry, f"enforcement.exceptions[{i}]", ids, rules_by_id, overlay["expires_on"]) for i, entry in enumerate(exceptions)
        ]
    return out


def _exception(value: object, label: str, ids: _Ids, rules_by_id: dict, file_expires: dt.date) -> dict:
    """One expiring exception (§3.1): it relaxes the enforcement rule `rule` names until `expires_on`, which is no later
    than the file's own. `allows` are values of that rule's kind: for protected_branch, branches the rule stops
    protecting; for deploy_host, package_registry and cloud_account, extra approved hosts, registries or accounts.
    `where` limits it to repositories, and only the pull-request check reads it. Messages name positions, never a value
    from enforcement."""
    if not isinstance(value, dict):
        raise OverlayError(f"{label}: expected an object with id, rule, allows, approver_role, expires_on and optional where")
    extra = set(value) - set(EXCEPTION_FIELDS)
    missing = set(EXCEPTION_FIELDS) - {"where"} - set(value)
    if extra:
        raise OverlayError(
            f"{label}: {_count(extra, 'unknown field')}; an exception has id, rule, allows, approver_role, expires_on and "
            "optional where, and no free text"
        )
    if missing:
        raise OverlayError(f"{label}: missing fields {sorted(missing)}")
    out = {"id": ids.add(value["id"], f"{label}.id")}
    # Enforcement rules have no aliases, so an exception names its rule by id.
    rule = rules_by_id.get(value["rule"]) if isinstance(value["rule"], str) else None
    if rule is None:
        raise OverlayError(f"{label}.rule: expected the id of a rule in enforcement.rules")
    out["rule"] = rule["id"]
    allows = value["allows"]
    if not isinstance(allows, list) or not 1 <= len(allows) <= VALUES_MAX:
        raise OverlayError(f"{label}.allows: expected a list of 1 to {VALUES_MAX} values")
    seen = set()
    for j, entry in enumerate(allows):
        where = f"{label}.allows[{j}]"
        if not isinstance(entry, str):
            raise OverlayError(f"{where}: expected a quoted string")
        problem = value_problem(rule["kind"], entry)
        if problem:
            raise OverlayError(f"{where}: {problem}; an exception allows values of its rule's kind, here {rule['kind']}")
        normalized = normalize_value(rule["kind"], entry)
        if rule["kind"] == "protected_branch":
            normalized = normalized.casefold()  # the hook matches branches ignoring case (policy.branch_matches)
        if normalized in seen:
            raise OverlayError(f"{where}: duplicates an earlier value of this exception")
        seen.add(normalized)
    out["allows"] = list(allows)
    role = _item(value["approver_role"], f"{label}.approver_role", max_len=APPROVER_ROLE_MAX)
    if EMAIL_RE.search(role):
        raise OverlayError(f"{label}.approver_role: expected a role, such as a job title, not an email address")
    if URL_RE.search(role):
        raise OverlayError(f"{label}.approver_role: expected a role, such as a job title, not a URL")
    out["approver_role"] = role
    expires = _date(value["expires_on"], f"{label}.expires_on")
    if expires > file_expires:
        raise OverlayError(f"{label}.expires_on: after the file's expires_on; an exception never outlives the file")
    out["expires_on"] = expires
    if "where" in value:
        out["where"] = _where(value["where"], f"{label}.where")
    return out


def _where(value: object, label: str) -> dict:
    if not isinstance(value, dict) or set(value) != {"repositories"}:
        raise OverlayError(f"{label}: expected an object with repositories and nothing else")
    repositories = value["repositories"]
    if not isinstance(repositories, list) or not 1 <= len(repositories) <= VALUES_MAX:
        raise OverlayError(f"{label}.repositories: expected a list of 1 to {VALUES_MAX} repositories")
    seen = set()
    for j, entry in enumerate(repositories):
        if not isinstance(entry, str) or not REPOSITORY_RE.fullmatch(entry):
            raise OverlayError(f"{label}.repositories[{j}]: expected a repository as owner/name")
        if entry.lower() in seen:
            raise OverlayError(f"{label}.repositories[{j}]: duplicates an earlier repository (case is ignored)")
        seen.add(entry.lower())
    return {"repositories": list(repositories)}


def _rule(value: object, label: str, ids: _Ids, targets: set[str]) -> dict:
    if not isinstance(value, dict):
        raise OverlayError(f"{label}: expected an object with id, kind, values, and optional mode and use_instead")
    extra = set(value) - {"id", "kind", "mode", "values", "use_instead"}
    missing = {"id", "kind", "values"} - set(value)
    if extra:
        raise OverlayError(f"{label}: {_count(extra, 'unknown field')}; a rule has id, kind, values, optional mode and use_instead, and no free text")
    if missing:
        raise OverlayError(f"{label}: missing fields {sorted(missing)}")
    out = {"id": ids.add(value["id"], f"{label}.id")}
    kind = value["kind"]
    if not isinstance(kind, str) or kind not in RULE_KINDS:
        raise OverlayError(f"{label}.kind: expected one of {', '.join(ACCEPTED_KINDS)}")
    if kind not in ACCEPTED_KINDS:
        raise OverlayError(
            f"{label}.kind: {kind} enters the schema with its first consumer (OVERLAY_V2.md §2.2); "
            f"this release accepts {', '.join(ACCEPTED_KINDS)}"
        )
    out["kind"] = kind
    if "mode" in value:
        out["mode"] = _mode(value["mode"], f"{label}.mode")
    values = value["values"]
    if not isinstance(values, list) or not 1 <= len(values) <= VALUES_MAX:
        raise OverlayError(f"{label}.values: expected a list of 1 to {VALUES_MAX} values")
    seen = set()
    for j, entry in enumerate(values):
        where = f"{label}.values[{j}]"
        if not isinstance(entry, str):
            raise OverlayError(f"{where}: expected a quoted string")
        problem = value_problem(kind, entry)
        if problem:
            raise OverlayError(f"{where}: {problem}")
        normalized = normalize_value(kind, entry)
        if kind == "protected_branch":
            normalized = normalized.casefold()  # the hook matches branches ignoring case (policy.branch_matches)
        if normalized in seen:
            raise OverlayError(f"{where}: duplicates an earlier value of this rule")
        seen.add(normalized)
    out["values"] = list(values)
    if "use_instead" in value:
        target = value["use_instead"]
        if not isinstance(target, str) or target not in targets:
            raise OverlayError(f"{label}.use_instead: expected the id or an alias of an item in hosting.approved or services.approved")
        out["use_instead"] = target
    return out


def _count(things: set, noun: str) -> str:
    return f"{len(things)} {noun}{'' if len(things) == 1 else 's'}"


def _host_problem(value: str) -> str | None:
    host = value[2:] if value.startswith("*.") else value
    labels = host.split(".")
    if (
        len(host) > 253
        or len(labels) < 2
        or not all(_HOST_LABEL_RE.fullmatch(label) for label in labels)
        or labels[-1].isdigit()
    ):
        return "expected a lowercase host name with at least one dot, optionally starting with *.; no scheme, port, path or credentials"
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None
    return "IP addresses are not allowed; list host names"


BRANCH_MAX = 255  # catpilot_guard/policy.py VALUE_MAX_CHARS: the hook refuses a longer value
REGISTRY_MAX = 255  # the same limit


def _branch_problem(value: str) -> str | None:
    if len(value) > BRANCH_MAX:
        return f"expected a Git branch name of at most {BRANCH_MAX} characters"
    if value.startswith("refs/"):
        return "write the branch name without refs/heads/ (or any refs/ prefix): pushes are matched by branch name"
    base = value[:-2] if value.endswith("/*") else value
    bad = (
        not base
        or "*" in base
        or any(c in _BRANCH_FORBIDDEN or c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base)
        or base.startswith(("-", "/"))
        or base.endswith(("/", "."))
        or ".." in base
        or "//" in base
        or "@{" in base
        or base in ("@", "HEAD")
        or any(part.startswith(".") or part.endswith(".lock") for part in base.split("/"))
    )
    if bad:
        return "expected a Git branch name (no spaces, .., ~, ^, :, ?, [, \\ or leading -), with * only as a trailing /*"
    return None


def value_problem(kind: str, value: str) -> str | None:
    """Why a value does not match its kind (§6.3 rule 5), or None. Never repeats the value."""
    if kind == "protected_branch":
        return _branch_problem(value)
    if kind == "deploy_host":
        return _host_problem(value)
    if kind == "package_registry":
        if len(value) > REGISTRY_MAX:
            return f"expected a registry of at most {REGISTRY_MAX} characters"
        host, _, path = value.partition("/")
        problem = _host_problem(host)
        if problem:
            return problem
        if path and not _REGISTRY_PATH_RE.fullmatch(path):
            return "expected a registry host name and an optional path of letters, digits, ., _, - and /; no scheme, query or credentials"
        if any(segment in (".", "..") for segment in path.split("/")):
            return "expected a path without . or .. segments: a .. segment makes the value cover more than its path"
        return None
    if kind == "cloud_account":
        if not _CLOUD_ACCOUNT_RE.fullmatch(value):
            return "expected aws:<12 digits>, azure:<lowercase subscription GUID> or gcp:<project id>"
        return None
    return f"unknown kind {kind}"


def normalize_value(kind: str, value: str) -> str:
    """A value as uniqueness compares it (§6.3 rule 5): case folded for names that ignore case."""
    if kind == "protected_branch":
        return value
    if kind == "package_registry":
        return value.lower().rstrip("/")
    return value.lower()


# ----------------------------------------------------------------- views for consumers


def model_facing(overlay: dict) -> dict:
    """The parts of a validated overlay a model may see.

    Version 1 is returned as it is. Version 2 loses `enforcement` and `salt`
    (never rendered, never returned: OVERLAY_V2.md §2.2, §6.3 rule 10) and
    every item's `aliases` (no rules-block or bundle consumer: §4). Ids, text
    and `contacts` (§3.1) stay.
    """
    if not _is_version(overlay.get("schema_version"), 2):
        return overlay
    out = {key: copy.deepcopy(value) for key, value in overlay.items() if key not in MACHINE_ONLY}
    for _, item in _iter_items(out):
        item.pop("aliases", None)
    return out


MACHINE_ONLY = ("salt", "enforcement")


def v1_projection(overlay: dict) -> dict:
    """A validated overlay in version 1's shape, for consumers written against it.

    Version 1 is returned as it is. Version 2 becomes the version 1 overlay it
    corresponds to: each item's `text` in place of the item, ids and aliases
    dropped, no `enforcement`. It is what `validate_structure` returns for the
    version 1 file `migrate` started from, so bundles, paste blocks and the
    server answer the same for a file and its migration. No `salt` either, and
    no `contacts`, which version 1 has no field for: the server reads them
    with `topic_contacts`, and the rules block through `model_facing`.
    """
    if not _is_version(overlay.get("schema_version"), 2):
        return overlay

    def texts(items: list[dict]) -> list[str]:
        return [item["text"] for item in items]

    out: dict = {"schema_version": 1, "organization": overlay["organization"], "owner": overlay["owner"]}
    if "intake_url" in overlay:
        out["intake_url"] = overlay["intake_url"]
    out["reviewed_on"] = overlay["reviewed_on"]
    out["expires_on"] = overlay["expires_on"]
    out["data_classes"] = {k: texts(v) for k, v in overlay["data_classes"].items()}
    out["hosting"] = {k: texts(v) for k, v in overlay["hosting"].items()}
    out["services"] = {k: texts(v) for k, v in overlay["services"].items()}
    out["identity"] = {"default": overlay["identity"]["default"]["text"], "never": texts(overlay["identity"]["never"])}
    out["review_triggers"] = texts(overlay["review_triggers"])
    out["templates"] = [dict(t) for t in overlay.get("templates", [])]
    return out


def topic_contacts(overlay: dict) -> dict:
    """A validated overlay's topic contacts (§3.1), {topic: {name, optional intake_url}}; empty
    for version 1 and for a version 2 file without them. A copy: model-facing, like owner."""
    if not _is_version(overlay.get("schema_version"), 2):
        return {}
    return copy.deepcopy(overlay.get("contacts") or {})


def _iter_items(overlay: dict):
    """(label, item) for every model-facing item of a version 2 overlay, in file order."""
    for group, key, _ in LISTS:
        for i, item in enumerate(overlay[group][key]):
            yield f"{group}.{key}[{i}]", item
    yield "identity.default", overlay["identity"]["default"]
    for i, item in enumerate(overlay["identity"]["never"]):
        yield f"identity.never[{i}]", item
    for i, item in enumerate(overlay["review_triggers"]):
        yield f"review_triggers[{i}]", item


# ----------------------------------------------------------------- content


def _walk_strings(node: object, path: str = "overlay"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_strings(v, f"{path}[{i}]")


def _validate_https_url(location: str, label: str, allowed_hosts: set[str], errors: list[str]) -> None:
    try:
        parts = urlsplit(location)
    except ValueError as exc:
        raise OverlayError(f"{label}: could not parse as a URL ({exc})") from None
    if parts.scheme != "https":
        errors.append(f"{label}: must be an https URL, not {parts.scheme or 'a schemeless value'!r}")
    elif not parts.hostname:
        errors.append(f"{label}: must include a hostname")
    elif parts.username or parts.password:
        errors.append(f"{label}: must not carry credentials")
    elif parts.query or parts.fragment:
        errors.append(f"{label}: must not carry a query string or fragment")
    elif parts.hostname not in allowed_hosts:
        errors.append(f"{label}: host {parts.hostname!r} is not on the allowlist (pass --allow-host)")


def _looks_like_secret(text: str) -> bool:
    return any(pattern.search(text) for pattern in SECRET_PATTERNS)


def validate_content(overlay: dict, allowed_hosts: set[str]) -> list[str]:
    """Return content errors: secrets, disallowed URLs, identifiers, narratives.

    A template's location and optional intake_url are validated directly (not by
    first finding something URL-shaped with URL_RE), because a value that is not
    URL-shaped at all is still not an https URL and must be rejected.

    In version 2 the scan covers every model-facing value (texts, ids,
    aliases and contacts); `enforcement` gets the secret scan only, since its
    values are host and branch names checked by their kind (§6.3 rule 8), and
    none of its host values may appear in a model-facing value (rule 7). A
    contact's `name` may be an email address, as owner may, and nowhere else
    may (§3.1); a contact's `intake_url` is checked as intake_url is.
    """
    errors: list[str] = []
    model = {key: value for key, value in overlay.items() if key not in MACHINE_ONLY}
    templates = model.get("templates", [])
    allowed_url_paths = set()
    for i, template in enumerate(templates):
        location = template.get("location")
        if location is None:
            continue
        label = f"overlay.templates[{i}].location"
        allowed_url_paths.add(label)
        _validate_https_url(location, label, allowed_hosts, errors)
    if "intake_url" in model and model["intake_url"] is not None:
        label = "overlay.intake_url"
        allowed_url_paths.add(label)
        _validate_https_url(model["intake_url"], label, allowed_hosts, errors)
    allowed_email_paths = {"overlay.owner"}
    email_where = "owner"
    contacts = model.get("contacts") if _is_version(overlay.get("schema_version"), 2) else None
    if contacts:
        email_where = "owner and contacts.<topic>.name"
        for topic, contact in contacts.items():
            allowed_email_paths.add(f"overlay.contacts.{topic}.name")
            if "intake_url" in contact:
                label = f"overlay.contacts.{topic}.intake_url"
                allowed_url_paths.add(label)
                _validate_https_url(contact["intake_url"], label, allowed_hosts, errors)
    for path, text in _walk_strings(model):
        if _looks_like_secret(text):
            errors.append(f"{path}: looks like a secret; overlays never contain credentials")
        if path not in allowed_url_paths:
            for _ in URL_RE.findall(text):
                errors.append(f"{path}: URLs are only allowed in templates[].location and intake_url")
                break
        if path not in allowed_email_paths and EMAIL_RE.search(text):
            errors.append(f"{path}: email addresses are only allowed in {email_where}")
        for candidate in IP_RE.findall(text):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            errors.append(f"{path}: IP addresses are internal identifiers and are not allowed")
            break
        if NARRATIVE_RE.search(text):
            errors.append(f"{path}: reads like an incident narrative; overlay values are lists of approved things, not stories")
    for key in MACHINE_ONLY:
        for path, text in _walk_strings(overlay.get(key), f"overlay.{key}"):
            if _looks_like_secret(text):
                errors.append(f"{path}: looks like a secret; overlays never contain credentials")
    enforcement = overlay.get("enforcement")
    if enforcement:
        errors.extend(_enforcement_values_in_model_text(model, enforcement))
    return errors


def _needles(kind: str, value: str) -> list[str]:
    """The forms of an allow-list value that must not appear in model-facing text."""
    value = value.lower()
    if value.startswith("*."):
        value = value[2:]
    needles = [value]
    if kind == "package_registry" and "/" in value:
        needles.append(value.split("/", 1)[0])
    if kind == "cloud_account":
        needles.append(value.split(":", 1)[1])
    return needles


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def _enforcement_values_in_model_text(model: dict, enforcement: dict) -> list[str]:
    """§6.3 rule 7, an error (decision 5): no deploy_host, package_registry or
    cloud_account value, a rule's or an exception's, in a model-facing phrase, id or alias, an enforcement rule's or
    exception's id (in deny reasons and evidence), or in organization, owner or a contact's name, ignoring case and a
    leading `*.`. An id cannot hold a
    dot, so an id, alias or template kind is checked for the value with each run of
    other characters as one hyphen, the form `migrate` would give it.
    templates[].location, intake_url and a contact's intake_url are exempt. The error
    names the rule or exception, never the value."""
    texts: list[tuple[str, str]] = [("overlay.organization", model["organization"]), ("overlay.owner", model["owner"])]
    texts.extend((f"overlay.contacts.{topic}.name", contact["name"]) for topic, contact in (model.get("contacts") or {}).items())
    identifiers: list[tuple[str, str]] = []
    for label, item in _iter_items(model):
        texts.append((f"overlay.{label}.text", item["text"]))
        identifiers.append((f"overlay.{label}.id", item["id"]))
        identifiers.extend((f"overlay.{label}.aliases[{i}]", a) for i, a in enumerate(item.get("aliases", [])))
    identifiers.extend((f"overlay.templates[{i}].kind", t["kind"]) for i, t in enumerate(model.get("templates", [])))
    # Enforcement ids too: a rule id is in every deny reason the model reads, and both kinds of id are in evidence.
    identifiers.extend((f"enforcement.rules[{i}].id", rule["id"]) for i, rule in enumerate(enforcement["rules"]))
    identifiers.extend((f"enforcement.exceptions[{i}].id", exc["id"]) for i, exc in enumerate(enforcement.get("exceptions", [])))
    kinds = {rule["id"]: rule["kind"] for rule in enforcement["rules"]}
    # Each rule's values, then each exception's allows, which are values of its rule's kind (§3.1).
    sources = [(f"enforcement rule {rule['id']!r}", f"enforcement.rules[{i}]", rule["kind"], rule["values"])
               for i, rule in enumerate(enforcement["rules"])]
    sources += [(f"enforcement exception {exc['id']!r}", f"enforcement.exceptions[{i}]", kinds[exc["rule"]], exc["allows"])
                for i, exc in enumerate(enforcement.get("exceptions", []))]
    errors = []
    own_ids = {f"enforcement rule {rule['id']!r}": rule["id"] for rule in enforcement["rules"]}
    own_ids.update({f"enforcement exception {exc['id']!r}": exc["id"] for exc in enforcement.get("exceptions", [])})
    all_slugs = [s for _, _, kind, values in sources if kind in HOST_KINDS
                 for s in (_slug(n) for value in values for n in _needles(kind, value)) if s]
    for name, position, kind, values in sources:
        if kind not in HOST_KINDS:
            continue
        needles = [n for value in values for n in _needles(kind, value)]
        slugs = [s for s in (_slug(n) for n in needles) if s]
        # A source whose id holds any enforcement value (its own or another's) is named by position, never by that id.
        if any(f"-{s}-" in f"-{own_ids[name]}-" for s in all_slugs):
            name = position
        message = f"names a value of {name}; enforcement values never appear in model-facing text"
        for path, text in texts:
            if any(n in text.lower() for n in needles):
                errors.append(f"{path}: {message}")
        for path, ident in identifiers:
            if any(f"-{s}-" in f"-{ident}-" for s in slugs):
                if path.startswith("enforcement."):
                    # The id is the offending text, so the error names the source by position, never by id.
                    errors.append(f"{path}: names a value of {position}; enforcement values never appear in model-facing text")
                else:
                    errors.append(f"{path}: {message}")
    return errors


def validate_expiry(overlay: dict, today: dt.date | None = None) -> list[str]:
    today = today or dt.date.today()
    if overlay["expires_on"] < today:
        return [f"expires_on: {overlay['expires_on'].isoformat()} has passed; renew the review before building a private bundle"]
    if overlay["reviewed_on"] > today:
        return [f"reviewed_on: {overlay['reviewed_on'].isoformat()} is in the future"]
    return []


def lint_overlay(overlay: dict, today: dt.date | None = None) -> list[str]:
    """Warnings that do not fail validation (§6.3 rule 9). Each names a rule or exception by id, never a value.

    - `ask` has no prompt on Codex, in the pull-request check or in a run with
      nobody to answer, and acts as `block` there (decision 2);
    - `block` on a kind whose consumer has no host verification note yet;
    - a kind no hook acts on in this release (ENFORCED_KINDS), in place of the
      two above, since its mode does nothing yet;
    - an exception within EXCEPTION_WARN_DAYS days of its expires_on, or already
      past it, and so ignored (§3.1); and an exception with `where`, which no hook
      applies, since only the pull-request check, not built yet, reads `where`.
    """
    enforcement = overlay.get("enforcement")
    if not enforcement:
        return []
    today = today or dt.date.today()
    warnings = []
    for i, rule in enumerate(enforcement["rules"]):
        mode = rule.get("mode", enforcement["default_mode"])
        where = f"enforcement.rules[{i}] ({rule['id']})"
        if rule["kind"] not in ENFORCED_KINDS:
            # Its mode does nothing yet, so this is the one thing to say about it.
            warnings.append(f"{where}: kind {rule['kind']} is validated and compiled, and no hook acts on it in this release")
            continue
        if mode == "ask":
            warnings.append(
                f"{where}: mode ask differs by host; where no prompt is possible (Codex, the pull-request check, "
                "a run with nobody to answer) it acts as block"
            )
        if mode == "block" and rule["kind"] not in HOST_VERIFIED_KINDS:
            warnings.append(
                f"{where}: mode block for kind {rule['kind']}, which has no host verification note yet; consider monitor first"
            )
    for i, exception in enumerate(enforcement.get("exceptions", [])):
        where = f"enforcement.exceptions[{i}] ({exception['id']})"
        expires = exception["expires_on"]
        if expires < today:
            warnings.append(
                f"{where}: expired on {expires.isoformat()} and is ignored; rule {exception['rule']} applies as written. "
                "Remove it, or renew it with a reviewer"
            )
        elif (expires - today).days <= EXCEPTION_WARN_DAYS:
            warnings.append(
                f"{where}: expires on {expires.isoformat()}, within {EXCEPTION_WARN_DAYS} days; after that rule "
                f"{exception['rule']} applies as written"
            )
        if "where" in exception:
            warnings.append(
                f"{where}: has where, so no hook applies it; only the pull-request check, which is not built yet, reads where"
            )
    return warnings


def parse_yaml(text: str) -> object:
    """`yaml.safe_load`, refusing a key that appears twice in one mapping, and merge keys.

    PyYAML keeps the last of two equal keys, so a second `enforcement:` block
    or a second `values:` in a rule would silently replace the first. A merge
    key (`<<: *anchor`) changes values the same quiet way, so it is refused
    too. The error names the key's path, and the key only when it is a
    schema field. Raises OverlayError for either, and what safe_load raises
    otherwise.
    """
    node = yaml.compose(text, Loader=yaml.SafeLoader)
    if node is not None:
        _check_duplicate_keys(node, "overlay", yaml.SafeLoader(""), set())
    return yaml.safe_load(text)


def _check_duplicate_keys(node: yaml.Node, path: str, loader: yaml.SafeLoader, visited: set[int]) -> None:
    if id(node) in visited:  # an alias: its node was checked where its anchor is
        return
    visited.add(id(node))
    if isinstance(node, yaml.MappingNode):
        keys = []
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                # A merge key would let a value arrive silently from elsewhere, and a rules file has no use for one.
                raise OverlayError(f"{path}.<<: YAML merge keys are not allowed in a rules file; write each value out")
            key = loader.construct_object(key_node, deep=True)
            where = f"{path}.{key}" if isinstance(key, str) and key in FIELD_NAMES else f"{path}.<a key>"
            try:
                repeated = key in keys
            except TypeError:  # an unhashable key never validates anyway
                repeated = False
            if repeated:
                raise OverlayError(f"{where}: duplicate key; a key may appear once in each mapping")
            keys.append(key)
            _check_duplicate_keys(value_node, where, loader, visited)
    elif isinstance(node, yaml.SequenceNode):
        for i, child in enumerate(node.value):
            _check_duplicate_keys(child, f"{path}[{i}]", loader, visited)


def load_overlay_file(path: Path) -> tuple[dict, bytes]:
    if path.is_symlink():
        raise OverlayError(f"{path}: symlinks are not allowed")
    raw = path.read_bytes()
    if len(raw) > 131072:
        raise OverlayError(f"{path}: larger than 128 KiB; an overlay is a short list")
    try:
        data = parse_yaml(raw.decode("utf-8"))
    except OverlayError as exc:
        raise OverlayError(f"{path}: {exc}") from None
    except (UnicodeDecodeError, yaml.YAMLError, ValueError, RecursionError) as exc:
        # ValueError: an impossible date such as 2026-13-45. RecursionError: nesting too deep to parse.
        raise OverlayError(f"{path}: could not parse YAML ({exc.__class__.__name__})") from None
    return data, raw


def validate_overlay(data: object, allowed_hosts: set[str] | None = None, today: dt.date | None = None) -> tuple[dict, list[str]]:
    """Return (normalized overlay, errors). Structural errors raise OverlayError.

    A version 2 result still holds `enforcement`. Give a renderer or the server
    `model_facing()` or `v1_projection()` of it, never the result itself.
    """
    overlay = validate_structure(data)
    errors = validate_expiry(overlay, today) + validate_content(overlay, allowed_hosts or set())
    return overlay, errors


# ----------------------------------------------------------------- migrate (§2.4)


def derive_id(prefix: str, text: str, taken: set[str]) -> str:
    """An id from a phrase, as OVERLAY_V2.md §2.4 says: the list's prefix, a hyphen,
    the text lowercased with each run of other characters as one hyphen, cut at a
    hyphen to at most 48 characters; a repeat gets -2, -3. Adds the id to `taken`.

    Leading and trailing hyphens are dropped, since the id grammar has none. A first
    word too long to fit is cut at 48 characters rather than dropped.
    """
    slug = _slug(text)
    base = f"{prefix}-{slug}" if slug else prefix
    if len(base) > MIGRATED_ID_MAX:
        cut = base.rfind("-", 0, MIGRATED_ID_MAX + 1)
        base = base[:cut] if cut > len(prefix) else base[:MIGRATED_ID_MAX].rstrip("-")
    candidate, n = base, 2
    while candidate in taken:
        candidate, n = f"{base}-{n}", n + 1
    taken.add(candidate)
    return candidate


def migrate(data: object) -> dict:
    """A version 1 overlay as version 2 (OVERLAY_V2.md §2.4).

    Sets `schema_version: 2`, turns each phrase into `{id, text}`, copies
    everything else, and adds no `enforcement` and so no `salt`. The dates
    stay: no value changed. Deterministic. A phrase with no ASCII letter or
    digit gets the bare prefix as its id (`data`, then `data-2`). Raises OverlayError for a version 2 file, which
    needs no migration, and for anything that is not a valid version 1 file.
    """
    if isinstance(data, dict) and _is_version(data.get("schema_version"), 2):
        raise OverlayError("schema_version: the file is already version 2; migrate converts version 1 files only, so there is nothing to do")
    source = validate_structure(data)
    # Template kinds are ids too (§2.1): a generated id steps around them.
    taken: set[str] = {t["kind"] for t in source["templates"]}

    def items(values: list[str], prefix: str) -> list[dict]:
        return [{"id": derive_id(prefix, text, taken), "text": text} for text in values]

    out: dict = {"schema_version": 2, "organization": source["organization"], "owner": source["owner"]}
    if "intake_url" in source:
        out["intake_url"] = source["intake_url"]
    out["reviewed_on"] = source["reviewed_on"]
    out["expires_on"] = source["expires_on"]
    out["data_classes"] = {}
    out["hosting"] = {}
    out["services"] = {}
    for group, key, prefix in LISTS:
        out[group][key] = items(source[group][key], prefix)
    default = items([source["identity"]["default"]], "identity")[0]
    out["identity"] = {"default": default, "never": items(source["identity"]["never"], "identity")}
    out["review_triggers"] = items(source["review_triggers"], "trigger")
    out["templates"] = [dict(t) for t in source["templates"]]
    _validate_structure_v2(out)  # a migrated file is a valid version 2 file
    return out


def _quoted(text: str) -> str:
    return yaml.safe_dump(text, default_style='"', allow_unicode=True, width=1 << 30).rstrip("\n")


def _plain(text: str) -> str:
    """An identifier as a plain scalar when YAML reads it back as the same string."""
    try:
        if yaml.safe_load(f"{{k: {text}}}") == {"k": text}:
            return text
    except yaml.YAMLError:
        pass
    return _quoted(text)


def _flow_item(item: dict) -> str:
    return "{id: " + _plain(item["id"]) + ", text: " + _quoted(item["text"]) + "}"


def migrate_text(data: object) -> str:
    """`migrate(data)` as YAML, in the layout of OVERLAY_V2.md §5.2: one item per line. Comments are not carried over."""
    overlay = migrate(data)
    lines = ["schema_version: 2", f"organization: {_quoted(overlay['organization'])}", f"owner: {_quoted(overlay['owner'])}"]
    if "intake_url" in overlay:
        lines.append(f"intake_url: {_quoted(overlay['intake_url'])}")
    lines += [f"reviewed_on: {overlay['reviewed_on'].isoformat()}", f"expires_on: {overlay['expires_on'].isoformat()}"]
    for group in ("data_classes", "hosting", "services"):
        lines += ["", f"{group}:"]
        for key, items in overlay[group].items():
            lines.append(f"  {key}:")
            lines += [f"    - {_flow_item(item)}" for item in items]
    lines += ["", "identity:", f"  default: {_flow_item(overlay['identity']['default'])}", "  never:"]
    lines += [f"    - {_flow_item(item)}" for item in overlay["identity"]["never"]]
    lines += ["", "review_triggers:"]
    lines += [f"  - {_flow_item(item)}" for item in overlay["review_triggers"]]
    if overlay["templates"]:
        lines += ["", "templates:"]
        for template in overlay["templates"]:
            entry = "kind: " + _plain(template["kind"])
            if "location" in template:
                entry += ", location: " + _quoted(template["location"])
            lines.append("  - {" + entry + "}")
    return "\n".join(lines) + "\n"


# ----------------------------------------------------------------- CLI


def migrate_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_overlay.py migrate",
        description="Print a version 1 company rules file as version 2: each phrase becomes {id, text}; dates stay; no enforcement section; comments are not carried over.",
    )
    parser.add_argument("overlay", type=Path)
    parser.add_argument("--output", type=Path, help="write here instead of stdout; refused if the file exists")
    args = parser.parse_args(argv)
    try:
        data, _ = load_overlay_file(args.overlay)
        text = migrate_text(data)
    except (OSError, OverlayError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    if args.output is None:
        sys.stdout.write(text)
    else:
        try:
            with open(args.output, "x", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
        except OSError as exc:
            print(f"REFUSED: {args.output}: {exc.strerror or exc.__class__.__name__}; migrate never overwrites a file", file=sys.stderr)
            return 1
    print(
        "migrated to schema_version 2: every phrase now has an id; reviewed_on and expires_on are unchanged; no enforcement "
        "section was added; comments were not carried over. Validate the result before you use it.",
        file=sys.stderr,
    )
    return 0


# ----------------------------------------------------------------- compile (§2.2)


def compile_policy(overlay: dict, raw: bytes) -> dict | None:
    """The JSON policy the company-rules hook reads, for a validated overlay; None without enforcement rules.

    Each rule keeps its id, kind and values, gets its mode resolved (its own, else
    default_mode), and has use_instead resolved to the approved item's text. The policy
    also carries the file's expires_on and the SHA-256 of its bytes, and, only when the
    file has exceptions, `exceptions`: each with its id, the id of the rule it relaxes,
    its allows, its expires_on, and its where when it has one (§3.1). Nothing else from
    the file is copied: no other list, no owner, no salt, no approver_role.
    """
    enforcement = overlay.get("enforcement")
    if not enforcement:
        return None
    texts = {}
    for group, key in USE_INSTEAD_LISTS:
        for item in overlay[group][key]:
            for name in [item["id"], *item.get("aliases", [])]:
                texts[name] = item["text"]
    rules = []
    for rule in enforcement["rules"]:
        out = {
            "id": rule["id"],
            "kind": rule["kind"],
            "mode": rule.get("mode", enforcement["default_mode"]),
            "values": list(rule["values"]),
        }
        if "use_instead" in rule:
            out["use_instead_text"] = texts[rule["use_instead"]]
        rules.append(out)
    policy = {
        "format": POLICY_FORMAT,
        "format_version": POLICY_FORMAT_VERSION,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "expires_on": overlay["expires_on"].isoformat(),
        "rules": rules,
    }
    exceptions = []
    for exception in enforcement.get("exceptions", []):
        out = {
            "id": exception["id"],
            "rule": exception["rule"],
            "allows": list(exception["allows"]),
            "expires_on": exception["expires_on"].isoformat(),
        }
        if "where" in exception:
            out["where"] = {"repositories": list(exception["where"]["repositories"])}
        exceptions.append(out)
    if exceptions:
        policy["exceptions"] = exceptions
    return policy


def policy_text(policy: dict) -> str:
    """The policy as compile writes it: the same input gives byte-identical output (§6.2). UTF-8, not \\u escapes,
    so a file of non-ASCII names stays within the size the hook reads."""
    return json.dumps(policy, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def check_hook_reads(text: str) -> None:
    """Refuse a policy the company-rules hook would not load (its own parser, catpilot_guard/policy.py), so that
    compile never writes a file that leaves every company rule unenforced. Raises OverlayError."""
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    from catpilot_guard import policy as hook_policy

    try:
        hook_policy.parse(text.encode("utf-8"))
    except hook_policy.PolicyError:
        raise OverlayError(
            "compile: the company-rules hook would not load this policy (too large, or a value it cannot read); "
            "nothing was written"
        ) from None


# What each mode does on each tool (§2.3, decision 2), for the table compile prints.
HOST_EFFECTS = {
    "block": ("deny", "deny"),
    "ask": ("deny; asks the person only if the hook command has --ask", "deny (Codex cannot ask)"),
    "monitor": ("log would_deny only", "log would_deny only"),
}


def effective_modes(policy: dict, today: dt.date | None = None) -> list[str]:
    """One line per rule: id, kind, mode, and what it does on Claude Code and on Codex; then, when the policy has
    exceptions, one line per exception: id, the rule it relaxes, its expiry, and whether the hooks apply it. Never a
    value, and never an exception's allows or repositories."""
    lines = ["rule | kind | mode | Claude Code | Codex"]
    for rule in policy["rules"]:
        if rule["kind"] in ENFORCED_KINDS:
            claude_code, codex = HOST_EFFECTS[rule["mode"]]
        else:
            claude_code = codex = "not enforced in this release"
        lines.append(f"{rule['id']} | {rule['kind']} | {rule['mode']} | {claude_code} | {codex}")
    exceptions = policy.get("exceptions") or []
    if exceptions:
        today = today or dt.date.today()
        lines.append("exception | rule | expires_on | hooks")
        for exception in exceptions:
            if "where" in exception:
                applied = "not applied: it has where, which only the pull-request check reads"
            elif dt.date.fromisoformat(exception["expires_on"]) < today:
                applied = "expired: ignored, the rule applies as written"
            else:
                applied = "applied until it expires"
            lines.append(f"{exception['id']} | {exception['rule']} | {exception['expires_on']} | {applied}")
    return lines


def write_policy(path: Path, text: str, mode: int = 0o644) -> None:
    """Write the policy beside its destination and move it into place, mode 644. A symlink is refused."""
    if path.is_symlink():
        raise OverlayError(f"{path}: symlinks are not allowed")
    directory = path.parent if str(path.parent) else Path(".")
    fd, temporary = tempfile.mkstemp(prefix=".catpilot-policy.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def compile_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_overlay.py compile",
        description="Validate a company rules file and write the JSON policy the company-rules hook reads: the "
        "enforcement rules with their modes resolved, expires_on and the file's SHA-256. A file without enforcement "
        "rules writes nothing. Prints each rule's effect per tool; never prints a listed value.",
    )
    parser.add_argument("overlay", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="where to write the policy (replaced if present)")
    parser.add_argument("--allow-host", action="append", default=[], help="hostname allowed in templates[].location and intake_url, top-level or a contact's (repeatable)")
    args = parser.parse_args(argv)
    try:
        data, raw = load_overlay_file(args.overlay)
        overlay, errors = validate_overlay(data, set(args.allow_host))
        if errors:
            for error in errors:
                print(f"INVALID: {error}", file=sys.stderr)
            return 1
        policy = compile_policy(overlay, raw)
        if policy is None:
            print("no enforcement rules in this file: nothing to compile, and no policy was written", file=sys.stderr)
            return 0
        text = policy_text(policy)
        check_hook_reads(text)
        write_policy(args.out, text)
    except (OSError, OverlayError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    for warning in lint_overlay(overlay):
        print(f"WARNING: {warning}", file=sys.stderr)
    for line in effective_modes(policy):
        print(line)
    count = len(policy["rules"])
    excepted = len(policy.get("exceptions", []))
    with_exceptions = f" and {excepted} exception{'' if excepted == 1 else 's'}" if excepted else ""
    print(
        f"compiled {count} enforcement rule{'' if count == 1 else 's'}{with_exceptions}, expiring {policy['expires_on']}, to {args.out}. "
        "Install it root-owned, mode 644, where the company-rules hook's --policy names it.",
        file=sys.stderr,
    )
    return 0


# ----------------------------------------------------------------- export (issue #100, experimental)

EXPORT_FORMAT = "catpilot-allowlist-export"
EXPORT_FORMAT_VERSION = 2
# Allow-list kinds are `allow` lists; a protect-list kind is a `deny` list (OVERLAY_V2.md §2.2).
EXPORT_LISTS = {"deploy_host": "allow", "package_registry": "allow", "cloud_account": "allow", "protected_branch": "deny"}


def export_policy(overlay: dict, today: dt.date | None = None) -> dict | None:
    """A generic list of the company rules for a gateway or policy engine; None without enforcement rules.

    One object per rule, as the hook evaluates them: a target is outside policy if ANY rule of its kind does not list
    it (an allow rule), or inside a rule's values and not excepted (a deny rule). Rules are never merged. Each carries
    its id, kind, resolved mode, sorted values and that rule's active exceptions without `where` (id, allows, expiry);
    an expired exception is dropped and one with `where` is left out (only the pull-request check reads it). No
    timestamp, salt, source hash, owner, approver_role or use_instead text: the same file and date give identical output.
    """
    enforcement = overlay.get("enforcement")
    if not enforcement:
        return None
    today = today or dt.date.today()
    out = []
    for rule in enforcement["rules"]:
        entry = {
            "rule_id": rule["id"],
            "kind": rule["kind"],
            "list": EXPORT_LISTS[rule["kind"]],
            "mode": rule.get("mode", enforcement["default_mode"]),
            "values": sorted(rule["values"]),
        }
        exceptions = [
            {"exception_id": e["id"], "allows": sorted(e["allows"]), "expires_on": e["expires_on"].isoformat()}
            for e in enforcement.get("exceptions", [])
            if e["rule"] == rule["id"] and "where" not in e and e["expires_on"] >= today
        ]
        if exceptions:
            entry["exceptions"] = sorted(exceptions, key=lambda e: e["exception_id"])
        out.append(entry)
    out.sort(key=lambda e: e["rule_id"])
    return {
        "format": EXPORT_FORMAT,
        "format_version": EXPORT_FORMAT_VERSION,
        "experimental": True,
        "expires_on": overlay["expires_on"].isoformat(),
        "rules": out,
    }


def export_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_overlay.py export",
        description="EXPERIMENTAL. Validate a company rules file and write a generic allow/deny list as JSON "
        "(docs/spec/policy-export.schema.json). It holds the enforcement values, so treat it like the rules file.",
    )
    parser.add_argument("overlay", type=Path)
    parser.add_argument("--out", type=Path, required=True, help="where to write the export (replaced if present)")
    parser.add_argument("--today", help="YYYY-MM-DD, for which exceptions are active (default: today)")
    parser.add_argument("--allow-host", action="append", default=[], help="as for compile (repeatable)")
    args = parser.parse_args(argv)
    try:
        today = dt.date.fromisoformat(args.today) if args.today else None
        data, _ = load_overlay_file(args.overlay)
        overlay, errors = validate_overlay(data, set(args.allow_host))
        if errors:
            for error in errors:
                print(f"INVALID: {error}", file=sys.stderr)
            return 1
        document = export_policy(overlay, today)
        if document is None:
            print("no enforcement rules in this file: nothing to export, and nothing was written", file=sys.stderr)
            return 0
        write_policy(args.out, policy_text(document), 0o600)
    except (OSError, OverlayError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"exported (experimental) to {args.out}; it lists the company's enforcement values, so it is written mode 600; keep it private.", file=sys.stderr)
    return 0


_SALT_LINE = re.compile(r"^salt:(?P<value>[^\r\n]*?)(?P<comment>[ \t]+#[^\r\n]*)?(?P<cr>\r?)$", re.MULTILINE)
_ENFORCEMENT_LINE = re.compile(r"^enforcement:", re.MULTILINE)


def set_salt_text(text: str, salt: str) -> str:
    """`text` with its top-level `salt:` line replaced, or one added before `enforcement:` (else at the end).

    A plain text edit: no other line changes, and a replaced line keeps its line ending and a
    trailing comment. Raises OverlayError when the result does not read
    back as the same file with only the salt changed (a salt written over several lines, say).
    """
    line = f'salt: "{salt}"'
    newline = "\r\n" if "\r\n" in text else "\n"
    found = _SALT_LINE.findall(text)
    if len(found) == 1:
        # The line keeps its own ending and any trailing comment.
        edited = _SALT_LINE.sub(lambda m: line + (m.group("comment") or "") + m.group("cr"), text)
    elif not found:
        place = _ENFORCEMENT_LINE.search(text)
        if place:
            edited = text[: place.start()] + line + newline + newline + text[place.start():]
        else:
            edited = text + ("" if not text or text.endswith("\n") else newline) + line + newline
    else:
        raise OverlayError("salt: more than one top-level salt line; keep one")
    before = parse_yaml(text)
    try:
        after = parse_yaml(edited)
    except (yaml.YAMLError, ValueError, RecursionError):
        after = None
    if not isinstance(before, dict) or not isinstance(after, dict) or after.get("salt") != salt or {k: v for k, v in after.items() if k != "salt"} != {
        k: v for k, v in before.items() if k != "salt"
    }:
        raise OverlayError("salt: could not set the salt with a one-line edit; set it by hand")
    return edited


def salt_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="validate_overlay.py salt",
        description="Set a new random salt in a version 2 company rules file, changing no other line. An existing salt: line "
        "is replaced, keeping its line ending and any trailing comment. The salt is never printed.",
    )
    parser.add_argument("overlay", type=Path)
    args = parser.parse_args(argv)
    try:
        data, raw = load_overlay_file(args.overlay)  # refuses a symlink
        if not isinstance(data, dict) or not _is_version(data.get("schema_version"), 2):
            raise OverlayError("salt: only a version 2 file has a salt; convert a version 1 file with `migrate` first")
        edited = set_salt_text(raw.decode("utf-8"), new_salt())
        with open(args.overlay, "w", encoding="utf-8", newline="") as handle:
            handle.write(edited)
    except (OSError, OverlayError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(
        f"{args.overlay}: set a new random salt. The file's SHA-256 changes, so rebuild and redeploy anything built from it.",
        file=sys.stderr,
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv[:1] == ["migrate"]:
        return migrate_main(argv[1:])
    if argv[:1] == ["salt"]:
        return salt_main(argv[1:])
    if argv[:1] == ["compile"]:
        return compile_main(argv[1:])
    if argv[:1] == ["export"]:
        return export_main(argv[1:])
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("overlay", type=Path, help="the file to validate; `migrate FILE` converts a version 1 file, `salt FILE` sets a new salt, and `compile FILE --out POLICY` writes the hook's policy instead")
    parser.add_argument("--allow-host", action="append", default=[], help="hostname allowed in templates[].location and intake_url, top-level or a contact's (repeatable)")
    args = parser.parse_args(argv)
    try:
        data, _ = load_overlay_file(args.overlay)
        overlay, errors = validate_overlay(data, set(args.allow_host))
    except (OSError, OverlayError) as exc:
        print(f"INVALID: {exc}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    for warning in lint_overlay(overlay):
        print(f"WARNING: {warning}", file=sys.stderr)
    message = (
        f"OK: overlay for {overlay['organization']} is structurally valid; reviewed {overlay['reviewed_on']}, "
        f"expires {overlay['expires_on']}. Whether the listed items are actually approved is the reviewer's call."
    )
    if overlay["schema_version"] == 2:
        rules = len((overlay.get("enforcement") or {}).get("rules", []))
        excepted = len((overlay.get("enforcement") or {}).get("exceptions", []))
        message += (
            f" Version 2, {rules} enforcement rule{'' if rules == 1 else 's'}: `compile` writes them as the policy the "
            "company-rules hook reads, which acts on protected_branch, deploy_host, package_registry and cloud_account rules."
        )
        if excepted:
            message += f" {excepted} expiring exception{'' if excepted == 1 else 's'}, which `compile` copies into the policy too."
    print(message)
    return 0


if __name__ == "__main__":
    sys.exit(main())
