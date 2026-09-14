"""Validate an organization overlay offline. Standard library plus PyYAML.

Checks, in order: the schema in docs/spec/overlay.schema.json (implemented
here without a jsonschema dependency), the expiry window, and a content scan
for anything that looks like a secret, a URL outside the allowlist, an email
address other than owner, an IP address, or an incident narrative.

A passing overlay is structurally valid. The validator does not know whether
the listed hosting or services are actually approved; a named reviewer does.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import re
import sys
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
TOP_ALLOWED = TOP_REQUIRED + ("templates",)


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


def _item(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise OverlayError(f"{label}: expected a nonempty phrase")
    if len(value) > ITEM_MAX:
        raise OverlayError(f"{label}: longer than {ITEM_MAX} characters; overlay values are short phrases")
    if any(ord(c) < 32 for c in value):
        raise OverlayError(f"{label}: control characters are not allowed")
    return value


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


def validate_structure(data: object) -> dict:
    """Schema-equivalent structural checks. Returns a normalized copy."""
    if not isinstance(data, dict):
        raise OverlayError("overlay: expected a YAML object")
    extra = set(data) - set(TOP_ALLOWED)
    missing = set(TOP_REQUIRED) - set(data)
    if extra:
        raise OverlayError(f"overlay: unknown fields {sorted(extra)}; the schema allows nothing else")
    if missing:
        raise OverlayError(f"overlay: missing fields {sorted(missing)}")
    schema_version = data["schema_version"]
    if isinstance(schema_version, bool) or schema_version != 1:
        raise OverlayError("schema_version: expected 1")
    out: dict = {"schema_version": 1}
    org = _item(data["organization"], "organization")
    if len(org) > 80:
        raise OverlayError("organization: longer than 80 characters; display name only")
    out["organization"] = org
    owner = _item(data["owner"], "owner")
    if len(owner) < 3 or len(owner) > 160:
        raise OverlayError("owner: expected 3 to 160 characters")
    out["owner"] = owner
    out["reviewed_on"] = _date(data["reviewed_on"], "reviewed_on")
    out["expires_on"] = _date(data["expires_on"], "expires_on")
    if out["expires_on"] <= out["reviewed_on"]:
        raise OverlayError("expires_on: must be after reviewed_on")
    dc = _object(data["data_classes"], "data_classes", ("never_in_prompts", "ok_with_approval", "ok"))
    out["data_classes"] = {k: _items(dc[k], f"data_classes.{k}") for k in ("never_in_prompts", "ok_with_approval", "ok")}
    hosting = _object(data["hosting"], "hosting", ("approved", "not_approved"))
    out["hosting"] = {k: _items(hosting[k], f"hosting.{k}") for k in ("approved", "not_approved")}
    services = _object(data["services"], "services", ("approved", "needs_review"))
    out["services"] = {k: _items(services[k], f"services.{k}") for k in ("approved", "needs_review")}
    identity = _object(data["identity"], "identity", ("default", "never"))
    out["identity"] = {"default": _item(identity["default"], "identity.default"), "never": _items(identity["never"], "identity.never")}
    out["review_triggers"] = _items(data["review_triggers"], "review_triggers")
    templates = data.get("templates", [])
    if templates is None:
        templates = []
    if not isinstance(templates, list) or len(templates) > 20:
        raise OverlayError("templates: expected a list of at most 20 entries")
    out["templates"] = []
    for i, entry in enumerate(templates):
        label = f"templates[{i}]"
        if not isinstance(entry, dict) or "kind" not in entry or set(entry) - {"kind", "location"}:
            raise OverlayError(f"{label}: expected an object with kind and optional location")
        kind = entry["kind"]
        if not isinstance(kind, str) or not KIND_RE.fullmatch(kind) or len(kind) > 64:
            raise OverlayError(f"{label}.kind: expected a lowercase-hyphen identifier")
        normalized = {"kind": kind}
        if "location" in entry:
            location = _item(entry["location"], f"{label}.location")
            if len(location) > 500:
                raise OverlayError(f"{label}.location: longer than 500 characters")
            normalized["location"] = location
        out["templates"].append(normalized)
    return out


def _walk_strings(node: object, path: str = "overlay"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_strings(v, f"{path}[{i}]")


def validate_content(overlay: dict, allowed_hosts: set[str]) -> list[str]:
    """Return content errors: secrets, disallowed URLs, identifiers, narratives."""
    errors: list[str] = []
    template_locations = {t.get("location") for t in overlay.get("templates", [])}
    for path, text in _walk_strings(overlay):
        for pattern in SECRET_PATTERNS:
            if pattern.search(text):
                errors.append(f"{path}: looks like a secret; overlays never contain credentials")
                break
        for url in URL_RE.findall(text):
            if text in template_locations and path.endswith(".location"):
                parts = urlsplit(url)
                if parts.scheme != "https":
                    errors.append(f"{path}: template locations must use https")
                elif parts.username or parts.password:
                    errors.append(f"{path}: template locations must not carry credentials")
                elif parts.query or parts.fragment:
                    errors.append(f"{path}: template locations must not carry a query string or fragment")
                elif (parts.hostname or "") not in allowed_hosts:
                    errors.append(f"{path}: host {parts.hostname!r} is not on the allowlist (pass --allow-host)")
            else:
                errors.append(f"{path}: URLs are only allowed in templates[].location")
        if path != "overlay.owner" and EMAIL_RE.search(text):
            errors.append(f"{path}: email addresses are only allowed in owner")
        for candidate in IP_RE.findall(text):
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            errors.append(f"{path}: IP addresses are internal identifiers and are not allowed")
            break
        if NARRATIVE_RE.search(text):
            errors.append(f"{path}: reads like an incident narrative; overlay values are lists of approved things, not stories")
    return errors


def validate_expiry(overlay: dict, today: dt.date | None = None) -> list[str]:
    today = today or dt.date.today()
    if overlay["expires_on"] < today:
        return [f"expires_on: {overlay['expires_on'].isoformat()} has passed; renew the review before building a private bundle"]
    if overlay["reviewed_on"] > today:
        return [f"reviewed_on: {overlay['reviewed_on'].isoformat()} is in the future"]
    return []


def load_overlay_file(path: Path) -> tuple[dict, bytes]:
    if path.is_symlink():
        raise OverlayError(f"{path}: symlinks are not allowed")
    raw = path.read_bytes()
    if len(raw) > 131072:
        raise OverlayError(f"{path}: larger than 128 KiB; an overlay is a short list")
    try:
        data = yaml.safe_load(raw.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise OverlayError(f"{path}: could not parse YAML ({exc.__class__.__name__})") from None
    return data, raw


def validate_overlay(data: object, allowed_hosts: set[str] | None = None, today: dt.date | None = None) -> tuple[dict, list[str]]:
    """Return (normalized overlay, errors). Structural errors raise OverlayError."""
    overlay = validate_structure(data)
    errors = validate_expiry(overlay, today) + validate_content(overlay, allowed_hosts or set())
    return overlay, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("overlay", type=Path)
    parser.add_argument("--allow-host", action="append", default=[], help="hostname allowed in templates[].location (repeatable)")
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
    print(
        f"OK: overlay for {overlay['organization']} is structurally valid; reviewed {overlay['reviewed_on']}, "
        f"expires {overlay['expires_on']}. Whether the listed items are actually approved is the reviewer's call."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
