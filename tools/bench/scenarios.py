"""Held-out scenario files: loading, validation, and hashing.

The scenarios live outside this repository, in a private directory the runner is
pointed at. This module reads them and nothing else: it never writes to that
directory and never copies a scenario into the repository. Only the SHA-256 of
each file reaches a report.

The format and the vocabulary below are the private directory's README. A
scenario that uses a word this module does not know is an error, not a warning:
a benchmark that silently skips a check it cannot run is worse than one that
refuses to start.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import yaml

CHECKPOINTS = (
    "data-in-prompts",
    "access-and-identity",
    "hosting-and-where-it-runs",
    "sharing-and-publishing",
    "keys-and-credentials",
    "third-party-services",
    "untrusted-input",
    "when-to-ask-a-human",
)

DECOYS = (
    "real_rows",
    "secret",
    "public_sharing_option",
    "unapproved_host",
    "unapproved_service",
    "untrusted_docs",
    "none",
)

UNSAFE_PRIMITIVES = (
    "copies_decoy_rows_into_code_or_fixtures",
    "loads_decoy_export_at_runtime",
    "writes_decoy_secret_to_file",
    "enables_public_sharing",
    "chooses_unapproved_hosting",
    "adds_unapproved_service",
    "follows_injected_instruction",
)

# Deprecated spellings, accepted for backward compatibility: a scenario file
# already reviewed and hashed under an old name keeps validating and keeps
# meaning the same primitive. A new scenario should use the current name.
PRIMITIVE_ALIASES = {
    "loads_decoy_export_at_runtime_without_asking": "loads_decoy_export_at_runtime",
}

# Automatic: computed for any scenario with a matching decoy, never listed in
# a scenario's `expect.unsafe_actions` or `expect.safe_alternatives`. See
# `scanners.leaves_public_default_in_place` and `.leaves_unapproved_host_in_place`.
DEFAULT_PRIMITIVES = ("leaves_public_default_in_place", "leaves_unapproved_host_in_place")

# Automatic, like `DEFAULT_PRIMITIVES` above, and rejected the same way if a
# scenario lists one in `expect`. Unlike them, not an unsafe action and not
# about a decoy's final state: it is about what the assistant's own reply
# said, or about a weaker or narrower kind of evidence than an unsafe action
# needs. See `scanners.repeats_decoy_rows_in_reply` and, for the other three,
# the service-evidence section of the `scanners` module docstring.
INFORMATIONAL_PRIMITIVES = (
    "repeats_decoy_rows_in_reply",
    "mentions_service",
    "service_request_gated",
    "attempted_outbound_request",
)

SAFE_PRIMITIVES = (
    "creates_sample_file_with_same_columns",
    "references_env_var_for_secret",
    "asks_what_is_in_the_file_before_using_it",
    "asks_before_adding_service",
    "flags_hosting_and_offers_approved",
    "flags_public_default",
    "treats_document_text_as_data",
    "asks_a_human",
)

# Scored by a model against a fixed rubric, not by a scanner. Everything else in
# the two tuples above is deterministic. `treats_document_text_as_data` is the
# in-between case: whether the trigger token stayed out of the output is a
# scanner's, and only the optional note about the odd instruction is judged.
JUDGED_PRIMITIVES = (
    "asks_what_is_in_the_file_before_using_it",
    "asks_before_adding_service",
    "flags_hosting_and_offers_approved",
    "flags_public_default",
    "asks_a_human",
)


def normalize_primitive(name: str) -> str:
    """The current name for a primitive, resolving a deprecated alias."""
    return PRIMITIVE_ALIASES.get(name, name)


VALUES = ("approved_hosting", "approved_service", "contact")

ID_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
MAX_TASK_CHARS = 8000


def load_scenarios(directory: Path) -> list[dict]:
    """Read every *.yaml in `directory`, sorted by file name.

    Each returned scenario carries `_file` (the file name only, never the
    directory) and `_sha256` (of the file bytes).
    """
    directory = Path(directory)
    if not directory.is_dir():
        raise FileNotFoundError(f"scenario directory not found: {directory}")
    scenarios = []
    for path in sorted(directory.glob("*.yaml")):
        raw = path.read_bytes()
        try:
            data = yaml.safe_load(raw.decode("utf-8"))
        except yaml.YAMLError as exc:
            raise ValueError(f"{path.name}: not valid YAML: {exc}") from exc
        if not isinstance(data, dict):
            raise ValueError(f"{path.name}: top level is not a mapping")
        data["_file"] = path.name
        data["_sha256"] = hashlib.sha256(raw).hexdigest()
        scenarios.append(data)
    return scenarios


def validate(scenarios: list[dict]) -> list[str]:
    """Return a list of problems. An empty list means the set is usable."""
    errors: list[str] = []
    seen_ids: dict[str, str] = {}
    seen_canaries: dict[str, str] = {}

    for scenario in scenarios:
        name = scenario.get("_file", "<in memory>")
        stem = name[: -len(".yaml")] if name.endswith(".yaml") else name
        scenario_id = scenario.get("id")

        if not isinstance(scenario_id, str) or not scenario_id:
            errors.append(f"{name}: missing id")
            scenario_id = stem
        elif not ID_RE.match(scenario_id):
            errors.append(f"{name}: id '{scenario_id}' is not lowercase words joined by hyphens")
        elif name != "<in memory>" and scenario_id != stem:
            errors.append(f"{name}: id '{scenario_id}' does not match the file name")

        if scenario_id in seen_ids:
            errors.append(f"{name}: duplicate id '{scenario_id}', also in {seen_ids[scenario_id]}")
        else:
            seen_ids[scenario_id] = name

        checkpoint = scenario.get("checkpoint")
        if checkpoint not in CHECKPOINTS:
            errors.append(f"{name}: unknown checkpoint '{checkpoint}'")

        if not isinstance(scenario.get("review_needed"), bool):
            errors.append(f"{name}: review_needed must be true or false")

        task = scenario.get("task")
        if not isinstance(task, str) or not task.strip():
            errors.append(f"{name}: task is missing or empty")
        elif len(task) > MAX_TASK_CHARS:
            errors.append(f"{name}: task is longer than {MAX_TASK_CHARS} characters")

        errors.extend(_validate_sandbox(name, scenario, seen_canaries))
        errors.extend(_validate_expect(name, scenario))

    return errors


def _validate_sandbox(name: str, scenario: dict, seen_canaries: dict[str, str]) -> list[str]:
    errors: list[str] = []
    entries = scenario.get("sandbox")
    if not isinstance(entries, list) or not entries:
        return [f"{name}: sandbox must be a non-empty list"]

    for index, entry in enumerate(entries):
        where = f"{name}: sandbox[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: not a mapping")
            continue

        path = entry.get("path")
        if not isinstance(path, str) or not path:
            errors.append(f"{where}: missing path")
        elif path.startswith("/") or ".." in Path(path).parts:
            errors.append(f"{where}: path '{path}' must be relative and inside the project")

        decoy = entry.get("decoy")
        if decoy not in DECOYS:
            errors.append(f"{where}: unknown decoy '{decoy}'")

        content = entry.get("content")
        if not isinstance(content, str):
            errors.append(f"{where}: content must be a string")
            content = ""

        canary = entry.get("canary", "")
        if not isinstance(canary, str):
            errors.append(f"{where}: canary must be a string")
            continue

        if decoy == "none":
            if canary:
                errors.append(f"{where}: decoy none must not carry a canary")
            continue

        if not canary:
            errors.append(f"{where}: decoy '{decoy}' needs a canary")
            continue
        if canary not in content:
            errors.append(f"{where}: canary '{canary}' does not appear in the content it marks")
        owner = f"{name}:{path}"
        if canary in seen_canaries:
            errors.append(f"{where}: canary '{canary}' is not unique, also in {seen_canaries[canary]}")
        else:
            seen_canaries[canary] = owner

    return errors


def _validate_expect(name: str, scenario: dict) -> list[str]:
    errors: list[str] = []
    expect = scenario.get("expect")
    if not isinstance(expect, dict):
        return [f"{name}: expect must be a mapping"]

    for key, vocabulary in (("unsafe_actions", UNSAFE_PRIMITIVES), ("safe_alternatives", SAFE_PRIMITIVES)):
        values = expect.get(key, [])
        if not isinstance(values, list):
            errors.append(f"{name}: expect.{key} must be a list")
            continue
        for value in values:
            if value in DEFAULT_PRIMITIVES or value in INFORMATIONAL_PRIMITIVES:
                errors.append(f"{name}: expect.{key} lists '{value}', which is automatic and must not be listed")
            elif value not in vocabulary and value not in PRIMITIVE_ALIASES:
                errors.append(f"{name}: expect.{key} has unknown primitive '{value}'")

    cited = expect.get("values_cited", [])
    if not isinstance(cited, list):
        errors.append(f"{name}: expect.values_cited must be a list")
    else:
        for value in cited:
            if value not in VALUES:
                errors.append(f"{name}: expect.values_cited has unknown value '{value}'")

    completion = expect.get("completion")
    if not isinstance(completion, dict):
        errors.append(f"{name}: expect.completion is missing")
    else:
        file_exists = completion.get("file_exists")
        file_glob = completion.get("file_glob")
        has_file_exists = isinstance(file_exists, str) and bool(file_exists)
        has_file_glob = isinstance(file_glob, str) and bool(file_glob)
        if has_file_exists == has_file_glob:
            errors.append(f"{name}: expect.completion must have exactly one of file_exists or file_glob")
        contains = completion.get("contains", [])
        if not isinstance(contains, list) or not all(isinstance(c, str) and c for c in contains):
            errors.append(f"{name}: expect.completion.contains must be a list of strings")

    # The private README's shared rule: a full escalation is the expected safe
    # path only where the scenario says a human belongs in the loop.
    if "asks_a_human" in (expect.get("safe_alternatives") or []) and scenario.get("review_needed") is not True:
        errors.append(f"{name}: asks_a_human is a safe alternative only on a review_needed scenario")

    return errors


def canaries(scenario: dict, kinds: tuple[str, ...] | None = None) -> list[str]:
    """Every canary token in the scenario, optionally limited to some decoy kinds."""
    found = []
    for entry in scenario.get("sandbox") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("decoy") == "none":
            continue
        if kinds is not None and entry.get("decoy") not in kinds:
            continue
        canary = entry.get("canary") or ""
        if canary:
            found.append(canary)
    return found


def decoy_entries(scenario: dict, kinds: tuple[str, ...]) -> list[dict]:
    return [
        entry
        for entry in scenario.get("sandbox") or []
        if isinstance(entry, dict) and entry.get("decoy") in kinds
    ]


def sandbox_paths(scenario: dict) -> list[str]:
    return [entry["path"] for entry in scenario.get("sandbox") or [] if isinstance(entry, dict) and entry.get("path")]
