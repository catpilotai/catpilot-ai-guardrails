"""Validate synthetic evaluation inputs offline; never run or grade an agent."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CASES = REPO_ROOT / "evals" / "cases.json"
ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
CATEGORIES = {"test-data", "sharing", "secrets", "policy", "coverage"}
VARIANTS = {"safe", "unsafe", "unknown", "adversarial"}
POLICY_STATES = {"approved", "missing", "expired", "conflicting"}
DECISIONS = {"proceed", "redirect", "clarify", "review"}


def validate_cases(document: object, repo_root: Path = REPO_ROOT) -> list[str]:
    """Return structural errors, not behavioral scores or security findings."""
    errors: list[str] = []

    def fields(value: object, names: set[str], at: str) -> bool:
        if not isinstance(value, dict):
            errors.append(f"{at}: expected an object")
            return False
        missing = names - value.keys()
        extra = value.keys() - names
        if missing:
            errors.append(f"{at}: missing fields {sorted(missing)}")
        if extra:
            errors.append(f"{at}: unknown fields {sorted(extra)}")
        return not missing and not extra

    def nonempty(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    def strings(value: object, at: str, allow_empty: bool = False) -> bool:
        if not isinstance(value, list) or (not value and not allow_empty):
            errors.append(f"{at}: expected {'a' if allow_empty else 'a nonempty'} string list")
            return False
        if not all(nonempty(item) for item in value):
            errors.append(f"{at}: entries must be nonempty strings")
            return False
        if len(set(value)) != len(value):
            errors.append(f"{at}: duplicate entries")
            return False
        return True

    def choice(value: object, options: set[str], at: str) -> bool:
        if not isinstance(value, str) or value not in options:
            errors.append(f"{at}: expected one of {sorted(options)}")
            return False
        return True

    if not fields(document, {"schema_version", "data_classification", "cases"}, "corpus"):
        return errors
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        errors.append("schema_version: expected integer 1")
    if document["data_classification"] != "synthetic-only":
        errors.append("data_classification: expected synthetic-only")
    cases = document["cases"]
    if not isinstance(cases, list) or not cases:
        return errors + ["cases: expected a nonempty list"]

    seen: set[str] = set()
    coverage: set[tuple[str, str]] = set()
    for index, case in enumerate(cases):
        at = f"cases[{index}]"
        case_fields = {
            "id", "category", "variant", "component_ids", "prompt", "context", "expected"
        }
        if not fields(case, case_fields, at):
            continue
        case_id = case["id"]
        if not isinstance(case_id, str) or len(case_id) > 80 or not ID_PATTERN.fullmatch(case_id):
            errors.append(f"{at}.id: expected a lowercase/hyphen ID of 1–80 characters")
        elif case_id in seen:
            errors.append(f"{at}.id: duplicate {case_id}")
        else:
            seen.add(case_id)
        category_ok = choice(case["category"], CATEGORIES, f"{at}.category")
        variant_ok = choice(case["variant"], VARIANTS, f"{at}.variant")
        if category_ok and variant_ok:
            coverage.add((case["category"], case["variant"]))
        if not nonempty(case["prompt"]):
            errors.append(f"{at}.prompt: expected a nonempty string")
        if strings(case["component_ids"], f"{at}.component_ids"):
            for component in case["component_ids"]:
                if not ID_PATTERN.fullmatch(component):
                    errors.append(f"{at}.component_ids: invalid component ID {component!r}")
                elif not (repo_root / "src" / "skills" / "core" / component / "SKILL.md").is_file():
                    errors.append(f"{at}.component_ids: unknown core component {component!r}")

        context = case["context"]
        context_ok = fields(
            context,
            {"policy_status", "policy_version", "policy", "facts"},
            f"{at}.context",
        )
        if context_ok:
            status = context["policy_status"]
            status_ok = choice(status, POLICY_STATES, f"{at}.context.policy_status")
            strings(context["facts"], f"{at}.context.facts")
            strings(context["policy"], f"{at}.context.policy", allow_empty=status == "missing")
            if status == "missing":
                if context["policy_version"] is not None or context["policy"] != []:
                    errors.append(f"{at}.context: missing policy requires null version and empty policy")
            elif status_ok and not nonempty(context["policy_version"]):
                errors.append(f"{at}.context.policy_version: expected a nonempty version")

        expected = case["expected"]
        if not fields(
            expected,
            {"decision", "required_concepts", "forbidden_behaviors", "max_questions"},
            f"{at}.expected",
        ):
            continue
        decision = expected["decision"]
        choice(decision, DECISIONS, f"{at}.expected.decision")
        strings(expected["required_concepts"], f"{at}.expected.required_concepts")
        strings(expected["forbidden_behaviors"], f"{at}.expected.forbidden_behaviors")
        questions = expected["max_questions"]
        if type(questions) is not int or questions not in {0, 1}:
            errors.append(f"{at}.expected.max_questions: expected integer 0 or 1")
        if case["variant"] == "safe" and decision != "proceed":
            errors.append(f"{at}: safe control case must expect proceed")
        if case["variant"] in ("unsafe", "unknown") and decision == "proceed":
            errors.append(f"{at}: unsafe/unknown case must not expect proceed")
        if context_ok and context["policy_status"] != "approved" and decision == "proceed":
            errors.append(f"{at}: proceed requires an approved policy in this corpus")

    for category in ("test-data", "sharing", "secrets"):
        for variant in ("safe", "unsafe"):
            if (category, variant) not in coverage:
                errors.append(f"coverage: missing {category}/{variant} case")
    return errors


def load_cases(path: Path) -> object:
    def unique_keys(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON field {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> None:
        raise ValueError(f"non-JSON constant {value}")

    return json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=unique_keys,
        parse_constant=reject_constant,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    args = parser.parse_args()
    try:
        document = load_cases(args.cases)
    except (OSError, ValueError) as exc:
        print(f"INVALID: could not read evaluation cases: {exc}", file=sys.stderr)
        return 1
    errors = validate_cases(document)
    if errors:
        for error in errors:
            print(f"INVALID: {error}", file=sys.stderr)
        return 1
    print(f"OK: {len(document['cases'])} synthetic fixtures validated; agent behavior NOT TESTED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
