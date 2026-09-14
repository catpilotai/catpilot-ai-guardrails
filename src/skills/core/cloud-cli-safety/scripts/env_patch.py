"""Pure Azure environment patch planning. No cloud calls or value logging."""

import re

NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _entry(entry):
    if not isinstance(entry, dict) or not isinstance(entry.get("name"), str) or not NAME.fullmatch(entry["name"]):
        raise ValueError("invalid environment name")
    if set(entry) not in ({"name", "value"}, {"name", "secretRef"}):
        raise ValueError("each entry must have exactly one value or secretRef")
    field = "secretRef" if "secretRef" in entry else "value"
    value = entry[field]
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid environment value")
    if field == "secretRef" and (not value or any(c.isspace() for c in value)):
        raise ValueError("invalid secret reference")
    if field == "value" and value.startswith("secretref:"):
        raise ValueError("literal value collides with Azure secretref syntax")
    return entry["name"], f"{entry['name']}={'secretref:' if field == 'secretRef' else ''}{value}"


def plan_patch(current, requested):
    """Return argv values and rollback; caller owns authorization and execution.

    Inputs are complete typed env entries for one explicitly selected container.
    The result is private data: do not print it or interpolate it into a shell.
    This planner only adds/updates names; it never replaces the whole environment.
    """
    if not isinstance(current, list) or not isinstance(requested, list):
        raise ValueError("expected environment entry lists")
    previous, changes = {}, {}
    for entries, target in ((current, previous), (requested, changes)):
        for item in entries:
            name, argument = _entry(item)
            if name in target:
                raise ValueError("duplicate environment name")
            target[name] = argument
    names = sorted(name for name in changes if previous.get(name) != changes[name])
    return {
        "set_env_vars": [changes[name] for name in names],
        "rollback": {
            "set_env_vars": [previous[name] for name in names if name in previous],
            "remove_env_vars": [name for name in names if name not in previous],
        },
    }


def summarize_patch(plan):
    """Display names only; neither values nor secret reference targets."""
    return {
        "changed_names": [arg.split("=", 1)[0] for arg in plan["set_env_vars"]],
        "restored_names": [arg.split("=", 1)[0] for arg in plan["rollback"]["set_env_vars"]],
        "removed_on_rollback": list(plan["rollback"]["remove_env_vars"]),
    }
