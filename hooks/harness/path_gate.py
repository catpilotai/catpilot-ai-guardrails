#!/usr/bin/env python3
"""In-harness gate for file-path confinement: enforce workspace boundaries and block credential paths.

Scope, stated honestly:
  - Enforces path confinement on the file-read, file-write, or file-delete tool
    calls your harness routes through it.
  - Resolves `~` and symlinks (`Path.resolve()`), blocks access to well-known
    credential and system files (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`,
    `~/.config/gcloud`, `~/.docker`, `~/.openclaw`, `~/.netrc`, `/etc/passwd`,
    `/etc/shadow`, `/etc/sudoers`) even if a caller mistakenly includes the home
    directory in `allowed_dirs`, and requires the resolved target path to lie
    inside at least one directory in `allowed_dirs`.
  - Returns a plain-language reason string on a blocked path, or `None` when
    the path is inside `allowed_dirs` and not a sensitive path. Never returns
    "allow". Fails closed on non-string paths or an empty `allowed_dirs`.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Iterable

HOME_CREDENTIAL_RELPATHS = (
    ".ssh",
    ".aws",
    ".gnupg",
    ".kube",
    ".docker",
    ".openclaw",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".config/gcloud",
    ".config/gh",
)

SYSTEM_SENSITIVE_PATHS = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/master.passwd",
    "/private/etc/passwd",
    "/private/etc/shadow",
    "/private/etc/sudoers",
    "/private/etc/master.passwd",
)


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def _resolved_With_expanduser(raw: str | Path, base_dir: Path | None = None) -> Path:
    expanded = Path(os.path.expanduser(str(raw)))
    if not expanded.is_absolute() and base_dir is not None:
        expanded = base_dir / expanded
    return expanded.resolve()


def gate_file_path(
    path: str,
    *,
    allowed_dirs: Iterable[str | Path],
    base_dir: str | Path | None = None,
) -> str | None:
    """Return a deny reason if `path` resolves outside `allowed_dirs` or into a credential path, else None.

    Raises ValueError if `path` is not a string or `allowed_dirs` is empty (fail-closed).
    """
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    if "\x00" in path or not path.strip():
        return "Blocked file path: path is empty or contains a NUL byte."

    resolved_allowed: list[Path] = []
    for d in allowed_dirs or []:
        if not isinstance(d, (str, Path)) or not str(d).strip():
            continue
        resolved_allowed.append(Path(os.path.expanduser(str(d))).resolve())
    if not resolved_allowed:
        raise ValueError("allowed_dirs must contain at least one directory")

    anchor = Path(os.path.expanduser(str(base_dir))).resolve() if base_dir is not None else resolved_allowed[0]
    try:
        target = _resolved_With_expanduser(path, base_dir=anchor)
    except (OSError, RuntimeError):
        return "Blocked file path: could not resolve path safely (failing closed)."

    # Always block well-known credential directories and sensitive system files
    home = Path.home().resolve()
    for rel in HOME_CREDENTIAL_RELPATHS:
        cred_path = (home / rel).resolve()
        if target == cred_path or _is_within(target, cred_path):
            return (
                f"Blocked file path: access to credential path '~/{rel}' is prohibited "
                "even inside an allowed directory."
            )

    for sys_raw in SYSTEM_SENSITIVE_PATHS:
        sys_path = Path(sys_raw)
        if target == sys_path or _is_within(target, sys_path):
            return f"Blocked file path: access to system file '{sys_raw}' is prohibited."

    if not any(target == allowed or _is_within(target, allowed) for allowed in resolved_allowed):
        return (
            "Blocked file path: resolved path is outside the allowed workspace directories. "
            "Pass a relative path inside the workspace."
        )

    return None


def gate_path_tool_call(
    tool_name: str,
    tool_input: dict,
    *,
    allowed_dirs: Iterable[str | Path],
    field: str = "file_path",
    base_dir: str | Path | None = None,
) -> str | None:
    """Gate a tool call dictionary by checking `tool_input[field]` with `gate_file_path`."""
    if not isinstance(tool_input, dict):
        return f"Blocked {tool_name}: tool_input must be an object."
    value = tool_input.get(field)
    if not isinstance(value, str) or not value.strip():
        return f"Blocked {tool_name}: required string field {field!r} is missing or empty."
    return gate_file_path(value, allowed_dirs=allowed_dirs, base_dir=base_dir)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: python hooks/harness/path_gate.py '<path>' '<allowed_dir>' [...]", file=sys.stderr)
        sys.exit(2)
    verdict = gate_file_path(sys.argv[1], allowed_dirs=sys.argv[2:])
    if verdict:
        print(verdict)
        sys.exit(1)
