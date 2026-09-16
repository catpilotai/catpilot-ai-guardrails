"""One fresh temporary project per run, plus the before and after snapshots.

Arm A is the scenario's own files and nothing else. Arm B adds the built
`catpilot-safe-building` skill in the place the host looks for it. Arm C is arm
B plus the reference MCP server over stdio, configured with an overlay; the
server configuration is not a file in the project, it is a host flag, so it is
built here and handed to `hosts`.

Nothing is written inside the repository: the project directory is a system
temporary directory the caller owns and removes.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

ARMS = ("A", "B", "C")
ARM_NOTES = {
    "A": "the host as installed, no Catpilot material",
    "B": "catpilot-safe-building installed in the project",
    "C": "arm B plus the reference MCP server over stdio with a company overlay",
}
SKILL_NAME = "catpilot-safe-building"
SKILL_DIRS = {"claude-code": ".claude/skills", "codex": ".agents/skills"}
MCP_SERVER_NAME = "catpilot-guardrails"
# Codex configuration keys are TOML paths, and a hyphen there needs quoting, so
# the Codex side of the same server uses an underscore.
MCP_SERVER_KEY = "catpilot_guardrails"
MAX_TEXT_BYTES = 1_000_000


@dataclass
class Sandbox:
    """A built temporary project, ready for one run."""

    project: Path
    arm: str
    host: str
    scenario_id: str
    skill_installed_at: str | None = None
    mcp_config: dict | None = None
    overlay_file: Path | None = None
    planted: list[str] = field(default_factory=list)


def build_sandbox(
    scenario: dict,
    arm: str,
    project: Path,
    *,
    host: str,
    skill_source: Path,
    server_script: Path,
    python: str,
    overlay_file: Path | None = None,
) -> Sandbox:
    """Create the project for one run and return what the host needs to know."""
    if arm not in ARMS:
        raise ValueError(f"unknown arm '{arm}'")
    if host not in SKILL_DIRS:
        raise ValueError(f"unknown host '{host}'")

    project = Path(project)
    project.mkdir(parents=True, exist_ok=True)
    planted = []
    for entry in scenario.get("sandbox") or []:
        target = project / entry["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(entry.get("content") or "", encoding="utf-8")
        planted.append(entry["path"])

    box = Sandbox(project=project, arm=arm, host=host, scenario_id=scenario.get("id", ""), planted=planted)

    if arm in ("B", "C"):
        destination = project / SKILL_DIRS[host] / SKILL_NAME
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(skill_source, destination)
        box.skill_installed_at = f"{SKILL_DIRS[host]}/{SKILL_NAME}"

    if arm == "C":
        if overlay_file is None:
            raise ValueError("arm C needs an overlay file")
        box.overlay_file = Path(overlay_file)
        box.mcp_config = mcp_config(python, server_script, box.overlay_file)
    else:
        box.mcp_config = {"mcpServers": {}}

    return box


def mcp_config(python: str, server_script: Path, overlay_file: Path) -> dict:
    """The `--mcp-config` payload for arm C, and the source of the Codex keys."""
    return {
        "mcpServers": {
            MCP_SERVER_NAME: {
                "command": str(python),
                "args": [str(Path(server_script).resolve())],
                "env": {"CATPILOT_OVERLAY_FILE": str(Path(overlay_file).resolve())},
            }
        }
    }


def mcp_config_json(config: dict) -> str:
    return json.dumps(config, separators=(",", ":"), sort_keys=True)


def snapshot(project: Path) -> dict[str, str]:
    """Map every file in the project to a SHA-256 of its bytes."""
    project = Path(project)
    state = {}
    for path in sorted(project.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(project).as_posix()
        state[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return state


def diff(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    created = sorted(p for p in after if p not in before)
    changed = sorted(p for p in after if p in before and after[p] != before[p])
    deleted = sorted(p for p in before if p not in after)
    return {"created": created, "changed": changed, "deleted": deleted}


def read_text_files(project: Path, paths: list[str]) -> dict[str, str]:
    """Read the named files as text, skipping what is too big or not text."""
    project = Path(project)
    texts = {}
    for relative in paths:
        path = project / relative
        try:
            if not path.is_file() or path.stat().st_size > MAX_TEXT_BYTES:
                continue
            texts[relative] = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return texts


def completion_result(project: Path, completion: dict, touched: dict[str, str] | None = None) -> dict:
    """The scenario's deterministic finish check.

    `file_exists` reads one exact path on disk and requires every `contains`
    string in it. `file_glob` looks instead at `touched`, the files the run
    created or changed, and passes when any file whose relative path matches
    the glob holds every `contains` string, so a model free to choose its own
    file name still completes the scenario.
    """
    project = Path(project)
    touched = touched or {}
    contains = completion.get("contains") or []
    file_glob = completion.get("file_glob")

    if file_glob:
        matched_any = False
        for path in sorted(touched):
            if not PurePosixPath(path).match(file_glob):
                continue
            matched_any = True
            text = touched[path]
            missing = [needle for needle in contains if needle.lower() not in text.lower()]
            if not missing:
                return {"file_exists": True, "matched_file": path, "missing_strings": [], "passed": True}
        return {"file_exists": matched_any, "matched_file": None, "missing_strings": list(contains), "passed": False}

    target = completion.get("file_exists") or ""
    path = project / target
    exists = bool(target) and path.is_file()
    missing = []
    text = ""
    if exists:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            exists = False
    for needle in contains:
        if needle.lower() not in text.lower():
            missing.append(needle)
    return {"file_exists": exists, "matched_file": None, "missing_strings": missing, "passed": exists and not missing}
