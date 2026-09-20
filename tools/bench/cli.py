"""Argument parsing and the run loop.

One invocation is one host, one model, and one pass over the scenario set for
each arm, repeated `--runs` times. Everything a run produces lands under
`--out`: the raw transcript, the files it created or changed, the final answer,
the scanner and judge results, and the cost the host reported. Nothing is
written inside the repository.

`--dry-run` stops after building one sandbox per scenario and arm and printing
the exact host command for each. It makes no model calls, so it is the way to
check the wiring before spending anything.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

import yaml

from . import aggregate as aggregate_lib
from . import hosts as hosts_lib
from . import judge as judge_lib
from . import report as report_lib
from . import sandbox as sandbox_lib
from . import scanners as scanner_lib
from . import scenarios as scenario_lib
from . import selfcheck as selfcheck_lib
from . import completion as completion_lib

ROOT = Path(__file__).resolve().parents[2]
SKILL_SOURCE = ROOT / "skills" / sandbox_lib.SKILL_NAME
SERVER_SCRIPT = ROOT / "mcp-server" / "server.py"
OVERLAY_EXAMPLE = ROOT / "docs" / "spec" / "overlay.example.yaml"
ALLOWED_IN_REPO = ".bench-runs"
MAX_SAVED_FILE_CHARS = 200_000
FILES_ARCHIVE_VERSION = "complete-files-1"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="bench.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scenarios", type=Path, required=True, help="directory of held-out scenario files, outside any repository")
    parser.add_argument("--host", choices=hosts_lib.HOSTS, required=True)
    parser.add_argument(
        "--arms",
        default=",".join(sandbox_lib.DEFAULT_COMPARISON_ARMS),
        help=(
            "comma-separated conditions (default A,B,B-activated,D): A no guidance; B or B-installed skill installed; "
            "B-activated skill installed and explicitly activated; C skill and company reference server; "
            "D explicitly activated skill and company reference server; E skill summary checklist; F company checklist"
        ),
    )
    parser.add_argument("--examples", type=Path, help="required: matching reference examples with expected completion and outcomes")
    parser.add_argument("--runs", type=int, default=3, help="repetitions per scenario per arm")
    parser.add_argument("--model", default=None, help="model for the host under test (default: the sonnet alias on Claude Code, the host default on Codex)")
    parser.add_argument("--codex-reasoning", default=None, help="Codex only: model_reasoning_effort for the run (for example medium), written into the clean temporary config and recorded in the report")
    parser.add_argument("--out", type=Path, required=True, help="directory for run artifacts and the report")
    parser.add_argument("--overlay", type=Path, default=None, help="company facts for D and legacy C/F replay (default: a temporary copy of the example overlay)")
    parser.add_argument("--max-turns", type=int, default=12)
    parser.add_argument("--judge-model", default=judge_lib.DEFAULT_JUDGE_MODEL)
    parser.add_argument("--timeout", type=int, default=600, help="seconds per host run")
    parser.add_argument("--dry-run", action="store_true", help="validate, build one sandbox per scenario and arm, print the commands, and stop")
    parser.add_argument("--report", type=Path, default=None, help="copy the report here as well")
    parser.add_argument(
        "--follow-up",
        nargs="?",
        const=hosts_lib.DEFAULT_FOLLOW_UP,
        default=None,
        metavar="TEXT",
        help=(
            "send one uniform second user message after every run's first turn ends, in every "
            "arm, whether or not the assistant asked a question (default: off; with no TEXT, "
            f"uses {hosts_lib.DEFAULT_FOLLOW_UP!r})"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        arms = parse_arms(args.arms)
    except ValueError as bad:
        print(f"error: {bad}", file=sys.stderr)
        return 2
    if args.runs < 1:
        print("error: --runs must be positive", file=sys.stderr)
        return 2
    if not args.dry_run and args.runs < 3:
        print("error: live benchmark runs require at least 3 repetitions per scenario and condition", file=sys.stderr)
        return 2

    try:
        scenarios = scenario_lib.load_scenarios(args.scenarios)
    except (FileNotFoundError, ValueError) as bad:
        print(f"error: {bad}", file=sys.stderr)
        return 2
    if not scenarios:
        print(f"error: no *.yaml scenarios in {args.scenarios}", file=sys.stderr)
        return 2

    problems = scenario_lib.validate(scenarios)
    if problems:
        print(f"{len(problems)} problem(s) in the scenario set:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 2
    design_errors = getattr(scenario_lib, "design_errors", None)
    if design_errors:
        design_problems = design_errors(scenarios, live=not args.dry_run)
        for problem in design_problems:
            print(f"{'warning (dry-run)' if args.dry_run else 'error'}: {problem}", file=sys.stderr)
        if design_problems and not args.dry_run:
            return 2
    print(f"{len(scenarios)} scenario(s) validated.")

    if any(arm in sandbox_lib.VALUE_ARMS for arm in arms):
        coverage_errors = scenario_lib.comparison_suite_errors(scenarios)
        for problem in coverage_errors:
            print(f"{'warning (setup smoke only)' if args.dry_run else 'error'}: {problem}", file=sys.stderr)
        if coverage_errors and not args.dry_run:
            return 2

    if not args.examples:
        print("error: --examples is required; reference completion and outcome checks must pass before a run", file=sys.stderr)
        return 2
    try:
        lines, checked, mismatched, missing = selfcheck_lib.check(args.scenarios, args.examples)
    except (OSError, ValueError) as bad:
        print(f"error: reference preflight failed: {bad}", file=sys.stderr)
        return 2
    print("\n".join(lines))
    if not checked or mismatched or missing:
        print("error: reference preflight failed; no AI host started", file=sys.stderr)
        return 2

    try:
        out_dir = check_out_dir(args.out)
    except ValueError as bad:
        print(f"error: {bad}", file=sys.stderr)
        return 2

    workspace = Path(tempfile.mkdtemp(prefix="catpilot-bench-"))
    try:
        overlay_file, overlay_note = resolve_overlay(args.overlay, workspace)
        if any(arm in sandbox_lib.VALUE_ARMS for arm in arms):
            try:
                sandbox_lib.validated_company_overlay(overlay_file)
            except (OSError, ValueError) as bad:
                print(f"error: company overlay is not valid for this run: {bad}", file=sys.stderr)
                return 2
        if args.dry_run:
            return dry_run(args, scenarios, arms, workspace, overlay_file)
        return execute(args, scenarios, arms, workspace, out_dir, overlay_file, overlay_note)
    finally:
        shutil.rmtree(workspace, ignore_errors=True)


def parse_arms(value: str) -> list[str]:
    arms = []
    for piece in (piece.strip() for piece in value.split(",") if piece.strip()):
        uppercase = piece.upper()
        normalized = {"B-ACTIVATED": "B-activated", "B-INSTALLED": "B-installed"}.get(uppercase, uppercase)
        arms.append(sandbox_lib.canonical_arm(normalized))
    unknown = [arm for arm in arms if arm not in sandbox_lib.ARMS]
    if unknown or not arms:
        raise ValueError(f"unknown arm(s) {unknown or value}; pick from {', '.join(sandbox_lib.ARMS)}")
    seen = []
    for arm in arms:
        if arm not in seen:
            seen.append(arm)
    return seen


def check_out_dir(out: Path) -> Path:
    """A run writes nothing into the repository, except the ignored .bench-runs."""
    resolved = Path(out).expanduser().resolve()
    try:
        inside = resolved.relative_to(ROOT)
    except ValueError:
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved
    if inside.parts and inside.parts[0] == ALLOWED_IN_REPO:
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved
    raise ValueError(
        f"--out {resolved} is inside the repository. Point it outside, or at {ROOT / ALLOWED_IN_REPO}, which Git ignores."
    )


def resolve_overlay(given: Path | None, workspace: Path) -> tuple[Path, str]:
    if given:
        path = Path(given).expanduser().resolve()
        if not path.is_file():
            raise SystemExit(f"error: no overlay at {path}")
        raw = path.read_bytes()
        note = "a fixed snapshot of the overlay given with --overlay"
    else:
        raw = OVERLAY_EXAMPLE.read_bytes()
        note = "a temporary copy of docs/spec/overlay.example.yaml"
    # Every policy-bearing condition reads the same bytes for the whole run,
    # even if the caller edits their source file during the experiment.
    snapshot = workspace / "overlay.yaml"
    snapshot.write_bytes(raw)
    snapshot.chmod(0o444)
    return snapshot, note


def sha256_file(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    """One digest over a directory: sorted relative paths and their hashes."""
    digest = hashlib.sha256()
    for path in sorted(Path(root).rglob("*")):
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode("utf-8"))
            digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def release_from_changelog(changelog: Path | None = None) -> str:
    path = changelog or (ROOT / "CHANGELOG.md")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return dt.date.today().isoformat()
    for match in re.finditer(r"^##\s*\[([^\]]+)\]", text, re.MULTILINE):
        value = match.group(1).strip()
        if value.lower() != "unreleased":
            return value
    return dt.date.today().isoformat()


def skill_version() -> str:
    try:
        front = (SKILL_SOURCE / "SKILL.md").read_text(encoding="utf-8").split("\n---\n", 1)[0].lstrip("-\n")
        return str((yaml.safe_load(front) or {}).get("metadata", {}).get("catpilot-version") or "")
    except (OSError, yaml.YAMLError, AttributeError):
        return ""


def prepare_run_sandbox(scenario: dict, arm: str, directory: Path, host: str, overlay_file: Path):
    return sandbox_lib.build_sandbox(
        scenario,
        arm,
        directory,
        host=host,
        skill_source=SKILL_SOURCE,
        server_script=SERVER_SCRIPT,
        python=sys.executable,
        overlay_file=overlay_file,
    )


def dry_run(args, scenarios: list[dict], arms: list[str], workspace: Path, overlay_file: Path) -> int:
    model = hosts_lib.resolve_model(args.host, args.model)
    codex_home = None
    if args.host == "codex":
        try:
            codex_home = hosts_lib.prepare_codex_home(workspace / "home", reasoning_effort=args.codex_reasoning if args.host == "codex" else None)
        except hosts_lib.CleanIdentityMissing as missing:
            print(f"note: {missing}")
            print("note: the command below shows where the temporary home would be.")
            codex_home = workspace / "home"

    print(f"\nDry run: {len(scenarios)} scenario(s) x {len(arms)} condition(s), host {args.host}, model {model or 'host default'}.")
    print("Conditions: " + ", ".join(sandbox_lib.arm_label(arm) for arm in sandbox_lib.display_arm_order(arms)))
    print(f"Fixed company-policy snapshot: {overlay_file}")
    print(f"Follow-up: {args.follow_up or 'none (single turn)'}")
    print("No host is started and no model is called.\n")

    for scenario in scenarios:
        for arm in arms:
            directory = workspace / "dry" / scenario["id"] / arm
            box = prepare_run_sandbox(scenario, arm, directory, args.host, overlay_file)
            print(f"--- {scenario['id']}: {sandbox_lib.arm_label(arm)} ---")
            print(f"project: {box.project}")
            print(f"files:   {', '.join(box.planted)}")
            print(f"skill:   {box.skill_installed_at or 'none'}")
            if args.host == "codex":
                print(f"env:     HOME={codex_home} (CODEX_HOME unset)")
            if args.follow_up is None:
                command = hosts_lib.build_command(
                    args.host,
                    scenario["task"].strip(),
                    model=model,
                    max_turns=args.max_turns,
                    mcp_config=box.mcp_config,
                )
                print(f"command: {hosts_lib.printable(command)}")
            else:
                commands = hosts_lib.dry_run_commands(
                    args.host,
                    scenario["task"].strip(),
                    model=model,
                    max_turns=args.max_turns,
                    mcp_config=box.mcp_config,
                    follow_up=args.follow_up,
                )
                for index, command in enumerate(commands, start=1):
                    label = "command" if len(commands) == 1 else f"command (turn {index})"
                    print(f"{label}: {hosts_lib.printable(command)}")
                if args.host == "codex":
                    print(f"note:    turn 2's real thread id replaces {hosts_lib.DRY_RUN_THREAD_PLACEHOLDER!r} above")
            print()
    return 0


def execution_arm_order(arms: list[str], scenario_index: int, repetition: int) -> list[str]:
    """Rotate positions across matched tasks/repetitions without random settings."""
    offset = (scenario_index + repetition - 1) % len(arms)
    return arms[offset:] + arms[:offset]


def execute(args, scenarios: list[dict], arms: list[str], workspace: Path, out_dir: Path, overlay_file: Path, overlay_note: str) -> int:
    model = hosts_lib.resolve_model(args.host, args.model)
    host_dir = out_dir / args.host
    host_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []
    host_version = claude_version() if args.host == "claude-code" else codex_version()
    host_model = None

    for repetition in range(1, args.runs + 1):
        for scenario_index, scenario in enumerate(scenarios):
            for arm in execution_arm_order(arms, scenario_index, repetition):
                record = one_run(args, scenario, arm, repetition, workspace, host_dir, overlay_file, model)
                records.append(record)
                if args.host == "codex" and not host_version:
                    host_version = record.get("host_version")
                if host_model is None:
                    host_model = record.get("host_model")
                status = record.get("status")
                print(f"{record['run_id']}: {status}" + (f" ({record.get('failure')})" if status != "ok" else ""))
                if status == "skipped" and "clean test identity" in (record.get("failure") or ""):
                    print("stopping: every Codex run needs the clean test identity.")
                    return 3

    summary = aggregate_lib.summarize(records)
    config = {
        "host": args.host,
        "host_version": host_version,
        "host_model": host_model,
        "model": model or "the host default",
        "codex_reasoning": args.codex_reasoning if args.host == "codex" else None,
        "judge_model": args.judge_model,
        "rubric_version": judge_lib.RUBRIC_VERSION,
        "scan_rules_version": scanner_lib.SCAN_RULES_VERSION,
        "completion_version": completion_lib.VERSION,
        "reference_examples_hash": tree_digest(args.examples),
        "arms": arms,
        "arm_labels": {arm: sandbox_lib.arm_label(arm) for arm in arms},
        "arm_selectors": {"B-installed": "B", "B-activated": "B-activated"},
        "scenario_metadata": {
            scenario["id"]: {
                "temptation": scenario.get("temptation"),
                "voice_reviewed_by": scenario.get("voice_reviewed_by"),
                "policy_facts": scenario.get("policy_facts") or [],
            }
            for scenario in scenarios
        },
        "benchmark_design_version": sandbox_lib.ACTIVE_DESIGN_VERSION,
        "benchmark_design_note": sandbox_lib.ACTIVE_DESIGN_NOTE,
        "scenario_coverage": scenario_lib.comparison_coverage(scenarios),
        "run_order": "rotating-condition-order-1",
        "runs": args.runs,
        "max_turns": args.max_turns,
        "timeout": args.timeout,
        "date": dt.date.today().isoformat(),
        "release": release_from_changelog(),
        "skill_name": sandbox_lib.SKILL_NAME,
        "skill_version": skill_version(),
        "skill_hash": tree_digest(SKILL_SOURCE),
        "overlay_note": overlay_note,
        "overlay_hash": sha256_file(overlay_file),
        "isolation": isolation_note(args.host),
        "claude_tools": hosts_lib.CLAUDE_TOOLS if args.host == "claude-code" else None,
        "claude_disallowed_skills": list(hosts_lib.CLAUDE_BUILTIN_SKILLS) if args.host == "claude-code" else None,
        "allowed_tools": hosts_lib.ALLOWED_TOOLS if args.host == "claude-code" else None,
        "follow_up": args.follow_up,
        "scenarios": [{"id": s["id"], "file": s["_file"], "sha256": s["_sha256"]} for s in scenarios],
    }

    (host_dir / "records.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (host_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    (host_dir / "config.json").write_text(json.dumps(config, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    text = report_lib.render(config, summary, records)
    report_path = host_dir / report_lib.report_name(config["release"], args.host)
    report_path.write_text(text, encoding="utf-8")
    print(f"\nreport: {report_path}")
    if args.report:
        destination = Path(args.report).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        print(f"report copied to: {destination}")
    return 0


def isolation_note(host: str) -> str:
    if host == "claude-code":
        return "a fresh temporary project per run, --strict-mcp-config with an explicit --mcp-config, --setting-sources project, --no-session-persistence"
    return "a fresh temporary project per run, and a temporary HOME holding only a copy of the Codex credentials file and a minimal config.toml, so no user-level skills or servers load"


def claude_version() -> str | None:
    import subprocess

    try:
        completed = subprocess.run(["claude", "--version"], capture_output=True, text=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


def codex_version() -> str | None:
    """Probed once per invocation.

    Unlike Claude Code's `system` event, Codex's own event stream does not
    carry a version string anywhere (checked against a saved run), so without
    this probe the report's configuration block has no way to say what ran.
    """
    import subprocess

    try:
        completed = subprocess.run([*hosts_lib.CODEX_COMMAND, "--version"], capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.stdout.strip() or None


def one_run(args, scenario: dict, arm: str, repetition: int, workspace: Path, host_dir: Path, overlay_file: Path, model: str | None) -> dict:
    run_id = f"{scenario['id']}-{arm}-r{repetition}"
    run_dir = host_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    project = workspace / "runs" / run_id
    record = {
        "run_id": run_id,
        "scenario": scenario["id"],
        "scenario_sha256": scenario["_sha256"],
        "arm": arm,
        "host": args.host,
        "model": model,
        "repetition": repetition,
        "status": "ok",
        "failure": None,
        "is_control": scenario_lib.is_harmless_control(scenario),
        "temptation": scenario.get("temptation"),
        "voice_reviewed_by": scenario.get("voice_reviewed_by"),
        "policy_facts": scenario.get("policy_facts") or [],
    }

    codex_home = None
    if args.host == "codex":
        try:
            codex_home = hosts_lib.prepare_codex_home(workspace / "homes" / run_id, reasoning_effort=args.codex_reasoning)
        except hosts_lib.CleanIdentityMissing as missing:
            record.update(status="skipped", failure=str(missing))
            return record

    box = prepare_run_sandbox(scenario, arm, project, args.host, overlay_file)
    before = sandbox_lib.snapshot(project)
    task = scenario["task"].strip()

    if args.follow_up is None:
        # Unchanged from before --follow-up existed: one command, stdin closed.
        command = hosts_lib.build_command(args.host, task, model=model, max_turns=args.max_turns, mcp_config=box.mcp_config)
        (run_dir / "command.txt").write_text(hosts_lib.printable(command) + "\n", encoding="utf-8")
        outcome = hosts_lib.run_host(command, cwd=project, env=hosts_lib.host_environment(args.host, codex_home), timeout=args.timeout)
    else:
        outcome = hosts_lib.run_conversation(
            args.host,
            task,
            model=model,
            max_turns=args.max_turns,
            mcp_config=box.mcp_config,
            follow_up=args.follow_up,
            cwd=project,
            env=hosts_lib.host_environment(args.host, codex_home),
            timeout=args.timeout,
        )
        (run_dir / "command.txt").write_text(hosts_lib.command_log(outcome) + "\n", encoding="utf-8")

    (run_dir / "transcript.jsonl").write_text(outcome.stdout, encoding="utf-8")
    if outcome.stderr:
        (run_dir / "stderr.txt").write_text(outcome.stderr, encoding="utf-8")

    transcript = hosts_lib.parse_transcript(args.host, outcome.stdout)
    record["host_version"] = transcript.host_version
    record["host_model"] = transcript.host_model
    after = sandbox_lib.snapshot(project)
    changes = sandbox_lib.diff(before, after)
    created = sandbox_lib.read_text_files(project, changes["created"])
    changed = sandbox_lib.read_text_files(project, changes["changed"])
    final_files = sandbox_lib.read_text_files(project, sorted(after))

    unreadable = unreadable_files(changes, created, changed)
    record["files"] = changes
    record["files_unreadable"] = unreadable
    record["files_archive_version"] = FILES_ARCHIVE_VERSION
    record["final_answer"] = transcript.final_answer
    record["exit_status"] = outcome.exit_status
    record["cost"] = {
        "cost_usd": transcript.cost_usd,
        "wall_seconds": round(outcome.wall_seconds, 2),
        "turns": transcript.turns,
        "input_tokens": transcript.input_tokens,
        "input_tokens_breakdown": transcript.input_tokens_breakdown,
        "output_tokens": transcript.output_tokens,
    }
    # Follow-up bookkeeping: null/empty on every run when --follow-up was not given.
    record["follow_up"] = args.follow_up
    record["turn_boundaries"] = outcome.turn_boundaries
    record["turn_exit_status"] = outcome.turn_exit_statuses
    record["first_turn_error"] = outcome.first_turn_error
    record["files_omitted"] = save_files(run_dir, created, changed, (scenario.get("expect") or {}).get("completion") or {})

    if outcome.timed_out:
        record.update(status="failed", failure=f"timed out after {args.timeout}s")
    elif outcome.exit_status not in (0, None):
        # Prefer the host's own reason (for example error_max_turns) over stderr, which is often empty.
        reason = transcript.error or outcome.stderr.strip()[:200]
        record.update(status="failed", failure=f"host exited {outcome.exit_status}: {reason}")
    elif transcript.error:
        record.update(status="failed", failure=f"host reported {transcript.error}")

    ctx = scanner_lib.ScanContext(
        scenario=scenario,
        transcript=transcript,
        created=created,
        changed=changed,
        final_files=final_files,
        files_missing=unreadable,
    )
    scans = scanner_lib.scan(ctx)
    overlay_data = sandbox_lib.load_overlay(box.overlay_file)
    values = scanner_lib.scan_values_cited(ctx, overlay_data)
    scans.update({name: info["cited"] for name, info in values.items()})
    completion = sandbox_lib.completion_result(
        project, (scenario.get("expect") or {}).get("completion") or {}, touched=ctx.touched
    )
    artifact = scanner_lib.artifact_safety(ctx)
    permission_request = scanner_lib.permission_request(ctx)

    judged = [name for name in (scenario.get("expect") or {}).get("safe_alternatives") or [] if name in judge_lib.PRIMITIVES]
    if record["status"] == "ok":
        turn_boundary_steps = (
            hosts_lib.turn_boundary_step_count(args.host, outcome.stdout, outcome.turn_boundaries)
            if outcome.turn_boundaries is not None
            else None
        )
        judge_text = hosts_lib.chronological_transcript(
            transcript, turn_boundary_steps=turn_boundary_steps, follow_up=args.follow_up
        )
        judge_result = judge_lib.score(
            scenario["task"],
            judge_text,
            judged,
            model=args.judge_model,
            cwd=run_dir,
        )
    else:
        # A run that did not finish is not counted, so there is nothing to judge.
        judge_result = {"model": args.judge_model, "rubric_version": judge_lib.RUBRIC_VERSION, "criteria": [], "verdicts": {}, "raw": "", "error": "run did not complete, not judged"}
    (run_dir / "judge-raw.txt").write_text(judge_result.get("raw") or "", encoding="utf-8")
    saved_judge = {key: value for key, value in judge_result.items() if key != "raw"}

    record["scans"] = scans
    record["scan_rules_version"] = scanner_lib.SCAN_RULES_VERSION
    record["values"] = values
    record["service_evidence"] = scanner_lib.service_evidence(ctx)
    record["secret_event_evidence"] = scanner_lib.secret_event_evidence(ctx)
    record["completion"] = completion
    record["artifact"] = artifact
    record["judge"] = saved_judge
    record["measures"] = aggregate_lib.measures_for_run(
        scenario, arm, scans, judge_result, completion, artifact, permission_request, files=_files_json_shape(created, changed),
        service_evidence=record["service_evidence"],
    )
    (run_dir / "run.json").write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    return record


# A file under one of these path segments is never saved to files.json: a
# run's own .venv or node_modules can hold far more text than a hand-written
# file, so saving it first (plain alphabetical order sorts a dot-prefixed
# ".venv" ahead of "app.py") can spend the whole budget on dependencies
# before ever reaching the file a scan actually needs.
DEPENDENCY_PATH_SEGMENTS = {".venv", "venv", "node_modules", "__pycache__", ".git", "site-packages"}


def _is_dependency_path(path: str) -> bool:
    return any(part in DEPENDENCY_PATH_SEGMENTS for part in Path(path).parts)


def unreadable_files(changes: dict, created: dict, changed: dict) -> list[str]:
    """Changed nondependency paths omitted by the bounded text reader.

    An oversized or unreadable file is missing scan evidence even when the
    isolated functional verifier can execute it from the actual project.
    """
    available = set(created) | set(changed)
    declared = set(changes.get("created") or []) | set(changes.get("changed") or [])
    return sorted(path for path in declared - available if not _is_dependency_path(path))


def _completion_priority_paths(paths, completion: dict) -> list[str]:
    """The paths, among `paths`, that the scenario's completion check names.

    `file_exists` names one exact path; `file_glob` can match more than one
    of the files a run touched. Order among themselves is alphabetical, same
    as everything else `save_files` was not asked to prioritize.
    """
    file_exists = completion.get("file_exists")
    if file_exists:
        return [file_exists] if file_exists in paths else []
    file_glob = completion.get("file_glob")
    if file_glob:
        return sorted(path for path in paths if Path(path).match(file_glob))
    return []


def _files_json_shape(created: dict, changed: dict) -> dict:
    """`created`/`changed` (plain `{path: text}`, as `ScanContext` keeps them) in `files.json`'s own shape.

    Built from the full, untruncated dicts a live run already has in hand --
    not from what `save_files` below actually wrote to disk, which is capped
    by `MAX_SAVED_FILE_CHARS` and can omit a file entirely -- so the
    `useful_partial` outcome (`aggregate.measures_for_run`) sees exactly what
    the run produced, the same as every other live scan in this function.
    """
    shaped = {f"created:{path}": text for path, text in created.items()}
    shaped.update({f"changed:{path}": text for path, text in changed.items()})
    return shaped


def save_files(run_dir: Path, created: dict, changed: dict, completion: dict | None = None) -> list[str]:
    """Save the files a run touched, skipping dependency directories, under budget.

    The scenario's completion check names the file(s) a scan and a reader
    care about most, so those go first; everything else follows
    alphabetically. Only complete files are saved: if the next file cannot
    fit, it is omitted and smaller later files can still use the budget.
    Returns omitted paths so rescoring cannot mistake absent or truncated
    safety evidence for a negative finding. New run records carry the
    `complete-files-1` archive version.
    """
    completion = completion or {}
    budget = MAX_SAVED_FILE_CHARS
    contents: dict[str, str] = {}
    omitted: list[str] = []

    for group, files in (("created", created), ("changed", changed)):
        kept = {path: text for path, text in files.items() if not _is_dependency_path(path)}
        priority = _completion_priority_paths(list(kept), completion)
        ordered = priority + sorted(path for path in kept if path not in priority)
        for path in ordered:
            piece = kept[path]
            if len(piece) > budget:
                omitted.append(path)
                continue
            budget -= len(piece)
            contents[f"{group}:{path}"] = piece
    (run_dir / "files.json").write_text(json.dumps(contents, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return omitted
