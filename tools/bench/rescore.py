"""Rescore saved benchmark runs under a newer scan-rules (or rubric) version.

A run directory `tools/bench.py` wrote is not tied to the scanner and judge
code that produced it: `run.json` carries the raw transcript's shape (via
`files.json` and `transcript.jsonl`), not the verdicts alone, so a scoring fix
can be re-applied to it without spending anything on the host again. This
script rebuilds the `ScanContext` for every saved run under `<run-dir>/<host>`
from those saved artifacts, recomputes the deterministic scans, artifact
safety, and the aggregate measures with the code in this checkout, and writes
a new `records.json`, `summary.json`, and Markdown report under `--out`.

The judge verdicts already saved in each run's `run.json` are reused as-is,
because re-running the judge means calling a model. Pass `--rejudge` to score
the assistant's text again instead, against the rubric this checkout ships
(`judge.RUBRIC_VERSION`) and the model named by `--judge-model`; without that
flag no model is ever called, by anyone, for any reason.

Runs that did not complete are carried over unchanged and stay excluded from
the counts, exactly as `tools/bench/aggregate.py` already excludes them: this
script does not change what "did not complete" means, only how a completed
run's transcript is scored.

Usage:
  python tools/bench/rescore.py <run-dir>/<host> --scenarios <dir> --out <dir> \\
      [--rejudge] [--judge-model sonnet]

Writes records.json, summary.json, and <original report stem>-rescored.md
under --out, which must be outside the repository or under .bench-runs/, the
same rule `tools/bench.py` enforces.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path

# Runnable directly (`python tools/bench/rescore.py ...`), which gives this
# module no package context, so `from . import ...` would fail; put the
# repository root on sys.path and import absolutely instead, exactly as the
# `tools/bench.py` wrapper does for the rest of this package.
ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tools.bench import aggregate as aggregate_lib  # noqa: E402
from tools.bench import hosts as hosts_lib  # noqa: E402
from tools.bench import judge as judge_lib  # noqa: E402
from tools.bench import report as report_lib  # noqa: E402
from tools.bench import rescore_completion  # noqa: E402
from tools.bench import scanners as scanner_lib  # noqa: E402
from tools.bench import scenarios as scenario_lib  # noqa: E402
from tools.bench.cli import check_out_dir  # noqa: E402

NOT_JUDGED = {
    "model": None,
    "rubric_version": None,
    "criteria": [],
    "verdicts": {},
    "error": "run did not complete, not judged",
}

# Kept in sync by hand with cli.save_files's own copy of this list: cli.py is
# under a separate, narrower change constraint for this project, so this is
# not a shared import. A path under one of these segments was never expected
# to be saved to files.json in the first place, so it is not "missing".
DEPENDENCY_PATH_SEGMENTS = {".venv", "venv", "node_modules", "__pycache__", ".git", "site-packages"}


def _is_dependency_path(path: str) -> bool:
    return any(part in DEPENDENCY_PATH_SEGMENTS for part in Path(path).parts)


# ---------------------------------------------------------------------------
# Rebuilding a run's saved artifacts into a ScanContext


def load_run_record(run_dir: Path) -> dict:
    return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))


def load_files(run_dir: Path) -> dict:
    path = run_dir / "files.json"
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def split_files(files: dict) -> tuple[dict, dict]:
    """`files.json`'s `created:<path>`/`changed:<path>` keys, split back apart."""
    created, changed = {}, {}
    for key, text in files.items():
        if key.startswith("created:"):
            created[key.split(":", 1)[1]] = text
        elif key.startswith("changed:"):
            changed[key.split(":", 1)[1]] = text
    return created, changed


def rebuild_final_files(scenario: dict, changed: dict) -> dict:
    """Best-effort final state of every planted path.

    The changed content if the run changed it, else the scenario's own
    planted content -- a full final snapshot is never saved, only the diff,
    so a planted path the run left alone is assumed to still hold what was
    planted there.
    """
    final_files = {}
    for entry in scenario.get("sandbox") or []:
        path = entry.get("path")
        if not path:
            continue
        final_files[path] = changed.get(path, entry.get("content") or "")
    return final_files


def rebuild_context(scenario: dict, record: dict, run_dir: Path) -> scanner_lib.ScanContext:
    transcript_path = run_dir / "transcript.jsonl"
    stdout = transcript_path.read_text(encoding="utf-8") if transcript_path.is_file() else ""
    transcript = hosts_lib.parse_transcript(record.get("host") or "claude-code", stdout)
    created, changed = split_files(load_files(run_dir))
    return scanner_lib.ScanContext(
        scenario=scenario,
        transcript=transcript,
        created=created,
        changed=changed,
        final_files=rebuild_final_files(scenario, changed),
        final_answer=record.get("final_answer"),
    )


def missing_files(record: dict, files_json: dict) -> list[str]:
    """Paths `run.json` says the run created or changed that files.json never saved.

    The saved-files budget (`cli.save_files`) can skip a file entirely rather
    than truncate it, most often because a run's own dependency directory
    (`.venv`, `node_modules`, ...) crowded it out; a run's `files_omitted`
    already names those when the run is new enough to carry it, and an older
    saved run is covered the same way, by diffing what `run.json` declares
    against what `files.json` actually has. A scan sees a decoy path missing
    like this fall back to the transcript's write texts instead (see
    `scanners.loads_decoy_export_at_runtime`), which is why this is reported
    rather than silently accepted.
    """
    declared = list((record.get("files") or {}).get("created") or [])
    declared += list((record.get("files") or {}).get("changed") or [])
    declared += list(record.get("files_omitted") or [])
    saved = {key.split(":", 1)[1] for key in files_json if ":" in key}
    return sorted({path for path in declared if path not in saved and not _is_dependency_path(path)})


# ---------------------------------------------------------------------------
# Per-run and per-host-directory rescoring


def check_scenario_matches(record: dict, scenario: dict | None) -> str | None:
    """None on a match, else the message to print before refusing."""
    run_id = record.get("run_id", "<unknown run>")
    scenario_id = record.get("scenario")
    if scenario is None:
        return f"{run_id}: no scenario '{scenario_id}' in the given --scenarios directory"
    expected, actual = record.get("scenario_sha256"), scenario.get("_sha256")
    if expected != actual:
        return f"{run_id}: scenario_sha256 mismatch for '{scenario_id}': run recorded {expected}, loaded file is {actual}"
    return None


def rescore_run(record: dict, scenario: dict, run_dir: Path, *, rejudge: bool, judge_model: str, judge_runner=None) -> dict:
    """One rescored record: saved fields reused, scans/artifact/measures recomputed."""
    new_record = dict(record)
    ctx = rebuild_context(scenario, record, run_dir)
    new_record["files_missing"] = missing_files(record, load_files(run_dir))

    scans = scanner_lib.scan(ctx)
    artifact = scanner_lib.artifact_safety(ctx)
    permission_request = scanner_lib.permission_request(ctx)
    completion = record.get("completion") or {}

    if rejudge and record.get("status") == "ok":
        judged = [name for name in (scenario.get("expect") or {}).get("safe_alternatives") or [] if name in judge_lib.PRIMITIVES]
        judge_result = judge_lib.score(
            scenario["task"],
            ctx.transcript.all_assistant_text(),
            judged,
            include_values=(record.get("arm") == "C"),
            model=judge_model,
            runner=judge_runner,
        )
        saved_judge = {key: value for key, value in judge_result.items() if key != "raw"}
    else:
        saved_judge = record.get("judge") or dict(NOT_JUDGED)
        judge_result = {"verdicts": saved_judge.get("verdicts") or {}}

    new_record["scans"] = scans
    new_record["scan_rules_version"] = scanner_lib.SCAN_RULES_VERSION
    new_record["artifact"] = artifact
    new_record["judge"] = saved_judge
    new_record["measures"] = aggregate_lib.measures_for_run(
        scenario, record.get("arm"), scans, judge_result, completion, artifact, permission_request
    )
    return new_record


def rescore_host_dir(
    host_dir: Path,
    scenarios_by_id: dict[str, dict],
    *,
    rejudge: bool = False,
    judge_model: str = judge_lib.DEFAULT_JUDGE_MODEL,
    judge_runner=None,
) -> tuple[list[dict], list[str]]:
    """Rescore every run subdirectory of `host_dir`. Stops at the first scenario mismatch."""
    run_dirs = sorted(p for p in host_dir.iterdir() if p.is_dir() and (p / "run.json").is_file())
    new_records: list[dict] = []
    for run_dir in run_dirs:
        record = load_run_record(run_dir)
        scenario = scenarios_by_id.get(record.get("scenario"))
        problem = check_scenario_matches(record, scenario)
        if problem:
            return new_records, [problem]
        new_records.append(
            rescore_run(record, scenario, run_dir, rejudge=rejudge, judge_model=judge_model, judge_runner=judge_runner)
        )
    return new_records, []


# ---------------------------------------------------------------------------
# The report: locating the original, and its configuration block


def find_original_report(host_dir: Path, host: str) -> Path | None:
    """The report `tools/bench.py` wrote for this directory, if it is still there.

    Its name is `report.report_name(release, host)`; a hand-renamed copy (for
    example a reviewer's `FINAL-...`) is skipped in favor of the one whose
    prefix still looks like the CalVer release it was published under.
    """
    suffix = f"-benchmark-{host}.md"
    candidates = [p for p in host_dir.glob(f"*{suffix}") if not p.name.endswith("-rescored.md")]
    calver = [p for p in candidates if re.fullmatch(r"\d{4}\.\d{2}\.\d{2}" + re.escape(suffix), p.name)]
    if calver:
        return sorted(calver)[0]
    return sorted(candidates)[0] if candidates else None


def find_release(host_dir: Path, host: str) -> str | None:
    report = find_original_report(host_dir, host)
    if report is None:
        return None
    return report.name[: -len(f"-benchmark-{host}.md")]


def load_original_config(host_dir: Path) -> dict | None:
    """`<host_dir>/config.json`, if `cli.execute` saved one, else None.

    Runs from before that one-line addition (every run this command was first
    exercised against, 2026-09-15) have no such file, so `build_config` falls
    back to reconstructing what it can.
    """
    path = host_dir / "config.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _reconstruct_config(host_dir: Path, host: str, records: list[dict], scenarios: list[dict]) -> dict:
    """Best-effort config for a saved run directory with no `config.json`.

    `tools/bench.py` did not always write its config dict to disk on its own:
    on an older run it only ever appears rendered into a report's Markdown
    text. What the run itself carries covers most of what a reader needs --
    host, model, judge model and rubric version, the arms and scenarios
    actually run -- and the rest (max turns, timeout, the skill and overlay
    identity) is not recoverable from a saved run directory; `report.render`
    already falls back to "unknown" / "not reported" text for those fields
    when they are absent.
    """
    ok = [r for r in records if r.get("status") == "ok"]
    sample = ok[0] if ok else (records[0] if records else {})
    original_judge = sample.get("judge") or {}
    arms = sorted({r["arm"] for r in records if r.get("arm")})
    runs = max((r.get("repetition") or 1) for r in records) if records else None
    used_ids = {r.get("scenario") for r in records if r.get("scenario")}
    scenario_list = [{"id": s["id"], "file": s["_file"], "sha256": s["_sha256"]} for s in scenarios if s["id"] in used_ids]

    release = find_release(host_dir, host)
    # "date" and "release" are read with `config.get(key, default)`, a
    # positional default that only fires when the key is missing -- so an
    # unrecoverable value has to be left out of the dict entirely, not set to
    # None, or it would print as the word "None" instead of falling back.
    date = release.replace(".", "-") if release and re.fullmatch(r"\d{4}\.\d{2}\.\d{2}", release) else None

    config = {
        "host": host,
        "host_version": sample.get("host_version"),
        "model": sample.get("model"),
        "judge_model": original_judge.get("model"),
        "rubric_version": original_judge.get("rubric_version"),
        "arms": arms,
        "runs": runs,
        "scenarios": scenario_list,
    }
    if release:
        config["release"] = release
    if date:
        config["date"] = date
    return config


def build_config(
    host_dir: Path,
    host: str,
    records: list[dict],
    scenarios: list[dict],
    *,
    rejudge: bool,
    judge_model: str,
) -> dict:
    """The original run's configuration, preferring a saved `config.json`.

    Falls back to `_reconstruct_config` for a run directory saved before
    `cli.execute` started writing that file. Either way, the rescore-specific
    fields (scan rules, provenance, the judge note) are layered on the same
    way, and a `--rejudge` overrides the judge model and rubric version to
    the ones actually used for the fresh verdicts.
    """
    original = load_original_config(host_dir)
    config = dict(original) if original is not None else _reconstruct_config(host_dir, host, records, scenarios)
    config.setdefault("host", host)

    if rejudge:
        config["judge_model"] = judge_model
        config["rubric_version"] = judge_lib.RUBRIC_VERSION
        rescore_note = f"Judge re-run on model {judge_model} against rubric {judge_lib.RUBRIC_VERSION}."
    else:
        rescore_note = "Judge verdicts reused from the original run."

    config["scan_rules_version"] = scanner_lib.SCAN_RULES_VERSION
    config["rescored_from"] = f"{host_dir.resolve().parent.name}/{host_dir.resolve().name}"
    config["rescored_on"] = dt.date.today().isoformat()
    config["rescore_note"] = rescore_note
    return config


def missing_files_paragraph(missing_by_run: dict[str, list[str]]) -> str:
    """The note for the rescored report, or "" when nothing was missing."""
    if not missing_by_run:
        return ""
    count = len(missing_by_run)
    run_ids = ", ".join(f"`{run_id}`" for run_id in sorted(missing_by_run))
    return (
        f"{count} run{'s' if count != 1 else ''} had files the original run created but did not save "
        "(the saved-files budget was spent on dependency directories); their scans use the "
        f"transcript's write texts for those files. Affected: {run_ids}."
    )


def insert_under_results_table(text: str, paragraph: str) -> str:
    """`paragraph` right under the Results table -- before its explanatory prose."""
    if not paragraph:
        return text
    anchor = "Unsafe action counts only what a run itself wrote"
    block = paragraph + "\n\n"
    if anchor in text:
        return text.replace(anchor, block + anchor, 1)
    marker = "### By scenario"
    if marker in text:
        return text.replace(marker, block + marker, 1)
    return text.rstrip("\n") + "\n\n" + paragraph + "\n"


# ---------------------------------------------------------------------------
# CLI


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rescore.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run_dir", type=Path, help="a saved <out>/<host> directory from tools/bench.py")
    parser.add_argument("--scenarios", type=Path, required=True, help="directory of held-out scenario files, outside any repository")
    parser.add_argument("--out", type=Path, required=True, help="directory for the rescored records and report")
    parser.add_argument("--rejudge", action="store_true", help="score the assistant's text again with a model, instead of reusing saved verdicts")
    parser.add_argument("--judge-model", default=judge_lib.DEFAULT_JUDGE_MODEL, help="only used with --rejudge")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    host_dir = Path(args.run_dir).expanduser().resolve()
    if not host_dir.is_dir():
        print(f"error: no directory at {host_dir}", file=sys.stderr)
        return 2
    host = host_dir.name

    try:
        scenarios = scenario_lib.load_scenarios(args.scenarios)
    except (FileNotFoundError, ValueError) as bad:
        print(f"error: {bad}", file=sys.stderr)
        return 2
    scenarios_by_id = {s["id"]: s for s in scenarios}

    try:
        out_dir = check_out_dir(args.out)
    except ValueError as bad:
        print(f"error: {bad}", file=sys.stderr)
        return 2

    new_records, errors = rescore_host_dir(
        host_dir, scenarios_by_id, rejudge=args.rejudge, judge_model=args.judge_model
    )
    if errors:
        for problem in errors:
            print(f"error: {problem}", file=sys.stderr)
        return 2
    if not new_records:
        print(f"error: no run directories (with a run.json) found under {host_dir}", file=sys.stderr)
        return 2

    for record in new_records:
        print(f"{record['run_id']}: rescored ({record.get('status')})")

    missing_by_run = {r["run_id"]: r["files_missing"] for r in new_records if r.get("files_missing")}
    for run_id, missing in sorted(missing_by_run.items()):
        print(f"warning: {run_id} is missing saved content for: {', '.join(missing)}")

    summary = aggregate_lib.summarize(new_records)
    config = build_config(host_dir, host, new_records, scenarios, rejudge=args.rejudge, judge_model=args.judge_model)

    (out_dir / "records.json").write_text(json.dumps(new_records, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    text = report_lib.render(config, summary, new_records)
    text = insert_under_results_table(text, missing_files_paragraph(missing_by_run))
    completion_data = rescore_completion.collect(host_dir)
    artifact_lines = rescore_completion.render_lines(
        completion_data["by_arm"], completion_data["by_scenario"], completion_data["strict_by_arm"]
    )
    text = text.rstrip("\n") + "\n\n" + "\n".join(artifact_lines) + "\n"

    original = find_original_report(host_dir, host)
    stem = original.stem if original else f"{config.get('release') or 'unreleased'}-benchmark-{host}"
    report_path = out_dir / f"{stem}-rescored.md"
    report_path.write_text(text, encoding="utf-8")

    print(f"\nrescored {len(new_records)} run(s) under scan rules {scanner_lib.SCAN_RULES_VERSION}")
    print(f"report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
