#!/usr/bin/env python3
"""Summarize Catpilot evidence logs (JSONL) into a Markdown or JSON pilot report.

Reads one or more files written by CATPILOT_EVIDENCE_LOG from the Claude Code
hooks (pretooluse-secrets, pretooluse-write-private-key, pretooluse-destructive-ops)
and the reference MCP server (get_guidance, check_plan, get_template, list_approved).

Because the evidence log never records command text, file paths, file content,
plan descriptions, or free-text values, this summary contains only counts of
enumerated events, labels, tool calls, outcomes, and field names.

Usage:
    python3 tools/evidence_summary.py ~/.catpilot-guardrails/evidence.jsonl
    python3 tools/evidence_summary.py --format json /path/to/logs/*.jsonl
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


def summarize_lines(lines: list[str]) -> dict[str, Any]:
    total_events = 0
    invalid_lines = 0
    hook_denials_by_hook: Counter[str] = Counter()
    hook_denials_by_label: Counter[str] = Counter()
    hook_denials_by_tool: Counter[str] = Counter()
    hook_input_errors: Counter[str] = Counter()
    unique_sessions: set[str] = set()

    mcp_calls_by_tool: Counter[str] = Counter()
    mcp_errors: Counter[str] = Counter()
    mcp_policy_status: Counter[str] = Counter()
    mcp_unknown_policy_true = 0
    mcp_unknown_policy_false = 0

    check_plan_outcomes: Counter[str] = Counter()
    check_plan_ask_a_human_true = 0
    check_plan_ask_a_human_false = 0
    check_plan_fields: Counter[str] = Counter()

    guidance_topics: Counter[str] = Counter()
    template_kinds: Counter[str] = Counter()
    approved_categories: Counter[str] = Counter()

    earliest_ts: str | None = None
    latest_ts: str | None = None

    for raw in lines:
        stripped = raw.strip()
        if not stripped:
            continue
        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue
        if not isinstance(entry, dict):
            invalid_lines += 1
            continue

        total_events += 1
        ts = entry.get("ts")
        if isinstance(ts, str) and ts:
            if earliest_ts is None or ts < earliest_ts:
                earliest_ts = ts
            if latest_ts is None or ts > latest_ts:
                latest_ts = ts

        sid = entry.get("session_id")
        if isinstance(sid, str) and sid:
            unique_sessions.add(sid)

        source = entry.get("source")
        if source == "claude-code-hook":
            hook = str(entry.get("hook") or "unknown")
            event = entry.get("event")
            if event == "deny":
                hook_denials_by_hook[hook] += 1
                label = str(entry.get("label") or "unknown")
                hook_denials_by_label[label] += 1
                tool = str(entry.get("tool") or "unknown")
                hook_denials_by_tool[tool] += 1
            elif event == "input_error":
                hook_input_errors[hook] += 1
        elif source == "mcp-server":
            tool = str(entry.get("tool") or "unknown")
            mcp_calls_by_tool[tool] += 1
            err = entry.get("error")
            if err:
                mcp_errors[str(err)] += 1
            pstatus = entry.get("policy_status")
            if isinstance(pstatus, str) and pstatus:
                mcp_policy_status[pstatus] += 1
            if entry.get("unknown_policy") is True:
                mcp_unknown_policy_true += 1
            elif entry.get("unknown_policy") is False:
                mcp_unknown_policy_false += 1

            if tool == "check_plan":
                outcome = entry.get("outcome")
                if isinstance(outcome, str) and outcome:
                    check_plan_outcomes[outcome] += 1
                if entry.get("ask_a_human") is True:
                    check_plan_ask_a_human_true += 1
                elif entry.get("ask_a_human") is False:
                    check_plan_ask_a_human_false += 1
                fields = entry.get("fields")
                if isinstance(fields, list):
                    for f in fields:
                        if isinstance(f, str):
                            check_plan_fields[f] += 1
            elif tool == "get_guidance" and isinstance(entry.get("topic"), str):
                guidance_topics[entry["topic"]] += 1
            elif tool == "get_template" and isinstance(entry.get("kind"), str):
                template_kinds[entry["kind"]] += 1
            elif tool == "list_approved" and isinstance(entry.get("category"), str):
                approved_categories[entry["category"]] += 1

    return {
        "total_events": total_events,
        "invalid_lines": invalid_lines,
        "time_range": {"earliest": earliest_ts, "latest": latest_ts},
        "hooks": {
            "total_denials": sum(hook_denials_by_hook.values()),
            "total_input_errors": sum(hook_input_errors.values()),
            "unique_sessions_with_denials": len(unique_sessions),
            "denials_by_hook": dict(sorted(hook_denials_by_hook.items())),
            "denials_by_label": dict(sorted(hook_denials_by_label.items(), key=lambda kv: (-kv[1], kv[0]))),
            "denials_by_tool": dict(sorted(hook_denials_by_tool.items())),
            "input_errors_by_hook": dict(sorted(hook_input_errors.items())),
        },
        "mcp_server": {
            "total_calls": sum(mcp_calls_by_tool.values()),
            "calls_by_tool": dict(sorted(mcp_calls_by_tool.items())),
            "errors": dict(sorted(mcp_errors.items())),
            "policy_status": dict(sorted(mcp_policy_status.items())),
            "unknown_policy": {"true": mcp_unknown_policy_true, "false": mcp_unknown_policy_false},
            "check_plan": {
                "outcomes": dict(sorted(check_plan_outcomes.items())),
                "ask_a_human": {"true": check_plan_ask_a_human_true, "false": check_plan_ask_a_human_false},
                "supplied_fields": dict(sorted(check_plan_fields.items(), key=lambda kv: (-kv[1], kv[0]))),
            },
            "get_guidance_topics": dict(sorted(guidance_topics.items())),
            "get_template_kinds": dict(sorted(template_kinds.items())),
            "list_approved_categories": dict(sorted(approved_categories.items())),
        },
    }


def render_markdown(summary: dict[str, Any]) -> str:
    hooks = summary["hooks"]
    mcp = summary["mcp_server"]
    tr = summary["time_range"]
    window = f"{tr['earliest']} to {tr['latest']}" if tr["earliest"] else "none"
    out = [
        "# Catpilot Evidence Summary",
        "",
        f"- **Total events:** {summary['total_events']}",
        f"- **Time window:** {window}",
    ]
    if summary["invalid_lines"]:
        out.append(f"- **Malformed lines skipped:** {summary['invalid_lines']}")
    out += [
        "",
        "## Enforcement hooks (`claude-code-hook`)",
        "",
        f"- **Total denials:** {hooks['total_denials']}",
        f"- **Unique sessions with denials:** {hooks['unique_sessions_with_denials']}",
        f"- **Input errors (fail-closed):** {hooks['total_input_errors']}",
    ]
    if hooks["denials_by_label"]:
        out += ["", "| Denials by pattern / label | Count |", "| --- | --- |"]
        for label, count in hooks["denials_by_label"].items():
            out.append(f"| `{label}` | {count} |")
    out += [
        "",
        "## Guidance lookups (`mcp-server`)",
        "",
        f"- **Total tool calls:** {mcp['total_calls']}",
        f"- **Answered with approved company overlay (`unknown_policy: false`):** {mcp['unknown_policy']['false']}",
        f"- **Answered with generic defaults (`unknown_policy: true`):** {mcp['unknown_policy']['true']}",
    ]
    if mcp["calls_by_tool"]:
        out += ["", "| Tool | Calls |", "| --- | --- |"]
        for tool, count in mcp["calls_by_tool"].items():
            out.append(f"| `{tool}` | {count} |")
    cp = mcp["check_plan"]
    if cp["outcomes"]:
        out += [
            "",
            "### `check_plan` decisions",
            "",
            f"- **Escalated to a human (`ask_a_human: true`):** {cp['ask_a_human']['true']}",
            f"- **No human escalation needed (`ask_a_human: false`):** {cp['ask_a_human']['false']}",
            "",
            "| Outcome | Count |",
            "| --- | --- |",
        ]
        for outcome, count in cp["outcomes"].items():
            out.append(f"| `{outcome}` | {count} |")
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="+", type=Path, help="One or more evidence.jsonl files to summarize")
    parser.add_argument("--format", choices=("markdown", "json"), default="markdown", help="Output format (default: markdown)")
    args = parser.parse_args(argv)

    all_lines: list[str] = []
    for path in args.files:
        if not path.is_file():
            print(f"error: file not found: {path}", file=sys.stderr)
            return 2
        all_lines.extend(path.read_text(encoding="utf-8", errors="replace").splitlines())

    summary = summarize_lines(all_lines)
    if args.format == "json":
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        sys.stdout.write(render_markdown(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main())
