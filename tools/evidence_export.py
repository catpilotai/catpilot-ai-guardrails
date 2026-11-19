#!/usr/bin/env python3
"""Convert Catpilot evidence logs (JSONL) to OCSF 1.3.0 or ECS 8.11 JSON lines.

The field-by-field mapping, and why each event goes to the class it does, is docs/spec/EVIDENCE_MAPPINGS.md.
Every output keeps the original line whole (OCSF: unmapped.catpilot; ECS: catpilot), so nothing is lost and a
field without a standard home is still there. An evidence line is content-free (docs/spec/EVIDENCE.md §4), and
the conversion adds only fixed text, so the output is content-free too.

Usage:
    python3 tools/evidence_export.py --format ocsf ~/.catpilot-guardrails/evidence.jsonl > evidence.ocsf.jsonl
    python3 tools/evidence_export.py --format ecs logs/*.jsonl
    cat evidence.jsonl | python3 tools/evidence_export.py --format ecs -

Lines that are not JSON objects, or carry no known event or no readable time, are skipped and counted on
stderr, and the exit status is then 1. Lines written before schema version 1 convert too: a server line
without event is a lookup (EVIDENCE.md §3).

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

OCSF_VERSION = "1.3.0"
ECS_VERSION = "8.11.0"
PRODUCT = "Catpilot AI Guardrails"
VENDOR = "Catpilot"
MCP_SERVICE = "catpilot-guardrails-mcp"
SERVER_TOOLS = ("get_guidance", "check_plan", "get_template", "list_approved")
EVENTS = ("rules_delivered", "rules_expired", "deny", "ask", "would_deny", "policy_error", "input_error", "lookup")

SEVERITY = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High"}

# Detection Finding (class 2004): a check matched a tool call. (action_id, action, disposition_id, disposition, severity_id, title)
FINDING = {
    "deny": (2, "Denied", 2, "Blocked", 3, "Tool call denied"),
    "ask": (99, "Ask", 23, "Challenge", 2, "Tool call sent to the person to confirm"),
    "would_deny": (1, "Allowed", 15, "Detected", 1, "Tool call would have been denied (monitor)"),
    "input_error": (2, "Denied", 27, "Error", 2, "Tool call denied: the hook could not read its input"),
}
# An expiring exception covered everything the rule matched: allowed, by an approved exception.
EXCEPTION_DISPOSITION = (8, "Approved", "Tool call allowed by an expiring exception")

# Application Lifecycle (class 6002): the company rules' state. (activity_id, activity_name, status_id, status, severity_id)
LIFECYCLE = {
    "rules_delivered": (3, "Start", 1, "Success", 1),
    "rules_expired": (3, "Start", 2, "Failure", 2),
    "policy_error": (99, "Load", 2, "Failure", 3),
}

# ECS event.kind, event.category, event.type, event.outcome per event.
ECS_EVENT = {
    "deny": ("alert", ["intrusion_detection"], ["denied"], "success"),
    "ask": ("alert", ["intrusion_detection"], ["info"], "unknown"),
    "would_deny": ("alert", ["intrusion_detection"], ["allowed"], "success"),
    "input_error": ("event", ["intrusion_detection"], ["denied"], "failure"),
    "policy_error": ("event", ["configuration"], ["info"], "failure"),
    "rules_delivered": ("event", ["configuration"], ["access"], "success"),
    "rules_expired": ("event", ["configuration"], ["info"], "failure"),
    "lookup": ("event", ["configuration"], ["access"], None),  # outcome from error
}
ECS_SEVERITY = {"deny": 3, "ask": 2, "would_deny": 1, "input_error": 2, "policy_error": 3, "rules_delivered": 1, "rules_expired": 2, "lookup": 1}


class Skip(ValueError):
    """A line that cannot be converted."""


def event_of(line: dict) -> str:
    event = line.get("event")
    if event is None and line.get("tool") in SERVER_TOOLS:
        event = "lookup"  # a server line from before schema version 1
    if event not in EVENTS:
        raise Skip("unknown event")
    return event


def epoch_ms(ts: object) -> int:
    if not isinstance(ts, str):
        raise Skip("no time")
    try:
        moment = datetime.fromisoformat(ts[:-1] + "+00:00" if ts.endswith("Z") else ts)
    except ValueError:
        raise Skip("unreadable time") from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return int(moment.timestamp() * 1000)


def iso_utc(ms: int) -> str:
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def uid_of(line: dict, raw: str) -> str:
    """The line's event_id, or for a line without one (before schema version 1), a stable id from its bytes."""
    event_id = line.get("event_id")
    return event_id if isinstance(event_id, str) and event_id else "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def feature_of(line: dict) -> str:
    """The component that wrote the line: the hook's name, else the source (the server, for a line from before
    schema version 1, which had no source)."""
    return line.get("hook") or line.get("source") or ("mcp-server" if line.get("tool") in SERVER_TOOLS else "unknown")


def to_ocsf(line: dict, raw: str) -> dict:
    event = event_of(line)
    time_ms = epoch_ms(line.get("ts"))
    uid = uid_of(line, raw)
    product = {"name": PRODUCT, "vendor_name": VENDOR, "feature": {"name": feature_of(line)}}
    if line.get("release"):
        product["version"] = line["release"]
    out = {
        "time": time_ms,
        "metadata": {"version": OCSF_VERSION, "uid": uid, "original_time": line.get("ts"), "log_name": "catpilot-evidence", "product": product},
        "unmapped": {"catpilot": line},
    }
    actor = {}
    if line.get("host"):
        actor["app_name"] = line["host"]
    if line.get("session_id"):
        actor["session"] = {"uid": line["session_id"]}

    if event in FINDING:
        action_id, action, disposition_id, disposition, severity_id, title = FINDING[event]
        if event == "would_deny" and line.get("exception_id"):
            disposition_id, disposition, title = EXCEPTION_DISPOSITION
        finding = {"uid": uid, "title": f"{title} ({feature_of(line)})"}
        if line.get("rule_id"):
            finding["analytic"] = {"uid": line["rule_id"], "name": line["rule_id"], "type_id": 1, "type": "Rule"}
        elif line.get("label"):
            finding["analytic"] = {"name": line["label"], "type_id": 1, "type": "Rule"}
        if line.get("label"):
            finding["types"] = [line["label"]]
        out["metadata"]["profiles"] = ["security_control"]
        out.update({
            "class_uid": 2004, "class_name": "Detection Finding", "category_uid": 2, "category_name": "Findings",
            "activity_id": 1, "activity_name": "Create", "type_uid": 200401, "type_name": "Detection Finding: Create",
            "action_id": action_id, "action": action, "disposition_id": disposition_id, "disposition": disposition,
            "status_id": 1, "status": "New", "finding_info": finding, "message": finding["title"],
        })
    elif event in LIFECYCLE:
        activity_id, activity_name, status_id, status, severity_id = LIFECYCLE[event]
        app = {"name": PRODUCT + " company rules", "vendor_name": VENDOR, "feature": {"name": feature_of(line)}}
        if line.get("release"):
            app["version"] = line["release"]
        out.update({
            "class_uid": 6002, "class_name": "Application Lifecycle", "category_uid": 6, "category_name": "Application Activity",
            "activity_id": activity_id, "activity_name": activity_name, "type_uid": 600200 + activity_id,
            "type_name": f"Application Lifecycle: {activity_name}", "status_id": status_id, "status": status, "app": app,
            "message": {"rules_delivered": "Company rules delivered at session start", "rules_expired": "Company rules expired at session start",
                        "policy_error": "Company rules could not be loaded"}[event],
        })
        if event == "rules_expired":
            out["status_detail"] = "expired"
        elif event == "policy_error" and line.get("label"):
            out["status_detail"] = line["label"]
    else:  # lookup
        severity_id = 1
        failed = line.get("error") is not None
        tool = line.get("tool") or "unknown"
        out.update({
            "class_uid": 6003, "class_name": "API Activity", "category_uid": 6, "category_name": "Application Activity",
            "activity_id": 2, "activity_name": "Read", "type_uid": 600302, "type_name": "API Activity: Read",
            "api": {"operation": tool, "service": {"name": MCP_SERVICE}},
            # OCSF requires both; the server does not record its caller (EVIDENCE.md §4), so they say so.
            "src_endpoint": {"name": "unknown"},
            "status_id": 2 if failed else 1, "status": "Failure" if failed else "Success",
            "message": f"MCP tool {tool} " + ("refused the call" if failed else "answered"),
        })
        actor.setdefault("app_name", "unknown")
        if failed:
            out["status_detail"] = line["error"]
    out["severity_id"] = severity_id
    out["severity"] = SEVERITY[severity_id]
    if actor:
        out["actor"] = actor
    return out


def to_ecs(line: dict, raw: str) -> dict:
    event = event_of(line)
    time_ms = epoch_ms(line.get("ts"))
    kind, category, types, outcome = ECS_EVENT[event]
    if event == "lookup":
        outcome = "failure" if line.get("error") is not None else "success"
    ecs_event = {
        "id": uid_of(line, raw), "kind": kind, "category": category, "type": types, "action": event,
        "outcome": outcome, "provider": line.get("source") or feature_of(line), "module": "catpilot",
        "dataset": "catpilot.evidence", "severity": ECS_SEVERITY[event],
    }
    observer = {"product": PRODUCT, "vendor": VENDOR, "type": "guardrail"}
    if line.get("release"):
        observer["version"] = line["release"]
    out = {"@timestamp": iso_utc(time_ms), "ecs": {"version": ECS_VERSION}, "event": ecs_event, "observer": observer, "catpilot": line}
    rule = {}
    if line.get("rule_id"):
        rule = {"id": line["rule_id"], "name": line["rule_id"], "ruleset": "company-rules"}
    elif line.get("label") and event in FINDING:
        rule = {"name": line["label"], "ruleset": feature_of(line)}
    if line.get("label") and event in FINDING:
        rule["category"] = line["label"]
    if rule:
        out["rule"] = rule
    if event == "policy_error" and line.get("label"):
        out["error"] = {"code": line["label"]}
    if event == "lookup":
        out["service"] = {"name": MCP_SERVICE}
        if line.get("error") is not None:
            out["error"] = {"code": line["error"]}
    if event == "would_deny" and line.get("exception_id"):
        ecs_event["reason"] = "allowed by an expiring exception"
    return out


CONVERTERS = {"ocsf": to_ocsf, "ecs": to_ecs}


def convert_lines(lines, fmt: str) -> tuple:
    """(converted dicts, number of lines skipped) for an iterable of text lines. Blank lines are ignored."""
    convert = CONVERTERS[fmt]
    out, skipped = [], 0
    for raw in lines:
        raw = raw.rstrip("\r\n")
        if not raw.strip():
            continue
        try:
            line = json.loads(raw)
            if not isinstance(line, dict):
                raise Skip("not an object")
            out.append(convert(line, raw))
        except (ValueError, TypeError):
            skipped += 1
    return out, skipped


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert Catpilot evidence logs to OCSF or ECS JSON lines.")
    parser.add_argument("--format", choices=sorted(CONVERTERS), required=True)
    parser.add_argument("files", nargs="+", help="evidence log files, or - for standard input")
    args = parser.parse_args(argv)
    skipped = 0
    for name in args.files:
        try:
            if name == "-":
                text = sys.stdin.read()
            else:
                text = Path(name).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"{name}: cannot read: {exc.strerror or 'error'}", file=sys.stderr)
            return 2
        converted, file_skipped = convert_lines(text.splitlines(), args.format)
        skipped += file_skipped
        for item in converted:
            sys.stdout.write(json.dumps(item, sort_keys=True) + "\n")
    if skipped:
        print(f"skipped {skipped} line(s) that are not evidence lines", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
