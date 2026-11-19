#!/usr/bin/env python3
"""Check the hash chain of a Catpilot evidence log (docs/spec/EVIDENCE.md §8).

With CATPILOT_EVIDENCE_CHAIN set, each line the writer appends carries prev_sha256, the SHA-256 of the line
before it in the same file. This reads a file and reports where that stops holding: a line edited, deleted,
inserted or moved, or a line without the link after the chain started. It prints the head (the hash of the
last line), so it can be compared with a copy held off the machine: a person who can write the file can also
rewrite the whole chain, or cut lines from its end, and only a head or a line kept elsewhere shows that.

Usage:
    python3 tools/evidence_verify.py ~/.catpilot-guardrails/evidence.jsonl
    python3 tools/evidence_verify.py --expect-head <sha256> evidence.jsonl
    python3 tools/evidence_verify.py --format json evidence.jsonl

Exit status: 0 when every file's chain holds (and matches --expect-head), 1 when one does not, 2 when a file
cannot be read or has no chained line. Prints line numbers, hashes and reasons, never a line's content.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from catpilot_guard.evidence import GENESIS, line_sha256  # noqa: E402

HASH = re.compile(r"[0-9a-f]{64}")


def split_lines(data: bytes) -> list:
    """The file's lines as bytes, as the writer hashes them: split on newline, without a final empty piece."""
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    return lines


def link_of(raw: bytes) -> str | None:
    """The line's prev_sha256 when it is a JSON object with a well-formed one; None otherwise."""
    try:
        value = json.loads(raw.decode("utf-8")).get("prev_sha256")
    except (ValueError, AttributeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, str) and HASH.fullmatch(value) else None


def verify_bytes(data: bytes) -> dict:
    """The chain report for one file's bytes. Line numbers count from 1."""
    lines = split_lines(data)
    hashes = [line_sha256(raw) for raw in lines]
    position = {}
    for number, digest in enumerate(hashes, 1):
        position.setdefault(digest, number)
    links = [link_of(raw) for raw in lines]
    start = next((i for i, link in enumerate(links) if link is not None), None)
    breaks = []
    seen_links = {}
    if start is not None:
        for i in range(start, len(lines)):
            number = i + 1
            link = links[i]
            expected = GENESIS if i == 0 else hashes[i - 1]
            if link is None:
                breaks.append({"line": number, "reason": "unchained",
                               "detail": "no prev_sha256 after the chain started: the line was edited, is not an evidence line, or a writer without CATPILOT_EVIDENCE_CHAIN wrote it"})
                continue
            if link in seen_links and link != expected:
                breaks.append({"line": number, "reason": "fork",
                               "detail": f"links to the same line as line {seen_links[link]}: two writers without the lock, or an inserted line"})
            elif link != expected:
                earlier = position.get(link)
                if link == GENESIS:
                    detail = "links to the start of a file: lines before it were added, or it was copied from another file"
                elif earlier is not None:
                    detail = f"links to line {earlier}, not the line before it: lines were reordered, or a line was inserted"
                else:
                    detail = "links to a line that is not in the file: the line before it was edited, or lines were deleted"
                breaks.append({"line": number, "reason": "mismatch", "detail": detail})
            seen_links.setdefault(link, number)
    return {
        "lines": len(lines),
        "chained_from": None if start is None else start + 1,
        "unchained_before": len(lines) if start is None else start,
        "head_sha256": hashes[-1] if hashes else None,
        "breaks": breaks,
    }


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check the hash chain of Catpilot evidence logs.")
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--expect-head", metavar="SHA256", help="the head hash kept off this machine; fail when the file's differs")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    if args.expect_head is not None and not HASH.fullmatch(args.expect_head):
        parser.error("--expect-head takes a lowercase SHA-256")
    if args.expect_head is not None and len(args.files) != 1:
        parser.error("--expect-head checks one file")

    status = 0
    reports = {}
    for path in args.files:
        try:
            report = verify_bytes(path.read_bytes())
        except OSError as exc:
            report = {"error": f"cannot read: {exc.strerror or 'error'}"}
            status = max(status, 2)
            reports[str(path)] = report
            continue
        if report["chained_from"] is None:
            report["error"] = "no chained line: set CATPILOT_EVIDENCE_CHAIN=1 on the writers"
            status = max(status, 2)
        elif report["breaks"]:
            status = max(status, 1)
        if args.expect_head is not None:
            report["head_matches"] = report["head_sha256"] == args.expect_head
            if not report["head_matches"]:
                status = max(status, 1)
        reports[str(path)] = report

    if args.format == "json":
        print(json.dumps(reports, indent=2, sort_keys=True))
        return status
    for name, report in reports.items():
        if "lines" not in report:
            print(f"{name}: {report['error']}")
            continue
        verdict = "chain broken" if report["breaks"] else ("chain holds" if report["chained_from"] else report["error"])
        print(f"{name}: {verdict}; {report['lines']} lines, chained from line {report['chained_from']}, head {report['head_sha256']}")
        if report["unchained_before"] and report["chained_from"]:
            print(f"  lines 1-{report['unchained_before']} were written before the chain: line {report['chained_from']} fixes only the line before it, and the others are not covered")
        for item in report["breaks"]:
            print(f"  line {item['line']}: {item['reason']}: {item['detail']}")
        if "head_matches" in report:
            print("  head matches the expected hash" if report["head_matches"] else "  head DIFFERS from the expected hash: lines were cut from the end, or the chain was rewritten")
    if status != 2:
        print("A chain that holds shows only that the file is consistent with itself. Compare the head with a copy kept off this machine.")
    return status


if __name__ == "__main__":
    sys.exit(main())
