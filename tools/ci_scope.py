"""Decide how much of the baseline workflow a pull request needs. Standard library only.

A pull request that changes only documentation runs the test modules that name a changed file (spell its
path as a string or a chain such as ROOT / "docs" / "X.md"), not the
whole unit suite or the Windows jobs. Everything else runs in full: every push to main, every manual run,
any pull request that touches code, configuration, skills, build inputs or evaluation fixtures, and any
case this script cannot decide (git fails, the diff is empty). A docs-only run that misses a test is
caught by the full run on main after the merge.

Run from the repository root in a GitHub Actions checkout with `fetch-depth: 2`. A pull_request run
checks out GitHub's merge commit, whose first parent is the base branch, so `HEAD^1..HEAD` is exactly what
the pull request changes. Writes `docs_only` (`true` or `false`) and `tests` (space-separated module
names) to `$GITHUB_OUTPUT` when it is set, and prints the decision either way.
"""

import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Markdown under these is a build input, a packaged skill or a test fixture, never just documentation.
NOT_DOCS_PREFIXES = ("src/", "skills/", "dist/", "frameworks/", ".github/", "evals/")
# Exceptions inside evals/: prose only, read by no tool.
EVALS_DOCS = frozenset({"evals/BENCHMARK.md", "evals/HOST_VERIFICATION.md"})
# Root Markdown a script reads (setup.sh copies it into projects).
NOT_DOCS_FILES = frozenset({"FULL_GUARDRAILS.md"})

TEST_MODULE = re.compile(r"^test_\w+$")


def is_doc(path):
    """True for a Markdown file that only people read."""
    if not path.endswith(".md") or path in NOT_DOCS_FILES:
        return False
    if path.startswith("evals/"):
        return path in EVALS_DOCS or path.rsplit("/", 1)[-1] == "README.md"
    return not path.startswith(NOT_DOCS_PREFIXES)


def is_docs_only(paths):
    """True only for a non-empty change made entirely of documentation."""
    return bool(paths) and all(is_doc(p) for p in paths)


QUOTED = re.compile(r"""(["'])([^"'\n]*)\1""")
JOIN = re.compile(r"\s*/\s*$")


def named_paths(text):
    """Every path a module spells: a string ("docs/X.md") or a chain of strings (ROOT / "docs" / "X.md"),
    with the strings it contains, for the looser match in names()."""
    runs, strings, last_end = [], set(), None
    for m in QUOTED.finditer(text):
        strings.add(m.group(2))
        if last_end is not None and JOIN.match(text[last_end:m.start()]):
            runs[-1].append(m.group(2))
        else:
            runs.append([m.group(2)])
        last_end = m.end()
    return {"/".join(r) for r in runs}, strings


def names(path, spelled, strings):
    """True when a module names this repository path: spelled in full, or by file name in a module that also
    names the file's top directory (DOCS = ROOT / "docs", then DOCS / "X.md")."""
    if path in spelled:
        return True
    if "/" not in path:
        return False
    top, base = path.split("/", 1)[0], path.rsplit("/", 1)[-1]
    return base in spelled and top in strings


def tests_for(paths, tests_dir):
    """Test modules that name a changed file."""
    found = []
    for module in sorted(Path(tests_dir).glob("test_*.py")):
        if not TEST_MODULE.match(module.stem):
            continue
        spelled, strings = named_paths(module.read_text(encoding="utf-8", errors="replace"))
        if any(names(p, spelled, strings) for p in paths):
            found.append(module.stem)
    return found


def changed_files(cwd=ROOT):
    """Paths the pull request changes, both sides of a rename. None when git cannot say."""
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", "--no-renames", "HEAD^1", "HEAD"],
            cwd=str(cwd), capture_output=True, text=True, timeout=60, check=True,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return [line.strip() for line in out.splitlines() if line.strip()]


def decide(event, paths, tests_dir):
    """(docs_only, tests). Anything but a pull request with a known, docs-only diff runs in full."""
    if event != "pull_request" or paths is None or not is_docs_only(paths):
        return False, []
    return True, tests_for(paths, tests_dir)


def main():
    event = os.environ.get("GITHUB_EVENT_NAME", "")
    paths = changed_files() if event == "pull_request" else None
    docs_only, tests = decide(event, paths, ROOT / "tests")
    print(f"event: {event or '(none)'}")
    print("changed: " + (", ".join(paths) if paths else "(not computed)"))
    print("scope: " + ("docs only; tests: " + (" ".join(tests) or "(none name a changed file)") if docs_only else "full"))
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as fh:
            fh.write(f"docs_only={'true' if docs_only else 'false'}\n")
            fh.write(f"tests={' '.join(tests)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
