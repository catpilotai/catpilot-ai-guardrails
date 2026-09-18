"""Functional completion in an isolated, disposable container.

Scenario authors supply trusted test commands and expected outputs. Generated
programs never execute on the evaluator's host. Images must be digest-pinned
and already installed; this module never pulls an image or enables networking.
Legacy filename/substring checks remain artifact observations, not completion.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath

VERSION = "functional-completion-2"
IMAGE_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[0-9a-f]{64}$")
SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__"}
MAX_BYTES = 20_000_000
MAX_FILES = 2000
MAX_ENTRIES = 4000
MAX_OUTPUT = 200_000


def relative_path(value: object) -> bool:
    return isinstance(value, str) and bool(value) and "\x00" not in value and not PurePosixPath(value).is_absolute() and ".." not in PurePosixPath(value).parts and "\\" not in value and PurePosixPath(value).as_posix() != "."


def _valid_json(value: object) -> bool:
    if value is None or type(value) in (str, bool, int):
        return True
    if type(value) is float:
        return math.isfinite(value)
    if isinstance(value, list):
        return all(_valid_json(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _valid_json(item) for key, item in value.items())
    return False


def _json_equal(actual: object, expected: object) -> bool:
    """JSON structural equality without Python's bool/number equivalence."""
    if isinstance(actual, bool) or isinstance(expected, bool):
        return type(actual) is type(expected) and actual == expected
    if isinstance(actual, dict) and isinstance(expected, dict):
        return actual.keys() == expected.keys() and all(_json_equal(actual[key], expected[key]) for key in actual)
    if isinstance(actual, list) and isinstance(expected, list):
        return len(actual) == len(expected) and all(_json_equal(a, e) for a, e in zip(actual, expected))
    return actual == expected


def validate(spec: dict, *, require_functional: bool = False) -> list[str]:
    errors = []
    for field in ("file_exists", "file_glob"):
        if field in spec and not relative_path(spec[field]):
            errors.append(f"completion.{field} must stay inside the project")
    functional = spec.get("functional")
    if functional is None:
        return errors + (["completion.functional is required for a new benchmark"] if require_functional else [])
    if not isinstance(functional, dict):
        return errors + ["completion.functional must be a mapping"]
    if not IMAGE_RE.fullmatch(str(functional.get("image", ""))):
        errors.append("completion.functional.image must use an immutable @sha256 digest")
    timeout = functional.get("timeout_seconds", 10)
    if type(timeout) is not int or not 1 <= timeout <= 60:
        errors.append("completion.functional.timeout_seconds must be an integer from 1 to 60")
    cases = functional.get("cases")
    if not isinstance(cases, list) or not cases:
        return errors + ["completion.functional.cases must be a nonempty list"]
    names = set()
    for i, case in enumerate(cases):
        where = f"completion.functional.cases[{i}]"
        if not isinstance(case, dict):
            errors.append(f"{where} must be a mapping")
            continue
        if "name" in case:
            name = case["name"]
            if not isinstance(name, str) or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", name):
                errors.append(f"{where}.name must be lowercase words joined by hyphens")
            elif name in names:
                errors.append(f"{where}.name must be unique: {name}")
            else:
                names.add(name)
        argv = case.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(x, str) and x and "\x00" not in x for x in argv):
            errors.append(f"{where}.argv must be a nonempty list of strings")
        if ("stdout" in case) == ("stdout_json" in case):
            errors.append(f"{where} must specify exactly one of stdout or stdout_json")
        if "stdout" in case and not isinstance(case["stdout"], str):
            errors.append(f"{where}.stdout must be a string")
        if "stdout_json" in case and not _valid_json(case["stdout_json"]):
            errors.append(f"{where}.stdout_json must be a JSON value with string keys and finite numbers")
        if not isinstance(case.get("stdin", ""), str):
            errors.append(f"{where}.stdin must be a string")
        elif len(case.get("stdin", "").encode("utf-8")) > MAX_BYTES:
            errors.append(f"{where}.stdin exceeds the input size limit")
        if type(case.get("exit_code", 0)) is not int:
            errors.append(f"{where}.exit_code must be an integer")
        inputs = case.get("files", {})
        if not isinstance(inputs, dict) or any(not relative_path(p) or not isinstance(t, str) for p, t in inputs.items()):
            errors.append(f"{where}.files must map relative paths to text")
        else:
            if len(inputs) > MAX_FILES or sum(len(text.encode("utf-8")) for text in inputs.values()) > MAX_BYTES:
                errors.append(f"{where}.files exceeds the input size limit")
            input_entries = set()
            for path in inputs:
                input_entries.add(PurePosixPath(path))
                input_entries.update(PurePosixPath(path).parents)
                if len(input_entries) > MAX_ENTRIES:
                    errors.append(f"{where}.files exceeds the entry limit")
                    break
                exact = spec.get("file_exists")
                pattern = spec.get("file_glob")
                if (isinstance(exact, str) and PurePosixPath(path) == PurePosixPath(exact)) or (isinstance(pattern, str) and pattern and PurePosixPath(path).match(pattern)):
                    errors.append(f"{where}.files must not overwrite the completion artifact: {path}")
    return errors


def preflight(spec: dict) -> list[str]:
    errors = validate(spec, require_functional=True)
    if errors:
        return errors
    try:
        result = subprocess.run(["docker", "image", "inspect", spec["functional"]["image"]], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError) as exc:
        return [f"functional verifier unavailable: {exc}"]
    return [] if result.returncode == 0 else ["functional verifier requires a running Docker daemon and the pinned image installed locally"]


def _copy_project(project: Path, destination: Path) -> tuple[int, int]:
    """Stream a bounded regular-file snapshot without following symlinks.

    Directory descriptors keep traversal anchored even if a source path is
    renamed while being inspected. O_NOFOLLOW closes the final-component
    symlink race; fstat checks the object actually opened before copying.
    The resulting host snapshot is mounted read-only in the verifier.
    """
    count = total = entries = 0
    destination.mkdir(parents=True, exist_ok=True)
    destination.chmod(0o755)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW

    def copy_directory(source_fd: int, target_dir: Path, relative: PurePosixPath) -> None:
        nonlocal count, total, entries
        with os.scandir(source_fd) as children:
            for child in children:
                entries += 1
                if entries > MAX_ENTRIES:
                    raise ValueError("functional verifier project entry limit exceeded")
                if child.name in SKIP_DIRS:
                    continue
                rel = relative / child.name
                metadata = os.stat(child.name, dir_fd=source_fd, follow_symlinks=False)
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError(f"cannot verify a project containing a symlink: {rel}")
                target = target_dir / child.name
                if stat.S_ISDIR(metadata.st_mode):
                    target.mkdir(mode=0o755)
                    nested_fd = os.open(child.name, directory_flags, dir_fd=source_fd)
                    try:
                        copy_directory(nested_fd, target, rel)
                    finally:
                        os.close(nested_fd)
                    continue
                if not stat.S_ISREG(metadata.st_mode):
                    raise ValueError(f"cannot verify non-regular file: {rel}")
                count += 1
                if count > MAX_FILES or total + metadata.st_size > MAX_BYTES:
                    raise ValueError("functional verifier project size limit exceeded")
                file_fd = os.open(child.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=source_fd)
                with os.fdopen(file_fd, "rb") as source:
                    opened = os.fstat(source.fileno())
                    if not stat.S_ISREG(opened.st_mode):
                        raise ValueError(f"cannot verify non-regular file: {rel}")
                    with target.open("wb") as output:
                        while True:
                            chunk = source.read(min(65536, MAX_BYTES - total + 1))
                            if not chunk:
                                break
                            total += len(chunk)
                            if total > MAX_BYTES:
                                raise ValueError("functional verifier project size limit exceeded")
                            output.write(chunk)
                    target.chmod(0o755 if opened.st_mode & 0o111 else 0o644)

    root_fd = os.open(project, directory_flags)
    try:
        copy_directory(root_fd, destination, PurePosixPath("."))
    finally:
        os.close(root_fd)
    return count, total


# Python is part of the trusted, digest-pinned verifier image. -I -S prevents
# candidate modules/site customizations from running before this bootstrap
# imports its standard library. Candidate files never become host-writable
# mounts: only the bounded tmpfs copy is writable during the test.
BOOTSTRAP = (
    "import os, shutil, sys; "
    "shutil.copytree('/input', '/workspace/project'); "
    "os.chdir('/workspace/project'); "
    "os.execvp(sys.argv[1], sys.argv[1:])"
)


def _capture_bounded(command: list[str], stdin: bytes, timeout: float) -> dict:
    """Capture at most MAX_OUTPUT bytes per stream, killing on overflow.

    Pipes are drained incrementally without unbounded communicate() buffers
    or disk spool files. Input is likewise written incrementally, avoiding a
    deadlock when a candidate writes before consuming stdin.
    """
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    captured = {"stdout": bytearray(), "stderr": bytearray()}
    timed_out = output_limit_exceeded = False
    input_offset = 0
    deadline = time.monotonic() + timeout
    try:
        with selectors.DefaultSelector() as streams:
            for label, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                streams.register(stream, selectors.EVENT_READ, label)
            if stdin:
                os.set_blocking(process.stdin.fileno(), False)
                streams.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            while streams.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    timed_out = True
                    break
                for key, _mask in streams.select(min(remaining, 0.1)):
                    stream, label = key.fileobj, key.data
                    if label == "stdin":
                        try:
                            input_offset += os.write(stream.fileno(), stdin[input_offset:input_offset + 65536])
                        except BlockingIOError:
                            continue
                        except BrokenPipeError:
                            input_offset = len(stdin)
                        if input_offset == len(stdin):
                            streams.unregister(stream)
                            stream.close()
                        continue
                    try:
                        chunk = os.read(stream.fileno(), min(65536, MAX_OUTPUT - len(captured[label]) + 1))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        streams.unregister(stream)
                        stream.close()
                        continue
                    room = MAX_OUTPUT - len(captured[label])
                    captured[label].extend(chunk[:room])
                    if len(chunk) > room:
                        output_limit_exceeded = True
                        break
                if output_limit_exceeded:
                    break
        if timed_out or output_limit_exceeded:
            process.kill()
        try:
            process.wait(timeout=max(0.1, deadline - time.monotonic()) if not (timed_out or output_limit_exceeded) else 5)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            process.wait(timeout=5)
        return {
            "returncode": process.returncode,
            "stdout": bytes(captured["stdout"]), "stderr": bytes(captured["stderr"]),
            "timed_out": timed_out, "output_limit_exceeded": output_limit_exceeded,
        }
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream and not stream.closed:
                stream.close()


def _remove_container(name: str) -> None:
    """Stop the container even when the attached Docker client was killed."""
    subprocess.run(["docker", "rm", "--force", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)


def run_case(project: Path, functional: dict, case: dict) -> dict:
    name = "catpilot-verify-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="catpilot-verify-") as temporary:
        workspace = Path(temporary) / "input"
        count, total = _copy_project(project, workspace)
        for rel, text in case.get("files", {}).items():
            if not relative_path(rel):
                raise ValueError("functional case input path leaves the project")
            target = workspace / rel
            encoded = text.encode("utf-8")
            previous_size = target.stat().st_size if target.is_file() else 0
            total += len(encoded) - previous_size
            count += not target.exists()
            if total > MAX_BYTES or count > MAX_FILES:
                raise ValueError("functional verifier combined input size limit exceeded")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(encoded)
            target.chmod(0o644)
        command = [
            "docker", "run", "--rm", "--pull=never", "--name", name,
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=64",
            "--memory=256m", "--cpus=1", "--user=65534:65534",
            "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=32m,nr_inodes=1024",
            "--tmpfs", "/workspace:rw,nosuid,nodev,size=64m,nr_inodes=4096,mode=1777",
            "--workdir", "/workspace",
            "--mount", f"type=bind,src={workspace},dst=/input,readonly",
            "--entrypoint", "python3", "--interactive", functional["image"],
            "-I", "-S", "-c", BOOTSTRAP, *case["argv"],
        ]
        try:
            captured = _capture_bounded(command, case.get("stdin", "").encode(), functional.get("timeout_seconds", 10))
            output = captured["stdout"].decode("utf-8", errors="replace")
            error = captured["stderr"].decode("utf-8", errors="replace")
            if captured["timed_out"] or captured["output_limit_exceeded"]:
                return {"verified": True, "passed": False, "reason": "functional case timed out" if captured["timed_out"] else "functional case output limit exceeded",
                        "stdout": output, "stderr": error, "output_truncated": captured["output_limit_exceeded"]}
            if "stdout_json" in case:
                try:
                    actual = json.loads(output)
                    matches = _valid_json(actual) and _json_equal(actual, case["stdout_json"])
                except (ValueError, TypeError):
                    matches = False
            else:
                matches = output == case["stdout"]
            # 125 is Docker failure; 126/127 can mean unavailable bootstrap.
            # Treat them conservatively as infrastructure, not candidate failure.
            verified = captured["returncode"] not in (125, 126, 127)
            return {"verified": verified, "passed": verified and captured["returncode"] == case.get("exit_code", 0) and matches,
                    "exit_code": captured["returncode"], "stdout": output, "stderr": error, "output_truncated": False}
        finally:
            _remove_container(name)


def evaluate(project: Path, spec: dict, artifact: dict) -> dict:
    result = {**artifact, "artifact_matches": bool(artifact.get("passed")), "passed": False,
              "verified": False, "verification_version": VERSION, "cases": []}
    errors = validate(spec)
    if errors:
        return {**result, "reason": "; ".join(errors)}
    if "functional" not in spec:
        return {**result, "reason": "legacy text-only completion check; functionality unverified"}
    if not artifact.get("passed"):
        return {**result, "verified": True, "reason": "required artifact missing or does not match"}
    errors = preflight(spec)
    if errors:
        return {**result, "reason": "; ".join(errors)}
    try:
        cases = [{**run_case(project, spec["functional"], case),
                  **({"name": case["name"]} if "name" in case else {})}
                 for case in spec["functional"]["cases"]]
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        return {**result, "reason": f"functional verification unavailable: {exc}"}
    return {**result, "cases": cases, "verified": all(c["verified"] for c in cases),
            "passed": all(c["verified"] and c["passed"] for c in cases), "image": spec["functional"]["image"]}
