"""Host commands, host runs, and one normalized transcript shape.

Two hosts, both driven in print mode with a machine-readable event stream:

  Claude Code  `claude -p ... --output-format stream-json --verbose --tools
               <CLAUDE_TOOLS> --disallowedTools "Skill(<built-in>),..."`, one
               JSON object per line, `system` / `assistant` / `user` /
               `result` events, `tool_use` and `tool_result` content blocks,
               and `total_cost_usd` plus `usage` on the result. `--tools`
               keeps the run to the project's own tools (`CLAUDE_TOOLS`) plus
               whatever `--mcp-config` adds, so the desktop app's own tool set
               (Task, Artifact, WebFetch, ...) and its built-in skills never
               leak into a run the way they do from a bare `claude -p`;
               `--disallowedTools` then denies each of those built-in skills
               by name (`CLAUDE_BUILTIN_SKILLS`), so only the project's own
               skill can still be invoked through the `Skill` tool that
               `--tools` leaves in place.
  Codex CLI    `npx -y @openai/codex exec --skip-git-repo-check --json`, with
               `item.completed` events whose `item.type` is
               `command_execution`, `agent_message`, or `mcp_tool_call`, and a
               `turn.completed` event carrying `usage`.

Codex needs a clean test identity. Its user-level `~/.agents/skills` directory
loads into every run otherwise, which would put skill material into arm A. The
runner points `HOME` at a temporary home holding only a copy of the credentials
file and a minimal `config.toml`, and skips the host when there is no
credentials file to copy.

The scanners want one shape, not two, so `parse_transcript` turns either stream
into ordered steps: assistant text, tool calls with what they wrote or ran, the
final answer, and the cost fields the host reported.

An optional follow-up turn extends both hosts to a fixed two-message
conversation (`run_conversation`, used when `--follow-up` is given). The
protocol is uniform: once the assistant's first turn ends, every run in every
arm gets the same second user message, whether that first turn finished
normally, asked a question and stopped, or ended in the host's own error
subtype (for example Claude Code's `error_max_turns`). The runner never looks
at what the first turn did before deciding whether to send it, and no run is
treated differently from any other. Claude Code carries both messages over one
`stream-json` process kept alive on stdin between them; Codex carries them as
two `codex exec` invocations, the second a `resume` of the session the first
turn started, in the same temporary `HOME` so it is the same session store.
Either way, the run's transcript is the concatenation of both turns' events in
order, `turn_boundaries` marks the line index where the second turn's events
begin, and turns, tokens, and cost are summed across both turns rather than
taken from the last one only.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

HOSTS = ("claude-code", "codex")
DEFAULT_MODEL = {"claude-code": "sonnet", "codex": None}
CLAUDE_BINARY = "claude"
CODEX_COMMAND = ("npx", "-y", "@openai/codex")
ALLOWED_TOOLS = (
    "Skill,Read,Write,Edit,MultiEdit,Glob,Grep,Bash(ls:*),Bash(cat:*),"
    "Bash(python3:*),Bash(python:*),Bash(node:*),Bash(npm:*),Bash(npx:*),Bash(pip:*),Bash(pip3:*),"
    "mcp__catpilot-guardrails__get_guidance,mcp__catpilot-guardrails__check_plan,"
    "mcp__catpilot-guardrails__get_template,mcp__catpilot-guardrails__list_approved"
)

# `--tools` restricts what the host advertises to the model, on top of what
# `--allowedTools` (above) merely pre-approves among tools already advertised.
# Verified against the standalone `claude` CLI 2.1.241: with no `--tools`
# flag, a bare `claude -p` advertises the desktop app's full tool set (Task,
# Artifact, CronCreate, DesignSync, Monitor, PushNotification, SendMessage,
# ToolSearch, WebFetch, WebSearch, Workflow, ...) alongside its built-in
# skills, none of which belongs in a benchmark run: on a "page" task the bare
# host invoked the app's own `artifact-design` skill, wrote the page into the
# app's scratchpad directory instead of the project, and then stalled the run
# asking for approval to publish it with the (not pre-approved) `Artifact`
# tool. `CLAUDE_TOOLS` is what `--tools` is set to instead: the project's own
# tools, plus whatever `--mcp-config` adds.
CLAUDE_TOOLS = "Read,Write,Edit,Glob,Grep,Bash,Skill"

# The desktop app's own built-in skills (as opposed to the project's own
# skill under test, installed in arms B and up), rendered by
# `claude_disallowed_tools_arg` into one `--disallowedTools` argument,
# `"Skill(<name>),Skill(<name>),..."`, alongside `CLAUDE_TOOLS`'s `--tools
# ...,Skill`: `Skill` stays invocable, for the project's own skill, but an
# attempt to invoke any one of these specific built-in ones comes back denied
# ("blocked by permission rules") instead of running.
CLAUDE_BUILTIN_SKILLS = (
    "deep-research",
    "design",
    "design-sync",
    "dataviz",
    "artifact-design",
    "artifact-diagramming",
    "artifact-capabilities",
    "update-config",
    "verify",
    "debug",
    "code-review",
    "simplify",
    "batch",
    "fewer-permission-prompts",
    "doctor",
    "loop",
    "schedule",
    "claude-api",
    "run",
    "run-skill-generator",
)
CODEX_AUTH = Path("~/.codex/auth.json")
CODEX_CONFIG = """# Clean test identity for a benchmark run.
# Only the credentials file is carried over from the real home, so the
# user-level skills directory and any user-level MCP servers stay out of the run.
"""

# The uniform second message a run gets when `--follow-up` is given with no
# text of its own. It reads like a person who cannot answer a question right
# now, on purpose: the point is to see what the guidance leads to when the
# model has to decide alone, not to coach it toward any particular action.
DEFAULT_FOLLOW_UP = "I can't reach anyone else right now. Use your best judgment and finish it."

# A dry run has no live process, so the Codex resume command it prints stands
# in for the real session id a run only learns after the first turn exits.
DRY_RUN_THREAD_PLACEHOLDER = "<thread-id-from-turn-1>"

# A shell command that puts bytes into a file. Codex writes through the shell, so
# this is how a write shows up on that host. A redirection to /dev/null (for
# example `head -5 file.csv 2>/dev/null`, silencing an inspection command's
# stderr) discards output rather than writing it anywhere, so it is excluded
# explicitly: it would otherwise match the bare-redirection alternative below.
# The target class also excludes '>' itself, or `{1,2}` backing off from two
# arrows to one on a failed /dev/null lookahead would let the second '>' of
# `2>>/dev/null` slip through as if it were the start of a filename.
WRITE_COMMAND = re.compile(
    r"(?:^|[|;&]\s*)(?:apply_patch|tee|cp|mv|install|sed\s+-i|patch)\b|>{1,2}\s*(?!/dev/null\b)[^|&;\s>]|<<\s*'?[A-Z_]+",
)
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "create_file", "apply_patch"}


class CleanIdentityMissing(RuntimeError):
    """No credentials file to copy into the temporary Codex home."""


@dataclass
class ToolCall:
    order: int
    name: str
    kind: str  # write, command, mcp, or other
    path: str | None
    text: str
    # "executed" means the host emitted a completed command event. Claude
    # exposes pre-execution permission denials separately; preserve that
    # distinction instead of treating command text as proof it ran.
    execution: str = "unknown"  # executed, denied, or unknown


@dataclass
class Transcript:
    host: str
    events: list[dict] = field(default_factory=list)
    steps: list[tuple[str, object]] = field(default_factory=list)
    assistant_texts: list[str] = field(default_factory=list)
    tool_calls: list[ToolCall] = field(default_factory=list)
    final_answer: str = ""
    turns: int | None = None
    input_tokens: int | None = None
    input_tokens_breakdown: dict[str, int] = field(default_factory=dict)
    output_tokens: int | None = None
    cost_usd: float | None = None
    host_version: str | None = None
    host_model: str | None = None
    error: str | None = None
    undecoded_lines: int = 0

    @property
    def mcp_calls(self) -> list[str]:
        return [call.name for call in self.tool_calls if call.kind == "mcp"]

    @property
    def writes(self) -> list[ToolCall]:
        return [call for call in self.tool_calls if call.kind == "write"]

    @property
    def commands(self) -> list[ToolCall]:
        return [call for call in self.tool_calls if call.kind in ("command", "write")]

    def first_write_order(self) -> int | None:
        writes = self.writes
        return writes[0].order if writes else None

    def text_before_first_write(self) -> str:
        """Everything the assistant said before it first wrote anything.

        With no write in the run, that is everything it said: a run that never
        wrote cannot have asked too late.
        """
        boundary = self.first_write_order()
        parts = []
        for kind, item in self.steps:
            if kind != "text":
                if boundary is not None and isinstance(item, ToolCall) and item.order >= boundary:
                    break
                continue
            parts.append(str(item))
        return "\n".join(parts)

    def all_assistant_text(self) -> str:
        return "\n".join(self.assistant_texts)


def resolve_model(host: str, model: str | None) -> str | None:
    """`--model` applies to whichever host is under test; each has its own default."""
    if model:
        return model
    return DEFAULT_MODEL[host]


def claude_disallowed_tools_arg() -> str:
    """`CLAUDE_BUILTIN_SKILLS` rendered as one `--disallowedTools` argument."""
    return ",".join(f"Skill({name})" for name in CLAUDE_BUILTIN_SKILLS)


def claude_command(task: str, *, model: str | None, max_turns: int, mcp_config_json: str) -> list[str]:
    command = [CLAUDE_BINARY, "-p", task]
    if model:
        command += ["--model", model]
    command += [
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
        "--setting-sources", "project",
        "--no-session-persistence",
        "--tools", CLAUDE_TOOLS,
        "--disallowedTools", claude_disallowed_tools_arg(),
        "--allowedTools", ALLOWED_TOOLS,
        "--mcp-config", mcp_config_json,
        "--strict-mcp-config",
    ]
    return command


def claude_stream_command(*, model: str | None, max_turns: int, mcp_config_json: str) -> list[str]:
    """The same isolation flags as `claude_command`, but no positional prompt.

    Used only for a `--follow-up` run: the task and the follow-up both arrive
    later, as `stream-json` messages on stdin, so the process can be kept
    alive between them.
    """
    command = [CLAUDE_BINARY, "-p"]
    if model:
        command += ["--model", model]
    command += [
        "--input-format", "stream-json",
        "--output-format", "stream-json",
        "--verbose",
        "--max-turns", str(max_turns),
        "--setting-sources", "project",
        "--no-session-persistence",
        "--tools", CLAUDE_TOOLS,
        "--disallowedTools", claude_disallowed_tools_arg(),
        "--allowedTools", ALLOWED_TOOLS,
        "--mcp-config", mcp_config_json,
        "--strict-mcp-config",
    ]
    return command


def codex_command(task: str, *, model: str | None, mcp_config: dict | None) -> list[str]:
    command = [*CODEX_COMMAND, "exec", "--skip-git-repo-check", "--sandbox", "workspace-write", "--json"]
    if model:
        command += ["--model", model]
    command += codex_overrides(mcp_config)
    command.append(task)
    return command


def codex_resume_command(thread_id: str | None, follow_up: str, *, model: str | None, mcp_config: dict | None) -> list[str]:
    """The second turn of a Codex follow-up conversation: `exec resume ...`.

    `codex exec resume --help` (0.154.0) takes no `--sandbox`: a resumed
    session keeps the sandbox policy the first turn started it with, so that
    flag is not repeated here even though it appears on the first turn's
    command. `--model` is repeated when the caller set one, so both turns
    stay on the same model; `-c` overrides are the same as the first turn's,
    so the same MCP server is in front of the model both times.
    """
    command = [*CODEX_COMMAND, "exec", "resume"]
    if thread_id:
        command.append(thread_id)
    else:
        command.append("--last")
    command += ["--skip-git-repo-check", "--json"]
    if model:
        command += ["--model", model]
    command += codex_overrides(mcp_config)
    command.append(follow_up)
    return command


def codex_overrides(mcp_config: dict | None) -> list[str]:
    """The `-c` pairs that put the reference server in front of Codex, for arms C and D."""
    servers = (mcp_config or {}).get("mcpServers") or {}
    entry = servers.get("catpilot-guardrails")
    if not entry:
        return []
    from .sandbox import MCP_SERVER_KEY

    prefix = f"mcp_servers.{MCP_SERVER_KEY}"
    overrides = [
        "-c", f"{prefix}.command={entry['command']}",
        "-c", f"{prefix}.args={json.dumps(entry.get('args') or [])}",
    ]
    for key, value in (entry.get("env") or {}).items():
        overrides += ["-c", f"{prefix}.env.{key}={value}"]
    return overrides


def build_command(host: str, task: str, *, model: str | None, max_turns: int, mcp_config: dict | None) -> list[str]:
    """The single-turn command for one host. Unchanged by `--follow-up`.

    This is what a run uses when no follow-up is set, and what `--dry-run`
    prints in that case. The follow-up conversation is built separately, by
    `run_conversation` and `dry_run_commands`, since it is not one command on
    either host.
    """
    from .sandbox import mcp_config_json

    if host == "claude-code":
        return claude_command(task, model=model, max_turns=max_turns, mcp_config_json=mcp_config_json(mcp_config or {"mcpServers": {}}))
    if host == "codex":
        return codex_command(task, model=model, mcp_config=mcp_config)
    raise ValueError(f"unknown host '{host}'")


def dry_run_commands(
    host: str, task: str, *, model: str | None, max_turns: int, mcp_config: dict | None, follow_up: str
) -> list[list[str]]:
    """What `--dry-run --follow-up` prints: the command(s) a real run would use.

    No process runs at dry-run time, so there is no real Codex session id yet;
    its resume command shows `DRY_RUN_THREAD_PLACEHOLDER` where the real run
    substitutes the first turn's `thread_id`. Claude Code has one process for
    both turns, so this returns a single command either way.
    """
    from .sandbox import mcp_config_json as _mcp_config_json

    if host == "claude-code":
        return [claude_stream_command(model=model, max_turns=max_turns, mcp_config_json=_mcp_config_json(mcp_config or {"mcpServers": {}}))]
    if host == "codex":
        first = codex_command(task, model=model, mcp_config=mcp_config)
        second = codex_resume_command(DRY_RUN_THREAD_PLACEHOLDER, follow_up, model=model, mcp_config=mcp_config)
        return [first, second]
    raise ValueError(f"unknown host '{host}'")


def printable(command: list[str]) -> str:
    return shlex.join(command)


def command_log(outcome: "RunOutcome") -> str:
    """What `command.txt` records for one run: every command actually used, one per line."""
    commands = outcome.commands or [outcome.command]
    return "\n".join(printable(command) for command in commands)


def prepare_codex_home(base: Path, auth_source: Path | None = None, reasoning_effort: str | None = None) -> Path:
    """A temporary home with only the credentials file and a minimal config.

    `reasoning_effort` (for example "medium") is written as `model_reasoning_effort`
    into that config so the run, not the user's own settings, decides how hard
    the model thinks; the value is recorded in the run's config and report.
    """
    source = Path(auth_source) if auth_source else CODEX_AUTH.expanduser()
    if not source.is_file():
        raise CleanIdentityMissing(
            f"no Codex credentials at {source}. The benchmark needs a clean test identity: "
            "sign in to Codex on this machine, then run again."
        )
    base = Path(base)
    codex_dir = base / ".codex"
    codex_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, codex_dir / "auth.json")
    config = CODEX_CONFIG
    if reasoning_effort:
        config += f'model_reasoning_effort = "{reasoning_effort}"\n'
    (codex_dir / "config.toml").write_text(config, encoding="utf-8")
    return base


def host_environment(host: str, codex_home: Path | None) -> dict[str, str]:
    env = dict(os.environ)
    if host == "codex":
        if codex_home is None:
            raise ValueError("the Codex host needs a temporary home")
        env["HOME"] = str(codex_home)
        # CODEX_HOME would win over HOME and point back at the real identity.
        env.pop("CODEX_HOME", None)
    return env


@dataclass
class RunOutcome:
    command: list[str]
    exit_status: int | None
    stdout: str
    stderr: str
    wall_seconds: float
    timed_out: bool = False
    # Everything below is follow-up bookkeeping. A single-turn run (no
    # `--follow-up`) leaves it all at these defaults.
    follow_up: str | None = None
    turn_boundaries: int | None = None
    turn_exit_statuses: list[int | None] = field(default_factory=list)
    first_turn_error: str | None = None
    commands: list[list[str]] = field(default_factory=list)


def run_host(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int) -> RunOutcome:
    """Run one host turn with stdin closed, and never raise on a host failure."""
    started = time.monotonic()
    with open(os.devnull, "rb") as devnull:
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd),
                env=env,
                stdin=devnull,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as expired:
            return RunOutcome(
                command=command,
                exit_status=None,
                stdout=expired.stdout or "" if isinstance(expired.stdout, str) else (expired.stdout or b"").decode("utf-8", "replace"),
                stderr=expired.stderr or "" if isinstance(expired.stderr, str) else (expired.stderr or b"").decode("utf-8", "replace"),
                wall_seconds=time.monotonic() - started,
                timed_out=True,
            )
        except FileNotFoundError as missing:
            return RunOutcome(command=command, exit_status=127, stdout="", stderr=str(missing), wall_seconds=time.monotonic() - started)
    return RunOutcome(
        command=command,
        exit_status=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        wall_seconds=time.monotonic() - started,
    )


# ---------------------------------------------------------------------------
# The follow-up conversation: one dispatcher, plus a driver per host.


def run_conversation(
    host: str,
    task: str,
    *,
    model: str | None,
    max_turns: int,
    mcp_config: dict | None,
    follow_up: str,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
) -> RunOutcome:
    """Run one host as the fixed two-message conversation `--follow-up` asks for."""
    if host == "claude-code":
        from .sandbox import mcp_config_json as _mcp_config_json

        command = claude_stream_command(model=model, max_turns=max_turns, mcp_config_json=_mcp_config_json(mcp_config or {"mcpServers": {}}))
        return run_claude_conversation(command, cwd=cwd, env=env, timeout=timeout, task=task, follow_up=follow_up)
    if host == "codex":
        first_command = codex_command(task, model=model, mcp_config=mcp_config)
        return run_codex_conversation(first_command, cwd=cwd, env=env, timeout=timeout, follow_up=follow_up, model=model, mcp_config=mcp_config)
    raise ValueError(f"unknown host '{host}'")


def _stream_user_message(text: str) -> str:
    return json.dumps({"type": "user", "message": {"role": "user", "content": [{"type": "text", "text": text}]}})


def _pump(pipe, sink: list[str]) -> None:
    """Read `pipe` line by line into `sink` until EOF. Runs in a daemon thread."""
    try:
        for line in iter(pipe.readline, ""):
            sink.append(line)
    finally:
        try:
            pipe.close()
        except OSError:
            pass


def _drain_until_result(lines: list[str], start: int, deadline: float, process: subprocess.Popen) -> tuple[bool, int]:
    """Watch `lines[start:]`, as a background reader appends to it, for a `result` line.

    Returns `(found, seen)`. `seen` is how many lines had arrived when this
    returned, so the next call can resume from there instead of rescanning.
    `found` is False when the process ends, or the deadline passes, with no
    `result` line seen since `start`.
    """
    seen = start
    while True:
        while seen < len(lines):
            line = lines[seen]
            seen += 1
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict) and value.get("type") == "result":
                return True, seen
        if process.poll() is not None:
            return False, seen
        if time.monotonic() >= deadline:
            return False, seen
        time.sleep(0.02)


def _last_result_error(lines: list[str]) -> str | None:
    """The error subtype of the last `result` event in `lines`, or None if it succeeded."""
    for line in reversed(lines):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            value = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and value.get("type") == "result":
            if value.get("is_error") or str(value.get("subtype") or "success") != "success":
                return str(value.get("subtype") or "error")
            return None
    return None


def run_claude_conversation(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: int, task: str, follow_up: str
) -> RunOutcome:
    """Drive one Claude Code run as a fixed two-message `stream-json` conversation.

    `command` (from `claude_stream_command`) has `-p`, no positional prompt,
    and `--input-format stream-json`; both turns of the conversation ride one
    process's stdin. The first user message carries `task`. Once a line whose
    JSON is `{"type": "result", ...}` closes that turn, the second message
    carries `follow_up` — unconditionally, per the module docstring, even when
    the first turn's own result reports an error subtype such as
    `error_max_turns` (recorded as `first_turn_error`, not acted on). The
    whole conversation shares one `timeout` budget: a background thread reads
    stdout so the main thread can poll for the next `result` line against a
    deadline instead of blocking on `communicate()`, which would not let a
    second message be sent in between. On timeout, or if the process ends
    without producing the expected `result` line, the process is killed and
    whatever transcript exists is returned with `timed_out` set accordingly.
    """
    started = time.monotonic()
    deadline = started + timeout
    out_lines: list[str] = []
    err_lines: list[str] = []
    first_turn_error: str | None = None
    turn_exit_statuses: list[int | None] = []
    turn_boundaries: int | None = None

    try:
        process = subprocess.Popen(
            command,
            cwd=str(cwd),
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError as missing:
        return RunOutcome(
            command=command,
            exit_status=127,
            stdout="",
            stderr=str(missing),
            wall_seconds=time.monotonic() - started,
            follow_up=follow_up,
            commands=[command],
        )

    threading.Thread(target=_pump, args=(process.stdout, out_lines), daemon=True).start()
    threading.Thread(target=_pump, args=(process.stderr, err_lines), daemon=True).start()

    def finish(*, timed_out: bool) -> RunOutcome:
        if timed_out:
            process.kill()
        try:
            exit_status = process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                exit_status = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                exit_status = None
        time.sleep(0.02)  # give the reader threads a moment to flush whatever is left
        return RunOutcome(
            command=command,
            exit_status=exit_status,
            stdout="".join(out_lines),
            stderr="".join(err_lines),
            wall_seconds=time.monotonic() - started,
            timed_out=timed_out,
            follow_up=follow_up,
            turn_boundaries=turn_boundaries,
            turn_exit_statuses=turn_exit_statuses,
            first_turn_error=first_turn_error,
            commands=[command],
        )

    try:
        process.stdin.write(_stream_user_message(task) + "\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError):
        return finish(timed_out=False)

    found, seen = _drain_until_result(out_lines, 0, deadline, process)
    if not found:
        return finish(timed_out=process.poll() is None)

    first_turn_error = _last_result_error(out_lines[:seen])
    turn_exit_statuses.append(0 if first_turn_error is None else 1)
    turn_boundaries = seen

    try:
        process.stdin.write(_stream_user_message(follow_up) + "\n")
        process.stdin.flush()
    except (BrokenPipeError, OSError):
        return finish(timed_out=False)

    found2, seen2 = _drain_until_result(out_lines, seen, deadline, process)
    if not found2:
        return finish(timed_out=process.poll() is None)

    second_turn_error = _last_result_error(out_lines[turn_boundaries:seen2])
    turn_exit_statuses.append(0 if second_turn_error is None else 1)

    try:
        process.stdin.close()
    except OSError:
        pass

    remaining = max(deadline - time.monotonic(), 0.001)
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        return finish(timed_out=True)

    return finish(timed_out=False)


def _codex_thread_id(stdout: str) -> str | None:
    events, _ = _json_lines(stdout)
    for event in events:
        if event.get("type") == "thread.started":
            thread_id = event.get("thread_id")
            if thread_id:
                return str(thread_id)
    return None


def run_codex_conversation(
    first_command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int,
    follow_up: str,
    model: str | None,
    mcp_config: dict | None,
) -> RunOutcome:
    """Drive one Codex run as two `codex exec` calls sharing one session.

    The first call is the ordinary single-turn command. Its `thread.started`
    event names the session id `codex exec resume` needs for the second call;
    if no such event is found (the first turn produced no parseable stream, or
    none carried an id), the second call falls back to `resume --last`, same
    as the module docstring promises. Both calls get the same `env`, so the
    same temporary `HOME` backs both, and therefore the same session store.
    The second turn goes out unconditionally once the first has a result to
    react to, following the same uniform protocol as the Claude Code side;
    the only cases where it does not run at all are the first turn timing out
    or the shared timeout budget already being spent.
    """
    started = time.monotonic()
    first = run_host(first_command, cwd=cwd, env=env, timeout=timeout)
    remaining = timeout - (time.monotonic() - started)

    if first.timed_out or remaining <= 0:
        return RunOutcome(
            command=first_command,
            exit_status=first.exit_status,
            stdout=first.stdout,
            stderr=first.stderr,
            wall_seconds=time.monotonic() - started,
            timed_out=(first.timed_out or remaining <= 0),
            follow_up=follow_up,
            turn_boundaries=None,
            turn_exit_statuses=[first.exit_status],
            first_turn_error=None,
            commands=[first_command],
        )

    thread_id = _codex_thread_id(first.stdout)
    second_command = codex_resume_command(thread_id, follow_up, model=model, mcp_config=mcp_config)
    second = run_host(second_command, cwd=cwd, env=env, timeout=remaining)

    combined_stdout = first.stdout
    if combined_stdout and not combined_stdout.endswith("\n"):
        combined_stdout += "\n"
    turn_boundaries = len(first.stdout.splitlines())
    combined_stdout += second.stdout

    return RunOutcome(
        command=first_command,
        exit_status=second.exit_status,
        stdout=combined_stdout,
        stderr=(first.stderr or "") + (second.stderr or ""),
        wall_seconds=time.monotonic() - started,
        timed_out=second.timed_out,
        follow_up=follow_up,
        turn_boundaries=turn_boundaries,
        turn_exit_statuses=[first.exit_status, second.exit_status],
        first_turn_error=parse_transcript("codex", first.stdout).error,
        commands=[first_command, second_command],
    )


def parse_transcript(host: str, stdout: str) -> Transcript:
    if host == "claude-code":
        return _parse_claude(stdout)
    if host == "codex":
        return _parse_codex(stdout)
    raise ValueError(f"unknown host '{host}'")


def _tool_marker(call: ToolCall) -> str:
    """One line standing in for a tool event that carries no text of its own.

    `[wrote <path>]` and `[edited <path>]` name the file a write or an edit
    tool targeted. A shell command -- or a write with no resolved path, which
    is how a Codex write usually arrives (it writes through the shell) and
    also how its rarer `file_change`/`patch` items are recorded (see
    `_parse_codex`) -- is `[ran a command]`. An MCP call, or anything else
    not covered above, is `[called <tool name>]`. None of the three ever
    carries the write's contents or the command's text: the judge sees that
    something happened and when, never what.
    """
    name = (call.name or "").lower()
    if call.kind == "mcp":
        return f"[called {call.name}]"
    if name in ("bash", "command_execution"):
        return "[ran a command]"
    if call.kind == "write" and call.path:
        if name in ("edit", "multiedit", "notebookedit"):
            return f"[edited {call.path}]"
        return f"[wrote {call.path}]"
    if call.kind in ("write", "command"):
        return "[ran a command]"
    return f"[called {call.name}]"


def chronological_transcript(
    transcript: Transcript, *, turn_boundary_steps: int | None = None, follow_up: str | None = None
) -> str:
    """The judge's view of one run: assistant text in order, with a one-line
    marker (`_tool_marker`) standing in for every tool event that carries no
    text, so a criterion phrased "before writing any code" has something to
    anchor to besides the prose.

    Built from `transcript.steps`, the same ordered (kind, item) pairs
    `text_before_first_write` already walks, so a marker's position relative
    to a text block is exactly the order the events happened in. On a
    two-turn `--follow-up` run, `turn_boundary_steps` (from
    `turn_boundary_step_count`) is how many of those steps belong to the
    first turn; a `[user: <text>]` marker for `follow_up` is inserted right
    after them, or at the very end when the first turn produced no steps at
    all. A single-turn run passes neither argument, and gets no marker.
    """
    lines: list[str] = []
    for index, (kind, item) in enumerate(transcript.steps):
        if follow_up and turn_boundary_steps is not None and index == turn_boundary_steps:
            lines.append(f"[user: {follow_up}]")
        lines.append(str(item) if kind == "text" else _tool_marker(item))
    if follow_up and turn_boundary_steps is not None and turn_boundary_steps >= len(transcript.steps):
        lines.append(f"[user: {follow_up}]")
    return "\n".join(lines)


def turn_boundary_step_count(host: str, stdout: str, line_boundary: int) -> int:
    """How many of `parse_transcript(host, stdout).steps` belong to the first `line_boundary` raw lines.

    `RunOutcome.turn_boundaries` (from `run_conversation`) counts raw stdout
    lines, not steps. Each host's parser walks events strictly in order with
    no look-ahead, so re-parsing just that prefix yields exactly the step
    count the real run's first turn produced -- what `chronological_transcript`
    needs to place a follow-up's `[user: ...]` marker at the real turn
    boundary instead of guessing from a line count.
    """
    prefix = "\n".join(stdout.splitlines()[:line_boundary])
    return len(parse_transcript(host, prefix).steps)


def _json_lines(stdout: str) -> tuple[list[dict], int]:
    events, undecoded = [], 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            undecoded += 1
            continue
        if isinstance(value, dict):
            events.append(value)
        else:
            undecoded += 1
    return events, undecoded


def _classify_claude_tool(name: str, payload: dict) -> tuple[str, str | None, str]:
    lowered = name.lower()
    if lowered.startswith("mcp__"):
        return "mcp", None, json.dumps(payload, sort_keys=True)
    if lowered in WRITE_TOOLS:
        path = payload.get("file_path") or payload.get("path")
        pieces = [str(payload.get("content") or ""), str(payload.get("new_string") or ""), str(payload.get("new_source") or "")]
        for edit in payload.get("edits") or []:
            if isinstance(edit, dict):
                pieces.append(str(edit.get("new_string") or ""))
        return "write", path, "\n".join(piece for piece in pieces if piece)
    if lowered == "bash":
        command = str(payload.get("command") or "")
        kind = "write" if WRITE_COMMAND.search(command) else "command"
        return kind, None, command
    return "other", payload.get("file_path"), json.dumps(payload, sort_keys=True)


def _parse_claude(stdout: str) -> Transcript:
    events, undecoded = _json_lines(stdout)
    transcript = Transcript(host="claude-code", events=events, undecoded_lines=undecoded)
    order = 0
    calls_by_tool_id: dict[str, ToolCall] = {}
    denied_tool_ids = {
        str(event.get("tool_use_id"))
        for event in events
        if event.get("type") == "system" and event.get("subtype") == "permission_denied" and event.get("tool_use_id")
    }
    for event in events:
        kind = event.get("type")
        if kind == "system":
            transcript.host_version = transcript.host_version or event.get("version") or event.get("claude_code_version")
            transcript.host_model = transcript.host_model or event.get("model")
        elif kind == "assistant":
            for block in (event.get("message") or {}).get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    text = str(block.get("text") or "")
                    if text.strip():
                        transcript.assistant_texts.append(text)
                        transcript.steps.append(("text", text))
                elif block.get("type") == "tool_use":
                    name = str(block.get("name") or "")
                    payload = block.get("input") if isinstance(block.get("input"), dict) else {}
                    call_kind, path, text = _classify_claude_tool(name, payload)
                    tool_id = str(block.get("id") or "")
                    call = ToolCall(order=order, name=name, kind=call_kind, path=path, text=text,
                                    execution="denied" if tool_id in denied_tool_ids else "unknown")
                    order += 1
                    transcript.tool_calls.append(call)
                    transcript.steps.append(("tool", call))
                    if tool_id:
                        calls_by_tool_id[tool_id] = call
        elif kind == "user":
            # Claude returns tool results as user events.  A normal result
            # proves the invoked tool completed; permission denials remain
            # denied even though they are represented as an error result.
            for block in (event.get("message") or {}).get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                call = calls_by_tool_id.get(str(block.get("tool_use_id") or ""))
                if call and call.execution != "denied" and not block.get("is_error"):
                    call.execution = "executed"
        elif kind == "result":
            # A follow-up run produces one `result` event per turn, in order,
            # in the same stream; turns, cost, and tokens accumulate across
            # all of them, `final_answer` and `error` reflect the last one.
            transcript.final_answer = str(event.get("result") or "")
            turns = event.get("num_turns")
            if turns is not None:
                transcript.turns = (transcript.turns or 0) + int(turns)
            cost = event.get("total_cost_usd")
            if isinstance(cost, (int, float)):
                transcript.cost_usd = (transcript.cost_usd or 0.0) + float(cost)
            usage = event.get("usage") or {}
            turn_input, turn_breakdown = _sum_input_tokens(
                usage, ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
            )
            if turn_input is not None:
                transcript.input_tokens = (transcript.input_tokens or 0) + turn_input
            for key, value in turn_breakdown.items():
                transcript.input_tokens_breakdown[key] = transcript.input_tokens_breakdown.get(key, 0) + value
            turn_output = _as_int(usage.get("output_tokens"))
            if turn_output is not None:
                transcript.output_tokens = (transcript.output_tokens or 0) + turn_output
            if event.get("is_error") or str(event.get("subtype") or "success") != "success":
                errors = [str(e) for e in (event.get("errors") or []) if str(e).strip()]
                transcript.error = str(event.get("subtype") or "error") + (": " + "; ".join(errors)[:200] if errors else "")
            else:
                transcript.error = None
    if not transcript.final_answer and transcript.assistant_texts:
        transcript.final_answer = transcript.assistant_texts[-1]
    return transcript


def _parse_codex(stdout: str) -> Transcript:
    events, undecoded = _json_lines(stdout)
    transcript = Transcript(host="codex", events=events, undecoded_lines=undecoded)
    order = 0
    completed_items = 0
    for event in events:
        version = event.get("version") or ((event.get("session") or {}) if isinstance(event.get("session"), dict) else {}).get("version")
        if isinstance(version, str) and not transcript.host_version:
            transcript.host_version = version
        model = event.get("model") or ((event.get("session") or {}) if isinstance(event.get("session"), dict) else {}).get("model")
        if isinstance(model, str) and model and not transcript.host_model:
            transcript.host_model = model
        kind = event.get("type")
        if kind == "item.completed":
            item = event.get("item") or {}
            item_type = str(item.get("type") or "")
            completed_items += 1
            if item_type == "agent_message":
                text = str(item.get("text") or "")
                if text.strip():
                    transcript.assistant_texts.append(text)
                    transcript.steps.append(("text", text))
                    transcript.final_answer = text
            elif item_type == "command_execution":
                command = str(item.get("command") or "")
                call_kind = "write" if WRITE_COMMAND.search(command) else "command"
                status = str(item.get("status") or "").lower()
                if status in ("denied", "rejected", "blocked", "permission_denied"):
                    execution = "denied"
                # `item.completed` only says the event was delivered.  Codex
                # command execution itself is evidenced by its exit code.
                elif isinstance(item.get("exit_code"), int):
                    execution = "executed"
                else:
                    execution = "unknown"
                call = ToolCall(order=order, name="command_execution", kind=call_kind, path=None, text=command, execution=execution)
                order += 1
                transcript.tool_calls.append(call)
                transcript.steps.append(("tool", call))
            elif item_type == "mcp_tool_call":
                name = f"mcp__{item.get('server', 'unknown')}__{item.get('tool', 'unknown')}"
                call = ToolCall(order=order, name=name, kind="mcp", path=None, text=json.dumps(item, sort_keys=True))
                order += 1
                transcript.tool_calls.append(call)
                transcript.steps.append(("tool", call))
            elif "patch" in item_type or "file_change" in item_type:
                call = ToolCall(order=order, name=item_type, kind="write", path=None, text=json.dumps(item, sort_keys=True))
                order += 1
                transcript.tool_calls.append(call)
                transcript.steps.append(("tool", call))
        elif kind == "turn.completed":
            # As on the Claude Code side: a follow-up run's concatenated
            # stream carries one of these per turn, and usage accumulates
            # across them. Reaching a normal completion also clears any
            # error the previous turn left, so a turn that recovers after a
            # follow-up is not still flagged as failed from the first one.
            transcript.error = None
            usage = event.get("usage") or {}
            turn_input, turn_breakdown = _codex_input_tokens(usage)
            if turn_input is not None:
                transcript.input_tokens = (transcript.input_tokens or 0) + turn_input
            for key, value in turn_breakdown.items():
                transcript.input_tokens_breakdown[key] = transcript.input_tokens_breakdown.get(key, 0) + value
            turn_output = _as_int(usage.get("output_tokens"))
            if turn_output is not None:
                transcript.output_tokens = (transcript.output_tokens or 0) + turn_output
        elif kind in ("turn.failed", "error"):
            transcript.error = str(event.get("error") or event.get("message") or kind)
    transcript.turns = completed_items or None
    if not transcript.host_model:
        transcript.host_model = "not reported"
    return transcript


def _as_int(value) -> int | None:
    return int(value) if isinstance(value, (int, float)) else None


def _sum_input_tokens(usage: dict, fields: tuple[str, ...]) -> tuple[int | None, dict[str, int]]:
    """The input token total across every part a host's usage object reports.

    Claude Code splits input into `input_tokens`, `cache_creation_input_tokens`,
    and `cache_read_input_tokens`; Codex splits it into `input_tokens` and
    `cached_input_tokens`. Reading only the first field undercounts by however
    much of the context came from cache. A field the host left out is recorded
    as 0 in the breakdown; the total is None only when none of the fields were
    present at all.
    """
    parts: dict[str, int] = {}
    seen = False
    for name in fields:
        value = _as_int(usage.get(name))
        parts[name] = value or 0
        if value is not None:
            seen = True
    return (sum(parts.values()) if seen else None), parts


def _codex_input_tokens(usage: dict) -> tuple[int | None, dict[str, int]]:
    """Codex's input token total for one turn: `input_tokens` alone.

    Unlike Claude Code's three additive usage parts, Codex's protocol reports
    `cached_input_tokens` as a *subset* of `input_tokens`, not an addition to
    it: codex-rs's `TokenUsage::non_cached_input` computes
    `input_tokens - cached_input_tokens`. Summing the two (as
    `_sum_input_tokens` does for Claude Code's genuinely additive parts)
    double-counts the cached portion, so a turn with 1,000 input tokens and
    800 of them cached previously reported 1,800. The breakdown still keeps
    both fields, as information only -- `cached_input_tokens` is never added
    into the total here.
    """
    parts = {
        "input_tokens": _as_int(usage.get("input_tokens")) or 0,
        "cached_input_tokens": _as_int(usage.get("cached_input_tokens")) or 0,
    }
    return _as_int(usage.get("input_tokens")), parts
