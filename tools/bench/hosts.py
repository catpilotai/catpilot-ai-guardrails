"""Host commands, host runs, and one normalized transcript shape.

Two hosts, both driven in print mode with a machine-readable event stream:

  Claude Code  `claude -p ... --output-format stream-json --verbose`, one JSON
               object per line, `system` / `assistant` / `user` / `result`
               events, `tool_use` and `tool_result` content blocks, and
               `total_cost_usd` plus `usage` on the result.
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
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

HOSTS = ("claude-code", "codex")
DEFAULT_MODEL = {"claude-code": "sonnet", "codex": None}
CLAUDE_BINARY = "claude"
CODEX_COMMAND = ("npx", "-y", "@openai/codex")
ALLOWED_TOOLS = (
    "Skill,Read,Write,Edit,MultiEdit,Glob,Grep,Bash(ls:*),Bash(cat:*),"
    "mcp__catpilot-guardrails__get_guidance,mcp__catpilot-guardrails__check_plan,"
    "mcp__catpilot-guardrails__get_template,mcp__catpilot-guardrails__list_approved"
)
CODEX_AUTH = Path("~/.codex/auth.json")
CODEX_CONFIG = """# Clean test identity for a benchmark run.
# Only the credentials file is carried over from the real home, so the
# user-level skills directory and any user-level MCP servers stay out of the run.
"""

# A shell command that puts bytes into a file. Codex writes through the shell, so
# this is how a write shows up on that host.
WRITE_COMMAND = re.compile(
    r"(?:^|[|;&]\s*)(?:apply_patch|tee|cp|mv|install|sed\s+-i|patch)\b|>{1,2}\s*[^|&;\s]|<<\s*'?[A-Z_]+",
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


def codex_overrides(mcp_config: dict | None) -> list[str]:
    """The `-c` pairs that put the reference server in front of Codex, for arm C."""
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
    from .sandbox import mcp_config_json

    if host == "claude-code":
        return claude_command(task, model=model, max_turns=max_turns, mcp_config_json=mcp_config_json(mcp_config or {"mcpServers": {}}))
    if host == "codex":
        return codex_command(task, model=model, mcp_config=mcp_config)
    raise ValueError(f"unknown host '{host}'")


def printable(command: list[str]) -> str:
    return shlex.join(command)


def prepare_codex_home(base: Path, auth_source: Path | None = None) -> Path:
    """A temporary home with only the credentials file and a minimal config."""
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
    (codex_dir / "config.toml").write_text(CODEX_CONFIG, encoding="utf-8")
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


def parse_transcript(host: str, stdout: str) -> Transcript:
    if host == "claude-code":
        return _parse_claude(stdout)
    if host == "codex":
        return _parse_codex(stdout)
    raise ValueError(f"unknown host '{host}'")


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
    for event in events:
        kind = event.get("type")
        if kind == "system":
            transcript.host_version = transcript.host_version or event.get("version") or event.get("claude_code_version")
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
                    call = ToolCall(order=order, name=name, kind=call_kind, path=path, text=text)
                    order += 1
                    transcript.tool_calls.append(call)
                    transcript.steps.append(("tool", call))
        elif kind == "result":
            transcript.final_answer = str(event.get("result") or "")
            transcript.turns = event.get("num_turns")
            cost = event.get("total_cost_usd")
            transcript.cost_usd = float(cost) if isinstance(cost, (int, float)) else None
            usage = event.get("usage") or {}
            transcript.input_tokens, transcript.input_tokens_breakdown = _sum_input_tokens(
                usage, ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
            )
            transcript.output_tokens = _as_int(usage.get("output_tokens"))
            if event.get("is_error") or str(event.get("subtype") or "success") != "success":
                transcript.error = str(event.get("subtype") or "error")
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
                call = ToolCall(order=order, name="command_execution", kind=call_kind, path=None, text=command)
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
            usage = event.get("usage") or {}
            transcript.input_tokens, transcript.input_tokens_breakdown = _sum_input_tokens(
                usage, ("input_tokens", "cached_input_tokens")
            )
            transcript.output_tokens = _as_int(usage.get("output_tokens"))
        elif kind in ("turn.failed", "error"):
            transcript.error = str(event.get("error") or event.get("message") or kind)
    transcript.turns = completed_items or None
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
