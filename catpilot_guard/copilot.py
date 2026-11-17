"""GitHub Copilot CLI's PreToolUse event, read in the Claude Code shape the checks take.

deploy/org/install.sh registers the checks for Copilot CLI as policy hooks in /etc/github-copilot/policy.d/, under
the Claude-style event name PreToolUse, with --host copilot-cli. Copilot CLI then sends snake_case fields
(session_id, cwd, tool_name, tool_input) and reports tool_name as the Claude tool name: Bash for bash and powershell,
Write for create, and Edit for edit, str_replace_editor and apply_patch. tool_input holds the runtime tool's own
arguments, parsed from JSON when possible: create {path, file_text}, edit {path, old_str, new_str},
str_replace_editor {command, path, file_text | old_str | new_str}, and apply_patch the patch, possibly as a plain
string. write_bash and write_powershell, which send input to a running shell, keep their runtime names
(docs.github.com/en/copilot/reference/hooks-reference, read on 2026-11-17).

to_claude() returns the event the checks read, so no check has a Copilot branch of its own:
  Bash                         unchanged
  write_bash, write_powershell Bash, with the input as tool_input.command
  Write, Edit                  Write with the file text as content, or Edit with the new text as new_string; an
                               Edit carrying a patch (a string, or a command, patch or input field holding one)
                               becomes apply_patch, whose added lines the write check reads
  a view, an undo, an edit     nothing to check: the same tool with empty text, only when every argument is one
  that only removes text       of a known set (path, old_str, command, view_range, ...)
  write_bash with {enter}      Bash, with {enter} and a carriage return as line breaks; any other key token ({up},
                               {backspace}, {tab}, ...) or control character (Ctrl-A, ESC, tab, DEL) can change
                               which command runs, so ValueError. Matched in any case and after `$` too, since
                               Copilot may read ${home} as $ and the Home key, so ${HOME}, {{end}} and f'{end}'
                               are refused as well (use $HOME, or the bash tool)
  a patch beside text fields   Edit with the patch's added lines and every text field checked together
  an argument it does not know ValueError: it could hold text this module does not read
  any other Write or Edit      ValueError, so the hook exits 2 and Copilot denies the call (fail closed)
  an event without tool_name   ValueError: not the PreToolUse shape (a hook registered under preToolUse)
  any other tool               unchanged; the checks decide nothing for it

with_copilot_fields() adds the top-level permissionDecision and permissionDecisionReason that Copilot documents,
beside hookSpecificOutput, which Claude Code and Codex read.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import re

COPILOT_CLI = "copilot-cli"
SHELL_INPUT_TOOLS = ("write_bash", "write_powershell")
# Every argument that can hold text written to a file, in Copilot's runtime tools and in Claude Code's.
TEXT_KEYS = ("file_text", "new_str", "content", "new_string", "insert_text")
PATCH_KEYS = ("patch", "input", "command")
PATCH_START = "*** Begin Patch"
# A terminal acts on raw control characters too: a carriage return submits a line, Ctrl-A moves to its start, ESC
# begins an arrow key, tab completes and DEL erases. Only a line feed (and a carriage return, read as one) is kept.
CONTROL = re.compile("[\x00-\x09\x0b-\x1f\x7f]")
# Arguments of a call that writes nothing new: a view, an undo, or an edit that only removes text.
NO_TEXT_KEYS = {"path", "file_path", "old_str", "old_string", "command", "view_range", "replace_all", "insert_line"}
NO_TEXT_COMMANDS = ("view", "undo_edit")
# Every argument a file write may carry. Any other one could hold text this module does not read, so it fails closed.
KNOWN_KEYS = set(TEXT_KEYS) | set(PATCH_KEYS) | NO_TEXT_KEYS
# write_bash key tokens. {enter} submits the line; any other key (arrows, backspace, tab, ...) can change which
# command runs, so the input cannot be read as a command and the hook fails closed.
ENTER = re.compile(r"\{enter\}", re.IGNORECASE)
KEY_TOKEN = re.compile(
    r"\{(?:up|down|left|right|backspace|delete|del|tab|home|end|esc|escape|pageup|pagedown|insert|space"
    r"|(?:ctrl|alt|meta|shift)[+-][a-z0-9]+)\}",
    re.IGNORECASE,
)


def _patch(tool_input: object) -> str | None:
    if isinstance(tool_input, str):
        return tool_input
    if isinstance(tool_input, dict):
        for key in PATCH_KEYS:
            value = tool_input.get(key)
            if isinstance(value, str) and PATCH_START in value:
                return value
    return None


def to_claude(event: object) -> object:
    """The event in the shape the checks read. Raises ValueError for a file write of a shape it does not know."""
    if not isinstance(event, dict):
        return event
    name = event.get("tool_name")
    if not isinstance(name, str):
        # Not the PreToolUse shape: a hook registered under the camelCase event name gets toolName and toolArgs.
        raise ValueError("event without tool_name")
    tool_input = event.get("tool_input")
    out = dict(event)
    if name in SHELL_INPUT_TOOLS:
        text = tool_input.get("input") if isinstance(tool_input, dict) else None
        if not isinstance(text, str):
            raise ValueError("shell input without text")
        text = ENTER.sub("\n", text.replace("\r\n", "\n").replace("\r", "\n"))
        if KEY_TOKEN.search(text) or CONTROL.search(text):
            raise ValueError("shell input with key tokens or control characters")
        out["tool_name"], out["tool_input"] = "Bash", {"command": text}
        return out
    if name not in ("Write", "Edit"):
        return out
    patch = _patch(tool_input) if name == "Edit" else None
    if isinstance(tool_input, str) and patch is not None:
        out["tool_name"], out["tool_input"] = "apply_patch", {"command": patch}
        return out
    if not isinstance(tool_input, dict):
        raise ValueError("file write of an unknown shape")
    present = {key for key, value in tool_input.items() if value is not None}  # a null argument is absent
    if present - KNOWN_KEYS:
        raise ValueError("file write with an argument it cannot read")
    texts = [tool_input[key] for key in TEXT_KEYS if tool_input.get(key) is not None]
    if any(not isinstance(text, str) for text in texts):
        raise ValueError("file write of an unknown shape")
    if patch is not None:
        if not texts:
            out["tool_name"], out["tool_input"] = "apply_patch", {"command": patch}
            return out
        # A patch beside other text: check what the patch adds and every text field together.
        from .write_secrets import patch_added_text

        texts = texts + patch_added_text(patch)
    if not texts:
        nothing_new = present <= NO_TEXT_KEYS and (
            tool_input.get("command") in NO_TEXT_COMMANDS or "old_str" in tool_input or "old_string" in tool_input)
        if not nothing_new:
            raise ValueError("file write of an unknown shape")
        texts = [""]  # a view, an undo, or an edit that only removes text: nothing is written
    text = "\n".join(texts)
    out["tool_input"] = {"content": text} if name == "Write" else {"new_string": text}
    return out


def with_copilot_fields(result: dict) -> dict:
    """A decision with Copilot's top-level fields added; the empty decision stays empty."""
    specific = result.get("hookSpecificOutput") if isinstance(result, dict) else None
    if not isinstance(specific, dict) or "permissionDecision" not in specific:
        return result
    out = dict(result)
    out["permissionDecision"] = specific["permissionDecision"]
    out["permissionDecisionReason"] = specific.get("permissionDecisionReason", "")
    return out
