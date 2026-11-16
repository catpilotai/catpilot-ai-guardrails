#!/usr/bin/env bash
# Checks of what deploy/org/install.sh placed, run as a normal user. It checks that the files are present,
# that the Python interpreter the hook commands use can start, that each installed hook denies a harmless
# probe (AWS's documentation-only example key, a force push to main) and lets an ordinary command through,
# and that managed-settings.json actually runs each hook on the tools it covers. It writes only to a
# temporary directory it removes on exit, sends nothing anywhere, and writes no evidence line.
#
# It runs the hooks directly, not through Claude Code, so it proves nothing about what a session does:
# Claude Code's own PATH can differ from this shell's, and only a session shows the host applying a deny.
# The behavioral checks (a denied command, a server lookup, a skill load) are in docs/DEPLOY_ORG.md.
set -uo pipefail
case "$(uname -s)" in
  Darwin) DEFAULT_CC_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux) DEFAULT_CC_DIR="/etc/claude-code" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
CC_DIR="${CATPILOT_CC_DIR:-$DEFAULT_CC_DIR}"
CODEX_DIR="${CATPILOT_CODEX_DIR:-/etc/codex}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
HOOK_DIR="$CC_DIR/catpilot-guardrails/hooks"
TIMEOUT_SECONDS=10  # the timeout managed-settings.json gives each hook
NO_START="Claude Code treats a hook that cannot start as a non-blocking error, so commands and writes would run unchecked."
ok=0; missing=0; failed=0; python_ok=0

WORK="$(mktemp -d "${TMPDIR:-/tmp}/catpilot-verify.XXXXXX")" || { echo "cannot create a temporary directory" >&2; exit 2; }
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/home"

check() { if [ -e "$1" ]; then echo "present  $1"; ok=$((ok+1)); else echo "MISSING  $1"; missing=$((missing+1)); fi; }
fail() { echo "FAIL     $1"; failed=$((failed+1)); }
json_ok() {
  if [ "$python_ok" -ne 1 ]; then echo "skipped  $1 JSON check (no working interpreter)"; return; fi
  "$PYTHON_BIN" -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" 2>/dev/null && echo "valid    $1 parses as JSON" || { echo "INVALID  $1 does not parse as JSON"; missing=$((missing+1)); }
}

# run_limited SECONDS STDIN_FILE STDOUT_FILE COMMAND...: the command's exit status, or 124 when it ran too long.
# Plain bash, because macOS has no timeout(1).
run_limited() {
  local seconds="$1" input="$2" output="$3" pid ticks=0
  shift 3
  "$@" < "$input" > "$output" 2>/dev/null &
  pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$ticks" -ge $((seconds * 10)) ]; then
      kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124
    fi
    sleep 0.1; ticks=$((ticks + 1))
  done
  wait "$pid"
}

check_python() {
  local resolved status version
  resolved="$(command -v "$PYTHON_BIN" 2>/dev/null || true)"
  if [ -z "$resolved" ]; then
    fail "$PYTHON_BIN is not on this PATH. $NO_START"; return
  fi
  if [ "$(uname -s)" = "Darwin" ] && [ "$resolved" = "/usr/bin/python3" ] && ! xcode-select -p >/dev/null 2>&1; then
    fail "$PYTHON_BIN is the macOS Command Line Tools stub ($resolved) and the tools are not installed, so it opens an install prompt instead of running. $NO_START"; return
  fi
  run_limited "$TIMEOUT_SECONDS" /dev/null "$WORK/version" "$resolved" -c \
    'import sys; print("%d.%d" % sys.version_info[:2]); sys.exit(0 if sys.version_info >= (3, 8) else 3)'
  status=$?
  version="$(head -n 1 "$WORK/version" 2>/dev/null || true)"
  case "$status" in
    0) echo "runs     $PYTHON_BIN, Python $version ($resolved)"; python_ok=1 ;;
    3) fail "$PYTHON_BIN is Python $version ($resolved); the hooks need 3.8 or later. $NO_START" ;;
    124) fail "$PYTHON_BIN ($resolved) did not start within ${TIMEOUT_SECONDS}s. $NO_START" ;;
    *) fail "$PYTHON_BIN ($resolved) exited $status instead of starting. $NO_START" ;;
  esac
}

# judge NAME WHAT EXPECT STATUS: report the output of the last run in $WORK/out.
judge() {
  local name="$1" what="$2" expect="$3" status="$4"
  if [ "$status" -eq 124 ]; then
    fail "$name did not finish $what within the ${TIMEOUT_SECONDS}s hook timeout"; return 1
  elif [ "$status" -ne 0 ]; then
    fail "$name exited $status on $what instead of returning a decision (2 means it could not read the event)"; return 1
  elif [ "$expect" = deny ]; then
    if grep -q '"permissionDecision": *"deny"' "$WORK/out"; then return 0; fi
    fail "$name did not deny $what"; return 1
  else
    if [ "$(tr -d '[:space:]' < "$WORK/out")" = "{}" ]; then return 0; fi
    fail "$name did not let $what through unchanged"; return 1
  fi
}

# probe HOOK_FILE WHAT EVENT_FILE EXPECT: run one installed hook directly with the checked interpreter.
probe() {
  local name status
  name="$(basename "$1")"
  run_limited "$TIMEOUT_SECONDS" "$3" "$WORK/out" env -u CATPILOT_EVIDENCE_LOG -u CATPILOT_EVIDENCE_SYSLOG "$PYTHON_BIN" "$1"
  status=$?
  if judge "$name" "$2" "$4" "$status"; then
    if [ "$4" = deny ]; then echo "denies   $name: $2"; else echo "passes   $name: $2"; fi
  fi
}

# Probe events. The key is AWS's documentation-only example; nothing here is a real credential or target.
bash_event() {
  printf '{"session_id":"catpilot-verify","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"%s"},"cwd":"%s"}\n' "$1" "$WORK" > "$2"
}
bash_event "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE && echo ok" "$WORK/event-credential"
bash_event "git push --force origin main" "$WORK/event-force-push"
bash_event "ls" "$WORK/event-ls"
printf '{"session_id":"catpilot-verify","hook_event_name":"PreToolUse","tool_name":"Write","tool_input":{"file_path":"%s/probe.env","content":"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\\n"},"cwd":"%s"}\n' "$WORK" "$WORK" > "$WORK/event-write"

# Lists each managed PreToolUse hook command that runs a Catpilot hook: kind, file name, the tools its matcher
# does not cover, and the command, separated by \037 and terminated by NUL.
WIRING_PY='
import json, re, sys
WRITE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
HOOKS = (("pretooluse-secrets.py", "secrets", ("Bash",)),
         ("pretooluse-destructive-ops.py", "destructive", ("Bash",)),
         ("pretooluse-write-secrets.py", "write", WRITE_TOOLS),
         ("pretooluse-write-private-key.py", "write", WRITE_TOOLS))
def covers(matcher, tool):
    if matcher in (None, "", "*"):
        return True
    try:
        return re.fullmatch(matcher, tool) is not None
    except re.error:
        return False
settings = json.load(open(sys.argv[1]))
hooks = settings.get("hooks") if isinstance(settings, dict) else None
groups = hooks.get("PreToolUse") if isinstance(hooks, dict) else None
for group in groups if isinstance(groups, list) else []:
    if not isinstance(group, dict):
        continue
    for entry in group.get("hooks") or []:
        command = entry.get("command") if isinstance(entry, dict) else None
        if not isinstance(command, str):
            continue
        for filename, kind, tools in HOOKS:
            if filename in command:
                uncovered = ",".join(t for t in tools if not covers(group.get("matcher"), t))
                sys.stdout.write("%s\037%s\037%s\037%s\0" % (kind, filename, uncovered, command))
'

# check_wiring: run each Catpilot hook command in managed-settings.json the way Claude Code would (through a
# shell, with this shell's PATH), with HOME pointed at the temporary directory so the command's own
# CATPILOT_EVIDENCE_LOG="$HOME/..." writes nowhere real.
check_wiring() {
  local settings="$CC_DIR/managed-settings.json" kind filename uncovered command event status
  local seen_secrets=0 seen_destructive=0 seen_write=0
  "$PYTHON_BIN" -c "$WIRING_PY" "$settings" > "$WORK/wiring" 2>/dev/null || { echo "skipped  managed-settings.json hook commands (could not read the file)"; return; }
  while IFS=$'\037' read -r -d '' kind filename uncovered command; do
    case "$kind" in
      secrets) seen_secrets=1; event="$WORK/event-credential" ;;
      destructive) seen_destructive=1; event="$WORK/event-force-push" ;;
      *) seen_write=1; event="$WORK/event-write" ;;
    esac
    if [ -n "$uncovered" ]; then
      fail "managed-settings.json runs $filename under a matcher that does not cover $uncovered"
    fi
    case "$command" in
      *CATPILOT_EVIDENCE_SYSLOG*) echo "skipped  managed-settings.json command for $filename (it forwards evidence to syslog; check it in a session)"; continue ;;
    esac
    run_limited "$TIMEOUT_SECONDS" "$event" "$WORK/out" env -u CATPILOT_EVIDENCE_LOG -u CATPILOT_EVIDENCE_SYSLOG HOME="$WORK/home" bash -c "$command"
    status=$?
    if judge "managed-settings.json command for $filename" "its probe" deny "$status"; then
      echo "wired    managed-settings.json runs $filename and it denies its probe"
    fi
  done < "$WORK/wiring"
  [ "$seen_secrets" -eq 1 ] || fail "managed-settings.json does not run pretooluse-secrets.py (install.sh prints the hooks block to merge when the file already existed)"
  [ "$seen_destructive" -eq 1 ] || fail "managed-settings.json does not run pretooluse-destructive-ops.py (install.sh prints the hooks block to merge when the file already existed)"
  [ "$seen_write" -eq 1 ] || fail "managed-settings.json does not run pretooluse-write-secrets.py (install.sh prints the hooks block to merge when the file already existed)"
}

echo "Interpreter for the hook commands (Claude Code uses its own PATH, which can differ from this shell's)"
check_python
echo

echo "Claude Code (managed dir: $CC_DIR)"
check "$CC_DIR/managed-settings.json"; [ -e "$CC_DIR/managed-settings.json" ] && json_ok "$CC_DIR/managed-settings.json"
[ -e "$CC_DIR/managed-mcp.json" ] && { echo "present  $CC_DIR/managed-mcp.json (fixed server set: only its servers load in CLI sessions)"; json_ok "$CC_DIR/managed-mcp.json"; } || echo "absent   $CC_DIR/managed-mcp.json (optional; the server may come from managedMcpServers or a repository .mcp.json)"
check "$HOOK_DIR/pretooluse-secrets.py"
check "$HOOK_DIR/pretooluse-write-secrets.py"
check "$HOOK_DIR/pretooluse-write-private-key.py"  # compatibility entry point for older settings
check "$HOOK_DIR/pretooluse-destructive-ops.py"
for s in "$CC_DIR"/.claude/skills/catpilot-*/SKILL.md; do [ -e "$s" ] && echo "present  $s"; done
echo

echo "Hooks, run directly on harmless probes"
if [ "$python_ok" -ne 1 ]; then
  echo "skipped  no working interpreter (see the FAIL line above)"
else
  [ -e "$HOOK_DIR/pretooluse-secrets.py" ] && {
    probe "$HOOK_DIR/pretooluse-secrets.py" "a command carrying AWS's documentation example key" "$WORK/event-credential" deny
    probe "$HOOK_DIR/pretooluse-secrets.py" "ls" "$WORK/event-ls" pass
  }
  [ -e "$HOOK_DIR/pretooluse-destructive-ops.py" ] && {
    probe "$HOOK_DIR/pretooluse-destructive-ops.py" "git push --force origin main" "$WORK/event-force-push" deny
    probe "$HOOK_DIR/pretooluse-destructive-ops.py" "ls" "$WORK/event-ls" pass
  }
  for f in pretooluse-write-secrets.py pretooluse-write-private-key.py; do
    [ -e "$HOOK_DIR/$f" ] && probe "$HOOK_DIR/$f" "a file write carrying AWS's documentation example key" "$WORK/event-write" deny
  done
  [ -e "$CC_DIR/managed-settings.json" ] && check_wiring
fi
echo

echo "Codex CLI (managed dir: $CODEX_DIR)"
check "$CODEX_DIR/managed_config.toml"
for s in "$CODEX_DIR"/skills/catpilot-*/SKILL.md; do [ -e "$s" ] && echo "present  $s"; done
echo
echo "Evidence log for this user"
if [ -e "$HOME/.catpilot-guardrails/evidence.jsonl" ]; then
  echo "present  $HOME/.catpilot-guardrails/evidence.jsonl ($(wc -l < "$HOME/.catpilot-guardrails/evidence.jsonl" | tr -d ' ') lines); last line:"; tail -n 1 "$HOME/.catpilot-guardrails/evidence.jsonl"
else
  echo "none yet: it appears after the first denied command or write"
fi
echo
echo "$ok present, $missing missing, $failed failed. Next: start Claude Code and run /status (expect 'Enterprise managed settings'),"
echo "then claude mcp list, then the test prompts in docs/DEPLOY_ORG.md."
[ "$missing" -eq 0 ] && [ "$failed" -eq 0 ]
