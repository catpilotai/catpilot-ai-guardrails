#!/usr/bin/env bash
# Checks of what deploy/org/install.sh placed, run as a normal user. It checks that the files are present
# (the zipapp, catpilot-guard.pyz, with the SHA-256 install.sh recorded beside it and owned by root, or after
# install.sh --package-tree the hooks and the catpilot_guard package they import from beside them), that the Python
# interpreter the hook commands name (the absolute path install.sh recorded, or python3 from PATH for an earlier install) runs
# Python 3.8 or later, that each installed hook denies a harmless probe (AWS's documentation-only
# example key, a force push to main) and lets an ordinary command through, and that managed-settings.json
# actually runs each hook on the tools it covers. For Codex it checks the hook copies under
# /etc/codex/catpilot-guardrails/hooks/, runs each on harmless probes in Codex's event shape (Bash, apply_patch),
# and runs each PreToolUse command /etc/codex/requirements.toml declares. After an install with --overlay it also checks the company
# rules at session start: the block and its sidecar on each tool and that their SHA-256 hashes match, the
# marked section of the managed CLAUDE.md, the expiry date, the session-start script run directly for each
# tool, and the SessionStart hook that managed-settings.json and /etc/codex/requirements.toml register, run
# the way the tool would. It works in a temporary directory it removes on exit, where the probes' evidence lines
# go, as long as the registered commands are install.sh's own: a built-in hook's command changed to another
# evidence path, a wrapper or an env file writes its probe lines where those send them (one naming syslog is
# skipped); a company-rules command that is not exactly install.sh's is not run.
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
COPILOT_DIR="${CATPILOT_COPILOT_DIR:-/etc/github-copilot}"
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=interpreter.sh
. "$HERE/interpreter.sh" || { echo "interpreter.sh is not beside verify.sh: run verify.sh from a checkout" >&2; exit 2; }
# The interpreter install.sh recorded in the hook commands; PYTHON_BIN overrides it; python3 for an earlier install.
RECORDED_PYTHON="$(recorded_interpreter "$CC_DIR/managed-settings.json" "$CODEX_DIR/requirements.toml" "$COPILOT_DIR/policy.d/catpilot-guardrails.json")"
PYTHON_BIN="${PYTHON_BIN:-${RECORDED_PYTHON:-python3}}"
RULES_FILES="$HERE/session_start_files.py"
HOOK_DIR="$CC_DIR/catpilot-guardrails/hooks"
ZIPAPP="$HOOK_DIR/catpilot-guard.pyz"
TIMEOUT_SECONDS=10  # the timeout managed-settings.json gives each hook
NO_START="Claude Code (with onFailure block) then blocks every command and write the hooks cover, and Codex can let them run unchecked."
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

# count_report: echo report lines from session_start_files.py and count them like check() and fail() do.
count_report() {
  local line
  while IFS= read -r line; do
    echo "$line"
    case "$line" in
      "present  "*) ok=$((ok+1)) ;;
      MISSING*|INVALID*) missing=$((missing+1)) ;;
      FAIL*) failed=$((failed+1)) ;;
    esac
  done
}

check_python() {
  if [ -n "$RECORDED_PYTHON" ]; then
    echo "recorded $RECORDED_PYTHON (the interpreter the hook commands name)"
    [ "$PYTHON_BIN" = "$RECORDED_PYTHON" ] || echo "note     PYTHON_BIN=$PYTHON_BIN is checked here instead of the recorded interpreter"
  else
    echo "note     the hook commands name python3 from each session's PATH (an install before the interpreter was recorded);"
    echo "         run install.sh again, which proves an interpreter and records its absolute path"
  fi
  if prove_interpreter "$PYTHON_BIN"; then
    echo "runs     $PYTHON_BIN, Python $PROVEN_VERSION ($PROVEN_PYTHON)"; python_ok=1
  else
    fail "$PROVEN_ERROR. $NO_START"
  fi
}

# judge NAME WHAT EXPECT STATUS: report the output of the last run in $WORK/out.
judge() {
  local name="$1" what="$2" expect="$3" status="$4"
  if [ "$status" -eq 124 ]; then
    fail "$name did not finish $what within the ${TIMEOUT_SECONDS}s hook timeout"; return 1
  elif [ "$status" -ne 0 ]; then
    fail "$name exited $status on $what instead of returning a decision (2 means it could not read the event or load the catpilot_guard package)"; return 1
  elif [ "$expect" = deny ]; then
    if grep -q '"permissionDecision": *"deny"' "$WORK/out"; then return 0; fi
    fail "$name did not deny $what"; return 1
  else
    if [ "$(tr -d '[:space:]' < "$WORK/out")" = "{}" ]; then return 0; fi
    fail "$name did not let $what through unchanged"; return 1
  fi
}

# probe HOOK_FILE WHAT EVENT_FILE EXPECT [CHECK]: run one installed hook directly with the checked interpreter; with
# CHECK, HOOK_FILE names the check and it runs from the zipapp.
probe() {
  local name status target=("$1")
  name="$(basename "$1")"
  [ $# -ge 5 ] && target=("$ZIPAPP" "$5")
  run_limited "$TIMEOUT_SECONDS" "$3" "$WORK/out" env -u CATPILOT_EVIDENCE_LOG -u CATPILOT_EVIDENCE_SYSLOG "$PYTHON_BIN" "${target[@]}"
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
# The check each hook file runs in the zipapp (install.sh without --package-tree).
CHECKS = {"pretooluse-secrets.py": "secrets", "pretooluse-destructive-ops.py": "destructive",
          "pretooluse-write-secrets.py": "write-secrets"}
def runs(command, filename):
    if filename in command:
        return True
    check = CHECKS.get(filename)
    return check is not None and re.search(r"catpilot-guard\.pyz\"?\s+%s(?=[\s\"\x27]|$)" % re.escape(check), command) is not None
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
            if runs(command, filename):
                uncovered = ",".join(t for t in tools if not covers(group.get("matcher"), t))
                on_failure = entry.get("onFailure") if isinstance(entry.get("onFailure"), str) else ""
                sys.stdout.write("%s\037%s\037%s\037%s\037%s\0" % (kind, filename, uncovered, on_failure, command))
'

# check_wiring: run each Catpilot hook command in managed-settings.json the way Claude Code would (through a
# shell, with this shell's PATH), with HOME pointed at the temporary directory so the command's own
# CATPILOT_EVIDENCE_LOG="$HOME/..." writes nowhere real.
check_wiring() {
  local settings="$CC_DIR/managed-settings.json" kind filename uncovered on_failure command event status
  local seen_secrets=0 seen_destructive=0 seen_write=0
  "$PYTHON_BIN" -c "$WIRING_PY" "$settings" > "$WORK/wiring" 2>/dev/null || { echo "skipped  managed-settings.json hook commands (could not read the file)"; return; }
  while IFS=$'\037' read -r -d '' kind filename uncovered on_failure command; do
    case "$kind" in
      secrets) seen_secrets=1; event="$WORK/event-credential" ;;
      destructive) seen_destructive=1; event="$WORK/event-force-push" ;;
      *) seen_write=1; event="$WORK/event-write" ;;
    esac
    if [ -n "$uncovered" ]; then
      fail "managed-settings.json runs $filename under a matcher that does not cover $uncovered"
    fi
    if [ "$on_failure" != "block" ]; then
      echo "note     managed-settings.json runs $filename without \"onFailure\": \"block\", so Claude Code lets a call run when the hook cannot start or times out (the key needs Claude Code 2.1.295 or later)"
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
if [ -e "$ZIPAPP" ]; then
  # The zipapp: its SHA-256 against the one install.sh recorded, its owner and mode, the modules in it.
  if [ "$python_ok" -ne 1 ]; then
    check "$ZIPAPP"; check "$ZIPAPP.sha256"; fail "the zipapp's SHA-256 was not checked (no working interpreter)"
  elif [ ! -f "$RULES_FILES" ]; then
    check "$ZIPAPP"; fail "$RULES_FILES, which checks the zipapp, is not beside verify.sh: run verify.sh from a checkout"
  else
    count_report < <("$PYTHON_BIN" "$RULES_FILES" verify-zipapp --hooks-dir "$HOOK_DIR" 2>&1 \
                       || echo "FAIL     the zipapp checks stopped with an error (above)")
  fi
else
  check "$HOOK_DIR/pretooluse-secrets.py"
  check "$HOOK_DIR/pretooluse-write-secrets.py"
  check "$HOOK_DIR/pretooluse-write-private-key.py"  # compatibility entry point for older settings
  check "$HOOK_DIR/pretooluse-destructive-ops.py"
  # The package the hooks import from beside them; a hook that cannot load it exits 2, which blocks everything it covers.
  for m in __init__ secrets write_secrets destructive evidence session_start; do check "$HOOK_DIR/catpilot_guard/$m.py"; done
fi
for s in "$CC_DIR"/.claude/skills/catpilot-*/SKILL.md; do [ -e "$s" ] && echo "present  $s"; done
echo

echo "Hooks, run directly on harmless probes"
if [ "$python_ok" -ne 1 ]; then
  echo "skipped  no working interpreter (see the FAIL line above)"
elif [ -e "$ZIPAPP" ]; then
  # The checks keep the names of the hook files they replace, so the lines read the same in either layout.
  probe pretooluse-secrets.py "a command carrying AWS's documentation example key" "$WORK/event-credential" deny secrets
  probe pretooluse-secrets.py "ls" "$WORK/event-ls" pass secrets
  probe pretooluse-destructive-ops.py "git push --force origin main" "$WORK/event-force-push" deny destructive
  probe pretooluse-destructive-ops.py "ls" "$WORK/event-ls" pass destructive
  probe pretooluse-write-secrets.py "a file write carrying AWS's documentation example key" "$WORK/event-write" deny write-secrets
  [ -e "$CC_DIR/managed-settings.json" ] && check_wiring
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
# The PreToolUse hooks requirements.toml declares, run directly and through a shell the way Codex would, with HOME
# at the temporary directory and no evidence variable, so install.sh's own commands write their probes' evidence
# there; a command changed to send it elsewhere (another path, a wrapper, an env file) writes it there.
if [ ! -f "$RULES_FILES" ]; then
  fail "$RULES_FILES, which checks the Codex hooks, is not beside verify.sh: run verify.sh from a checkout"
elif [ "$python_ok" -ne 1 ]; then
  echo "skipped  Codex hooks (no working interpreter; see the FAIL line above)"
else
  count_report < <("$PYTHON_BIN" "$RULES_FILES" verify-codex-hooks --codex-dir "$CODEX_DIR" --home "$WORK/home" --timeout "$TIMEOUT_SECONDS" 2>&1 \
                     || echo "FAIL     the Codex hook checks stopped with an error (above)")
fi
echo

# Copilot CLI policy hooks, run directly in Copilot's event shape and through a shell as the policy file declares
# them, with HOME at the temporary directory and no evidence variable.
echo "GitHub Copilot CLI (policy dir: $COPILOT_DIR/policy.d)"
if [ ! -e "$COPILOT_DIR/policy.d/catpilot-guardrails.json" ] && [ ! -e "$COPILOT_DIR/catpilot-guardrails" ]; then
  echo "skipped  no Copilot CLI policy hooks installed"
elif [ ! -f "$RULES_FILES" ]; then
  fail "$RULES_FILES, which checks the Copilot CLI hooks, is not beside verify.sh: run verify.sh from a checkout"
elif [ "$python_ok" -ne 1 ]; then
  echo "skipped  Copilot CLI hooks (no working interpreter; see the FAIL line above)"
else
  count_report < <("$PYTHON_BIN" "$RULES_FILES" verify-copilot-hooks --copilot-dir "$COPILOT_DIR" --home "$WORK/home" --timeout "$TIMEOUT_SECONDS" 2>&1 \
                     || echo "FAIL     the Copilot CLI hook checks stopped with an error (above)")
fi
echo

# Company rules at session start (install.sh --overlay). The checks and the runs are in session_start_files.py:
# each run gets a SessionStart event on stdin, HOME pointed at the temporary directory and no evidence variable,
# so install.sh's own commands write their evidence there (a changed command writes it where it sends it).
echo "Company rules at session start (advice, not enforcement)"
if [ ! -f "$RULES_FILES" ]; then
  if [ -e "$CC_DIR/catpilot-guardrails/instructions/company-checklist.json" ] || [ -e "$CODEX_DIR/catpilot-guardrails/instructions/company-checklist.json" ]; then
    fail "the company rules at session start are installed, and $RULES_FILES, which checks them, is not beside verify.sh: run verify.sh from a checkout"
  else
    echo "skipped  session_start_files.py is not beside verify.sh"
  fi
elif [ "$python_ok" -ne 1 ]; then
  echo "skipped  no working interpreter (see the FAIL line above)"
else
  count_report < <("$PYTHON_BIN" "$RULES_FILES" verify --cc-dir "$CC_DIR" --codex-dir "$CODEX_DIR" --home "$WORK/home" --timeout "$TIMEOUT_SECONDS" 2>&1 \
                     || echo "FAIL     the session-start checks stopped with an error (above)")
fi
echo

# Company enforcement rules (install.sh --overlay with an enforcement section): the compiled policy and the
# company-rules hook on each tool, run directly and as the managed file registers it (only when it is install.sh's
# own command), with HOME at the temporary directory, where the probes' evidence lines go.
echo "Company enforcement rules (the company-rules hook)"
if [ ! -e "$CC_DIR/catpilot-guardrails/policy/company-policy.json" ] && [ ! -e "$CODEX_DIR/catpilot-guardrails/policy/company-policy.json" ] \
   && [ ! -e "$COPILOT_DIR/catpilot-guardrails/policy/company-policy.json" ] \
   && ! grep -qs pretooluse-company-rules "$CC_DIR/managed-settings.json" "$CODEX_DIR/requirements.toml" "$COPILOT_DIR"/policy.d/*.json; then
  echo "skipped  no compiled company policy and no company-rules hook on any tool (install.sh --overlay places them when the rules file has enforcement rules)"
elif [ ! -f "$RULES_FILES" ]; then
  fail "a company policy is installed, and $RULES_FILES, which checks it, is not beside verify.sh: run verify.sh from a checkout"
elif [ "$python_ok" -ne 1 ]; then
  echo "skipped  no working interpreter (see the FAIL line above)"
else
  count_report < <("$PYTHON_BIN" "$RULES_FILES" verify-company-rules --cc-dir "$CC_DIR" --codex-dir "$CODEX_DIR" --copilot-dir "$COPILOT_DIR" --home "$WORK/home" --timeout "$TIMEOUT_SECONDS" 2>&1 \
                     || echo "FAIL     the company-rules checks stopped with an error (above)")
fi
echo
echo "Evidence log for this user"
if [ -e "$HOME/.catpilot-guardrails/evidence.jsonl" ]; then
  echo "present  $HOME/.catpilot-guardrails/evidence.jsonl ($(wc -l < "$HOME/.catpilot-guardrails/evidence.jsonl" | tr -d ' ') lines); last line:"; tail -n 1 "$HOME/.catpilot-guardrails/evidence.jsonl"
else
  echo "none yet: it appears after the first denied command or write"
fi
echo
echo "$ok present, $missing missing, $failed failed. Next: start Claude Code and run /status. 'Setting sources' must name the"
echo "file, as '(file)' or '(remote + file, merged)'. If 'Skipped sources' lists the file, the hooks are not running: see"
echo "docs/DEPLOY_ORG.md. Then claude mcp list, then the test prompts in docs/DEPLOY_ORG.md."
if [ -e "$CC_DIR/catpilot-guardrails/instructions/company-checklist.json" ]; then
  echo "Company rules at session start: in Claude Code, /context all lists $CC_DIR/CLAUDE.md under Memory files and /hooks"
  echo "lists the SessionStart hook; in Codex, /hooks lists it as managed. Then the session checks in docs/DEPLOY_ORG.md."
fi
[ "$missing" -eq 0 ] && [ "$failed" -eq 0 ]
