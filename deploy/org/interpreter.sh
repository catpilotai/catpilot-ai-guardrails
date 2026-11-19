# Sourced by install.sh, verify.sh and uninstall.sh: the Python interpreter the hook commands name (issue #97,
# option 1). install.sh proves the interpreter runs Python 3.8 or later before it writes anything, refuses
# otherwise, and records its absolute path in every hook command, so a session does not depend on its own PATH.
# A hook whose interpreter cannot start does not run: Claude Code, with "onFailure": "block", then blocks every
# command and write the hooks cover; another host may let them run unchecked. Hence the proof, not a guess.

INTERPRETER_TIMEOUT=10  # the timeout managed-settings.json gives each hook

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

# prove_interpreter CANDIDATE: run CANDIDATE (a name on PATH or a path) and set PROVEN_PYTHON to its absolute path
# and PROVEN_VERSION to its version when it runs Python 3.8 or later; otherwise set PROVEN_ERROR and return 1.
prove_interpreter() {
  local candidate="$1" resolved status out
  PROVEN_PYTHON=""; PROVEN_VERSION=""; PROVEN_ERROR=""
  resolved="$(command -v -- "$candidate" 2>/dev/null || true)"
  if [ -z "$resolved" ]; then PROVEN_ERROR="$candidate is not on this PATH"; return 1; fi
  case "$resolved" in
    /*) ;;
    */*) resolved="$(cd "$(dirname "$resolved")" && pwd)/$(basename "$resolved")" ;;
    *) PROVEN_ERROR="$candidate is not a program (a shell alias or function?)"; return 1 ;;
  esac
  case "$resolved" in
    *[\"\'\\\$\`]*|*[[:cntrl:]]*)
      PROVEN_ERROR="$resolved holds a quote, backslash, \$, \` or control character, which a hook command cannot carry"; return 1 ;;
  esac
  # macOS ships /usr/bin/python3 as a stub that opens an install prompt until the Command Line Tools are installed.
  if [ "$(uname -s)" = "Darwin" ] && [ "$resolved" = "/usr/bin/python3" ] && ! xcode-select -p >/dev/null 2>&1; then
    PROVEN_ERROR="$resolved is the macOS Command Line Tools stub and the tools are not installed, so it opens an install prompt instead of running Python"
    return 1
  fi
  out="$(mktemp "${TMPDIR:-/tmp}/catpilot-python.XXXXXX")" || { PROVEN_ERROR="cannot create a temporary file"; return 1; }
  run_limited "$INTERPRETER_TIMEOUT" /dev/null "$out" "$resolved" -c \
    'import sys; print("%d.%d.%d" % sys.version_info[:3]); sys.exit(0 if sys.version_info >= (3, 8) else 3)'
  status=$?
  PROVEN_VERSION="$(head -n 1 "$out" 2>/dev/null || true)"
  rm -f "$out"
  case "$status" in
    0) PROVEN_PYTHON="$resolved"; return 0 ;;
    3) PROVEN_ERROR="$resolved is Python $PROVEN_VERSION; the hooks need 3.8 or later" ;;
    124) PROVEN_ERROR="$resolved did not start within ${INTERPRETER_TIMEOUT}s" ;;
    *) PROVEN_ERROR="$resolved exited $status instead of running Python" ;;
  esac
  PROVEN_VERSION=""
  return 1
}

# recorded_interpreter FILE...: the absolute interpreter path the first hook command in these files names, as
# install.sh records it after the evidence prefix (JSON-escaped or not); nothing for a command naming python3.
recorded_interpreter() {
  local f found
  for f in "$@"; do
    [ -f "$f" ] || continue
    found="$(sed -nE 's#.*evidence\.jsonl\\?" \\?"(/[^"\\]+)\\?" .*#\1#p' "$f" 2>/dev/null | head -n 1)"
    [ -n "$found" ] && { printf '%s\n' "$found"; return 0; }
  done
  return 0
}
