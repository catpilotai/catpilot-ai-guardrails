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

# resolve_path PATH: PATH with every symlink followed, absolute (realpath(1) is not on every macOS).
resolve_path() {
  local p="$1" target n=0
  while [ -L "$p" ] && [ "$n" -lt 40 ]; do
    target="$(readlink "$p")"
    case "$target" in /*) p="$target" ;; *) p="$(dirname "$p")/$target" ;; esac
    n=$((n + 1))
  done
  printf '%s/%s\n' "$(cd -P "$(dirname "$p")" 2>/dev/null && pwd)" "$(basename "$p")"
}

# unprotected_entry PATH: the first of PATH and its parent directories that someone other than root can change: not
# owned by root, or writable by its group (unless the group is root's, gid 0) or by everyone. A symlink's own mode
# does not matter (its directory decides who can replace it). Running as a non-root user (CATPILOT_ALLOW_NONROOT,
# tests only), that user and its groups also count as root's. Prints "PATH (reason)", or nothing.
unprotected_entry() {
  local p="$1" listing perms uid gid me groups=" 0 "
  me="$(id -u)"
  [ "$me" = 0 ] || groups=" 0 $(id -G) "
  while :; do
    listing="$(ls -ldn -- "$p" 2>/dev/null)" || { printf '%s (cannot be read)\n' "$p"; return 0; }
    perms="${listing%% *}"
    uid="$(printf '%s\n' "$listing" | awk '{print $3}')"
    gid="$(printf '%s\n' "$listing" | awk '{print $4}')"
    case "$perms" in
      l*) ;;
      *)
        if [ "$uid" != 0 ] && [ "$uid" != "$me" ]; then printf '%s (owned by uid %s)\n' "$p" "$uid"; return 0; fi
        if [ "${perms:5:1}" = w ] && [ "${groups#* $gid }" = "$groups" ]; then printf '%s (writable by group %s)\n' "$p" "$gid"; return 0; fi
        if [ "${perms:8:1}" = w ]; then printf '%s (writable by everyone)\n' "$p"; return 0; fi
        ;;
    esac
    [ "$p" = / ] && return 0
    p="$(dirname "$p")"
  done
}

# protected_interpreter PATH: true when neither PATH (as the hook commands name it) nor the file it resolves to, nor
# any directory above either, can be changed by anyone but root; otherwise PROVEN_ERROR says which one.
protected_interpreter() {
  local found
  found="$(unprotected_entry "$1")"
  [ -n "$found" ] || found="$(unprotected_entry "$(resolve_path "$1")")"
  if [ -n "$found" ]; then
    PROVEN_ERROR="$found can be changed by an account other than root, and every person's hooks would run what it holds"
    return 1
  fi
  return 0
}

# managed_candidates SETTINGS_TEMPLATE: every managed file install.sh may have written, in SETTINGS_CANDIDATES,
# REQUIREMENTS_CANDIDATES and COPILOT_CANDIDATES: each variant (with and without the company rules and their
# enforcement), naming python3 (an earlier install) or RECORDED_PYTHON. Needs PYTHON_BIN, RULES_FILES, CC_DIR,
# CODEX_DIR and COPILOT_DIR. uninstall.sh removes such a file; install.sh replaces it.
managed_candidates() {
  local template="$1" interp variant
  SETTINGS_CANDIDATES=("$template")
  REQUIREMENTS_CANDIDATES=()
  COPILOT_CANDIDATES=()
  for interp in python3 ${RECORDED_PYTHON:+"$RECORDED_PYTHON"}; do
    CANDIDATE_PY_ARGS=()
    [ "$interp" = python3 ] || CANDIDATE_PY_ARGS=(--python "$interp")
    COPILOT_CANDIDATES+=("$(candidate copilot-policy --copilot-dir "$COPILOT_DIR")" "$(candidate copilot-policy --copilot-dir "$COPILOT_DIR" --enforce)")
    for variant in --no-rules "" --enforce; do
      SETTINGS_CANDIDATES+=("$(printf '%s\n' "$template" | candidate settings --cc-dir "$CC_DIR" ${variant:+"$variant"})")
      REQUIREMENTS_CANDIDATES+=("$(candidate requirements --codex-dir "$CODEX_DIR" ${variant:+"$variant"})")
    done
  done
}
candidate() { "$PYTHON_BIN" "$RULES_FILES" ${CANDIDATE_PY_ARGS[@]+"${CANDIDATE_PY_ARGS[@]}"} "$@" 2>/dev/null || true; }
