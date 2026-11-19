#!/usr/bin/env bash
# Place the Catpilot guardrails on one machine the way an organization would: root-owned files in
# the admin-managed locations that Claude Code and Codex CLI read above every user setting.
# Run as an administrator (sudo) from a checkout of this repository, on macOS or Linux.
#
#   sudo deploy/org/install.sh --server-url https://mcp.example.com/mcp \
#     [--skills safe-building,security-core] [--managed-mcp-json] \
#     [--overlay /private/path/overlay.yaml] [--allow-host intranet.example.org]
#
# What it does, and nothing else:
#   Claude Code  hooks copied to <managed dir>/catpilot-guardrails/hooks/, with the catpilot_guard package they run
#                beside them in hooks/catpilot_guard/ (its .py files only), managed-settings.json written
#                from deploy/org/claude-code/managed-settings.json with the server URL substituted (only
#                when no managed-settings.json exists; otherwise it prints the JSON for you to merge),
#                skills copied to <managed dir>/.claude/skills/<name>/; with --managed-mcp-json, the fixed-set
#                managed-mcp.json is written too (then only the servers it lists load in CLI sessions)
#   Codex CLI    /etc/codex/managed_config.toml written from deploy/org/codex/managed_config.toml (only
#                when absent; otherwise printed for you to merge), skills copied to /etc/codex/skills/<name>/,
#                the secret, file-write and destructive-operation hooks and their catpilot_guard package copied
#                to /etc/codex/catpilot-guardrails/hooks/, and /etc/codex/requirements.toml declaring them as
#                managed PreToolUse hooks (--host codex) with [features].hooks = true (only when absent;
#                otherwise printed for you to merge). Generating it needs Python 3.8+ (PYTHON_BIN), as the
#                hooks themselves do.
#   Copilot CLI  the secret, file-write and destructive-operation hooks and their catpilot_guard package copied to
#                /etc/github-copilot/catpilot-guardrails/hooks/, and /etc/github-copilot/policy.d/catpilot-guardrails.json
#                declaring them as policy PreToolUse hooks (--host copilot-cli), which people cannot turn off (only
#                when absent; otherwise printed for you to merge). Copilot loads a policy file only when root owns it.
#   With --overlay: validates and builds the private company bundle and host blocks into a temporary directory
#                outside the repository, then installs the private safe-building bundle and places the rendered
#                company CLAUDE.md and AGENTS.md blocks under <managed dir>/catpilot-guardrails/instructions/.
#                It also puts the company rules in front of the model at session start (advice, not enforcement):
#     Claude Code  the rules block, company-checklist.md, in the managed CLAUDE.md between the lines
#                  <!-- catpilot-company-rules:begin --> and <!-- catpilot-company-rules:end -->: the file is
#                  created when absent; when it has those markers, only the marked section is replaced; without
#                  them it is left alone and the section is printed for you to merge. A SessionStart hook,
#                  hooks/catpilot-company-rules.py --host claude-code, goes into managed-settings.json (in the
#                  JSON written or printed above) and reports at each session start whether the rules are current.
#     Codex CLI    the same script and the rules under /etc/codex/catpilot-guardrails/, and, in the
#                  requirements.toml above, the script as a managed SessionStart hook (--host codex) that gives
#                  the model the block.
#                When the rules file has an enforcement section, it is also compiled
#                (tools/validate_overlay.py compile) into the JSON policy the company-rules hook reads, placed
#                root-owned at <managed dir>/catpilot-guardrails/policy/company-policy.json for each tool, and the
#                hook, hooks/pretooluse-company-rules.py --policy <that file>, is registered on Bash in
#                managed-settings.json, requirements.toml and the Copilot CLI policy file (in the files written or
#                printed above). It enforces the company's own rules in monitor, ask or block; ask acts as block on
#                Codex. The session-start rules are not placed for Copilot CLI.
#                With no --overlay, nothing about session-start rules or company enforcement is placed or registered.
# The interpreter: before anything is written, PYTHON_BIN (default python3) is run with a version check and must
# be Python 3.8 or later, not the macOS Command Line Tools stub; otherwise nothing is installed. Its absolute path is
# recorded in every hook command, so the hooks do not depend on a session's PATH (issue #97, option 1).
# The hooks as one file (issue #97, option 2), the default: in place of the hook scripts and the catpilot_guard package
# described above, each tool's catpilot-guardrails/hooks/ gets catpilot-guard.pyz, built from this checkout by
# tools/build_zipapp.py (reproducible: the same sources give the same bytes), mode 444 and owned by root, with its
# SHA-256 recorded beside it in catpilot-guard.pyz.sha256; every hook command runs the recorded interpreter on it with
# the check's name (secrets, write-secrets, destructive, company-rules, session-start). --package-tree (or
# CATPILOT_PACKAGE_TREE=1) places the hook scripts and the package instead, as earlier releases did; it is kept for
# this release only. Switching layouts removes the files the other layout placed, unless a managed file this run kept
# still runs them. Run it again to update: hooks and package or zipapp are replaced, an unchanged managed file is
# reported current, one an earlier install wrote is replaced, any other is printed.
# It does not touch user settings, does not restart anything, and does not send anything anywhere.
# On Windows, use deploy/org/install.ps1; see docs/DEPLOY_ORG.md.
set -euo pipefail

SERVER_URL=""
SKILLS="safe-building,security-core"
MANAGED_MCP_JSON=0
OVERLAY_FILE=""
ALLOW_HOSTS=()
ALLOW_UNPROTECTED_PYTHON="${CATPILOT_ALLOW_UNPROTECTED_PYTHON:-0}"  # the same as --allow-unprotected-python
PACKAGE_TREE="${CATPILOT_PACKAGE_TREE:-0}"  # the same as --package-tree
while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="$2"; shift 2 ;;
    --skills) SKILLS="$2"; shift 2 ;;
    --managed-mcp-json) MANAGED_MCP_JSON=1; shift ;;
    --overlay) OVERLAY_FILE="$2"; shift 2 ;;
    --allow-host) ALLOW_HOSTS+=("--allow-host" "$2"); shift 2 ;;
    --allow-unprotected-python) ALLOW_UNPROTECTED_PYTHON=1; shift ;;
    --package-tree) PACKAGE_TREE=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SERVER_URL" ] || { echo "--server-url is required (your own server; the public endpoint serves generic defaults only)" >&2; exit 2; }
if [ "${CATPILOT_ALLOW_NONROOT:-0}" != "1" ]; then
  [ "$(id -u)" -eq 0 ] || { echo "run with sudo: the managed locations are root-owned on purpose" >&2; exit 2; }
fi

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
# shellcheck source=interpreter.sh
. "$REPO/deploy/org/interpreter.sh"
case "$(uname -s)" in
  Darwin) DEFAULT_CC_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux) DEFAULT_CC_DIR="/etc/claude-code" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
CC_DIR="${CATPILOT_CC_DIR:-$DEFAULT_CC_DIR}"
CODEX_DIR="${CATPILOT_CODEX_DIR:-/etc/codex}"
COPILOT_DIR="${CATPILOT_COPILOT_DIR:-/etc/github-copilot}"
RULES_FILES="$REPO/deploy/org/session_start_files.py"

PRIVATE_TMP=""
HOSTS_DIR=""
POLICY_FILE=""
# The interpreter every hook command names, proved to run Python 3.8+ before anything is written (interpreter.sh).
if ! prove_interpreter "${PYTHON_BIN:-python3}"; then
  echo "Not installed: $PROVEN_ERROR." >&2
  echo "The hooks run with the interpreter install.sh records; one that cannot start blocks every command (Claude Code)" >&2
  echo "or lets them run unchecked (other hosts). Install Python 3.8 or later and name it, for example:" >&2
  echo "  sudo PYTHON_BIN=/opt/homebrew/bin/python3 $0 --server-url ..." >&2
  exit 2
fi
# Run as root through sudo: the interpreter must also run for the person who ran sudo (a per-user Python would not).
if [ "$(id -u)" -eq 0 ] && [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] && command -v sudo >/dev/null 2>&1; then
  if ! sudo -u "$SUDO_USER" -- "$PROVEN_PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    echo "Not installed: $PROVEN_PYTHON runs as root but not as $SUDO_USER; the hooks run as each person. Name an interpreter every account can run." >&2
    exit 2
  fi
fi
# Whoever can change the interpreter, or a directory above it, runs code in every person's hooks: a Homebrew Python
# under /opt/homebrew owned by one person, a virtual environment in a home directory. Refused unless root alone can
# change it, run as root by sudo, Jamf or any MDM alike; --allow-unprotected-python is for an admin who has decided
# otherwise.
if ! protected_interpreter "$PROVEN_PYTHON"; then
  if [ "$ALLOW_UNPROTECTED_PYTHON" -eq 1 ]; then
    echo "warning $PROVEN_ERROR (--allow-unprotected-python)" >&2
  else
    echo "Not installed: $PROVEN_ERROR." >&2
    echo "Name an interpreter only root can change (for example a python.org or distribution package), or pass" >&2
    echo "--allow-unprotected-python if you accept that its owner can change what every person's hooks run." >&2
    exit 2
  fi
fi
PYTHON_BIN="$PROVEN_PYTHON"
echo "python  $PYTHON_BIN (Python $PROVEN_VERSION), recorded in every hook command"
BUILD_TMP=""
cleanup() {
  [ -n "$PRIVATE_TMP" ] && rm -rf "$PRIVATE_TMP"
  [ -n "$BUILD_TMP" ] && rm -rf "$BUILD_TMP"
  return 0
}
trap cleanup EXIT

# The zipapp, built before anything is written; its SHA-256 is recorded beside each copy (install_hooks).
ZIPAPP=catpilot-guard.pyz
ZIPAPP_SHA256=""
LAYOUT=(--zipapp)
if [ "$PACKAGE_TREE" -eq 1 ]; then
  LAYOUT=()
  echo "layout  package tree (--package-tree): hook scripts and the catpilot_guard package, as earlier releases"
else
  BUILD_TMP="$(mktemp -d "${TMPDIR:-/tmp}/catpilot-zipapp.XXXXXX")"
  ZIPAPP_SHA256="$("$PYTHON_BIN" "$REPO/tools/build_zipapp.py" --out "$BUILD_TMP/$ZIPAPP" | awk '{print $1}')" || ZIPAPP_SHA256=""
  if ! printf '%s' "$ZIPAPP_SHA256" | grep -Eq '^[0-9a-f]{64}$' || [ ! -f "$BUILD_TMP/$ZIPAPP" ]; then
    echo "Not installed: tools/build_zipapp.py did not build $ZIPAPP" >&2; exit 2
  fi
  echo "zipapp  $ZIPAPP built from this checkout, SHA-256 $ZIPAPP_SHA256, recorded beside each copy"
fi

if [ -n "$OVERLAY_FILE" ]; then
  [ -f "$OVERLAY_FILE" ] || { echo "no such overlay file: $OVERLAY_FILE" >&2; exit 2; }
  PRIVATE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/catpilot-private-bundle.XXXXXX")"
  "$PYTHON_BIN" "$REPO/tools/bundle.py" --overlay "$OVERLAY_FILE" --private-out "$PRIVATE_TMP" ${ALLOW_HOSTS[@]+"${ALLOW_HOSTS[@]}"}
  HOSTS_DIR="$(find "$PRIVATE_TMP" -maxdepth 1 -type d -name 'catpilot-safe-building-*-hosts' | head -n 1)"
  for f in company-checklist.md company-checklist.json; do
    [ -n "$HOSTS_DIR" ] && [ -f "$HOSTS_DIR/$f" ] || { echo "the private build wrote no $f, which the session-start hooks read" >&2; exit 2; }
  done
  # The enforcement section, compiled for the company-rules hook. A rules file without one writes no policy.
  "$PYTHON_BIN" "$REPO/tools/validate_overlay.py" compile "$OVERLAY_FILE" --out "$PRIVATE_TMP/company-policy.json" ${ALLOW_HOSTS[@]+"${ALLOW_HOSTS[@]}"}
  [ -f "$PRIVATE_TMP/company-policy.json" ] && POLICY_FILE="$PRIVATE_TMP/company-policy.json"
fi

# The managed files are generated before anything is written, so a value that cannot be written safely stops
# the install before it changes anything on the machine.
SETTINGS_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" -e "s#/Library/Application Support/ClaudeCode#$CC_DIR#g" "$REPO/deploy/org/claude-code/managed-settings.json")"
CODEX_TOML="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/codex/managed_config.toml")"
# Every hook command names the proved interpreter by absolute path. The settings are parsed and written out as JSON,
# never spliced into the text; with --overlay, the SessionStart hook, and with a compiled policy the company-rules
# hook, are added the same way.
TEMPLATE_JSON="$SETTINGS_JSON"
VARIANT=(--no-rules)
COPILOT_VARIANT=()
if [ -n "$HOSTS_DIR" ]; then
  VARIANT=()
  [ -n "$POLICY_FILE" ] && VARIANT=(--enforce)
fi
[ -n "$POLICY_FILE" ] && COPILOT_VARIANT=(--enforce)
# generate INTERPRETER [LAYOUT]: the three generated files of this variant naming INTERPRETER (python3: the earlier
# form), in LAYOUT (--zipapp, or empty for the package tree; this run's when omitted), in GENERATED_SETTINGS,
# GENERATED_REQUIREMENTS and GENERATED_COPILOT.
generate() {
  local args=(--python "$1")
  [ "$1" = python3 ] && args=()
  if [ $# -ge 2 ]; then
    [ -n "$2" ] && args+=("$2")
  else
    args+=(${LAYOUT[@]+"${LAYOUT[@]}"})
  fi
  GENERATED_SETTINGS="$(printf '%s\n' "$TEMPLATE_JSON" | "$PYTHON_BIN" "$RULES_FILES" ${args[@]+"${args[@]}"} settings --cc-dir "$CC_DIR" ${VARIANT[@]+"${VARIANT[@]}"})" || return 1
  GENERATED_REQUIREMENTS="$("$PYTHON_BIN" "$RULES_FILES" ${args[@]+"${args[@]}"} requirements --codex-dir "$CODEX_DIR" ${VARIANT[@]+"${VARIANT[@]}"})" || return 1
  GENERATED_COPILOT="$("$PYTHON_BIN" "$RULES_FILES" ${args[@]+"${args[@]}"} copilot-policy --copilot-dir "$COPILOT_DIR" ${COPILOT_VARIANT[@]+"${COPILOT_VARIANT[@]}"})" || return 1
}
generate "$PYTHON_BIN" || exit 2
SETTINGS_JSON="$GENERATED_SETTINGS"
REQUIREMENTS_TOML="$GENERATED_REQUIREMENTS"
COPILOT_POLICY_JSON="$GENERATED_COPILOT"
# What an earlier install wrote for the same options, naming the interpreter it recorded or python3: ours, so a
# re-install with another interpreter replaces it (place_managed) instead of printing a merge. A file written with other
# options (with or without --overlay, say) is not replaced: the options decide what it should hold, as before.
RECORDED_PYTHON="$(recorded_interpreter "$CC_DIR/managed-settings.json" "$CODEX_DIR/requirements.toml" "$COPILOT_DIR/policy.d/catpilot-guardrails.json")"
SETTINGS_CANDIDATES=()
REQUIREMENTS_CANDIDATES=()
COPILOT_CANDIDATES=()
[ "${VARIANT[*]-}" = --no-rules ] && SETTINGS_CANDIDATES+=("$TEMPLATE_JSON")
# In either layout, so a re-install that switches between the zipapp and the package tree replaces the earlier file.
for interp in python3 ${RECORDED_PYTHON:+"$RECORDED_PYTHON"}; do
  for layout in "" --zipapp; do
    if generate "$interp" "$layout" 2>/dev/null; then
      SETTINGS_CANDIDATES+=("$GENERATED_SETTINGS")
      REQUIREMENTS_CANDIDATES+=("$GENERATED_REQUIREMENTS")
      COPILOT_CANDIDATES+=("$GENERATED_COPILOT")
    fi
  done
done

# place_managed FILE CONTENT VERB [OURS...]: write FILE when absent; an identical file is current (a re-run changes
# nothing); one that is exactly what an earlier install wrote (OURS) is replaced; any other is left alone and the
# content printed for a merge.
place_managed() {
  local file="$1" content="$2" verb="$3" existing ours
  shift 3
  if [ -e "$file" ] || [ -L "$file" ]; then
    existing=""
    [ -f "$file" ] && [ ! -L "$file" ] && existing="$(cat "$file")"
    if [ -n "$existing" ] && [ "$existing" = "$content" ]; then
      echo "current $file"; return
    fi
    if [ -n "$existing" ]; then
      for ours in "$@"; do
        if [ -n "$ours" ] && [ "$existing" = "$ours" ]; then
          printf '%s\n' "$content" > "$file"; chmod 644 "$file"; echo "updated $file (an earlier install's; now this one's)"; return
        fi
      done
    fi
    echo "exists  $file (not overwritten); $verb:"; echo "$content"
  else
    printf '%s\n' "$content" > "$file"; chmod 644 "$file"; echo "policy  $file"
  fi
}

# install_package HOOKS_DIR: the catpilot_guard package the hook scripts import from beside them. Its .py files
# only, so no __pycache__ or .pyc from the checkout comes along, replacing any earlier copy, so a module a newer
# release dropped does not linger.
install_package() {
  local dir="$1/catpilot_guard"
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$REPO"/catpilot_guard/*.py "$dir/"
  chmod 755 "$dir"; chmod 644 "$dir/"*.py; echo "package $dir/"
}

# install_rules MANAGED_DIR: the session-start script (in the package tree; the zipapp holds it otherwise) and the two
# files it reads, under catpilot-guardrails/.
install_rules() {
  local root="$1/catpilot-guardrails"
  mkdir -p "$root/hooks" "$root/instructions"
  cp "$HOSTS_DIR/company-checklist.md" "$HOSTS_DIR/company-checklist.json" "$root/instructions/"
  chmod 755 "$root" "$root/hooks" "$root/instructions"
  chmod 644 "$root/instructions/company-checklist.md" "$root/instructions/company-checklist.json"
  if [ "$PACKAGE_TREE" -eq 1 ]; then
    cp "$REPO/hooks/session-start/catpilot-company-rules.py" "$root/hooks/"
    chmod 644 "$root/hooks/catpilot-company-rules.py"
    echo "rules   $root/ (hooks/catpilot-company-rules.py, instructions/company-checklist.md and .json)"
  else
    echo "rules   $root/instructions/ (company-checklist.md and .json, which $ZIPAPP session-start reads)"
  fi
}

# install_hooks HOOKS_DIR HOOK_FILE...: the checks a tool runs. The zipapp and its recorded SHA-256, each written
# beside its final name and renamed into place, so a session never runs a half-written file; or, with --package-tree,
# the hook scripts and the catpilot_guard package beside them.
install_hooks() {
  local dir="$1" name
  shift
  mkdir -p "$dir"; chmod 755 "$(dirname "$dir")" "$dir"
  if [ "$PACKAGE_TREE" -eq 1 ]; then
    for name in "$@"; do cp "$REPO/hooks/claude-code/$name" "$dir/"; chmod 644 "$dir/$name"; done
    echo "hooks   $dir/"
    install_package "$dir"
    return
  fi
  rm -f "$dir/.$ZIPAPP.new" "$dir/.$ZIPAPP.sha256.new"
  cp "$BUILD_TMP/$ZIPAPP" "$dir/.$ZIPAPP.new"
  printf '%s  %s\n' "$ZIPAPP_SHA256" "$ZIPAPP" > "$dir/.$ZIPAPP.sha256.new"
  chmod 444 "$dir/.$ZIPAPP.new" "$dir/.$ZIPAPP.sha256.new"
  if [ "$(id -u)" -eq 0 ]; then chown 0:0 "$dir/.$ZIPAPP.new" "$dir/.$ZIPAPP.sha256.new"; fi
  mv -f "$dir/.$ZIPAPP.new" "$dir/$ZIPAPP"
  mv -f "$dir/.$ZIPAPP.sha256.new" "$dir/$ZIPAPP.sha256"
  echo "zipapp  $dir/$ZIPAPP (SHA-256 recorded in $ZIPAPP.sha256)"
}

# The package tree's hook scripts, which an earlier install may have placed in a tool's hooks/ beside catpilot_guard/.
TREE_FILES=(pretooluse-secrets.py pretooluse-write-secrets.py pretooluse-write-private-key.py pretooluse-destructive-ops.py
            pretooluse-company-rules.py catpilot-company-rules.py)

# retire_other_layout HOOKS_DIR MANAGED_FILE...: once the tool's managed file is placed, remove what an install in the
# other layout placed in HOOKS_DIR, and only those files. While a managed file (one kept above as edited or not ours)
# still runs them, they stay: removing a file a hook command runs would block every command it covers, or let them
# run unchecked on a host that skips a hook it cannot start.
retire_other_layout() {
  local dir="$1" f name found="" names=()
  shift
  if [ "$PACKAGE_TREE" -eq 1 ]; then
    [ -e "$dir/$ZIPAPP" ] || [ -e "$dir/$ZIPAPP.sha256" ] || return 0
    names=("$ZIPAPP")
  else
    [ -e "$dir/catpilot_guard" ] && names=("${TREE_FILES[@]}")
    for name in "${TREE_FILES[@]}"; do [ -e "$dir/$name" ] && names=("${TREE_FILES[@]}"); done
    [ "${#names[@]}" -gt 0 ] || return 0
  fi
  for f in "$@"; do
    [ -f "$f" ] || continue
    for name in "${names[@]}"; do
      if grep -qF "$name" "$f" 2>/dev/null; then found="$f"; break 2; fi
    done
  done
  if [ -n "$found" ]; then
    echo "kept    the earlier install's files in $dir ($found still runs them; once it no longer does, run install.sh again)"
  elif [ "$PACKAGE_TREE" -eq 1 ]; then
    rm -f "$dir/$ZIPAPP" "$dir/$ZIPAPP.sha256"; echo "removed $dir/$ZIPAPP and its SHA-256 (an earlier install's; now the package tree)"
  else
    for name in "${TREE_FILES[@]}"; do rm -f "$dir/$name"; done
    rm -rf "$dir/catpilot_guard"
    echo "removed the package tree an earlier install placed in $dir (hook scripts and catpilot_guard/; now $ZIPAPP)"
  fi
}

# install_policy MANAGED_DIR: the compiled company policy the company-rules hook reads, under catpilot-guardrails/policy/,
# owned by whoever runs this (root) and writable only by them: the hook refuses a policy anyone else could have
# changed. A rules file without enforcement rules removes the policy an earlier install placed.
install_policy() {
  local dir="$1/catpilot-guardrails/policy"
  if [ -n "$POLICY_FILE" ]; then
    mkdir -p "$dir"; chmod 755 "$dir"
    cp "$POLICY_FILE" "$dir/company-policy.json"; chmod 644 "$dir/company-policy.json"
    echo "policy  $dir/company-policy.json (company enforcement rules for the company-rules hook)"
  elif [ -e "$dir" ]; then
    rm -rf "$dir"
    echo "removed $dir: this rules file has no enforcement rules. If a managed file kept above still runs"
    echo "        pretooluse-company-rules.py, remove that entry; until then it logs policy_error and enforces nothing"
  fi
}

install_skill() {  # $1 = destination root
  local name; for name in ${SKILLS//,/ }; do
    local src="$REPO/skills/catpilot-$name"
    local dst_name="catpilot-$name"
    if [ -n "$PRIVATE_TMP" ] && [ "$name" = "safe-building" ]; then
      local priv_dir
      priv_dir="$(find "$PRIVATE_TMP" -maxdepth 1 -type d -name 'catpilot-safe-building-*' ! -name '*-hosts' | head -n 1)"
      if [ -n "$priv_dir" ]; then
        src="$priv_dir"
        dst_name="$(basename "$priv_dir")"
      fi
    fi
    [ -d "$src" ] || { echo "no such skill: $src" >&2; exit 2; }
    rm -rf "$1/$dst_name"; mkdir -p "$1"; cp -R "$src" "$1/$dst_name"
    chmod -R a+rX "$1/$dst_name"; echo "skill   $1/$dst_name"
  done
}

# Claude Code: hooks, managed settings, skills. In the package tree the hooks are shims that import catpilot_guard
# from beside themselves.
install_hooks "$CC_DIR/catpilot-guardrails/hooks" pretooluse-secrets.py pretooluse-write-secrets.py \
  pretooluse-write-private-key.py pretooluse-destructive-ops.py pretooluse-company-rules.py

if [ -n "$HOSTS_DIR" ]; then
  mkdir -p "$CC_DIR/catpilot-guardrails/instructions"
  for f in CLAUDE.md AGENTS.md chatgpt-project-instructions.md copilot-agent-instructions.md; do
    [ -f "$HOSTS_DIR/$f" ] && cp "$HOSTS_DIR/$f" "$CC_DIR/catpilot-guardrails/instructions/$f"
  done
  chmod 644 "$CC_DIR/catpilot-guardrails/instructions/"* 2>/dev/null || true
  echo "blocks  $CC_DIR/catpilot-guardrails/instructions/"
  # Company rules at session start: the block in the managed CLAUDE.md, a status from the SessionStart hook.
  install_rules "$CC_DIR"
  install_policy "$CC_DIR"
  "$PYTHON_BIN" "$RULES_FILES" claude-md-place --block "$CC_DIR/catpilot-guardrails/instructions/company-checklist.md" --target "$CC_DIR/CLAUDE.md"
elif [ -e "$CC_DIR/catpilot-guardrails/instructions/company-checklist.json" ] || [ -e "$CODEX_DIR/catpilot-guardrails/instructions/company-checklist.json" ]; then
  echo "note    company rules at session start from an earlier --overlay install are still in place, unchanged;"
  echo "        install with --overlay to update them, or run uninstall.sh to remove them"
fi

place_managed "$CC_DIR/managed-settings.json" "$SETTINGS_JSON" "merge these keys into it" ${SETTINGS_CANDIDATES[@]+"${SETTINGS_CANDIDATES[@]}"}
retire_other_layout "$CC_DIR/catpilot-guardrails/hooks" "$CC_DIR/managed-settings.json"
install_skill "$CC_DIR/.claude/skills"
if [ "$MANAGED_MCP_JSON" -eq 1 ]; then
  MCP_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/claude-code/managed-mcp.json")"
  place_managed "$CC_DIR/managed-mcp.json" "$MCP_JSON" "merge this into it"
fi

# Codex CLI: managed defaults, skills, the PreToolUse hooks and the requirements.toml that declares them; with
# --overlay, also the session-start script and the rules it reads
mkdir -p "$CODEX_DIR"
place_managed "$CODEX_DIR/managed_config.toml" "$CODEX_TOML" "merge this into it"
install_skill "$CODEX_DIR/skills"
# A copy of its own, so each tool reads only from its own managed directory. The hooks and their package go in
# hooks/, the managed_dir that requirements.toml names; Codex loads managed hooks only when that directory exists.
# Codex sends file edits as apply_patch, so the legacy pretooluse-write-private-key.py name is not needed here.
install_hooks "$CODEX_DIR/catpilot-guardrails/hooks" pretooluse-secrets.py pretooluse-write-secrets.py \
  pretooluse-destructive-ops.py pretooluse-company-rules.py
if [ -n "$HOSTS_DIR" ]; then install_rules "$CODEX_DIR"; install_policy "$CODEX_DIR"; fi
place_managed "$CODEX_DIR/requirements.toml" "$REQUIREMENTS_TOML" "merge this into it, keeping one [features] and one [hooks] table" ${REQUIREMENTS_CANDIDATES[@]+"${REQUIREMENTS_CANDIDATES[@]}"}
retire_other_layout "$CODEX_DIR/catpilot-guardrails/hooks" "$CODEX_DIR/requirements.toml"

# Copilot CLI: the same three checks, and with a compiled policy the company-rules hook, as policy hooks. Copilot
# loads a policy file only when root owns it and no one else can write it; it reads them before user and project
# hooks, and people cannot turn them off.
install_hooks "$COPILOT_DIR/catpilot-guardrails/hooks" pretooluse-secrets.py pretooluse-write-secrets.py \
  pretooluse-destructive-ops.py pretooluse-company-rules.py
if [ -n "$HOSTS_DIR" ]; then install_policy "$COPILOT_DIR"; fi
# policy.d is created, mode 755, only when it does not exist: an existing directory, which may hold the
# organization's own policy files, keeps its owner and mode.
if [ ! -d "$COPILOT_DIR/policy.d" ]; then mkdir -p "$COPILOT_DIR/policy.d"; chmod 755 "$COPILOT_DIR/policy.d"; fi
place_managed "$COPILOT_DIR/policy.d/catpilot-guardrails.json" "$COPILOT_POLICY_JSON" "replace it with" ${COPILOT_CANDIDATES[@]+"${COPILOT_CANDIDATES[@]}"}
# On Copilot CLI any policy.d/*.json file may run the hooks, not only the one written above.
retire_other_layout "$COPILOT_DIR/catpilot-guardrails/hooks" "$COPILOT_DIR"/policy.d/*.json

echo
echo "Done. Verify on this machine as a normal user: deploy/org/verify.sh, then the checks in docs/DEPLOY_ORG.md."
