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
#                With no --overlay, nothing about session-start rules is placed or registered.
# It does not touch user settings, does not restart anything, and does not send anything anywhere.
# Windows paths differ and are not handled here; see docs/DEPLOY_ORG.md.
set -euo pipefail

SERVER_URL=""
SKILLS="safe-building,security-core"
MANAGED_MCP_JSON=0
OVERLAY_FILE=""
ALLOW_HOSTS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="$2"; shift 2 ;;
    --skills) SKILLS="$2"; shift 2 ;;
    --managed-mcp-json) MANAGED_MCP_JSON=1; shift ;;
    --overlay) OVERLAY_FILE="$2"; shift 2 ;;
    --allow-host) ALLOW_HOSTS+=("--allow-host" "$2"); shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SERVER_URL" ] || { echo "--server-url is required (your own server; the public endpoint serves generic defaults only)" >&2; exit 2; }
if [ "${CATPILOT_ALLOW_NONROOT:-0}" != "1" ]; then
  [ "$(id -u)" -eq 0 ] || { echo "run with sudo: the managed locations are root-owned on purpose" >&2; exit 2; }
fi

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
case "$(uname -s)" in
  Darwin) DEFAULT_CC_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux) DEFAULT_CC_DIR="/etc/claude-code" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
CC_DIR="${CATPILOT_CC_DIR:-$DEFAULT_CC_DIR}"
CODEX_DIR="${CATPILOT_CODEX_DIR:-/etc/codex}"
RULES_FILES="$REPO/deploy/org/session_start_files.py"

PRIVATE_TMP=""
HOSTS_DIR=""
PYTHON_BIN="${PYTHON_BIN:-python3}"
cleanup() { [ -n "$PRIVATE_TMP" ] && rm -rf "$PRIVATE_TMP" || true; }
trap cleanup EXIT

if [ -n "$OVERLAY_FILE" ]; then
  [ -f "$OVERLAY_FILE" ] || { echo "no such overlay file: $OVERLAY_FILE" >&2; exit 2; }
  PRIVATE_TMP="$(mktemp -d "${TMPDIR:-/tmp}/catpilot-private-bundle.XXXXXX")"
  "$PYTHON_BIN" "$REPO/tools/bundle.py" --overlay "$OVERLAY_FILE" --private-out "$PRIVATE_TMP" ${ALLOW_HOSTS[@]+"${ALLOW_HOSTS[@]}"}
  HOSTS_DIR="$(find "$PRIVATE_TMP" -maxdepth 1 -type d -name 'catpilot-safe-building-*-hosts' | head -n 1)"
  for f in company-checklist.md company-checklist.json; do
    [ -n "$HOSTS_DIR" ] && [ -f "$HOSTS_DIR/$f" ] || { echo "the private build wrote no $f, which the session-start hooks read" >&2; exit 2; }
  done
fi

# The managed files are generated before anything is written, so a value that cannot be written safely stops
# the install before it changes anything on the machine.
SETTINGS_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" -e "s#/Library/Application Support/ClaudeCode#$CC_DIR#g" "$REPO/deploy/org/claude-code/managed-settings.json")"
CODEX_TOML="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/codex/managed_config.toml")"
"$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1 || {
  echo "$PYTHON_BIN did not run as Python 3.8 or later; it writes /etc/codex/requirements.toml. (The hooks run python3 from each person's PATH; verify.sh checks that one.)" >&2
  echo "Set PYTHON_BIN to one, for example: sudo PYTHON_BIN=/opt/homebrew/bin/python3 $0 ..." >&2
  exit 2
}
if [ -n "$HOSTS_DIR" ]; then
  # The SessionStart hook is added to the parsed settings and written out as JSON, never spliced into the text.
  SETTINGS_JSON="$(printf '%s\n' "$SETTINGS_JSON" | "$PYTHON_BIN" "$RULES_FILES" settings --cc-dir "$CC_DIR")"
  REQUIREMENTS_TOML="$("$PYTHON_BIN" "$RULES_FILES" requirements --codex-dir "$CODEX_DIR")"
else
  REQUIREMENTS_TOML="$("$PYTHON_BIN" "$RULES_FILES" requirements --codex-dir "$CODEX_DIR" --no-rules)"
fi

# install_package HOOKS_DIR: the catpilot_guard package the hook scripts import from beside them. Its .py files
# only, so no __pycache__ or .pyc from the checkout comes along, replacing any earlier copy, so a module a newer
# release dropped does not linger.
install_package() {
  local dir="$1/catpilot_guard"
  rm -rf "$dir"; mkdir -p "$dir"
  cp "$REPO"/catpilot_guard/*.py "$dir/"
  chmod 755 "$dir"; chmod 644 "$dir/"*.py; echo "package $dir/"
}

# install_rules MANAGED_DIR: the session-start script and the two files it reads, under catpilot-guardrails/.
install_rules() {
  local root="$1/catpilot-guardrails"
  mkdir -p "$root/hooks" "$root/instructions"
  cp "$REPO/hooks/session-start/catpilot-company-rules.py" "$root/hooks/"
  cp "$HOSTS_DIR/company-checklist.md" "$HOSTS_DIR/company-checklist.json" "$root/instructions/"
  chmod 755 "$root" "$root/hooks" "$root/instructions"
  chmod 644 "$root/hooks/catpilot-company-rules.py" "$root/instructions/company-checklist.md" "$root/instructions/company-checklist.json"
  echo "rules   $root/ (hooks/catpilot-company-rules.py, instructions/company-checklist.md and .json)"
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

# Claude Code: hooks, managed settings, skills
mkdir -p "$CC_DIR/catpilot-guardrails/hooks"
cp "$REPO/hooks/claude-code/pretooluse-secrets.py" \
   "$REPO/hooks/claude-code/pretooluse-write-secrets.py" \
   "$REPO/hooks/claude-code/pretooluse-write-private-key.py" \
   "$REPO/hooks/claude-code/pretooluse-destructive-ops.py" \
   "$CC_DIR/catpilot-guardrails/hooks/"
chmod 644 "$CC_DIR/catpilot-guardrails/hooks/"*.py; echo "hooks   $CC_DIR/catpilot-guardrails/hooks/"
# The hooks are shims that import catpilot_guard from beside themselves.
install_package "$CC_DIR/catpilot-guardrails/hooks"

if [ -n "$HOSTS_DIR" ]; then
  mkdir -p "$CC_DIR/catpilot-guardrails/instructions"
  for f in CLAUDE.md AGENTS.md chatgpt-project-instructions.md copilot-agent-instructions.md; do
    [ -f "$HOSTS_DIR/$f" ] && cp "$HOSTS_DIR/$f" "$CC_DIR/catpilot-guardrails/instructions/$f"
  done
  chmod 644 "$CC_DIR/catpilot-guardrails/instructions/"* 2>/dev/null || true
  echo "blocks  $CC_DIR/catpilot-guardrails/instructions/"
  # Company rules at session start: the block in the managed CLAUDE.md, a status from the SessionStart hook.
  install_rules "$CC_DIR"
  "$PYTHON_BIN" "$RULES_FILES" claude-md-place --block "$CC_DIR/catpilot-guardrails/instructions/company-checklist.md" --target "$CC_DIR/CLAUDE.md"
elif [ -e "$CC_DIR/catpilot-guardrails/instructions/company-checklist.json" ] || [ -e "$CODEX_DIR/catpilot-guardrails/instructions/company-checklist.json" ]; then
  echo "note    company rules at session start from an earlier --overlay install are still in place, unchanged;"
  echo "        install with --overlay to update them, or run uninstall.sh to remove them"
fi

if [ -e "$CC_DIR/managed-settings.json" ]; then
  echo "exists  $CC_DIR/managed-settings.json (not overwritten); merge these keys into it:"; echo "$SETTINGS_JSON"
else
  printf '%s\n' "$SETTINGS_JSON" > "$CC_DIR/managed-settings.json"; chmod 644 "$CC_DIR/managed-settings.json"; echo "policy  $CC_DIR/managed-settings.json"
fi
install_skill "$CC_DIR/.claude/skills"
if [ "$MANAGED_MCP_JSON" -eq 1 ]; then
  MCP_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/claude-code/managed-mcp.json")"
  if [ -e "$CC_DIR/managed-mcp.json" ]; then
    echo "exists  $CC_DIR/managed-mcp.json (not overwritten); merge this into it:"; echo "$MCP_JSON"
  else
    printf '%s\n' "$MCP_JSON" > "$CC_DIR/managed-mcp.json"; chmod 644 "$CC_DIR/managed-mcp.json"; echo "policy  $CC_DIR/managed-mcp.json"
  fi
fi

# Codex CLI: managed defaults, skills, the PreToolUse hooks and the requirements.toml that declares them; with
# --overlay, also the session-start script and the rules it reads
mkdir -p "$CODEX_DIR"
if [ -e "$CODEX_DIR/managed_config.toml" ]; then
  echo "exists  $CODEX_DIR/managed_config.toml (not overwritten); merge this into it:"; echo "$CODEX_TOML"
else
  printf '%s\n' "$CODEX_TOML" > "$CODEX_DIR/managed_config.toml"; chmod 644 "$CODEX_DIR/managed_config.toml"; echo "policy  $CODEX_DIR/managed_config.toml"
fi
install_skill "$CODEX_DIR/skills"
# A copy of its own, so each tool reads only from its own managed directory. The hooks and their package go in
# hooks/, the managed_dir that requirements.toml names; Codex loads managed hooks only when that directory exists.
# Codex sends file edits as apply_patch, so the legacy pretooluse-write-private-key.py name is not needed here.
mkdir -p "$CODEX_DIR/catpilot-guardrails/hooks"
cp "$REPO/hooks/claude-code/pretooluse-secrets.py" \
   "$REPO/hooks/claude-code/pretooluse-write-secrets.py" \
   "$REPO/hooks/claude-code/pretooluse-destructive-ops.py" \
   "$CODEX_DIR/catpilot-guardrails/hooks/"
chmod 755 "$CODEX_DIR/catpilot-guardrails" "$CODEX_DIR/catpilot-guardrails/hooks"
chmod 644 "$CODEX_DIR/catpilot-guardrails/hooks/"*.py; echo "hooks   $CODEX_DIR/catpilot-guardrails/hooks/"
install_package "$CODEX_DIR/catpilot-guardrails/hooks"
[ -n "$HOSTS_DIR" ] && install_rules "$CODEX_DIR"
if [ -e "$CODEX_DIR/requirements.toml" ] || [ -L "$CODEX_DIR/requirements.toml" ]; then
  echo "exists  $CODEX_DIR/requirements.toml (not overwritten); merge this into it, keeping one [features] and one [hooks] table:"; echo "$REQUIREMENTS_TOML"
else
  printf '%s\n' "$REQUIREMENTS_TOML" > "$CODEX_DIR/requirements.toml"; chmod 644 "$CODEX_DIR/requirements.toml"; echo "policy  $CODEX_DIR/requirements.toml"
fi

echo
echo "Done. Verify on this machine as a normal user: deploy/org/verify.sh, then the checks in docs/DEPLOY_ORG.md."
