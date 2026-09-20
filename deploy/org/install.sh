#!/usr/bin/env bash
# Place the Catpilot guardrails on one machine the way an organization would: root-owned files in
# the admin-managed locations that Claude Code and Codex CLI read above every user setting.
# Run as an administrator (sudo) from a checkout of this repository, on macOS or Linux.
#
#   sudo deploy/org/install.sh --server-url https://mcp.example.com/mcp [--skills safe-building,security-core] [--managed-mcp-json]
#
# What it does, and nothing else:
#   Claude Code  hooks copied to <managed dir>/catpilot-guardrails/hooks/, managed-settings.json written
#                from deploy/org/claude-code/managed-settings.json with the server URL substituted (only
#                when no managed-settings.json exists; otherwise it prints the JSON for you to merge),
#                skills copied to <managed dir>/.claude/skills/<name>/; with --managed-mcp-json, the fixed-set
#                managed-mcp.json is written too (then only the servers it lists load in CLI sessions)
#   Codex CLI    /etc/codex/managed_config.toml written from deploy/org/codex/managed_config.toml (only
#                when absent; otherwise printed for you to merge), skills copied to /etc/codex/skills/<name>/
# It does not touch user settings, does not restart anything, and does not send anything anywhere.
# Windows paths differ and are not handled here; see docs/DEPLOY_ORG.md.
set -euo pipefail

SERVER_URL=""
SKILLS="safe-building,security-core"
MANAGED_MCP_JSON=0
while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="$2"; shift 2 ;;
    --skills) SKILLS="$2"; shift 2 ;;
    --managed-mcp-json) MANAGED_MCP_JSON=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SERVER_URL" ] || { echo "--server-url is required (your own server; the public endpoint serves generic defaults only)" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo: the managed locations are root-owned on purpose" >&2; exit 2; }

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
case "$(uname -s)" in
  Darwin) CC_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux) CC_DIR="/etc/claude-code" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
CODEX_DIR="/etc/codex"

install_skill() {  # $1 = destination root
  local name; for name in ${SKILLS//,/ }; do
    local src="$REPO/skills/catpilot-$name"
    [ -d "$src" ] || { echo "no such skill: $src" >&2; exit 2; }
    rm -rf "$1/catpilot-$name"; mkdir -p "$1"; cp -R "$src" "$1/catpilot-$name"
    chmod -R a+rX "$1/catpilot-$name"; echo "skill   $1/catpilot-$name"
  done
}

# Claude Code: hooks, managed settings, skills
mkdir -p "$CC_DIR/catpilot-guardrails/hooks"
cp "$REPO/hooks/claude-code/pretooluse-secrets.py" "$REPO/hooks/claude-code/pretooluse-write-private-key.py" "$CC_DIR/catpilot-guardrails/hooks/"
chmod 644 "$CC_DIR/catpilot-guardrails/hooks/"*.py; echo "hooks   $CC_DIR/catpilot-guardrails/hooks/"
SETTINGS_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" -e "s#/Library/Application Support/ClaudeCode#$CC_DIR#g" "$REPO/deploy/org/claude-code/managed-settings.json")"
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

# Codex CLI: managed defaults, skills
mkdir -p "$CODEX_DIR"
CODEX_TOML="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/codex/managed_config.toml")"
if [ -e "$CODEX_DIR/managed_config.toml" ]; then
  echo "exists  $CODEX_DIR/managed_config.toml (not overwritten); merge this into it:"; echo "$CODEX_TOML"
else
  printf '%s\n' "$CODEX_TOML" > "$CODEX_DIR/managed_config.toml"; chmod 644 "$CODEX_DIR/managed_config.toml"; echo "policy  $CODEX_DIR/managed_config.toml"
fi
install_skill "$CODEX_DIR/skills"

echo
echo "Done. Verify on this machine as a normal user: deploy/org/verify.sh, then the checks in docs/DEPLOY_ORG.md."
