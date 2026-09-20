#!/usr/bin/env bash
# Remove what deploy/org/install.sh placed, and nothing else. Run as an administrator (sudo).
# Removes the hook copies, the skills it installed, and the managed files only when they are
# byte-for-byte what install.sh writes for the given server URL; a managed file you have since
# edited or merged is left in place and named, so you can remove our keys by hand.
#
#   sudo deploy/org/uninstall.sh --server-url https://mcp.example.com/mcp
set -euo pipefail
SERVER_URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$SERVER_URL" ] || { echo "--server-url is required (the URL you installed with)" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run with sudo" >&2; exit 2; }
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
case "$(uname -s)" in
  Darwin) CC_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux) CC_DIR="/etc/claude-code" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
CODEX_DIR="/etc/codex"

remove_if_ours() {  # $1 = installed file, $2 = expected content
  if [ -e "$1" ]; then
    if [ "$(cat "$1")" = "$2" ]; then rm -f "$1"; echo "removed $1"; else echo "kept    $1 (edited since install; remove the catpilot keys by hand)"; fi
  fi
}
SETTINGS_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" -e "s#/Library/Application Support/ClaudeCode#$CC_DIR#g" "$REPO/deploy/org/claude-code/managed-settings.json")"
remove_if_ours "$CC_DIR/managed-settings.json" "$SETTINGS_JSON"
MCP_JSON="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/claude-code/managed-mcp.json")"
remove_if_ours "$CC_DIR/managed-mcp.json" "$MCP_JSON"
CODEX_TOML="$(sed -e "s#https://mcp.example.com/mcp#$SERVER_URL#" "$REPO/deploy/org/codex/managed_config.toml")"
remove_if_ours "$CODEX_DIR/managed_config.toml" "$CODEX_TOML"
for d in "$CC_DIR/catpilot-guardrails" "$CC_DIR/.claude/skills/catpilot-safe-building" "$CC_DIR/.claude/skills/catpilot-security-core" "$CODEX_DIR/skills/catpilot-safe-building" "$CODEX_DIR/skills/catpilot-security-core"; do
  [ -e "$d" ] && { rm -rf "$d"; echo "removed $d"; } || true
done
echo "Done. Per-user evidence logs under ~/.catpilot-guardrails/ are left in place."
