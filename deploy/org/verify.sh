#!/usr/bin/env bash
# Read-only checks of what deploy/org/install.sh placed, run as a normal user. Prints what is present
# and what to do next; it starts no session and proves nothing about behavior. The behavioral checks
# (a denied command, a server lookup, a skill load) are in docs/DEPLOY_ORG.md.
set -uo pipefail
case "$(uname -s)" in
  Darwin) CC_DIR="/Library/Application Support/ClaudeCode" ;;
  Linux) CC_DIR="/etc/claude-code" ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 2 ;;
esac
ok=0; missing=0
check() { if [ -e "$1" ]; then echo "present  $1"; ok=$((ok+1)); else echo "MISSING  $1"; missing=$((missing+1)); fi; }
json_ok() { python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$1" 2>/dev/null && echo "valid    $1 parses as JSON" || echo "INVALID  $1 does not parse as JSON"; }

echo "Claude Code (managed dir: $CC_DIR)"
check "$CC_DIR/managed-settings.json"; [ -e "$CC_DIR/managed-settings.json" ] && json_ok "$CC_DIR/managed-settings.json"
[ -e "$CC_DIR/managed-mcp.json" ] && { echo "present  $CC_DIR/managed-mcp.json (fixed server set: only its servers load in CLI sessions)"; json_ok "$CC_DIR/managed-mcp.json"; } || echo "absent   $CC_DIR/managed-mcp.json (optional; the server may come from managedMcpServers or a repository .mcp.json)"
check "$CC_DIR/catpilot-guardrails/hooks/pretooluse-secrets.py"
check "$CC_DIR/catpilot-guardrails/hooks/pretooluse-write-private-key.py"
for s in "$CC_DIR"/.claude/skills/catpilot-*/SKILL.md; do [ -e "$s" ] && echo "present  $s"; done
echo
echo "Codex CLI"
check /etc/codex/managed_config.toml
for s in /etc/codex/skills/catpilot-*/SKILL.md; do [ -e "$s" ] && echo "present  $s"; done
echo
echo "Evidence log for this user"
if [ -e "$HOME/.catpilot-guardrails/evidence.jsonl" ]; then
  echo "present  $HOME/.catpilot-guardrails/evidence.jsonl ($(wc -l < "$HOME/.catpilot-guardrails/evidence.jsonl" | tr -d ' ') lines); last line:"; tail -n 1 "$HOME/.catpilot-guardrails/evidence.jsonl"
else
  echo "none yet: it appears after the first denied command or write"
fi
echo
echo "$ok present, $missing missing. Next: start Claude Code and run /status (expect 'Enterprise managed settings'),"
echo "then claude mcp list, then the test prompts in docs/DEPLOY_ORG.md."
[ "$missing" -eq 0 ]
