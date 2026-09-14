#!/usr/bin/env bash
# Verify a hosted reference MCP server through its public hostname, and that the origin refuses direct requests.
#   deploy/verify.sh mcp.catpilot.ai [<app>.azurecontainerapps.io]
# Read-only apart from the final burst, which sends 80 requests to /health to show the rate limit answering 429.
set -u
HOST="${1:?public hostname, e.g. mcp.catpilot.ai}"
ORIGIN="${2:-}"
JSON_HEADERS=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"verify","version":"0"}}}'

echo "== GET /health (expect 200, cache-control: no-store, cf-cache-status: DYNAMIC)"
curl -sS -m 20 -D - "https://$HOST/health" | grep -iE '^(HTTP|cache-control|cf-cache-status|server|\{)'
echo "== GET / (expect 200 and the data statement)"
curl -sS -m 20 -o /dev/null -w 'HTTP %{http_code}\n' "https://$HOST/"
echo "== POST /mcp initialize (expect 200 and serverInfo)"
curl -sS -m 20 -w '\nHTTP %{http_code}\n' -X POST "https://$HOST/mcp" "${JSON_HEADERS[@]}" -d "$INIT" | grep -oE '"serverInfo":\{[^}]*\}|^HTTP .*'
echo "== POST /mcp tools/list (expect 200)"
curl -sS -m 20 -o /dev/null -w 'HTTP %{http_code}\n' -X POST "https://$HOST/mcp" "${JSON_HEADERS[@]}" -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
echo "== GET /admin (expect 403 from the edge firewall rule)"
curl -sS -m 20 -o /dev/null -w 'HTTP %{http_code}\n' "https://$HOST/admin"
if [ -n "$ORIGIN" ]; then
  echo "== GET https://$ORIGIN/health directly (expect 403 from the Container Apps ingress restriction)"
  curl -sS -m 20 -w '\nHTTP %{http_code}\n' "https://$ORIGIN/health" | head -c 200; echo
fi
echo "== burst: 80 parallel GET /health (expect mostly 200 and some 429 once the 10-second budget is spent)"
codes=$(for i in $(seq 1 80); do curl -sS -m 10 -o /dev/null -w '%{http_code}\n' "https://$HOST/health" & done; wait)
echo "$codes" | sort | uniq -c
