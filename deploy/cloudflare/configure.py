"""Configure mcp.<zone> in Cloudflare for the reference MCP server. Idempotent.

Creates or updates, scoped to the one hostname and never zone-wide:
  - a proxied CNAME to the container app, and the TXT record Azure uses to verify the domain;
  - one rate-limiting rule (Free plan: 10-second window, per IP);
  - one custom firewall rule that blocks anything except /mcp and /health;
  - one cache rule that bypasses the cache for the host.

Usage:
  CLOUDFLARE_TOKEN=... python deploy/cloudflare/configure.py --zone catpilot.ai --host mcp \\
      --target <app>.azurecontainerapps.io --verification-id <id> [--requests-per-10s 60]

The token is read from the environment only and never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

API = "https://api.cloudflare.com/client/v4"


class CF:
    def __init__(self, token: str):
        self.token = token

    def call(self, method: str, path: str, body: dict | None = None) -> dict:
        req = urllib.request.Request(f"{API}{path}", method=method, headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}, data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except urllib.error.HTTPError as e:
            payload = e.read().decode()
            if e.code == 404 and method == "GET":
                return {"success": False, "result": None, "errors": json.loads(payload).get("errors", [])}
            raise SystemExit(f"Cloudflare {method} {path} failed: HTTP {e.code} {payload[:400]}")

    def zone_id(self, name: str) -> str:
        zones = self.call("GET", f"/zones?name={name}")["result"] or []
        if not zones:
            raise SystemExit(f"zone {name} not found or token cannot read it")
        return zones[0]["id"]

    def upsert_dns(self, zone: str, record: dict) -> str:
        existing = self.call("GET", f"/zones/{zone}/dns_records?type={record['type']}&name={record['name']}")["result"] or []
        if existing:
            self.call("PUT", f"/zones/{zone}/dns_records/{existing[0]['id']}", record)
            return "updated"
        self.call("POST", f"/zones/{zone}/dns_records", record)
        return "created"

    def upsert_phase_rule(self, zone: str, phase: str, rule: dict) -> str:
        """Replace the rule with the same description in the phase entrypoint, or add it; keep other rules."""
        current = self.call("GET", f"/zones/{zone}/rulesets/phases/{phase}/entrypoint")
        rules = list((current.get("result") or {}).get("rules") or [])
        kept = [{k: r[k] for k in ("expression", "action", "description", "enabled", "action_parameters", "ratelimit") if k in r} for r in rules if r.get("description") != rule["description"]]
        verb = "updated" if len(kept) != len(rules) else "created"
        self.call("PUT", f"/zones/{zone}/rulesets/phases/{phase}/entrypoint", {"rules": kept + [rule]})
        return verb


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--zone", required=True)
    parser.add_argument("--host", default="mcp", help="subdomain label")
    parser.add_argument("--target", required=True, help="the container app FQDN the CNAME points at")
    parser.add_argument("--verification-id", help="Azure customDomainVerificationId for the asuid TXT record")
    parser.add_argument("--requests-per-10s", type=int, default=60)
    parser.add_argument("--strict-ssl", action="store_true", help="add a configuration rule setting SSL to Full (strict) for this host; only after the origin has a valid certificate for it")
    args = parser.parse_args(argv)
    token = os.environ.get("CLOUDFLARE_TOKEN")
    if not token:
        parser.error("CLOUDFLARE_TOKEN is not set")
    cf = CF(token)
    zone = cf.zone_id(args.zone)
    fqdn = f"{args.host}.{args.zone}"

    print("dns CNAME:", cf.upsert_dns(zone, {"type": "CNAME", "name": fqdn, "content": args.target, "proxied": True, "ttl": 1, "comment": "Catpilot reference MCP server"}))
    if args.verification_id:
        print("dns TXT asuid:", cf.upsert_dns(zone, {"type": "TXT", "name": f"asuid.{fqdn}", "content": args.verification_id, "proxied": False, "ttl": 1, "comment": "Azure custom domain verification"}))

    print("rate limit:", cf.upsert_phase_rule(zone, "http_ratelimit", {
        "description": f"catpilot-mcp rate limit {fqdn}",
        "expression": f'(http.host eq "{fqdn}")',
        "action": "block",
        "enabled": True,
        "ratelimit": {"characteristics": ["ip.src", "cf.colo.id"], "period": 10, "requests_per_period": args.requests_per_10s, "mitigation_timeout": 10},
    }))
    print("firewall:", cf.upsert_phase_rule(zone, "http_request_firewall_custom", {
        "description": f"catpilot-mcp allow only /mcp and /health on {fqdn}",
        "expression": f'(http.host eq "{fqdn}" and not http.request.uri.path in {{"/mcp" "/health" "/"}} and not starts_with(http.request.uri.path, "/.well-known/acme-challenge/"))',
        "action": "block",
        "enabled": True,
    }))
    print("cache bypass:", cf.upsert_phase_rule(zone, "http_request_cache_settings", {
        "description": f"catpilot-mcp bypass cache {fqdn}",
        "expression": f'(http.host eq "{fqdn}")',
        "action": "set_cache_settings",
        "enabled": True,
        "action_parameters": {"cache": False},
    }))
    if args.strict_ssl:
        print("strict ssl:", cf.upsert_phase_rule(zone, "http_config_settings", {
            "description": f"catpilot-mcp strict ssl {fqdn}",
            "expression": f'(http.host eq "{fqdn}")',
            "action": "set_config",
            "enabled": True,
            "action_parameters": {"ssl": "strict"},
        }))
    print(f"done: https://{fqdn}/mcp (proxied), rules scoped to that host only")
    return 0


if __name__ == "__main__":
    sys.exit(main())
