# Deploying the reference MCP server

Two scripts, both idempotent, both scoped to one hostname. They are what
Catpilot uses for `mcp.catpilot.ai`, kept here so anyone can run the same
thing on their own subscription and zone.

| Script | What it does |
| --- | --- |
| `azure/deploy.sh` | Resource group, consumption Container Apps environment, image built in ACR from `mcp-server/Dockerfile` (the `.dockerignore` keeps the build context to what the image copies), the container app with external ingress and a system-assigned identity for registry pull, 1 to 3 replicas of 0.25 CPU / 0.5 GiB by default, ingress restricted to Cloudflare's published IPv4 ranges (fetched from `https://api.cloudflare.com/client/v4/ips`) so the origin cannot be reached directly. Prints the FQDN and the domain verification id for the next step. |
| `cloudflare/configure.py` | A proxied CNAME for the host and the Azure verification TXT record; one rate-limiting rule (per client IP per Cloudflare location, 10-second window, default 60 requests); one firewall rule that blocks every path except `/mcp`, `/health`, `/`, and the ACME challenge path Azure's HTTP certificate validation would use; a strict-SSL rule for the host (with `--strict-ssl`); one cache-bypass rule (optional). Nothing zone-wide. Token from the environment only. |

Defaults: resource group `rg-catpilot-mcp`, location `eastus`, environment
`cae-catpilot-mcp`, app `mcp-catpilot-guardrails`, hostname `mcp.catpilot.ai`.
`azure/deploy.sh` needs `ACR=<registry name>` in the environment.

## Before you run anything

- `az` signed in to the target subscription, and an Azure Container Registry
  (`ACR=<registry name>`).
- A Cloudflare zone for the domain, and an API token in the `CLOUDFLARE_TOKEN`
  environment variable. `configure.py` reads it from there only and never
  prints it. Token permissions: Zone Read (to find the zone), DNS Edit, Zone
  WAF Edit (the custom rule and the rate-limiting rule), Config Rules Edit
  (for `--strict-ssl`). Cache Rules Edit is optional; without it the
  cache-bypass rule is skipped with a printed note, which is fine because the
  origin already sends `Cache-Control: no-store` and Cloudflare does not
  cache extension-less paths or POST responses by default.

Container Apps ingress is IPv4-only and rejects IPv6 ranges, so
`azure/deploy.sh` applies only the IPv4 list Cloudflare publishes. Creating
the environment without `--logs-destination` auto-creates a Log Analytics
workspace; it receives container stdout/stderr (startup lines only, no
request content) and platform logs.

## The working sequence

1. Run `azure/deploy.sh`. Note the app FQDN and the domain verification id it
   prints.
2. Run `cloudflare/configure.py --target <fqdn> --verification-id <id>`.
3. `az containerapp hostname add -n <app> -g <rg> --hostname <host>`.
4. `az containerapp hostname bind -n <app> -g <rg> --hostname <host> --environment <env> --validation-method TXT`.
   This creates a managed certificate and prints a validation token, then
   fails with `CertificateProvisioningError` because the certificate is still
   pending. That is expected.
5. Run `cloudflare/configure.py` again, adding `--cert-validation-token <token>`
   (writes the `_dnsauth.<host>` TXT record the certificate needs).
6. Wait until `az containerapp env certificate list -g <rg> -n <env> --managed-certificates-only`
   shows `provisioningState` `Succeeded`. Took under 15 minutes in testing;
   Azure allows up to 20.
7. `az containerapp hostname bind ... --certificate <managed certificate name>`
   binds it (`bindingType` `SniEnabled`).
8. Run `cloudflare/configure.py ... --strict-ssl` once the origin certificate
   is valid.
9. `deploy/verify.sh <host> <fqdn>`.

Redeploys are just `azure/deploy.sh` again: it builds a new image tagged with
the git short SHA and updates the app.

`cloudflare/configure.py` options: `--zone`, `--host` (default `mcp`),
`--target <app fqdn>`, `--verification-id <customDomainVerificationId>`
(writes the `asuid.<host>` TXT record), `--cert-validation-token <token>`,
`--requests-per-10s` (default 60), `--strict-ssl`.

## What the protections do

- Cloudflare, scoped to this one hostname and not zone-wide: a rate limit of
  60 requests per 10 seconds per client IP per Cloudflare location (then
  HTTP 429 for 10 seconds); a firewall rule allowing only `/mcp`, `/health`,
  `/`, and the ACME challenge path, HTTP 403 at the edge for everything else;
  a strict-SSL rule for the host once `--strict-ssl` runs, on top of Azure's
  managed certificate on the origin.
- The origin (Azure Container Apps) accepts connections only from
  Cloudflare's published IPv4 ranges. A direct request to the app's own
  hostname returns HTTP 403 "RBAC: access denied".

## Verifying

`deploy/verify.sh <host> [origin fqdn]` checks `/health`, `/`, `initialize`,
`tools/list`, a blocked path, the direct origin, and ends with an
80-request burst to show 429s. You do not need to read the script to use it.

## What this deployment is

A public, unauthenticated, stateless endpoint that serves the generic
defaults and stores nothing. What it is not: a place for a company overlay.
The tenant-scoped, authenticated server is a separate deployment with its
own identity and audit design.

## Cost

At the defaults: one 0.25 vCPU / 0.5 GiB replica always on, roughly ten to
fifteen US dollars a month plus a few cents of registry storage. Set
`MIN_REPLICAS=0` for scale-to-zero with cold starts of a few seconds.
