# Deploying the reference MCP server

Two scripts, both idempotent, both scoped to one hostname. They are what
Catpilot uses for `mcp.catpilot.ai`, kept here so anyone can run the same
thing on their own subscription and zone.

| Script | What it does |
| --- | --- |
| `azure/deploy.sh` | Resource group, consumption Container Apps environment, image built in ACR from `mcp-server/Dockerfile`, the container app with external ingress, system identity for registry pull, one small replica by default, ingress restricted to Cloudflare's published IP ranges so the origin cannot be reached directly. Prints the FQDN and the domain verification id for the next step. |
| `cloudflare/configure.py` | A proxied CNAME for the host and the Azure verification TXT record; one rate-limiting rule (per IP, 10-second window); one firewall rule that blocks every path except `/mcp`, `/health`, `/`, and the ACME challenge path Azure's managed certificate needs; one cache-bypass rule. Nothing zone-wide. Token from the environment only. |

Then bind the custom hostname on the app with TXT validation (the deploy
script prints the two commands), and verify from a client that speaks MCP.

What this deployment is: a public, unauthenticated, stateless endpoint that
serves the generic defaults and stores nothing. What it is not: a place for
a company overlay. The tenant-scoped, authenticated server is a separate
deployment with its own identity and audit design.

Costs at the defaults: one 0.25 vCPU / 0.5 GiB replica always on, roughly
ten to fifteen US dollars a month plus a few cents of registry storage. Set
`MIN_REPLICAS=0` for scale-to-zero with cold starts of a few seconds.
