#!/usr/bin/env bash
# Deploy the reference MCP server to Azure Container Apps. Idempotent; re-run to update.
#
# Prerequisites: an authenticated Azure CLI session with rights on the subscription, Docker or an ACR
# (the image is built in ACR, no local Docker needed), and the containerapp extension.
#
# Everything below is a public, unauthenticated, stateless endpoint that serves generic defaults.
# Do not point it at a company overlay; the tenant-scoped server is a separate, authenticated deployment.
set -euo pipefail

RG="${RG:-rg-catpilot-mcp}"
LOCATION="${LOCATION:-eastus}"
ENV_NAME="${ENV_NAME:-cae-catpilot-mcp}"
APP="${APP:-mcp-catpilot-guardrails}"
ACR="${ACR:?set ACR to an existing registry name, e.g. catpregistry}"
HOSTNAME="${HOSTNAME_FQDN:-mcp.catpilot.ai}"
MIN_REPLICAS="${MIN_REPLICAS:-1}"
MAX_REPLICAS="${MAX_REPLICAS:-3}"
TAG="${TAG:-$(git rev-parse --short HEAD)}"
IMAGE="$ACR.azurecr.io/catpilot-guardrails-mcp:$TAG"
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "== resource group $RG ($LOCATION)"
az group create -n "$RG" -l "$LOCATION" -o none

echo "== container apps environment $ENV_NAME (consumption)"
if ! az containerapp env show -n "$ENV_NAME" -g "$RG" -o none 2>/dev/null; then
  az containerapp env create -n "$ENV_NAME" -g "$RG" -l "$LOCATION" -o none
fi

echo "== build image $IMAGE in ACR (Dockerfile digest is resolved by the build)"
az acr build --registry "$ACR" --image "catpilot-guardrails-mcp:$TAG" --file "$REPO_ROOT/mcp-server/Dockerfile" "$REPO_ROOT" -o none

echo "== container app $APP"
if az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null; then
  az containerapp update -n "$APP" -g "$RG" --image "$IMAGE" \
    --set-env-vars "CATPILOT_MCP_ALLOWED_HOSTS=$HOSTNAME" \
    --min-replicas "$MIN_REPLICAS" --max-replicas "$MAX_REPLICAS" -o none
else
  az containerapp create -n "$APP" -g "$RG" --environment "$ENV_NAME" --image "$IMAGE" \
    --registry-server "$ACR.azurecr.io" --registry-identity system \
    --ingress external --target-port 8765 --transport http \
    --cpu 0.25 --memory 0.5Gi --min-replicas "$MIN_REPLICAS" --max-replicas "$MAX_REPLICAS" \
    --env-vars "CATPILOT_MCP_ALLOWED_HOSTS=$HOSTNAME" -o none
fi

FQDN="$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)"
VERIFICATION_ID="$(az containerapp show -n "$APP" -g "$RG" --query properties.customDomainVerificationId -o tsv)"

echo "== restrict ingress to Cloudflare's published ranges (the origin is not reachable directly)"
RULES_JSON="$(python3 - <<'PY'
import json, urllib.request
# The API endpoint is unauthenticated; the www.cloudflare.com/ips-v4 text files refuse non-browser clients.
# Container Apps ingress is IPv4-only and its IP restrictions reject IPv6 ranges, so only the IPv4 list applies.
req = urllib.request.Request("https://api.cloudflare.com/client/v4/ips", headers={"User-Agent": "catpilot-deploy/1"})
ranges = json.load(urllib.request.urlopen(req, timeout=20))["result"]["ipv4_cidrs"]
rules = [{"name": f"cloudflare-{i + 1}", "ipAddressRange": cidr, "action": "Allow", "description": "Cloudflare edge"}
         for i, cidr in enumerate(ranges)]
print(json.dumps(rules))
PY
)"
APP_ID="$(az containerapp show -n "$APP" -g "$RG" --query id -o tsv)"
# One full-resource update (GET, modify, PUT) instead of one round trip per range.
az resource update --ids "$APP_ID" --set "properties.configuration.ingress.ipSecurityRestrictions=$RULES_JSON" -o none
echo "   $(python3 -c 'import json,sys; print(len(json.loads(sys.argv[1])))' "$RULES_JSON") ranges allowed"

cat <<MSG

App FQDN:               $FQDN
Custom domain to add:   $HOSTNAME
Domain verification id: $VERIFICATION_ID

Next, if the hostname is not bound yet (see deploy/README.md):
  1. CLOUDFLARE_TOKEN=... python3 deploy/cloudflare/configure.py --zone <zone> --host <label> --target $FQDN --verification-id $VERIFICATION_ID
  2. az containerapp hostname add  -n $APP -g $RG --hostname $HOSTNAME
  3. az containerapp hostname bind -n $APP -g $RG --hostname $HOSTNAME --environment $ENV_NAME --validation-method TXT
     (creates a managed certificate and prints a validation token, then reports CertificateProvisioningError while it is pending)
  4. python3 deploy/cloudflare/configure.py ... --cert-validation-token <token>
  5. az containerapp env certificate list -g $RG -n $ENV_NAME --managed-certificates-only   # wait for provisioningState Succeeded
  6. az containerapp hostname bind -n $APP -g $RG --hostname $HOSTNAME --environment $ENV_NAME --certificate <managed certificate name>
  7. python3 deploy/cloudflare/configure.py ... --strict-ssl, then deploy/verify.sh $HOSTNAME $FQDN
MSG
