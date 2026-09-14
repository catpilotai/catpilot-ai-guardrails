# Catpilot guardrails reference MCP server, streamable HTTP, stateless.
# Build from the repository root:  docker build -f mcp-server/Dockerfile -t catpilot-guardrails-mcp .
# The base image is pinned by digest; refresh it deliberately, not by rebuilding.
FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements-dev.txt ./
RUN python -m pip install --only-binary=:all: --require-hashes -r requirements-dev.txt

COPY tools/validate_overlay.py tools/validate_overlay.py
COPY mcp-server/ mcp-server/

RUN useradd --system --uid 10001 --no-create-home app
USER app
EXPOSE 8765

# Host header allowlist comes from the environment at run time (CATPILOT_MCP_ALLOWED_HOSTS).
CMD ["python", "mcp-server/server.py", "--transport", "streamable-http", "--host", "0.0.0.0", "--port", "8765", "--stateless"]
