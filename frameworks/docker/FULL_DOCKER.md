# Docker Security Guardrails — Full Reference

> **Version:** 2.0.1

This document provides detailed security patterns for Dockerfiles and container interactions.

---

## Base Image Selection

### ❌ Vulnerable Patterns

```dockerfile
# Floating tags (unpredictable, mutable)
FROM node:latest
FROM python:3.9
FROM ubuntu:20.04

# Unverified issuers
FROM my-random-repo/node:14
```

### ✅ Safe Patterns

```dockerfile
# Pin by digest (immutable, verifiable)
FROM node:20-alpine@sha256:d8a88e8e75z9...

# Or specific versions (acceptable but mutable)
FROM node:20.9.0-alpine3.18
```

---

## User Privileges

### ❌ Vulnerable Patterns

```dockerfile
# Running as root (default)
FROM node:20-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

### ✅ Safe Patterns

```dockerfile
# Create and switch to non-root user
FROM node:20-alpine
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser
WORKDIR /app
COPY --chown=appuser:appgroup . .
CMD ["node", "index.js"]
```

---

## Secrets Handling

### ❌ Vulnerable Patterns

```dockerfile
# Secrets in ENV persist in image history
ENV API_KEY="sk_live_12345"
ARG PASSWORD="supersecretpassword"

# Copying config files with secrets
COPY .env .
```

### ✅ Safe Patterns

```dockerfile
# Use Docker BuildKit secrets: the file exists only for this RUN step and is never
# committed to a layer. Do not copy it anywhere (`cat /run/secrets/x > /app/config`
# would bake the secret into the image, which is what the mount is there to prevent).
RUN --mount=type=secret,id=npmrc,target=/root/.npmrc npm ci

# Or use environment variables at runtime (not build time)
CMD ["sh", "-c", "export API_KEY=${API_KEY} && node index.js"]
```

---

## Package Installation

### ❌ Vulnerable Patterns

```dockerfile
# No cache checking or pinning
RUN pip install requests
RUN npm install
RUN apt-get update && apt-get install python3
```

### ✅ Safe Patterns

```dockerfile
# Pin versions and check hashes
RUN pip install --require-hashes -r requirements.txt
RUN npm ci --omit=dev

# Clean up apt caches to reduce image size
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    && rm -rf /var/lib/apt/lists/*
```

---

## Runtime Security

### ❌ Vulnerable Patterns

```yaml
# docker-compose.yml
privileged: true
network_mode: host
pid: host
```

### ✅ Safe Patterns

```yaml
# docker-compose.yml
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
```
