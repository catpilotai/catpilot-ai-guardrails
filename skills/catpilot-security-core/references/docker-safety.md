# docker-safety

Component `docker-safety` · version 1.0.1 · severity critical · category container.
Full text of one component of the `catpilot-security-core` bundle. The baseline rules are in `../SKILL.md`; this file has the rest: examples, remediation, and detection patterns.
## Baseline

**Applies when:** Writing or running a `Dockerfile`/`Containerfile`, `docker-compose.yml`, `docker build`/`run`/`exec` (or podman/nerdctl/buildah equivalents), or a Kubernetes manifest setting `securityContext`, `hostNetwork`, `hostPID`, `hostIPC`, `privileged`, or `hostPath` volumes.

**Always:**
- Pin base images to an immutable digest (`FROM <image>@sha256:...`); floating tags (`latest`, major/minor only) are for non-deployed internal tooling only.
- Declare and switch to a non-root `USER` before `CMD`/`ENTRYPOINT`; `COPY --chown=app:app` files the runtime needs to read.
- Pass build-time secrets with BuildKit `--mount=type=secret`; pass runtime secrets via `--env-file` or a secret store, never baked into the image.
- Run production containers with `read_only`/`--read-only`, `no-new-privileges`, and `cap_drop: [ALL]` with only required capabilities re-added.
- Pin package versions, use the minimal-install flag, and clean the package cache in the same layer; verify checksums for downloaded binaries.

**Never:**
- `--privileged` / `privileged: true` — disables seccomp, AppArmor, and capability dropping.
- `--net=host` / `network_mode: host` or `--pid=host` / `pid: host` — shares the host's network or process namespace.
- `-v /:/host` or mounting `/var/run/docker.sock` into the container — full host filesystem or Docker daemon control.
- `ENV`/`ARG` for secrets, or `COPY .env .` — persists secrets in image history.
- `chmod -R 777` inside a container image.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

A Docker image and its run command together define the security posture
of every workload they produce. The same image can ship as a hardened,
non-root, read-only filesystem service — or as a root-owned container
with the host's `/var/run/docker.sock` mounted in, one `docker exec`
away from a host takeover.

The failures this skill blocks share a common shape: a single line in
a `Dockerfile`, a `docker-compose.yml`, or a `docker run` flag that
**breaks the isolation boundary the container is supposed to provide**.

- `FROM node:latest` ships a moving target. The same Dockerfile builds
  a different image week to week, and a CVE fixed upstream silently
  re-enters when the tag floats backward.
- A container running as `root` has UID 0 on the host's kernel
  namespace. With certain capabilities or a misconfigured runtime, a
  container compromise becomes a host compromise.
- `ENV API_KEY=sk_live_...` writes the secret into a layer that lives
  in the image's history forever — pushed to every registry the image
  is pushed to, pulled to every host that runs it.
- `--privileged` disables every capability filter, seccomp profile,
  and AppArmor profile the runtime would otherwise apply. The
  container is effectively a process running on the host with
  containment-as-suggestion.
- `--net=host` shares the host's network namespace, so the container
  can bind to host ports, reach host services on `127.0.0.1`, and
  receive traffic intended for the host. Combined with a vulnerable
  service in the container, this is a direct path to LAN exposure.
- A bind-mount of `/` or `/var/run/docker.sock` from the host into
  the container hands the container read/write access to the host
  filesystem or the host's Docker daemon. Either is escape-class.

This skill applies the same query-then-modify discipline used
elsewhere in the bundle: **non-root by default, immutable by default,
no secrets at build time, no host-namespace sharing.**

## When to apply

Apply this skill **before** the agent writes, recommends, or commits
any of the following:

- `Dockerfile`, `Containerfile`, or any image-build manifest.
- `docker-compose.yml`, `docker-compose.*.yml`, or any v2/v3 compose file.
- `docker build`, `docker buildx`, `nerdctl build`, `podman build`,
  `buildah` invocations.
- `docker run`, `docker exec`, `nerdctl run`, `podman run`, or any
  invocation that adds runtime flags.
- Kubernetes `PodSpec`, `Deployment`, `StatefulSet`, or `DaemonSet`
  manifests that set `securityContext`, `hostNetwork`, `hostPID`,
  `hostIPC`, `privileged`, or `volumes` with `hostPath`.
- CI workflows that build, tag, or push container images
  (GitHub Actions `docker/build-push-action`, GitLab CI Docker
  templates, BuildKit drivers, OCI build pipelines).

This skill is the container-runtime counterpart to `cloud-cli-safety`
(infrastructure), `local-cli-safety` (host shell), and
`secret-blocking` (credential material). All four apply together — a
Dockerfile that runs as root and also has `ENV API_KEY=...` matches
this skill and `secret-blocking` and must satisfy both.

## Rules

### Rule 1 — Base images are pinned by digest, never by floating tag

`FROM <image>:latest`, `FROM <image>:<major>`, `FROM <image>:<major>.<minor>`,
and `FROM <image>` (implicit `latest`) are prohibited for production
images. The base must be pinned to an immutable digest:

```dockerfile
FROM node:20.11.1-alpine3.19@sha256:f1fe1d...
```

Tag-only pinning (`FROM node:20.11.1-alpine3.19`) is acceptable for
internal tooling, throwaway scripts, and CI test rigs where image
reproducibility is not a requirement. It is **not** acceptable for
images that will be deployed, pushed to a public registry, or
referenced by a production manifest.

The base image must come from a verifiable source: an official Docker
Hub library image, a vendor-published registry (`gcr.io/distroless`,
`mcr.microsoft.com`, `public.ecr.aws`), or an organization-owned
registry. Random user namespaces are prohibited unless explicitly
approved.

### Rule 2 — Non-root `USER` is mandatory; no images run as root

Every image must declare a non-root `USER` before `CMD`/`ENTRYPOINT`.
The default Docker behavior of running as `root` (UID 0) is prohibited.
A non-root user is created and switched to inside the Dockerfile:

```dockerfile
RUN addgroup -S app && adduser -S app -G app
USER app
```

Files the runtime needs to read must be `COPY --chown=app:app`-ed in.
The container's filesystem must not contain files the running user
cannot read because the image was built as root and never adjusted.

For images that genuinely need to start as root (binding to port < 1024
without `CAP_NET_BIND_SERVICE`, package install on first boot), use
`gosu`, `su-exec`, or `tini` to drop to a non-root user before
executing the application. The application itself never runs as root.

### Rule 3 — Build-time secrets use BuildKit mounts, never ENV/ARG

`ENV API_KEY=...`, `ARG SECRET=...`, and `COPY .env .` are prohibited
in any image-build manifest. Each of these writes the secret into a
layer that is recoverable from the image's history by anyone who has
the image, including read-only registry consumers.

Build-time secrets use BuildKit's `--mount=type=secret`:

```dockerfile
# syntax=docker/dockerfile:1.7
RUN --mount=type=secret,id=npm_token \
    NPM_TOKEN=$(cat /run/secrets/npm_token) npm ci
```

Invoke the build with the secret passed in at build time:

```bash
docker build --secret id=npm_token,src=$HOME/.npmrc-token .
```

Runtime secrets (database passwords, API keys the running container
needs) are passed at `docker run` time via `--env-file`, an
orchestrator's secret store, or a sidecar like `vault-agent`. They are
not baked into the image.

### Rule 4 — Runtime flags do not break the isolation boundary

The following `docker run` / `docker-compose.yml` settings are
prohibited and must be flagged whenever the agent encounters them:

| Flag / setting | Why it is prohibited |
|---|---|
| `--privileged` / `privileged: true` | Disables seccomp, AppArmor, capability dropping. Container ≈ host process. |
| `--net=host` / `network_mode: host` | Shares host network namespace. Container binds host ports, reaches host loopback. |
| `--pid=host` / `pid: host` | Sees and can signal host processes. |
| `--ipc=host` / `ipc: host` | Shares host IPC namespace. Container can read host SHM. |
| `--uts=host` | Shares host UTS namespace. Container can rename the host. |
| `-v /:/host` (or any host-root bind) | Container has full host filesystem. |
| `-v /var/run/docker.sock:/var/run/docker.sock` | Container controls the host's Docker daemon. Trivial host takeover. |
| `--cap-add=SYS_ADMIN` (or `ALL`) | Broad capability that subsumes others. Restores most root powers. |
| `--security-opt apparmor=unconfined` | Disables the AppArmor profile. |
| `--security-opt seccomp=unconfined` | Disables the default seccomp filter. |
| `--userns=host` | Disables user-namespace remapping. |

If the user requests any of these, the agent surfaces the trade-off
explicitly ("`--privileged` removes the seccomp/AppArmor/capability
isolation that normally separates this container from the host") and
requires explicit, named confirmation. Diagnostic-only and
sandboxed-host exceptions exist; production deployment with these
flags does not.

### Rule 5 — Read-only root filesystem, `no-new-privileges`, dropped caps

Production containers run with:

- `read_only: true` (compose) / `--read-only` (run) — the container's
  root filesystem is mounted read-only. Writable paths the application
  needs are explicit `tmpfs` mounts.
- `security_opt: [no-new-privileges:true]` (compose) /
  `--security-opt=no-new-privileges` (run) — prevents `setuid` binaries
  from gaining privileges mid-execution.
- `cap_drop: [ALL]` followed by an explicit `cap_add` for only the
  capabilities the workload requires (commonly an empty list; rarely
  `NET_BIND_SERVICE`).

When the agent generates a `docker-compose.yml` or Kubernetes
`securityContext`, these settings are present unless the user has
explicitly opted out for a documented reason.

### Rule 6 — Package install is pinned, minimal, and cache-cleaned

OS and language-runtime package installs must:

- Pin versions where the package manager supports it
  (`apt-get install foo=1.2.3-1`, `apk add foo=1.2.3-r0`,
  `pip install -r requirements.txt --require-hashes`,
  `npm ci` rather than `npm install`).
- Use the minimal-install flag where one exists
  (`apt-get install --no-install-recommends`).
- Clean the package-manager cache in the same `RUN` layer
  (`rm -rf /var/lib/apt/lists/*` for apt, `apk --no-cache` for apk,
  `pip install --no-cache-dir` for pip).
- Verify checksums or signatures for binaries downloaded inside the
  build (cross-references `supply-chain`).

`apt-get update` without an install in the same `RUN` layer is
prohibited because cache invalidation makes the resulting image
non-reproducible.

## Negative examples

```dockerfile
# ❌ Floating tag — image is a moving target
FROM node:latest
FROM python:3
FROM ubuntu
```

```dockerfile
# ❌ Untrusted registry namespace
FROM random-user/node:14
```

```dockerfile
# ❌ Runs as root (default)
FROM node:20-alpine
WORKDIR /app
COPY . .
CMD ["node", "index.js"]
```

```dockerfile
# ❌ Build-time secret in ENV/ARG — persists in image history
ENV API_KEY="sk_live_12345"
ARG DB_PASSWORD="hunter2"
COPY .env .
```

```dockerfile
# ❌ Unpinned package install, no cache cleanup
RUN apt-get update && apt-get install -y python3 curl
RUN pip install requests
RUN npm install
```

```dockerfile
# ❌ chmod 777 inside the container
RUN chmod -R 777 /app
```

```yaml
# ❌ docker-compose: every isolation boundary broken at once
services:
  app:
    image: myapp:latest
    privileged: true
    network_mode: host
    pid: host
    volumes:
      - /:/host
      - /var/run/docker.sock:/var/run/docker.sock
```

```bash
# ❌ docker run with --privileged + host network
docker run --privileged --net=host -v /:/host myapp:latest

# ❌ Mounting the Docker socket
docker run -v /var/run/docker.sock:/var/run/docker.sock myapp:latest
```

```yaml
# ❌ Kubernetes PodSpec with host-namespace sharing
spec:
  hostNetwork: true
  hostPID: true
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      privileged: true
      runAsUser: 0
```

## Remediation

### Production-grade Dockerfile

```dockerfile
# syntax=docker/dockerfile:1.7

# ✅ Pinned by digest
FROM node:20.11.1-alpine3.19@sha256:f1fe1d05cce5b5d7caf24bc15ef79e7e58a31e7c8a7a7e0d3a5c6e7d8f9a0b1c AS deps

# ✅ Non-root user created before WORKDIR
RUN addgroup -S app && adduser -S app -G app
WORKDIR /app

# ✅ BuildKit secret mount for private-registry token
RUN --mount=type=secret,id=npm_token,uid=1000 \
    --mount=type=bind,source=package.json,target=package.json \
    --mount=type=bind,source=package-lock.json,target=package-lock.json \
    NPM_TOKEN=$(cat /run/secrets/npm_token) \
    npm ci --omit=dev

# ✅ COPY with --chown so non-root user can read app files
COPY --chown=app:app . .

USER app

CMD ["node", "index.js"]
```

### Production-grade `docker-compose.yml`

```yaml
services:
  app:
    image: myorg/app@sha256:f1fe1d...
    read_only: true
    tmpfs:
      - /tmp
      - /var/run
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE  # only if the app binds to port < 1024
    user: "1000:1000"
    networks:
      - app-net
    environment:
      LOG_LEVEL: info
    env_file:
      - secrets/runtime.env   # runtime secrets only, not in image
```

### Production-grade Kubernetes `securityContext`

```yaml
spec:
  automountServiceAccountToken: false  # if the pod doesn't talk to the API
  containers:
  - name: app
    image: registry.example.com/app@sha256:f1fe1d...
    securityContext:
      allowPrivilegeEscalation: false
      privileged: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      runAsGroup: 1000
      capabilities:
        drop: [ALL]
      seccompProfile:
        type: RuntimeDefault
```

### Safe `apt-get` pattern

```dockerfile
# ✅ Update + install + clean in one layer, no recommends, pinned
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates=20230311 \
        curl=7.88.1-10+deb12u5 \
 && rm -rf /var/lib/apt/lists/*
```

### Safe BuildKit secret invocation

```bash
# ✅ Secret never appears in image history
docker buildx build \
  --secret id=npm_token,src=$HOME/.npmrc-token \
  --tag myorg/app:$(git rev-parse --short HEAD) \
  --push \
  .
```

### `docker run` with a tight runtime profile

```bash
# ✅ Non-root, read-only, no new privileges, capabilities dropped
docker run \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  --security-opt no-new-privileges \
  --cap-drop ALL \
  --network app-net \
  --env-file secrets/runtime.env \
  myorg/app@sha256:f1fe1d...
```

## Production detection heuristics

Treat the Docker workload as production-class (escalating the protocol)
when **any** of these match:

- The image is tagged or pushed to a registry path containing `prod`,
  `production`, `release`, or `customer`.
- The compose file or PodSpec is in a directory containing `prod`,
  `production`, `release`, or `customer`.
- The deployment target is a managed orchestrator hostname pattern
  (`*.eks.amazonaws.com`, `*.gke.io`, `*.aks.azure.com`,
  `*.fly.io`, `*.railway.app`, `*.run.app`, `*.azurecontainer.io`).
- The image references a base from an organization-owned registry
  pinned by digest.
- CI workflow names or branch protection identify the build as a
  production release pipeline.

If any signal matches, all six rules apply without exception, and the
runtime-flag check (Rule 4) escalates to require named confirmation
in addition to surfacing the trade-off.

## References

- Docker development best practices — https://docs.docker.com/develop/dev-best-practices/
- BuildKit build-time secrets — https://docs.docker.com/build/building/secrets/
- Docker runtime privilege and Linux capabilities — https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities
- CIS Docker Benchmark — https://www.cisecurity.org/benchmark/docker
- Kubernetes Pod Security Standards — https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Distroless base images — https://github.com/GoogleContainerTools/distroless
- Snyk Top 10 Docker image security best practices — https://snyk.io/blog/10-docker-image-security-best-practices/
