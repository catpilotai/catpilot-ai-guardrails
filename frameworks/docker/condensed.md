# Docker Security

- **Base Images:** Pin by digest (`sha256:...`) or specific version. Avoid `:latest`.
- **User:** Always run as non-root (`USER appuser`).
- **Secrets:** NEVER use `ENV` or `ARG` for secrets. Use `--mount=type=secret`.
- **Installs:** Pin versions. Use `npm ci`, `pip install --no-cache-dir`.
