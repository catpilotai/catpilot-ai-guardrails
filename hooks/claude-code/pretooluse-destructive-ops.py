#!/usr/bin/env python3
"""Catpilot PreToolUse hook for Claude Code: block high-blast-radius destructive CLI commands.

Scope, stated exactly:
  - Runs only for the Bash tool (the matcher in settings selects it).
  - Scans the proposed command text for deterministic, high-confidence
    destructive signatures documented in the cloud-cli-safety,
    database-safety, and local-cli-safety components of catpilot-security-core:
      * partial-resource replacements that wipe unspecified fields or env vars
        (az containerapp update --yaml / --replace-env-vars, aws lambda
        update-function-configuration --environment, gcloud run services update
        --set-env-vars, gcloud projects set-iam-policy)
      * unconfirmed cloud / IaC / Kubernetes mass deletion (terraform apply/destroy
        -auto-approve, kubectl delete namespace, kubectl delete pods --all,
        aws s3 rb --force, aws s3 rm --recursive without --dryrun, gsutil rm -r,
        gcloud app versions delete --all --quiet, gcloud run services delete --quiet)
      * irreversible local filesystem or git history wipes (rm -rf against /, ~,
        $HOME, or an unguarded variable; chmod -R 777; dd to /dev/sd* or /dev/nvme*
        or /dev/disk*; git push --force/-f to main, master, production, staging,
        develop, or release/*)
      * direct credential exfiltration pipes (cat ~/.ssh/... | curl, env | curl)
  - On a match, returns a PreToolUse "deny" decision with a plain-language
    reason and the safer alternative. Never echoes the command text.
  - On anything else, returns an empty decision so the host's own permission
    rules apply unchanged. It never returns "allow".
  - Malformed or oversized input exits 2 (the host treats that as a blocking
    error), so a broken hook fails closed rather than silently allowing.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

MAX_INPUT_BYTES = 1_048_576


def _load_secrets_hook():
    hook_path = Path(__file__).resolve().parent / "pretooluse-secrets.py"
    spec = importlib.util.spec_from_file_location("catpilot_pretooluse_secrets", hook_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


_secrets = _load_secrets_hook()

# (label, compiled_pattern, safe_alternative_note)
DESTRUCTIVE_PATTERNS = [
    (
        "az containerapp partial-YAML or replace-env-vars reset",
        re.compile(r"\baz\s+containerapp\s+update\b.*?\s(?:--yaml|--replace-env-vars)\b", re.IGNORECASE | re.DOTALL),
        "Query current state with `az containerapp show` first and use `--set-env-vars` (which merges) or include the full resource specification.",
    ),
    (
        "aws lambda environment full-map replacement",
        re.compile(r"\baws\s+lambda\s+update-function-configuration\b.*?\s--environment\s+[\"']?Variables=\{", re.IGNORECASE | re.DOTALL),
        "Query existing variables with `aws lambda get-function-configuration`, merge them in a JSON file, and pass the complete merged map.",
    ),
    (
        "gcloud projects set-iam-policy full-binding replacement",
        re.compile(r"\bgcloud\s+projects\s+set-iam-policy\b", re.IGNORECASE),
        "Use `gcloud projects add-iam-policy-binding` so existing IAM bindings are preserved.",
    ),
    (
        "gcloud run services update --set-env-vars replacement",
        re.compile(r"\bgcloud\s+run\s+services\s+update\b.*?\s--set-env-vars\b", re.IGNORECASE | re.DOTALL),
        "Use `gcloud run services update --update-env-vars` so existing environment variables are preserved.",
    ),
    (
        "gcloud quiet service or version deletion",
        re.compile(r"\bgcloud\s+(?:app\s+versions\s+delete\s+--all|run\s+services\s+delete\b).*?\s--quiet\b", re.IGNORECASE | re.DOTALL),
        "Inspect existing revisions/versions first and require interactive confirmation before deleting.",
    ),
    (
        "terraform auto-approve apply or destroy",
        re.compile(r"\bterraform\s+(?:apply|destroy)\b.*?\s-auto-approve\b", re.IGNORECASE | re.DOTALL),
        "Run `terraform plan -out=tfplan`, show the plan to the user, and apply the reviewed plan without `-auto-approve`.",
    ),
    (
        "kubectl delete namespace or delete --all pods",
        re.compile(
            r"\bkubectl\s+delete\s+(?:(?:namespace|ns)\s+\S+|pods?\b.*?\s--all\b)(?!.*--dry-run)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Preview with `--dry-run=client` and get explicit user confirmation naming the target namespace.",
    ),
    (
        "aws s3 recursive delete or force bucket removal",
        re.compile(
            r"\baws\s+s3\s+(?:rb\b.*?\s--force\b|rm\b.*?\s--recursive\b(?!.*--dryrun))",
            re.IGNORECASE | re.DOTALL,
        ),
        "List bucket contents with `aws s3 ls` and run with `--dryrun` before any recursive delete.",
    ),
    (
        "gsutil recursive bucket delete",
        re.compile(r"\bgsutil\s+(?:-m\s+)?rm\s+-(?:r|R|rf|fr)\s+gs://", re.IGNORECASE),
        "Inventory objects with `gsutil ls` and confirm with the user before deleting.",
    ),
    (
        "rm -rf against root, home, or unguarded variable",
        re.compile(
            r"\brm\s+-(?:[a-zA-Z]*r[a-zA-Z]*f|[a-zA-Z]*f[a-zA-Z]*r)\s+(?:--\s+)?(?:/(?:\s|\*|$)|~(?:/|\s|$)|\$HOME(?:/|\s|$)|\"\$(?:HOME|\{HOME\})\"(?:/|\s|$)|\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\})",
        ),
        "Guard variable paths with `[[ -n \"$TARGET\" && \"$TARGET\" != \"/\" && \"$TARGET\" != \"$HOME\" ]]` and target a specific project subdirectory.",
    ),
    (
        "recursive chmod 777 or recursive chmod on credential directories",
        re.compile(
            r"\bchmod\s+-R\s+(?:777\b|[0-7]{3,4}\s+(?:~|\$HOME)(?:/\.(?:ssh|aws|openclaw|config/gcloud|kube|gnupg|docker))?\b)",
        ),
        "Scope `chmod` to specific files and use owner-only permissions (`700` for directories, `600` for key/credential files).",
    ),
    (
        "raw block-device overwrite via dd",
        re.compile(r"\bdd\b.*?\bof=/dev/(?:sd[a-z]|nvme\d+n\d+|disk\d+|rdisk\d+)\b", re.IGNORECASE | re.DOTALL),
        "Never write directly to raw block devices from an agent session.",
    ),
    (
        "git force-push to a protected branch",
        re.compile(
            r"\bgit\s+push\b(?=.*(?:\s--force\b|\s-f\b|\s\+[A-Za-z0-9_./\-]+:(?:refs/heads/)?(?:main|master|production|staging|develop|release/\S+)))(?!.*--force-with-lease).*?\b(?:main|master|production|staging|develop|release/\S+)\b",
            re.IGNORECASE,
        ),
        "Never force-push to `main`, `master`, `production`, `staging`, `develop`, or `release/*`; use a feature branch and `--force-with-lease`.",
    ),
    (
        "credential or environment exfiltration pipe to network client",
        re.compile(
            r"(?:\bcat\s+[^\n|;]*(?:\.ssh/|\.aws/|\.openclaw/|\.config/gcloud/|\.kube/|\.gnupg/|\.netrc)[^\n|;]*|\b(?:env|printenv)\b)\s*\|\s*(?:curl|wget|http|xh|nc|socat)\b",
            re.IGNORECASE,
        ),
        "Never pipe local credentials, SSH keys, or environment dumps into an outbound network request.",
    ),
    (
        "pipe-to-shell with sudo",
        re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*sudo\s+(?:bash|sh|zsh)\b", re.IGNORECASE),
        "Download the script to a temporary file, inspect its contents and SHA-256 digest, and run only after review.",
    ),
]

EVIDENCE_ENV = "CATPILOT_EVIDENCE_LOG"
SYSLOG_ENV = "CATPILOT_EVIDENCE_SYSLOG"
HOOK_NAME = "pretooluse-destructive-ops"


def record_evidence(event: str, **fields) -> None:
    path = os.environ.get(EVIDENCE_ENV, "").strip()
    syslog_spec = os.environ.get(SYSLOG_ENV, "").strip()
    if not path and not syslog_spec:
        return
    line = {"ts": datetime.now(timezone.utc).isoformat(timespec="seconds"), "source": "claude-code-hook", "hook": HOOK_NAME, "event": event}
    line.update({k: v for k, v in fields.items() if v is not None})
    serialized = json.dumps(line, sort_keys=True)
    if path:
        try:
            target = Path(os.path.expanduser(path))
            target.parent.mkdir(parents=True, exist_ok=True)
            with open(target, "a", encoding="utf-8") as fh:
                fh.write(serialized + "\n")
        except Exception:
            pass
    if syslog_spec:
        try:
            _secrets.emit_syslog(serialized, syslog_spec)
        except Exception:
            pass


def session_id_of(event: object) -> str | None:
    sid = event.get("session_id") if isinstance(event, dict) else None
    return sid if isinstance(sid, str) and 0 < len(sid) <= 128 else None


def find_destructive_op(command: str) -> tuple[str, str] | None:
    """Return (label, remediation) for the first destructive command pattern matched, or None."""
    if not command:
        return None
    for label, pattern, remediation in DESTRUCTIVE_PATTERNS:
        if pattern.search(command):
            return label, remediation
    return None


def decide(event: dict) -> dict:
    if not isinstance(event, dict):
        raise ValueError("hook event must be an object")
    if event.get("tool_name") != "Bash":
        return {}
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    command = tool_input.get("command", "")
    if not isinstance(command, str):
        raise ValueError("command must be a string")
    found = find_destructive_op(command)
    if found is None:
        return {}
    label, remediation = found
    record_evidence("deny", tool="Bash", label=label, session_id=session_id_of(event))
    reason = (
        f"Catpilot destructive-operation check: this command matches a high-blast-radius pattern ({label}). "
        f"{remediation} If this exact command is intentional, run it yourself in your own terminal."
    )
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def main() -> int:
    try:
        payload = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(payload) > MAX_INPUT_BYTES:
            raise ValueError("hook input too large")
        result = decide(json.loads(payload))
    except (ValueError, TypeError, RecursionError):
        record_evidence("input_error")
        print(
            "Catpilot destructive-operation check could not read the hook input, so the command was not allowed. "
            "Review the command and retry.",
            file=sys.stderr,
        )
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
