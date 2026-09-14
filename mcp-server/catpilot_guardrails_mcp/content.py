"""Generic guidance and starting points.

`defaults/guidance.json` is generated from `src/skills/safe-building/` by
`tools/bundle.py` and checked for drift in CI. `defaults/templates.json` is
authored. Both are read once at import; nothing here is fetched.
"""

from __future__ import annotations

import json
from pathlib import Path

DEFAULTS = Path(__file__).resolve().parent.parent / "defaults"

# Tool topic -> safe-building component id.
TOPICS: dict[str, str] = {
    "data-in-prompts": "data-in-prompts",
    "access": "access-and-identity",
    "hosting": "hosting-and-where-it-runs",
    "sharing": "sharing-and-publishing",
    "credentials": "keys-and-credentials",
    "third-party": "third-party-services",
    "untrusted-input": "untrusted-input",
    "review": "when-to-ask-a-human",
}
TEMPLATE_KINDS = ("internal-lookup-tool", "form-to-spreadsheet", "dashboard", "document-summarizer", "chatbot-over-docs")
CATEGORIES = ("hosting", "services", "data-classes", "contacts")


def load_guidance() -> dict:
    return json.loads((DEFAULTS / "guidance.json").read_text(encoding="utf-8"))


def load_templates() -> dict:
    return json.loads((DEFAULTS / "templates.json").read_text(encoding="utf-8"))
