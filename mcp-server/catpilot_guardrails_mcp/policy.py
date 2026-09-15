"""Company overlay as the server sees it: loaded and validated on every call, never trusted past its expiry.

The overlay path and template hosts come from process configuration only,
never from a tool argument, so a prompt cannot point the server at another
file. Local file ownership is the trust boundary of this reference server.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "tools"))
import validate_overlay  # noqa: E402  (repository tool; the server runs from a checkout)


@dataclass
class PolicyState:
    status: str                      # none | approved | expired | not-yet-valid | invalid | missing
    reason: str
    overlay: dict | None = None
    source: dict = field(default_factory=dict)

    @property
    def approved(self) -> bool:
        return self.status == "approved"

    @property
    def unknown_policy(self) -> bool:
        return not self.approved


def load_policy(path: str | None, allowed_hosts: set[str] | None = None, now: dt.date | None = None) -> PolicyState:
    if not path:
        return PolicyState("none", "No company overlay is configured; answers use generic defaults.")
    file = Path(path)
    if not file.is_absolute():
        return PolicyState("invalid", "CATPILOT_OVERLAY_FILE must be an absolute path.")
    try:
        data, raw = validate_overlay.load_overlay_file(file)
        overlay = validate_overlay.validate_structure(data)
    except FileNotFoundError:
        return PolicyState("missing", "The configured overlay file does not exist.")
    except (OSError, validate_overlay.OverlayError) as exc:
        return PolicyState("invalid", f"The configured overlay did not validate: {exc.__class__.__name__}.")
    today = now or dt.date.today()
    source = {
        "organization": overlay["organization"],
        "owner": overlay["owner"],
        "reviewed_on": overlay["reviewed_on"].isoformat(),
        "expires_on": overlay["expires_on"].isoformat(),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    try:
        content_errors = validate_overlay.validate_content(overlay, allowed_hosts or set())
    except validate_overlay.OverlayError as exc:
        return PolicyState("invalid", f"The configured overlay did not validate: {exc.__class__.__name__}.", None, source)
    if content_errors:
        return PolicyState("invalid", "The configured overlay failed the content scan; ask the owner to fix it.", None, source)
    if overlay["expires_on"] < today:
        return PolicyState("expired", f"The overlay expired on {source['expires_on']}; treat its values as unknown and ask {overlay['owner']}.", overlay, source)
    if overlay["reviewed_on"] > today:
        return PolicyState("not-yet-valid", "The overlay's review date is in the future.", overlay, source)
    return PolicyState("approved", "Values come from the company's reviewed overlay.", overlay, source)
