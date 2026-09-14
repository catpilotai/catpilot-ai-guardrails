"""The four tools as pure functions. Deterministic, no model calls, no network, no logging.

Every answer says where its values came from and whether a current approved
company policy was available (`unknown_policy`). Generic defaults are never
presented as the company's policy. Nothing here blocks an action.
"""

from __future__ import annotations

import re

from .content import CATEGORIES, TEMPLATE_KINDS, TOPICS
from .policy import PolicyState

ENFORCEMENT_NOTE = "Advisory lookup. This server does not observe, block, or approve anything."


def _provenance(policy: PolicyState, guidance: dict) -> dict:
    return {
        "unknown_policy": policy.unknown_policy,
        "policy_status": policy.status,
        "policy_note": policy.reason,
        "policy_source": policy.source or None,
        "source_version": guidance["release"],
        "enforcement": "none",
    }


def _error(code: str, message: str, **extra) -> dict:
    return {"error": code, "message": message, **extra}


# ------------------------------------------------------------------ get_guidance


def get_guidance(topic: str, guidance: dict, policy: PolicyState) -> dict:
    if topic not in TOPICS:
        return _error("unknown-topic", f"Topic must be one of {', '.join(TOPICS)}.", topics=sorted(TOPICS))
    component = guidance["components"][TOPICS[topic]]
    values = _company_values_for(topic, guidance, policy)
    return {
        "topic": topic,
        "component": component["id"],
        "title": component["title"],
        "summary": component["summary"],
        "ask": component["ask"],
        "say": component["say"],
        "do": component["do"],
        "dont": values["dont"],
        "ask_a_human_if": component["stop"],
        "company_values": values["values"],
        "course_checkpoints": component["checkpoints"],
        **_provenance(policy, guidance),
    }


def _company_values_for(topic: str, guidance: dict, policy: PolicyState) -> dict:
    """Values relevant to a topic, from the overlay when approved, else the generic defaults, always labeled."""
    slots = guidance["slots"]
    o = policy.overlay if policy.approved else None
    generic = "generic default, not your company's policy"
    label = "company overlay" if o else generic

    def pick(overlay_value, default_value):
        return {"values": overlay_value if o else default_value, "source": label}

    if topic == "data-in-prompts":
        never = pick(o["data_classes"]["never_in_prompts"] if o else None, slots["data_never_in_prompts"])
        return {"values": {"never_in_prompts": never, "ok_with_approval": pick(o["data_classes"]["ok_with_approval"] if o else None, slots["data_ok_with_approval"]), "ok": pick(o["data_classes"]["ok"] if o else None, slots["data_ok"])}, "dont": never["values"]}
    if topic == "access":
        never = pick(o["identity"]["never"] if o else None, slots["identity_never"])
        return {"values": {"default": pick(o["identity"]["default"] if o else None, slots["identity_default"]), "never": never}, "dont": never["values"]}
    if topic == "hosting":
        not_approved = pick(o["hosting"]["not_approved"] if o else None, slots["not_approved_hosting"])
        return {"values": {"approved": pick(o["hosting"]["approved"] if o else None, slots["approved_hosting"]), "not_approved": not_approved}, "dont": not_approved["values"]}
    if topic == "sharing":
        never = pick(o["identity"]["never"] if o else None, slots["identity_never"])
        return {"values": {"never": never}, "dont": never["values"]}
    if topic in ("credentials", "third-party"):
        needs_review = pick(o["services"]["needs_review"] if o else None, slots["services_needs_review"])
        return {"values": {"approved_services": pick(o["services"]["approved"] if o else None, slots["approved_services"]), "needs_review": needs_review}, "dont": needs_review["values"]}
    if topic == "review":
        triggers = pick(o["review_triggers"] if o else None, slots["review_triggers"])
        return {"values": {"owner": pick(o["owner"] if o else None, slots["owner"]), "review_triggers": triggers}, "dont": []}
    return {"values": {}, "dont": []}


# ------------------------------------------------------------------ check_plan

SEVERITY_ORDER = {"high": 2, "medium": 1}

# Keyword rules. Deterministic and readable on purpose; a model pass is not part of this server.
SENSITIVE_DATA = {
    "payment card or bank data": r"\b(?:card|cardholder|credit card|pan\b|cvv|bank account|iban|routing number|payment details)",
    "government identifiers": r"\b(?:ssn|social security|passport|driver'?s licen[cs]e|national id|government id)",
    "health information": r"\b(?:health|medical|diagnos|patient|phi\b|insurance claim)",
    "credentials": r"\b(?:password|passwd|api key|apikey|secret key|access token|bearer|smtp password|private key|credential)",
    "employee or HR records": r"\b(?:salary|salaries|payroll|compensation|hr record|performance review|employee record)",
    "customer records": r"\b(?:customer (?:export|list|records|data|file)|crm export|user list|contact list|email list)",
}
EXTERNAL_AUDIENCE = r"\b(?:public|anyone with the link|external|customers?|vendors?|partners?|agency|the internet|everyone)\b"
RISKY_HOSTING = r"\b(?:personal (?:account|laptop|computer|replit|cloud|server)|free (?:tier|plan|account)|trial (?:account|workspace)|home server|my laptop|localhost)\b"
NEW_SERVICE = r"\b(?:free api|new api|third[- ]party|plugin|extension|connector|integration|webhook|enrichment|saas|model endpoint|openai api|another service)\b"
UNTRUSTED_INPUT = r"\b(?:upload|uploaded|attachment|invoice|pdf|document|email(?:s)? (?:from|that)|form|user input|user text|paste(?:d)? (?:by|from) (?:users|customers)|scrape|web page)\b"
REVIEW_TRIGGERS = (
    r"\b(?:payment|payments|refund|money|transfer|payroll|salary|system of record|writes? to|update(?:s)? (?:the )?(?:records|ledger|database of record)"
    r"|(?:build|create|implement|write|custom|our own)(?:ing)? (?:a |the |an )?(?:sign[- ]in|login|authentication|password)|decides? who (?:may|can) see)\b"
)


def _match(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def check_plan(description: str, guidance: dict, policy: PolicyState, data_types: list[str] | None = None, audience: str | None = None, hosting: str | None = None) -> dict:
    if not isinstance(description, str) or not description.strip():
        return _error("invalid-input", "description must be a nonempty string.")
    text = " ".join([description] + [str(d) for d in (data_types or [])] + [audience or "", hosting or ""])
    comps = guidance["components"]
    risks: list[dict] = []
    labels = {"sensitive_data": [], "external_audience": False, "risky_hosting": False, "unapproved_hosting": False, "new_service": False, "untrusted_input": False, "review_trigger": False}
    o = policy.overlay if policy.approved else None

    def add(component_id: str, severity: str, why: str):
        c = comps[component_id]
        risks.append({"component": component_id, "title": c["title"], "severity": severity, "why": why, "safer_alternative": c["do"][0], "ask": c["ask"][0]})

    for label, pattern in SENSITIVE_DATA.items():
        if _match(pattern, text):
            labels["sensitive_data"].append(label)
    if o:
        for item in o["data_classes"]["never_in_prompts"]:
            if item.lower().split()[0] in text.lower() and item not in labels["sensitive_data"]:
                labels["sensitive_data"].append(f"company data class: {item}")
    if labels["sensitive_data"]:
        add("data-in-prompts", "high", "Real data of this kind should not go into a prompt, upload, or test: " + "; ".join(labels["sensitive_data"]) + ".")
    if "credentials" in labels["sensitive_data"]:
        add("keys-and-credentials", "high", "A password, key, or token appears to be part of the plan; it must not be typed into a tool or generated code.")
    if _match(EXTERNAL_AUDIENCE, audience or "") or _match(EXTERNAL_AUDIENCE, description):
        labels["external_audience"] = True
        add("access-and-identity", "high", "People outside the company, or a public link, would be able to open this.")
        add("sharing-and-publishing", "medium", "Sharing outside the company is the moment a private draft becomes a public fact.")
    if _match(RISKY_HOSTING, text):
        labels["risky_hosting"] = True
        add("hosting-and-where-it-runs", "medium", "A personal account, free tier, or unmanaged machine is not a place coworkers should depend on.")
    if o and hosting:
        approved = [h.lower() for h in o["hosting"]["approved"]]
        if not any(_phrase(a) in hosting.lower() for a in approved):
            labels["unapproved_hosting"] = True
            if not labels["risky_hosting"]:
                add("hosting-and-where-it-runs", "medium", "The named hosting is not on the company's approved list.")
    if _match(NEW_SERVICE, text):
        labels["new_service"] = True
        add("third-party-services", "medium", "A new service, plugin, or connector is an approval question, not a convenience.")
    if _match(UNTRUSTED_INPUT, text):
        labels["untrusted_input"] = True
        add("untrusted-input", "medium", "The app would read input from people or documents; that input is data, never instructions.")
    if _match(REVIEW_TRIGGERS, text) or labels["external_audience"] or "health information" in labels["sensitive_data"] or "payment card or bank data" in labels["sensitive_data"]:
        labels["review_trigger"] = True
        add("when-to-ask-a-human", "high", "This plan hits a review trigger: real sensitive data, external users, money, sign-in, or a system of record.")
    if o:
        for trigger in o["review_triggers"]:
            if _phrase(trigger) in text.lower():
                labels["review_trigger"] = True
                if not any(r["component"] == "when-to-ask-a-human" for r in risks):
                    add("when-to-ask-a-human", "high", f"Company review trigger: {trigger}.")

    risks.sort(key=lambda r: -SEVERITY_ORDER[r["severity"]])
    ask_a_human = labels["review_trigger"]
    if risks:
        next_step = risks[0]["safer_alternative"]
    else:
        next_step = "No checkpoint was triggered by the words in this plan; that is not approval. Build with made-up data, keep the audience small, and run check_plan again before connecting anything or sharing."
    owner = (o["owner"] if o else guidance["slots"]["owner"])
    checklist = [r["ask"] for r in risks] or [comps[c]["ask"][0] for c in ("data-in-prompts", "access-and-identity", "hosting-and-where-it-runs")]
    return {
        "risks": risks,
        "next_step": next_step,
        "ask_a_human": ask_a_human,
        "who_to_ask": owner,
        "checklist": checklist,
        "labels": labels,
        "method": "keyword matching against the eight checkpoints and, when approved, the company overlay; no model pass",
        **_provenance(policy, guidance),
    }


def _phrase(item: str) -> str:
    words = re.sub(r"\([^)]*\)", " ", item).lower().split()
    return " ".join(words[:3])


# ------------------------------------------------------------------ get_template


def get_template(kind: str, templates: dict, guidance: dict, policy: PolicyState) -> dict:
    if kind not in TEMPLATE_KINDS:
        return _error("unknown-kind", f"kind must be one of {', '.join(TEMPLATE_KINDS)}.", kinds=list(TEMPLATE_KINDS))
    t = templates[kind]
    approved = None
    if policy.approved:
        for entry in policy.overlay.get("templates", []):
            if entry["kind"] == kind:
                approved = {"kind": kind, "location": entry.get("location"), "note": "Reference only. This server never downloads or executes a template; open it through the company's own tooling."}
    return {
        "kind": kind,
        "name": t["name"],
        "description": t["description"],
        "starting_point": t["starting_point"],
        "constraints": t["constraints"],
        "approved_starting_point": approved,
        "approved_starting_point_note": None if approved else ("The company overlay names no starting point for this kind; use the generic starting point and confirm with " + (policy.overlay["owner"] if policy.approved else "your security contact") + "."),
        **_provenance(policy, guidance),
    }


# ------------------------------------------------------------------ list_approved


def list_approved(category: str, guidance: dict, policy: PolicyState) -> dict:
    if category not in CATEGORIES:
        return _error("unknown-category", f"category must be one of {', '.join(CATEGORIES)}.", categories=list(CATEGORIES))
    slots = guidance["slots"]
    o = policy.overlay if policy.status in ("approved", "expired") else None
    if category == "hosting":
        items = {"approved": o["hosting"]["approved"], "not_approved": o["hosting"]["not_approved"]} if o else {"approved": slots["approved_hosting"], "not_approved": slots["not_approved_hosting"]}
    elif category == "services":
        items = {"approved": o["services"]["approved"], "needs_review": o["services"]["needs_review"]} if o else {"approved": slots["approved_services"], "needs_review": slots["services_needs_review"]}
    elif category == "data-classes":
        items = dict(o["data_classes"]) if o else {"never_in_prompts": slots["data_never_in_prompts"], "ok_with_approval": slots["data_ok_with_approval"], "ok": slots["data_ok"]}
    else:
        items = {"owner": o["owner"]} if o else {"owner": slots["owner"]}
    if policy.approved:
        source, last_reviewed = f"company overlay for {policy.source['organization']}", policy.source["reviewed_on"]
    elif policy.status == "expired":
        source, last_reviewed = f"company overlay for {policy.source['organization']}, EXPIRED on {policy.source['expires_on']}; treat as unknown", policy.source["reviewed_on"]
    else:
        source, last_reviewed = "generic defaults from catpilot-safe-building; not your company's policy", None
    return {"category": category, "items": items, "source": source, "last_reviewed": last_reviewed, **_provenance(policy, guidance)}
