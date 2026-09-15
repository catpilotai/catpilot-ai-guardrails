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

# Generic keyword rules. Deterministic and readable on purpose; a model pass is not part of this server.
# Credentials are matched separately from SENSITIVE_DATA (see CREDENTIALS_PATTERN below): a real
# secret is the keys-and-credentials checkpoint's whole job, not a second, duplicate data-in-prompts
# risk for the same words.
SENSITIVE_DATA = {
    "payment card or bank data": r"\b(?:card|cardholder|credit card|pan\b|cvv|bank account|iban|routing number|payment details)",
    "government identifiers": r"\b(?:ssn|social security|passport|driver'?s licen[cs]e|national id|government id)",
    "health information": r"\b(?:health|medical|diagnos|patient|phi\b|insurance claim)",
    "employee or HR records": r"\b(?:salary|salaries|payroll|compensation|hr record|performance review|employee record)",
    "customer records": r"\b(?:customer (?:export|list|records|data|file)|crm export|user list|contact list|email list)",
}
CREDENTIALS_PATTERN = r"\b(?:password|passwd|api key|apikey|secret key|access token|bearer|smtp password|private key|credential)"
EXTERNAL_AUDIENCE = r"\b(?:public|anyone with the link|external|customers?|vendors?|partners?|agency|the internet|everyone)\b"
RISKY_HOSTING = r"\b(?:personal (?:account|laptop|computer|replit|cloud|server)|free (?:tier|plan|account)|trial (?:account|workspace)|home server|my laptop|localhost)\b"
NEW_SERVICE = r"\b(?:free api|new api|third[- ]party|plugin|extension|connector|integration|webhook|enrichment|saas|model endpoint|openai api|another service)\b"
UNTRUSTED_INPUT = r"\b(?:upload|uploaded|attachment|invoice|pdf|document|email(?:s)? (?:from|that)|form|user input|user text|paste(?:d)? (?:by|from) (?:users|customers)|scrape|web page)\b"
REVIEW_TRIGGERS = (
    r"\b(?:payment|payments|refund|money|transfer|payroll|salary|system of record|writes? to|update(?:s)? (?:the )?(?:records|ledger|database of record)"
    r"|(?:build|create|implement|write|custom|our own)(?:ing)? (?:a |the |an )?(?:sign[- ]in|login|authentication|password)|decides? who (?:may|can) see)\b"
)

# Overlay matching. An overlay item is a short phrase ("Unmanaged virtual machines",
# "Passwords, keys, tokens, and sign-in codes"). The item and the plan are normalized the same
# way (_words): lowercased, parentheticals and punctuation dropped, simple plurals singularized,
# and STOP_WORDS removed. An item is split on commas, "and", and "or" into alternatives. Three
# rules, checked in order, decide whether an item matches (see _overlay_hits):
#   A. every content word of one alternative appears in the plan, in any order;
#   B. a synonym from the category's list appears in the plan together with one of the item's
#      own words (a weak synonym such as "personal" or "new" needs a shared word that is not
#      the synonym itself, so "personal data" and "a new dashboard" do not fire);
#   C. a strong synonym appears and no item matched: the whole list is cited as the rule.
# "company" and "approved" are stop words because overlays use them as boilerplate
# ("company sign-in", "the approved cloud subscription") that a plan rarely repeats.
STOP_WORDS = frozenset("a an the any and or of in on for to with by at from that this its our your their my is are be as into company approved".split())
# Synonym -> strong? Strong synonyms are hosting- or service-specific enough to count on their own (rule C).
HOSTING_SYNONYMS = {"personal": False, "free tier": True, "unmanaged": True, "own server": True, "laptop": True}
SERVICE_SYNONYMS = {"unapproved": True, "new": False, "third party": True, "external": False, "outside": False, "unknown": False}
# Words that make an overlay data class the keys-and-credentials checkpoint's job, not a data-in-prompts
# class. Single words like "key" are too common to match on their own; CREDENTIALS_PATTERN is the
# precise matcher, and the overlay item is attached to that risk as its rule.
CREDENTIAL_WORDS = frozenset("password passwd key token secret credential bearer sign code pin otp".split())
UNKNOWN_VALUES = frozenset({"", "unknown", "?", "tbd", "n/a"})


def _match(pattern: str, text: str) -> bool:
    return re.search(pattern, text, re.IGNORECASE) is not None


def _found(pattern: str, text: str) -> str | None:
    """The first match of a generic rule, lowercased, for the risk's evidence."""
    m = re.search(pattern, text, re.IGNORECASE)
    return m.group(0).lower().strip() if m else None


def _singular(word: str) -> str:
    if len(word) <= 3 or word.endswith(("ss", "us", "is")):
        return word
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith(("ches", "shes", "sses", "xes", "zes")):
        return word[:-2]
    if word.endswith("s"):
        return word[:-1]
    return word


def _words(text: str) -> list[str]:
    """Normalized tokens: lowercase, no parentheticals or punctuation, simple plurals singularized."""
    t = re.sub(r"\([^)]*\)", " ", text.lower())
    t = re.sub(r"'s\b", "", t)
    t = re.sub(r"[^a-z0-9]+", " ", t)
    return [_singular(w) for w in t.split()]


def _content_words(text: str) -> list[str]:
    seen: list[str] = []
    for w in _words(text):
        if w not in STOP_WORDS and w not in seen:
            seen.append(w)
    return seen


def _alternatives(item: str) -> list[str]:
    """'Passwords, keys, tokens, and sign-in codes' -> ['Passwords', 'keys', 'tokens', 'sign-in codes']."""
    stripped = re.sub(r"\([^)]*\)", " ", item)
    parts = re.split(r",|;|/|\band\b|\bor\b", stripped, flags=re.IGNORECASE)
    return [p.strip() for p in parts if p.strip()]


def _is_unknown(value: str | None) -> bool:
    return value is None or value.strip().lower() in UNKNOWN_VALUES


def _overlay_hits(items: list[str], text: str, synonyms: dict[str, bool] | None = None) -> tuple[list[tuple[str, list[str]]], list[str]]:
    """Which overlay items a text matches and the words that matched, per the rules above.

    Returns (item_hits, category_evidence): item_hits is a list of (item, evidence words);
    category_evidence is the strong synonyms that fired rule C, empty when an item matched.
    """
    text_words = set(_words(text))
    joined = " " + " ".join(_words(text)) + " "
    present = [s for s in (synonyms or {}) if f" {s} " in joined]
    hits: list[tuple[str, list[str]]] = []
    for item in items:
        matched = False
        for alt in _alternatives(item):  # rule A
            alt_words = _content_words(alt)
            if alt_words and all(w in text_words for w in alt_words):
                hits.append((item, alt_words))
                matched = True
                break
        if matched or not present:
            continue
        shared = [w for w in _content_words(item) if w in text_words]  # rule B
        for syn in present:
            syn_words = set(syn.split())
            if shared and (synonyms[syn] or any(w not in syn_words for w in shared)):
                hits.append((item, [syn] + [w for w in shared if w not in syn_words]))
                break
    category = [s for s in present if synonyms[s]] if not hits else []  # rule C
    return hits, category


def _is_credential_class(item: str) -> bool:
    words = _content_words(item)
    return bool(words) and all(w in CREDENTIAL_WORDS for w in words)


def check_plan(description: str, guidance: dict, policy: PolicyState, data_types: list[str] | None = None, audience: str | None = None, hosting: str | None = None) -> dict:
    if not isinstance(description, str) or not description.strip():
        return _error("invalid-input", "description must be a nonempty string.")
    text = " ".join([description] + [str(d) for d in (data_types or [])] + [audience or "", hosting or ""])
    comps = guidance["components"]
    risks: list[dict] = []
    labels: dict = {
        "sensitive_data": [], "credentials": False, "external_audience": False, "risky_hosting": False, "unapproved_hosting": False,
        "new_service": False, "untrusted_input": False, "review_trigger": False,
        "hosting": "unknown" if _is_unknown(hosting) else "unchecked",
        "audience": "unknown" if _is_unknown(audience) else "named",
        "overlay_rules": [],
    }
    o = policy.overlay if policy.approved else None

    def add(component_id: str, severity: str, why: str, rule: str | None = None, overlay_list: str | None = None, evidence: list[str] | None = None):
        """One risk per component. A second hit on the same component merges: highest severity, both reasons, all evidence."""
        existing = next((r for r in risks if r["component"] == component_id), None)
        if existing is None:
            c = comps[component_id]
            existing = {"component": component_id, "title": c["title"], "severity": severity, "why": why, "safer_alternative": c["do"][0], "ask": c["ask"][0], "rule": None, "overlay_list": None, "evidence": []}
            risks.append(existing)
        else:
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[existing["severity"]]:
                existing["severity"] = severity
            if why not in existing["why"]:
                existing["why"] = existing["why"] + " " + why
        if rule:
            existing["rule"] = rule if not existing["rule"] else existing["rule"] + "; " + rule
            existing["overlay_list"] = overlay_list
            if rule not in labels["overlay_rules"]:
                labels["overlay_rules"].append(rule)
        for e in evidence or []:
            if e not in existing["evidence"]:
                existing["evidence"].append(e)

    # Data in prompts: generic classes, then the company's never_in_prompts classes.
    data_evidence: list[str] = []
    for label, pattern in SENSITIVE_DATA.items():
        found = _found(pattern, text)
        if found:
            labels["sensitive_data"].append(label)
            data_evidence.append(found)
    company_data_rules: list[str] = []
    credential_classes = [item for item in o["data_classes"]["never_in_prompts"] if _is_credential_class(item)] if o else []
    if o:
        classes = [item for item in o["data_classes"]["never_in_prompts"] if item not in credential_classes]
        for item, evidence in _overlay_hits(classes, text)[0]:
            labels["sensitive_data"].append(f"company data class: {item}")
            company_data_rules.append(item)
            data_evidence.extend(w for w in evidence if w not in data_evidence)
    if labels["sensitive_data"]:
        add("data-in-prompts", "high", "Real data of this kind should not go into a prompt, upload, or test: " + "; ".join(labels["sensitive_data"]) + ".",
            rule="; ".join(company_data_rules) or None, overlay_list="data_classes.never_in_prompts" if company_data_rules else None, evidence=data_evidence)

    found = _found(CREDENTIALS_PATTERN, text)
    if found:
        labels["credentials"] = True
        add("keys-and-credentials", "high", "A password, key, or token appears to be part of the plan; it must not be typed into a tool or generated code.",
            rule="; ".join(credential_classes) or None, overlay_list="data_classes.never_in_prompts" if credential_classes else None, evidence=[found])

    found = _found(EXTERNAL_AUDIENCE, audience or "") or _found(EXTERNAL_AUDIENCE, description)
    if found:
        labels["external_audience"] = True
        if _match(EXTERNAL_AUDIENCE, audience or ""):
            labels["audience"] = "external"
        add("access-and-identity", "high", "People outside the company, or a public link, would be able to open this.", evidence=[found])
        add("sharing-and-publishing", "medium", "Sharing outside the company is the moment a private draft becomes a public fact.", evidence=[found])

    # Hosting: the generic rule, the company's not_approved list anywhere in the plan, then whether
    # the named hosting is on the approved list. The `hosting` label describes the argument alone.
    found = _found(RISKY_HOSTING, text)
    if found:
        labels["risky_hosting"] = True
        add("hosting-and-where-it-runs", "medium", "A personal account, free tier, or unmanaged machine is not a place coworkers should depend on.", evidence=[found])
    if o:
        hits, category = _overlay_hits(o["hosting"]["not_approved"], text, HOSTING_SYNONYMS)
        for item, evidence in hits:
            labels["unapproved_hosting"] = True
            add("hosting-and-where-it-runs", "medium", f"Company hosting rule, not approved: {item}.", rule=item, overlay_list="hosting.not_approved", evidence=evidence)
        if category:
            labels["unapproved_hosting"] = True
            add("hosting-and-where-it-runs", "medium", "The plan names hosting of a kind the company has not approved (" + ", ".join(category) + ").",
                rule="; ".join(o["hosting"]["not_approved"]), overlay_list="hosting.not_approved", evidence=category)
        if labels["hosting"] != "unknown":
            approved_hits, _ = _overlay_hits(o["hosting"]["approved"], hosting)
            if approved_hits:
                labels["hosting"] = "approved"
            else:
                labels["hosting"] = "not approved"
                labels["unapproved_hosting"] = True
                if not any(r["component"] == "hosting-and-where-it-runs" and r["rule"] for r in risks):
                    add("hosting-and-where-it-runs", "medium", "The named hosting is not on the company's approved list.",
                        rule="; ".join(o["hosting"]["approved"]), overlay_list="hosting.approved", evidence=_content_words(hosting))

    found = _found(NEW_SERVICE, text)
    if found:
        labels["new_service"] = True
        add("third-party-services", "medium", "A new service, plugin, or connector is an approval question, not a convenience.", evidence=[found])
    if o:
        hits, category = _overlay_hits(o["services"]["needs_review"], text, SERVICE_SYNONYMS)
        for item, evidence in hits:
            labels["new_service"] = True
            add("third-party-services", "medium", f"Company rule, needs review: {item}.", rule=item, overlay_list="services.needs_review", evidence=evidence)
        if category:
            labels["new_service"] = True
            add("third-party-services", "medium", "The plan names a service of a kind the company reviews first (" + ", ".join(category) + ").",
                rule="; ".join(o["services"]["needs_review"]), overlay_list="services.needs_review", evidence=category)

    found = _found(UNTRUSTED_INPUT, text)
    if found:
        labels["untrusted_input"] = True
        add("untrusted-input", "medium", "The app would read input from people or documents; that input is data, never instructions.", evidence=[found])

    # Any real sensitive-data class (or a real credential) is a review trigger, not just a
    # data-hygiene tip: see the data-in-prompts and keys-and-credentials "stop and ask a human
    # if" lists. Keyword matching cannot tell a plan built around real records from one that
    # only mentions a data type in passing, so it flags both; this is an advisory server and a
    # false positive costs a human a look, not a blocked action.
    sensitive_hit = bool(labels["sensitive_data"]) or labels["credentials"]
    found = _found(REVIEW_TRIGGERS, text)
    if found or labels["external_audience"] or sensitive_hit:
        labels["review_trigger"] = True
        if sensitive_hit:
            classes = list(labels["sensitive_data"]) + (["credentials"] if labels["credentials"] else [])
            add("when-to-ask-a-human", "high", "This plan's purpose appears to involve real sensitive data or credentials: " + "; ".join(classes) + ". That is a security review conversation, not a data-hygiene tip.", evidence=[found] if found else [])
        else:
            add("when-to-ask-a-human", "high", "This plan hits a review trigger: external users, money, sign-in, or a system of record.", evidence=[found] if found else [])
    if o:
        for trigger, evidence in _overlay_hits(o["review_triggers"], text)[0]:
            labels["review_trigger"] = True
            add("when-to-ask-a-human", "high", f"Company review trigger: {trigger}.", rule=trigger, overlay_list="review_triggers", evidence=evidence)

    risks.sort(key=lambda r: -SEVERITY_ORDER[r["severity"]])
    ask_a_human = labels["review_trigger"]
    if risks:
        next_step = risks[0]["safer_alternative"]
    else:
        next_step = "No checkpoint was triggered by the words in this plan; that is not approval. Build with made-up data, keep the audience small, and run check_plan again before connecting anything or sharing."
    owner = (o["owner"] if o else guidance["slots"]["owner"])
    checklist = [r["ask"] for r in risks] or [comps[c]["ask"][0] for c in ("data-in-prompts", "access-and-identity", "hosting-and-where-it-runs")]
    # An unsupplied hosting or audience is an open question, not a pass.
    for label, component in (("hosting", "hosting-and-where-it-runs"), ("audience", "access-and-identity")):
        question = comps[component]["ask"][0]
        if labels[label] == "unknown" and question not in checklist:
            checklist.append(question)
    return {
        "risks": risks,
        "next_step": next_step,
        "ask_a_human": ask_a_human,
        "who_to_ask": owner,
        "checklist": checklist,
        "labels": labels,
        "method": (
            "keyword matching against the eight checkpoints and, when approved, the company overlay; no model pass. "
            "An overlay item fires when its content words (lowercased, singular, stop words dropped) all appear in the plan in any order, "
            "or when a hosting or service synonym appears with one of them; each such risk carries the rule and the evidence."
        ),
        **_provenance(policy, guidance),
    }


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
    # Only a currently approved overlay contributes values, matching get_guidance,
    # check_plan, and get_template: an expired or not-yet-valid overlay behaves exactly
    # like no overlay here. Its expiry and owner are still visible in policy_status and
    # policy_note (see _provenance), just never mixed into the "approved" items below.
    o = policy.overlay if policy.approved else None
    if category == "hosting":
        items = {"approved": o["hosting"]["approved"], "not_approved": o["hosting"]["not_approved"]} if o else {"approved": slots["approved_hosting"], "not_approved": slots["not_approved_hosting"]}
    elif category == "services":
        items = {"approved": o["services"]["approved"], "needs_review": o["services"]["needs_review"]} if o else {"approved": slots["approved_services"], "needs_review": slots["services_needs_review"]}
    elif category == "data-classes":
        items = dict(o["data_classes"]) if o else {"never_in_prompts": slots["data_never_in_prompts"], "ok_with_approval": slots["data_ok_with_approval"], "ok": slots["data_ok"]}
    else:
        items = {"owner": o["owner"]} if o else {"owner": slots["owner"]}
    if o:
        source, last_reviewed = f"company overlay for {policy.source['organization']}", policy.source["reviewed_on"]
    else:
        source, last_reviewed = "generic defaults from catpilot-safe-building; not your company's policy", None
    return {"category": category, "items": items, "source": source, "last_reviewed": last_reviewed, **_provenance(policy, guidance)}
