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

# Explicit fields decide; free text only hints. A plan that says "No external users or public
# links" or "synthetic patient records only" names a risk in order to rule it out, so words
# alone must never produce an outcome. The caller's fields (hosting, audience, data_classes,
# services, write_access) carry the decisions; the description is read for questions to ask.

SEVERITY_ORDER = {"high": 2, "medium": 1}
OUTCOME_ORDER = {"permitted": 0, "unknown": 1, "requires_review": 2, "prohibited": 3}

FIELD_COMPONENT = {
    "hosting": "hosting-and-where-it-runs",
    "audience": "access-and-identity",
    "data_classes": "data-in-prompts",
    "services": "third-party-services",
    "write_access": "when-to-ask-a-human",
}
# The severity each component has carried since the first release; a prohibited decision is high.
COMPONENT_SEVERITY = {
    "data-in-prompts": "high",
    "access-and-identity": "high",
    "hosting-and-where-it-runs": "medium",
    "sharing-and-publishing": "medium",
    "keys-and-credentials": "high",
    "third-party-services": "medium",
    "untrusted-input": "medium",
    "when-to-ask-a-human": "high",
}

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
# ``external connection`` describes network activity, not an audience. Keep the bare
# ``external`` audience cue for phrases such as "external partners". An intervening
# network noun is excluded only when it is not followed by a people/role term, so
# "external API developers" and "external service users" remain audience cues.
EXTERNAL_AUDIENCE = (
    r"\b(?:public|anyone with the link|external(?!\s+(?:connections?|services?|apis?|requests?|calls?)\b"
    r"(?!\s+(?:developers?|users?|providers?|partners?|customers?|teams?|staff|people|engineers?|administrators?|admins?)\b))"
    r"|customers?|vendors?|partners?|agency|the internet|everyone)\b"
)
RISKY_HOSTING = r"\b(?:personal (?:account|laptop|computer|replit|cloud|server)|free (?:tier|plan|account)|trial (?:account|workspace)|home server|my laptop|localhost)\b"
# A hosting value that says the thing is never deployed, hosted, or published anywhere -- it
# just runs on the builder's own machine, or by hand as a one-off. Whole phrases, not overlay
# items: NOT_DEPLOYED_HOSTING alone decides the category (see _hosting_category below).
NOT_DEPLOYED_HOSTING = (
    r"\b(?:not deployed|no deployment|not hosted|not published|locally|local|localhost|"
    r"my machine|my laptop|own laptop|own machine|workstation|workspace|"
    r"run by hand|run manually|one[- ]off|no new hosting|no hosting)\b"
)
# The subset of NOT_DEPLOYED_HOSTING that names a specific machine rather than just "not
# deployed": still not hosting, but a machine other people depend on is a review question once
# the audience is not the builder alone (see check_plan's hosting block).
MACHINE_ONLY_HOSTING = r"\b(?:my machine|my laptop|own laptop|own machine|workstation|localhost)\b"
# A value naming a personal cloud account or a free tier is never the not_deployed category,
# even alongside a not-deployed cue ("free tier on my laptop"): the existing approved/not-approved
# rules decide it instead.
PERSONAL_OR_FREE_TIER_HOSTING = r"\b(?:personal (?:account|cloud|computer|replit|server)|free[- ]tier|free (?:plan|account))\b"
NEW_SERVICE = r"\b(?:free api|new api|third[- ]party|plugin|extension|connector|integration|webhook|enrichment|saas|model endpoint|openai api|another service)\b"
UNTRUSTED_INPUT = r"\b(?:upload|uploaded|attachment|invoice|pdf|document|email(?:s)? (?:from|that)|form|user input|user text|paste(?:d)? (?:by|from) (?:users|customers)|scrape|web page)\b"
REVIEW_TRIGGERS = (
    r"\b(?:payment|payments|refund|money|transfer|payroll|salary|system of record|writes? to|update(?:s)? (?:the )?(?:records|ledger|database of record)"
    r"|(?:build|create|implement|write|custom|our own)(?:ing)? (?:a |the |an )?(?:sign[- ]in|login|authentication|password)|decides? who (?:may|can) see)\b"
)

# The generic rule sentence a decision cites when no overlay item does.
GENERIC_RULES = {
    "hosting_unknown": "hosting has to be named before it can be checked",
    "hosting_risky": "a personal account, free tier, trial workspace, home server, or unmanaged machine is not a place coworkers should depend on",
    "hosting_approved_list": "hosting must be on the company's approved list",
    "hosting_not_deployed": "not deployed; hosting is reviewed when the thing is published for others",
    "hosting_machine_dependency": "a machine other people depend on is not managed hosting",
    "audience_internal": "the smallest named group inside the company is the default audience",
    "audience_external": "people outside the company, or a public link, is a review conversation before it is a build",
    "audience_unknown": "who can open this has to be named before it can be checked",
    "data_prohibited": "real payment, government, health, or credential data does not go into prompts, uploads, or test runs",
    "data_review": "employee and customer records need the data owner's agreement in writing first",
    "data_ok": "made-up records that keep the shape of the real data are the safe default",
    "data_missing": "no data classes were named; say what data the app will touch",
    "data_unrecognized": "this data class is not covered by the available policy; ask the data owner",
    "service_review": "any new software service needs review",
    "service_missing": "no services were named; say what the app will connect to",
    "write_review": "writing to a system of record needs a human review before it goes live",
    "write_none": "an app that reads, or writes only to its own store, is not a system-of-record change",
    "write_unknown": "whether this writes to a system of record has to be answered before it can be checked",
}
# Generic data classes, when no overlay says otherwise. Credentials are handled separately.
GENERIC_DATA_OUTCOME = {
    "payment card or bank data": "prohibited",
    "government identifiers": "prohibited",
    "health information": "prohibited",
    "employee or HR records": "requires_review",
    "customer records": "requires_review",
}
AUDIENCE_WORDS = {
    "public": ("anyone", "public", "internet", "everyone", "world"),
    "external": ("customer", "vendor", "partner", "agency", "contractor", "external", "client", "supplier", "outside"),
    "internal": ("colleague", "team", "employee", "staff", "internal", "manager", "ops", "coworker", "department"),
}
# An audience value that names only the person building this, not anyone else: it decides
# whether a not_deployed hosting value needs no review or a plain one.
BUILDER_ALONE_AUDIENCE = r"\b(?:just me|only me|myself|the builder|me only|no one else|personal use)\b"
WRITE_ACCESS_QUESTION = "Will this write to a system of record (CRM, ERP, HR, finance, tickets, the production database)?"

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

# Free text says "synthetic", "no external users", "instead of the real export" to rule a risk
# out. A match under one of these does not become a hint.
HINT_NEGATIONS = ("no", "not", "never", "without", "none", "zero", "instead of", "neither", "nor")
SYNTHETIC = r"(?:synthetic|made[- ]up|make[- ]believe|fake|fictional|sample|dummy|placeholder|pretend|example\.com)"
CLAUSE_END = re.compile(r"[.;!?]")

# A data_classes item is synthetic only when the word is not itself being ruled out: "Health
# records, not synthetic" and "non-synthetic export" name the word to reject it, not to choose
# it. HINT_NEGATIONS already has "not", "no", "never", "without", "instead of"; these extend it
# for this check ("non-" is handled separately below, since "non-synthetic" does not tokenize
# apart into two words).
SYNTHETIC_NEGATION_EXTRA = ("isn't", "aren't", "rather than", "other than", "except")
# A real-data cue outweighs a synthetic-looking word: "sample rows and real customer records" is
# real data, not a safe made-up example. Whole words only, so "surreal" or "realistic" do not count.
REAL_DATA_CUE = r"\b(?:real|actual|live|production|genuine|customer records|employee records|export from)\b"
DATA_PROVENANCE_VALUES = ("synthetic", "real", "mixed", "unknown")
ENVIRONMENT_VARIABLE_NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,127}$")
NO_SERVICE_SENTINELS = frozenset({"none", "no service", "no services", "n/a"})

# A hosting or service value that names an approved item together with other words, or negates
# one, is not a plain approval: "Internal App Platform and a personal VPS" and "a new model
# endpoint instead of the company LLM gateway" both contain an approved item's words but do not
# simply choose it. HINT_NEGATIONS already has "not", "no", "instead of", "without"; these
# extend it for this check.
APPROVED_MENTION_NEGATION_EXTRA = ("rather than", "replacing", "other than", "no longer")


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


def _merge_evidence(*groups: list[str]) -> list[str]:
    """Several evidence lists, flattened and de-duplicated, first occurrence wins."""
    out: list[str] = []
    for group in groups:
        for word in group:
            if word not in out:
                out.append(word)
    return out


def _approved_mention(items: list[str], value: str) -> tuple[str, str, list[str]] | None:
    """How an explicit `hosting` or `services` value relates to one of the approved `items`.

    Returns (kind, item, evidence). "permitted": the value's content words exactly equal one
    item's, in any order (stop words, punctuation, and plurals aside) -- this is also the old
    "starts_approved" shortcut, since "approved" is itself a stop word, so "the approved
    transactional email service" already equals "The approved transactional email service" this
    way. Otherwise, when an item's words are all present together with other content words,
    "mixed" (nothing rules it out) or "negated" (a negation -- "not", "instead of", "rather
    than", "replacing", "other than", "no longer", "without" -- precedes them); evidence is the
    words beyond the item's own. None when `value` does not name any item at all.
    """
    content = _content_words(value)
    content_set = set(content)
    normalized = " ".join(_words(value))
    for item in items:
        item_words = _content_words(item)
        if item_words and (normalized == " ".join(_words(item)) or content_set == set(item_words)):
            return "permitted", item, content
    for item in items:
        item_words = _content_words(item)
        item_set = set(item_words)
        if item_words and item_set <= content_set:
            extra = [w for w in content if w not in item_set]
            kind = "negated" if _negated_approved_mention(value, item_words) else "mixed"
            return kind, item, extra
    return None


def _negated_approved_mention(value: str, item_words: list[str]) -> bool:
    """True when a negation precedes the leftmost occurrence of an approved item's words in `value`."""
    span = None
    for word in item_words:
        for m in re.finditer(r"\b" + re.escape(word) + r"[a-z]{0,3}\b", value, re.IGNORECASE):
            if span is None or m.start() < span[0]:
                span = (m.start(), m.end())
    return span is not None and _negated(value, span[0], span[1], APPROVED_MENTION_NEGATION_EXTRA)


def _hosting_category(value: str, o: dict | None) -> str | None:
    """The string "not_deployed" when `value` says the thing is never deployed, hosted, or
    published anywhere -- it runs locally, on the builder's own machine or laptop, in the
    developer's workspace, or by hand as a one-off -- and None otherwise.

    A value that also names an approved hosting entry (in any of the three ways
    `_approved_mention` recognizes), a specific not-approved entry (rule A or B of
    `_overlay_hits`, not the bare category synonym rule C -- that is the fault this category
    exists to fix: "laptop" alone is a strong not-approved synonym and must not condemn every
    not-deployed, laptop-only script), a personal cloud account, or a free tier is not this
    category; the existing rules decide it instead.
    """
    if not _match(NOT_DEPLOYED_HOSTING, value) or _match(PERSONAL_OR_FREE_TIER_HOSTING, value):
        return None
    if o:
        if _approved_mention(o["hosting"]["approved"], value) is not None:
            return None
        if _overlay_hits(o["hosting"]["not_approved"], value, HOSTING_SYNONYMS)[0]:
            return None
    return "not_deployed"


def _is_builder_alone(value: str | None) -> bool:
    """True when an audience value names only the person building this, not anyone else."""
    return value is not None and _match(BUILDER_ALONE_AUDIENCE, value)


def _is_credential_class(item: str) -> bool:
    words = _content_words(item)
    return bool(words) and all(w in CREDENTIAL_WORDS for w in words)


def _clause(text: str, start: int, end: int) -> tuple[str, str, str]:
    """The sentence around a match: what comes before it, what comes after it, and the whole of it."""
    left = 0
    for m in CLAUSE_END.finditer(text, 0, start):
        left = m.end()
    m = CLAUSE_END.search(text, end)
    right = m.start() if m else len(text)
    return text[left:start], text[end:right], text[left:right]


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9.'\-]+", text.lower())


def _negated(text: str, start: int, end: int, extra: tuple[str, ...] = ()) -> bool:
    """True when the plan names this thing in order to rule it out rather than to choose it.

    Negated: a negation word within about six words before the match, in the same sentence
    ("No external users"); "only synthetic" and its variants before it; or "only" within about
    four words after it in a sentence that also says synthetic, made-up, fake, or sample
    ("Use synthetic patient records only").
    """
    before, after, sentence = _clause(text, start, end)
    prior = " ".join(_tokens(before)[-6:])
    if re.search(r"\b(?:" + "|".join(HINT_NEGATIONS + extra) + r")\b", prior):
        return True
    if re.search(r"\bonly\s+" + SYNTHETIC, prior):
        return True
    follow = " ".join(_tokens(after)[:4])
    return bool(re.search(r"\bonly\b", follow) and re.search(SYNTHETIC, sentence, re.IGNORECASE))


def _hint(pattern: str, text: str, extra: tuple[str, ...] = ()) -> str | None:
    """The first match of a generic rule that the text does not negate, lowercased."""
    for m in re.finditer(pattern, text, re.IGNORECASE):
        if not _negated(text, m.start(), m.end(), extra):
            return m.group(0).lower().strip()
    return None


def _evidence_negated(text: str, words: list[str]) -> bool:
    """True when every occurrence of every matched overlay word sits under a negation."""
    seen = False
    for word in words:
        for m in re.finditer(r"\b" + re.escape(word) + r"[a-z]{0,3}\b", text, re.IGNORECASE):
            seen = True
            if not _negated(text, m.start(), m.end()):
                return False
    return seen


def _audience_category(value: str) -> str:
    """internal, external, public, or unknown, ignoring words the value itself rules out."""
    for category in ("public", "external", "internal"):
        for word in AUDIENCE_WORDS[category]:
            for m in re.finditer(r"\b" + word + r"s?\b", value, re.IGNORECASE):
                if not _negated(value, m.start(), m.end()):
                    return category
    return "unknown"


def _synthetic_negation_word(text: str, start: int, end: int) -> str | None:
    """The word/phrase that means a synthetic-pattern match at [start, end) rules synthetic data
    out rather than choosing it, or None. Either "not"/"non" sits directly against the match
    ("non-synthetic", which does not tokenize apart), or a negation occurs earlier in the same
    clause ("Health records, not synthetic", "rather than sample data", "isn't synthetic")."""
    immediate = re.search(r"\b(not|non)[\s-]*$", text[:start], re.IGNORECASE)
    if immediate:
        return immediate.group(1).lower()
    before = _clause(text, start, end)[0]
    m = re.search(r"\b(?:" + "|".join(HINT_NEGATIONS + SYNTHETIC_NEGATION_EXTRA) + r")\b", before, re.IGNORECASE)
    return m.group(0).lower() if m else None


def _data_class_provenance(item: str) -> tuple[bool, list[str], str | None]:
    """(is_synthetic, evidence, note) inferred from a data_classes item's own words, used when
    the caller does not pass an explicit `data_provenance`.

    Synthetic only when a SYNTHETIC word appears, is not negated, and no real-data cue is also
    present. An item with both a synthetic cue and a real cue, or a negated synthetic cue, is
    evaluated with the real-data rules instead; its evidence and a note say why.
    """
    m = re.search(r"\b" + SYNTHETIC + r"\b", item, re.IGNORECASE)
    if not m:
        return False, [], None
    synthetic_word = m.group(0).lower()
    real_word = _found(REAL_DATA_CUE, item)
    negation_word = _synthetic_negation_word(item, m.start(), m.end())
    if real_word or negation_word:
        evidence = [w for w in (negation_word, synthetic_word, real_word) if w]
        return False, evidence, "mixed or negated cue; treated as real"
    return True, [synthetic_word], None


def _credential_reference_error(references) -> dict | None:
    """Validate identifier-only credential metadata without ever accepting a credential value.

    This deliberately recognizes environment-variable names only.  Callers must use
    ``data_classes`` for secret material or an unknown value; the existing conservative
    data-class rules then apply.  The two flags make an identifier-only declaration
    auditable, but this narrow form cannot describe reading or sending a value.
    """
    if references is None:
        return None
    if not isinstance(references, list):
        return _error("invalid-input", "credential_references must be a list of identifier-only environment-variable references.")
    allowed = {"name", "value_in_model_context", "value_in_generated_artifacts"}
    for reference in references:
        if not isinstance(reference, dict) or set(reference) - allowed:
            return _error("invalid-input", "Each credential_references item may contain only name, value_in_model_context, and value_in_generated_artifacts.")
        name = reference.get("name")
        if not isinstance(name, str) or not ENVIRONMENT_VARIABLE_NAME.fullmatch(name):
            return _error("invalid-input", "credential_references.name must be an uppercase environment-variable identifier (letters, digits, and underscores; 128 characters max).")
        for flag in ("value_in_model_context", "value_in_generated_artifacts"):
            if flag not in reference or type(reference[flag]) is not bool:
                return _error("invalid-input", f"credential_references.{flag} must be a boolean.")
    return None


def _named_services(services: list[str] | None) -> list[str]:
    """Normalize explicit no-service declarations without treating a service name as one."""
    return [
        value for value in (str(service).strip() for service in (services or []))
        if value and " ".join(value.lower().split()) not in NO_SERVICE_SENTINELS
    ]


def check_plan(
    description: str,
    guidance: dict,
    policy: PolicyState,
    data_classes: list[str] | None = None,
    data_provenance: str | None = None,
    audience: str | None = None,
    hosting: str | None = None,
    services: list[str] | None = None,
    write_access: bool | None = None,
    data_types: list[str] | None = None,
    credential_references: list[dict] | None = None,
) -> dict:
    """Decide from the explicit fields; read the description only for hints.

    `data_types` is the deprecated name for `data_classes` and is merged into it.

    `data_provenance` overrides the text inference for every `data_classes` item: "synthetic"
    takes the made-up-data branch for all of them; "real" and "mixed" take the real-data rules
    for all of them, regardless of words like "sample" or "synthetic" in the text; "unknown" is
    treated as "real" and each data_classes decision carries a note saying so. Any other value
    is reported back as an error rather than raised.

    `credential_references` is only for identifier metadata such as
    ``{"name": "CHECKIN_RELAY_TOKEN", "value_in_model_context": false,
    "value_in_generated_artifacts": false}``. It never accepts a secret value. The two
    required flags say whether the value enters model context or generated artifacts;
    either true is prohibited. A local runtime environment lookup alone is neither.
    """
    if not isinstance(description, str) or not description.strip():
        return _error("invalid-input", "description must be a nonempty string.")
    if data_provenance is not None and data_provenance not in DATA_PROVENANCE_VALUES:
        return _error("invalid-input", f"data_provenance must be one of {', '.join(DATA_PROVENANCE_VALUES)}, or omitted.", data_provenance=data_provenance)
    credential_reference_error = _credential_reference_error(credential_references)
    if credential_reference_error:
        return credential_reference_error
    named_classes = [str(d).strip() for d in (list(data_classes or []) + list(data_types or [])) if str(d).strip()]
    named_services = _named_services(services)
    comps = guidance["components"]
    o = policy.overlay if policy.approved else None
    risks: list[dict] = []
    decisions: list[dict] = []
    hints: list[dict] = []
    questions: list[str] = []
    labels: dict = {
        "sensitive_data": [], "credentials": False, "external_audience": False, "risky_hosting": False, "unapproved_hosting": False,
        "new_service": False, "untrusted_input": False, "review_trigger": False,
        "hosting": "unknown", "audience": "unknown", "overlay_rules": [], "data_provenance": data_provenance,
    }

    def add(component_id: str, severity: str, why: str, rule: str | None = None, overlay_list: str | None = None, evidence: list[str] | None = None, basis: str = "hint"):
        """One risk per component. A second hit on the same component merges: highest severity, both reasons, all evidence."""
        existing = next((r for r in risks if r["component"] == component_id), None)
        if existing is None:
            c = comps[component_id]
            existing = {"component": component_id, "title": c["title"], "severity": severity, "why": why, "safer_alternative": c["do"][0], "ask": c["ask"][0], "rule": None, "overlay_list": None, "evidence": [], "basis": basis}
            risks.append(existing)
        else:
            if SEVERITY_ORDER[severity] > SEVERITY_ORDER[existing["severity"]]:
                existing["severity"] = severity
            if why not in existing["why"]:
                existing["why"] = existing["why"] + " " + why
            if basis == "decision":
                existing["basis"] = "decision"
        if rule:
            existing["rule"] = rule if not existing["rule"] else existing["rule"] + "; " + rule
            existing["overlay_list"] = overlay_list
            if rule not in labels["overlay_rules"]:
                labels["overlay_rules"].append(rule)
        for e in evidence or []:
            if e not in existing["evidence"]:
                existing["evidence"].append(e)

    def decide(field: str, value, outcome: str, rule: str, source: str, evidence: list[str] | None = None, note: str | None = None,
               component: str | None = None, why: str | None = None, overlay_list: str | None = None, risk_rule: str | None = None):
        """One decision from one explicit field, and the risk it raises when it is not permitted."""
        decisions.append({"field": field, "value": value, "outcome": outcome, "rule": rule, "source": source, "evidence": evidence or [], "note": note})
        component = component or FIELD_COMPONENT[field]
        decision_components.append(component)
        if outcome in ("prohibited", "requires_review"):
            severity = "high" if outcome == "prohibited" else COMPONENT_SEVERITY[component]
            cited = risk_rule if risk_rule is not None else (rule if source == "company overlay" else None)
            add(component, severity, why or f"{field}: {rule}.", rule=cited, overlay_list=overlay_list, evidence=evidence, basis="decision")

    def hint(component_id: str, evidence: str, note: str):
        hints.append({"component": component_id, "evidence": evidence, "note": note})

    decision_components: list[str] = []

    # ---------------------------------------------------------------- decisions

    # hosting
    if _is_unknown(hosting):
        decide("hosting", "unknown", "unknown", GENERIC_RULES["hosting_unknown"], "generic default", note="hosting was not given")
        questions.append(comps["hosting-and-where-it-runs"]["ask"][0])
    else:
        value = hosting.strip()
        if _hosting_category(value, o) == "not_deployed":
            labels["hosting"] = "not_deployed"
            builder_alone_or_unknown = _is_unknown(audience) or _is_builder_alone(audience)
            if builder_alone_or_unknown or not _match(MACHINE_ONLY_HOSTING, value):
                decide("hosting", value, "permitted", GENERIC_RULES["hosting_not_deployed"], "generic default",
                       _content_words(value), note="review hosting before anyone else uses it")
            else:
                decide("hosting", value, "requires_review", GENERIC_RULES["hosting_machine_dependency"], "generic default",
                       _content_words(value), note="the audience is not the builder alone, so a machine like this is not managed hosting",
                       why="A machine other people depend on is not managed hosting.")
        else:
            if _found(RISKY_HOSTING, value):
                labels["risky_hosting"] = True
            if o:
                not_hits, not_category = _overlay_hits(o["hosting"]["not_approved"], value, HOSTING_SYNONYMS)
                match = _approved_mention(o["hosting"]["approved"], value)
                if not_hits or not_category:
                    item = not_hits[0][0] if not_hits else "; ".join(o["hosting"]["not_approved"])
                    evidence = not_hits[0][1] if not_hits else not_category
                    labels["hosting"], labels["unapproved_hosting"] = "not_approved", True
                    decide("hosting", value, "prohibited", item, "company overlay", evidence,
                           note="on the company's not-approved hosting list", overlay_list="hosting.not_approved",
                           why=f"Company hosting rule, not approved: {item}.")
                elif match and match[0] == "permitted":
                    labels["hosting"] = "approved"
                    decide("hosting", value, "permitted", match[1], "company overlay", _content_words(value))
                elif match:
                    kind, approved_item, extra = match
                    rule = ("mixed mention: an approved item is named together with something else" if kind == "mixed"
                            else "negated mention of an approved item")
                    labels["hosting"], labels["unapproved_hosting"] = "unrecognized", True
                    decide("hosting", value, "requires_review", rule, "company overlay", extra, overlay_list="hosting.approved",
                           note=f"names the approved {approved_item}, " + ("but with something else added" if kind == "mixed" else "but negates it"),
                           why=(f"An approved hosting is named together with something else: {approved_item}." if kind == "mixed"
                                else f"This negates the approved hosting {approved_item} instead of choosing it."))
                else:
                    labels["hosting"], labels["unapproved_hosting"] = "unrecognized", True
                    decide("hosting", value, "requires_review", GENERIC_RULES["hosting_approved_list"], "company overlay",
                           _content_words(value), note="approved hosting: " + "; ".join(o["hosting"]["approved"]),
                           why="The named hosting is not on the company's approved list.",
                           risk_rule="; ".join(o["hosting"]["approved"]), overlay_list="hosting.approved")
            elif labels["risky_hosting"]:
                labels["hosting"] = "unrecognized"
                decide("hosting", value, "requires_review", GENERIC_RULES["hosting_risky"], "generic default", _content_words(value),
                       note="no company overlay; this is the generic rule, not your company's policy",
                       why="A personal account, free tier, or unmanaged machine is not a place coworkers should depend on.")
            else:
                decide("hosting", value, "unknown", GENERIC_RULES["hosting_approved_list"], "generic default", _content_words(value),
                       note="no company overlay; generic defaults cannot approve hosting")

    # audience
    if _is_unknown(audience):
        decide("audience", "unknown", "unknown", GENERIC_RULES["audience_unknown"], "generic default", note="audience was not given")
        questions.append(comps["access-and-identity"]["ask"][0])
    else:
        category = _audience_category(audience)
        labels["audience"] = category
        if category in ("external", "public"):
            labels["external_audience"] = True
            trigger = _overlay_hits(o["review_triggers"], "external users public " + audience)[0] if o else []
            rule = trigger[0][0] if trigger else GENERIC_RULES["audience_external"]
            decide("audience", category, "requires_review", rule, "company overlay" if trigger else "generic default",
                   _content_words(audience), overlay_list="review_triggers" if trigger else None,
                   why="People outside the company, or a public link, would be able to open this.")
            add("sharing-and-publishing", "medium", "Sharing outside the company is the moment a private draft becomes a public fact.",
                evidence=_content_words(audience), basis="decision")
        elif category == "internal":
            rule = o["identity"]["default"] if o else GENERIC_RULES["audience_internal"]
            decide("audience", category, "permitted", rule, "company overlay" if o else "generic default", _content_words(audience))
        else:
            decide("audience", "unknown", "unknown", GENERIC_RULES["audience_unknown"], "generic default", _content_words(audience),
                   note="the audience given does not say whether these people are inside or outside the company")
            questions.append(comps["access-and-identity"]["ask"][0])

    # data classes
    approved_service_names: list[list[str]] = []
    if not named_classes:
        decide("data_classes", "unknown", "unknown", GENERIC_RULES["data_missing"], "generic default", note="no data classes were given")
    for item in named_classes:
        component = "keys-and-credentials" if (_match(CREDENTIALS_PATTERN, item) or _is_credential_class(item)) else "data-in-prompts"
        if data_provenance == "synthetic":
            is_synthetic, provenance_evidence, provenance_note = True, [], None
        elif data_provenance in ("real", "mixed"):
            is_synthetic, provenance_evidence, provenance_note = False, [], None
        elif data_provenance == "unknown":
            is_synthetic, provenance_evidence, provenance_note = False, [], "provenance unknown; treated as real"
        else:
            is_synthetic, provenance_evidence, provenance_note = _data_class_provenance(item)
        if is_synthetic:
            ok_hits = _overlay_hits(o["data_classes"]["ok"], item)[0] if o else []
            if ok_hits:
                decide("data_classes", item, "permitted", ok_hits[0][0], "company overlay", ok_hits[0][1], component=component)
            else:
                decide("data_classes", item, "permitted", GENERIC_RULES["data_ok"], "generic default", component=component)
            continue
        if o:
            hit = _overlay_hits(o["data_classes"]["never_in_prompts"], item)[0]
            if hit:
                labels["sensitive_data"].append(f"company data class: {hit[0][0]}")
                if component == "keys-and-credentials":
                    labels["credentials"] = True
                decide("data_classes", item, "prohibited", hit[0][0], "company overlay", _merge_evidence(provenance_evidence, hit[0][1]), component=component,
                       overlay_list="data_classes.never_in_prompts",
                       why=f"Company data class, never in prompts: {hit[0][0]}.", note=provenance_note)
                continue
            hit = _overlay_hits(o["data_classes"]["ok_with_approval"], item)[0]
            if hit:
                decide("data_classes", item, "requires_review", hit[0][0], "company overlay", _merge_evidence(provenance_evidence, hit[0][1]), component=component,
                       overlay_list="data_classes.ok_with_approval",
                       why=f"Company data class, allowed only with the owner's approval: {hit[0][0]}.", note=provenance_note)
                continue
            hit = _overlay_hits(o["data_classes"]["ok"], item)[0]
            if hit:
                decide("data_classes", item, "permitted", hit[0][0], "company overlay", _merge_evidence(provenance_evidence, hit[0][1]), component=component, note=provenance_note)
                continue
            decide("data_classes", item, "unknown", GENERIC_RULES["data_unrecognized"], "company overlay", _merge_evidence(provenance_evidence), component=component,
                   note=provenance_note or "not in the company's data classes; ask the owner")
            continue
        if _match(CREDENTIALS_PATTERN, item):
            labels["credentials"] = True
            decide("data_classes", item, "prohibited", GENERIC_RULES["data_prohibited"], "generic default", _merge_evidence(provenance_evidence, [item.lower()]),
                   component="keys-and-credentials",
                   why="A password, key, or token appears to be part of the plan; it must not be typed into a tool or generated code.", note=provenance_note)
            continue
        generic = next((label for label, pattern in SENSITIVE_DATA.items() if _match(pattern, item)), None)
        if generic:
            outcome = GENERIC_DATA_OUTCOME[generic]
            labels["sensitive_data"].append(generic)
            decide("data_classes", item, outcome, GENERIC_RULES["data_prohibited"] if outcome == "prohibited" else GENERIC_RULES["data_review"],
                   "generic default", _merge_evidence(provenance_evidence, [item.lower()]), component=component,
                   why="Real data of this kind should not go into a prompt, upload, or test: " + generic + ".", note=provenance_note)
            continue
        decide("data_classes", item, "unknown", GENERIC_RULES["data_unrecognized"], "generic default", _merge_evidence(provenance_evidence), component=component,
               note=provenance_note or "not a class the generic defaults recognize; ask the data's owner")

    # Identifier-only credential references are metadata, not credential material. Their
    # names can safely appear in a plan without turning a local helper into a secret sink.
    for reference in credential_references or []:
        value_exposed = reference["value_in_model_context"] or reference["value_in_generated_artifacts"]
        if value_exposed:
            labels["credentials"] = True
            exposed_places = [key for key in ("value_in_model_context", "value_in_generated_artifacts") if reference[key]]
            decide("credential_references", reference["name"], "prohibited", GENERIC_RULES["data_prohibited"], "generic default",
                   [reference["name"], *exposed_places], component="keys-and-credentials",
                   why="A credential value would enter model context or a generated artifact; it must not be supplied to either.",
                   note="reference metadata says the credential value would be exposed")
        else:
            decide("credential_references", reference["name"], "permitted",
                   "identifier-only credential metadata does not include a credential value", "generic default",
                   [reference["name"]], component="keys-and-credentials",
                   note="the reference names an environment variable only; a local runtime lookup does not expose its value to the model or generated artifacts")

    # services
    if not named_services:
        if services is None:
            decide("services", "unknown", "unknown", GENERIC_RULES["service_missing"], "generic default", note="no services were given")
        else:
            decide("services", [], "permitted", "the plan connects to no external services", "generic default",
                   note="an empty service list or an exact no-service declaration was supplied")
    for item in named_services:
        match = _approved_mention(o["services"]["approved"], item) if o else None
        # "starts_approved": nothing else follows "approved" besides one thing's own words, so a
        # confirmed mixed or negated mention against the real catalog overrides it.
        starts_approved = bool(re.match(r"^(?:the\s+)?approved\b", item, re.IGNORECASE)) and (match is None or match[0] == "permitted")
        if (match and match[0] == "permitted") or starts_approved:
            approved_service_names.append(_content_words(item))
        if match and match[0] == "permitted":
            decide("services", item, "permitted", match[1], "company overlay", _content_words(item))
            continue
        if match:
            kind, approved_item, extra = match
            rule = ("mixed mention: an approved item is named together with something else" if kind == "mixed"
                    else "negated mention of an approved item")
            labels["new_service"] = True
            decide("services", item, "requires_review", rule, "company overlay", extra, overlay_list="services.approved",
                   note=f"names the approved {approved_item}, " + ("but with something else added" if kind == "mixed" else "but negates it"),
                   why=(f"An approved service is named together with something else: {approved_item}." if kind == "mixed"
                        else f"This negates the approved service {approved_item} instead of choosing it."))
            continue
        if o:
            hit = _overlay_hits(o["services"]["needs_review"], item)[0]
            if hit:
                labels["new_service"] = True
                decide("services", item, "requires_review", hit[0][0], "company overlay", hit[0][1],
                       overlay_list="services.needs_review", why=f"Company rule, needs review: {hit[0][0]}.")
                continue
        labels["new_service"] = True
        decide("services", item, "requires_review", GENERIC_RULES["service_review"], "generic default", _content_words(item),
               note="named services are reviewed by default; nothing here says this one is approved",
               why="A new service, plugin, or connector is an approval question, not a convenience.")

    # write access
    if write_access is None:
        decide("write_access", "unknown", "unknown", GENERIC_RULES["write_unknown"], "generic default", note="write_access was not given")
        questions.append(WRITE_ACCESS_QUESTION)
    elif write_access:
        trigger = _overlay_hits(o["review_triggers"], "writes to a system of record")[0] if o else []
        rule = trigger[0][0] if trigger else GENERIC_RULES["write_review"]
        decide("write_access", True, "requires_review", rule, "company overlay" if trigger else "generic default",
               ["system of record"], overlay_list="review_triggers" if trigger else None,
               why="The app would write to a system of record; a person reviews that before it goes live.")
    else:
        decide("write_access", False, "permitted", GENERIC_RULES["write_none"], "generic default")

    outcome = "permitted"
    for d in decisions:
        if OUTCOME_ORDER[d["outcome"]] > OUTCOME_ORDER[outcome]:
            outcome = d["outcome"]

    # ---------------------------------------------------------------- hints from the description

    text = description
    data_evidence: list[str] = []
    generic_classes: list[str] = []
    for label, pattern in SENSITIVE_DATA.items():
        found = _hint(pattern, text)
        if found:
            generic_classes.append(label)
            data_evidence.append(found)
            hint("data-in-prompts", found, f"the description mentions {label}; a hint only, pass data_classes to decide")
    company_data_rules: list[str] = []
    credential_classes = [item for item in o["data_classes"]["never_in_prompts"] if _is_credential_class(item)] if o else []
    if o:
        classes = [item for item in o["data_classes"]["never_in_prompts"] if item not in credential_classes]
        for item, evidence in _overlay_hits(classes, text)[0]:
            if _evidence_negated(text, evidence):
                continue
            generic_classes.append(f"company data class: {item}")
            company_data_rules.append(item)
            data_evidence.extend(w for w in evidence if w not in data_evidence)
            hint("data-in-prompts", " ".join(evidence), f"the description reads like the company data class {item}; a hint only, pass data_classes to decide")
    for label in generic_classes:
        if label not in labels["sensitive_data"]:
            labels["sensitive_data"].append(label)
    if generic_classes:
        add("data-in-prompts", "high", "Real data of this kind should not go into a prompt, upload, or test: " + "; ".join(generic_classes) + ".",
            rule="; ".join(company_data_rules) or None, overlay_list="data_classes.never_in_prompts" if company_data_rules else None, evidence=data_evidence)

    found = _hint(CREDENTIALS_PATTERN, text)
    if found:
        labels["credentials"] = True
        hint("keys-and-credentials", found, "the description mentions a password, key, or token; a hint only")
        add("keys-and-credentials", "high", "A password, key, or token appears to be part of the plan; it must not be typed into a tool or generated code.",
            rule="; ".join(credential_classes) or None, overlay_list="data_classes.never_in_prompts" if credential_classes else None, evidence=[found])

    found = _hint(EXTERNAL_AUDIENCE, text)
    if found:
        labels["external_audience"] = True
        hint("access-and-identity", found, "the description mentions people outside the company; a hint only, pass audience to decide")
        add("access-and-identity", "high", "People outside the company, or a public link, would be able to open this.", evidence=[found])
        add("sharing-and-publishing", "medium", "Sharing outside the company is the moment a private draft becomes a public fact.", evidence=[found])

    found = _hint(RISKY_HOSTING, text)
    if found:
        labels["risky_hosting"] = True
        hint("hosting-and-where-it-runs", found, "the description mentions a personal account, free tier, or unmanaged machine; a hint only, pass hosting to decide")
        add("hosting-and-where-it-runs", "medium", "A personal account, free tier, or unmanaged machine is not a place coworkers should depend on.", evidence=[found])
    if o:
        hits, category = _overlay_hits(o["hosting"]["not_approved"], text, HOSTING_SYNONYMS)
        for item, evidence in hits:
            if _evidence_negated(text, evidence):
                continue
            labels["unapproved_hosting"] = True
            hint("hosting-and-where-it-runs", " ".join(evidence), f"the description reads like the company hosting rule {item}; a hint only, pass hosting to decide")
            add("hosting-and-where-it-runs", "medium", f"Company hosting rule, not approved: {item}.", rule=item, overlay_list="hosting.not_approved", evidence=evidence)
        if category and not _evidence_negated(text, category):
            labels["unapproved_hosting"] = True
            hint("hosting-and-where-it-runs", " ".join(category), "the description names hosting of a kind the company has not approved; a hint only")
            add("hosting-and-where-it-runs", "medium", "The plan names hosting of a kind the company has not approved (" + ", ".join(category) + ").",
                rule="; ".join(o["hosting"]["not_approved"]), overlay_list="hosting.not_approved", evidence=category)

    def _new_service_hint() -> str | None:
        """A new-service match that the sentence does not already call approved, and that no approved
        service in `services` accounts for."""
        for m in re.finditer(NEW_SERVICE, text, re.IGNORECASE):
            if _negated(text, m.start(), m.end(), ("approved",)):
                continue
            sentence_words = set(_words(_clause(text, m.start(), m.end())[2]))
            if any(name and all(w in sentence_words for w in name) for name in approved_service_names):
                continue
            return m.group(0).lower().strip()
        return None

    found = _new_service_hint()
    if found:
        labels["new_service"] = True
        hint("third-party-services", found, "the description mentions a new service, plugin, or connector; a hint only, pass services to decide")
        add("third-party-services", "medium", "A new service, plugin, or connector is an approval question, not a convenience.", evidence=[found])
    if o:
        hits, category = _overlay_hits(o["services"]["needs_review"], text, SERVICE_SYNONYMS)
        for item, evidence in hits:
            if _evidence_negated(text, evidence):
                continue
            labels["new_service"] = True
            hint("third-party-services", " ".join(evidence), f"the description reads like the company service rule {item}; a hint only, pass services to decide")
            add("third-party-services", "medium", f"Company rule, needs review: {item}.", rule=item, overlay_list="services.needs_review", evidence=evidence)
        if category and not _evidence_negated(text, category):
            labels["new_service"] = True
            hint("third-party-services", " ".join(category), "the description names a service of a kind the company reviews first; a hint only")
            add("third-party-services", "medium", "The plan names a service of a kind the company reviews first (" + ", ".join(category) + ").",
                rule="; ".join(o["services"]["needs_review"]), overlay_list="services.needs_review", evidence=category)

    found = _hint(UNTRUSTED_INPUT, text)
    if found:
        labels["untrusted_input"] = True
        hint("untrusted-input", found, "the description says the app reads input from people or documents; a hint only")
        add("untrusted-input", "medium", "The app would read input from people or documents; that input is data, never instructions.", evidence=[found])

    # A real sensitive-data class or credential in the plan's own words is a review trigger, not
    # a data-hygiene tip: see the data-in-prompts and keys-and-credentials "stop and ask a human
    # if" lists. Only a non-negated hint counts, and only these three cases; a hint never sets
    # the outcome.
    sensitive_hit = bool(labels["sensitive_data"]) or labels["credentials"]
    found = _hint(REVIEW_TRIGGERS, text)
    if found or labels["external_audience"] or sensitive_hit:
        labels["review_trigger"] = True
        if sensitive_hit:
            classes = list(labels["sensitive_data"]) + (["credentials"] if labels["credentials"] else [])
            add("when-to-ask-a-human", "high", "This plan's purpose appears to involve real sensitive data or credentials: " + "; ".join(classes) + ". That is a security review conversation, not a data-hygiene tip.", evidence=[found] if found else [])
        else:
            add("when-to-ask-a-human", "high", "This plan hits a review trigger: external users, money, sign-in, or a system of record.", evidence=[found] if found else [])
        if found:
            hint("when-to-ask-a-human", found, "the description mentions a review trigger; a hint only, the fields decide")
    if o:
        for trigger, evidence in _overlay_hits(o["review_triggers"], text)[0]:
            if _evidence_negated(text, evidence):
                continue
            labels["review_trigger"] = True
            hint("when-to-ask-a-human", " ".join(evidence), f"the description reads like the company review trigger {trigger}; a hint only")
            add("when-to-ask-a-human", "high", f"Company review trigger: {trigger}.", rule=trigger, overlay_list="review_triggers", evidence=evidence)

    # ---------------------------------------------------------------- answer

    risks.sort(key=lambda r: (-SEVERITY_ORDER[r["severity"]], r["basis"] != "decision"))
    hint_asks_for_a_human = labels["external_audience"] or sensitive_hit
    ask_a_human = outcome in ("prohibited", "requires_review") or bool(hint_asks_for_a_human)
    worst = None
    for d, component in zip(decisions, decision_components):
        if d["outcome"] in ("prohibited", "requires_review") and (worst is None or OUTCOME_ORDER[d["outcome"]] > OUTCOME_ORDER[worst[0]]):
            worst = (d["outcome"], component)
    if worst:
        next_step = comps[worst[1]]["do"][0]
    elif risks:
        next_step = risks[0]["safer_alternative"]
    else:
        next_step = "No checkpoint was triggered by the words in this plan; that is not approval. Build with made-up data, keep the audience small, and run check_plan again before connecting anything or sharing."
    owner = (o["owner"] if o else guidance["slots"]["owner"])
    # A not_deployed hosting value has already been answered; do not still ask where it lives.
    default_checklist_components = ["data-in-prompts", "access-and-identity"]
    if labels["hosting"] != "not_deployed":
        default_checklist_components.append("hosting-and-where-it-runs")
    checklist = [r["ask"] for r in risks] or [comps[c]["ask"][0] for c in default_checklist_components]
    # An unsupplied field is an open question, not a pass.
    for question in questions:
        if question not in checklist:
            checklist.append(question)
    return {
        "outcome": outcome,
        "decisions": decisions,
        "hints": hints,
        "risks": risks,
        "next_step": next_step,
        "ask_a_human": ask_a_human,
        "who_to_ask": owner,
        "checklist": checklist,
        "labels": labels,
        "method": (
            "explicit fields decide; free text only hints; keyword matching with negation handling; no model pass. "
            "hosting, audience, data_classes, services, and write_access produce the decisions and the outcome; "
            "the description produces hints that name questions to ask and never an outcome. "
            "An overlay item fires when its content words (lowercased, singular, stop words dropped) all appear in the value or the plan, "
            "or when a hosting or service synonym appears with one of them; each such decision or risk carries the rule and the evidence."
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
