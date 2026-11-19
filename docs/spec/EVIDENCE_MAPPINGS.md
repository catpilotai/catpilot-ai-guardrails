# Evidence mappings: OCSF and ECS

**Status:** Active. Maps evidence schema version 1 ([`EVIDENCE.md`](./EVIDENCE.md)) to OCSF 1.3.0 and ECS 8.11.
Converter: [`tools/evidence_export.py`](../../tools/evidence_export.py). Golden files:
[`tests/evidence_golden/`](../../tests/evidence_golden/).

**Not verified in a SIEM.** The output follows the OCSF 1.3.0 class definitions and the ECS 8.11 field
reference as published, and the tests check the classes, the required attributes this document names and the
golden files. No output has been ingested by a SIEM or checked with an OCSF validator. Check a sample in yours
before relying on it.

---

## 1. Use

```bash
python3 tools/evidence_export.py --format ocsf ~/.catpilot-guardrails/evidence.jsonl > evidence.ocsf.jsonl
python3 tools/evidence_export.py --format ecs  ~/.catpilot-guardrails/evidence.jsonl > evidence.ecs.jsonl
```

One output line per input line, in order. A line that is not a JSON object, has no known `event`, or has no
readable `ts` is skipped and counted on stderr, and the exit status is 1. Lines written before schema version 1
convert: a server line without `event` is a `lookup` ([`EVIDENCE.md`](./EVIDENCE.md) §3), its component is the
server, and a line without `event_id` gets the stable id `sha256:<hash of the line>`.

**Nothing is dropped.** Every output carries the original line whole: OCSF in `unmapped.catpilot`, ECS in
`catpilot`. A field that has no standard home below (`tool`, `mode`, `policy_sha256`, `exception_id`,
`session_source`, `block_chars`, `block_lines`, `prev_sha256`, the server's `topic`, `category`, `kind`,
`outcome`, `ask_a_human`, `fields`, `policy_status`, `unknown_policy`) is read from there. The converter adds only
fixed text, so the output is as content-free as the input ([`EVIDENCE.md`](./EVIDENCE.md) §4).

**`host` is not the machine.** In an evidence line, `host` is the AI tool (`claude-code`, `codex`,
`copilot-cli`). It maps to OCSF `actor.app_name` and stays under `catpilot.host` in ECS. Neither output writes
OCSF `device` or ECS `host.*`, which name the machine; your collector adds those from where the file came from.

## 2. OCSF 1.3.0

### 2.1 Which class, and why

| Events | Class | Why |
| --- | --- | --- |
| `deny`, `ask`, `would_deny`, `input_error` | **Detection Finding** (`class_uid` 2004, category Findings, 2) | Each is a security check matching, or refusing, one tool call: a finding by a control, with an action and a disposition. The `security_control` profile carries `action_id` and `disposition_id`, which say what the check did. The alternatives fit worse: API Activity and Process Activity describe the activity itself, which the line deliberately does not record (no command, no path), and Security Finding is deprecated since 1.1. |
| `rules_delivered`, `rules_expired`, `policy_error` | **Application Lifecycle** (6002, category Application Activity, 6) | These are the state of a component, the company rules: loaded for a session, past their date, or not loadable. Application Lifecycle is the class for an application starting, stopping or failing to, and needs only `app`. |
| `lookup` | **API Activity** (6003, category Application Activity, 6), activity Read | The server answered an MCP tool call: a read through an API. OCSF requires `actor` and `src_endpoint`; the server does not record its caller, by design ([`EVIDENCE.md`](./EVIDENCE.md) §4), so both say `unknown` (`actor.app_name: "unknown"`, `src_endpoint.name: "unknown"`) rather than invent one. |

Profiles applied: `security_control` on Detection Finding. The `cloud`, `osint` and `host` profiles are not
applied: nothing in a line feeds them.

### 2.2 Every class

| OCSF attribute | Value |
| --- | --- |
| `time` | `ts` as milliseconds since the epoch |
| `metadata.version` | `1.3.0` |
| `metadata.uid` | `event_id` |
| `metadata.original_time` | `ts`, as written |
| `metadata.log_name` | `catpilot-evidence` |
| `metadata.product` | `name` `Catpilot AI Guardrails`, `vendor_name` `Catpilot`, `feature.name` the hook (`hook`) or else `source`, `version` the `release` when the line has one |
| `type_uid` | `class_uid` × 100 + `activity_id` |
| `class_name`, `category_name`, `activity_name`, `type_name`, `severity`, `status` | the captions of the ids |
| `actor.app_name` | `host` (the AI tool), when present |
| `actor.session.uid` | `session_id`, when present |
| `unmapped.catpilot` | the original line |

### 2.3 Detection Finding (2004)

`activity_id` 1 Create, `status_id` 1 New. `finding_info.uid` is `event_id`; `finding_info.title` and `message` are
fixed text naming what happened and the hook, for example `Tool call denied (pretooluse-secrets)`.
`finding_info.analytic` is the rule: for the company-rules hook `{uid, name}` = `rule_id`; for a built-in check
`name` = `label` (the credential or operation type). Both have `type_id` 1, Rule. `finding_info.types` is
`[label]` when the line has one.

| `event` | `action_id` | `disposition_id` | `severity_id` |
| --- | --- | --- | --- |
| `deny` | 2 Denied | 2 Blocked | 3 Medium |
| `ask` | 99 Other (`action` `Ask`) | 23 Challenge | 2 Low |
| `would_deny` | 1 Allowed | 15 Detected | 1 Informational |
| `would_deny` with `exception_id` | 1 Allowed | 8 Approved | 1 Informational |
| `input_error` | 2 Denied | 27 Error | 2 Low |

`ask` records that the person was asked, not what they chose ([`EVIDENCE.md`](./EVIDENCE.md) §3), so its
action is neither Allowed nor Denied. The severities are defaults for triage, not a risk rating: a `deny` means
a control worked. Override them in your pipeline if they do not fit.

### 2.4 Application Lifecycle (6002)

`app`: `name` `Catpilot AI Guardrails company rules`, `vendor_name` `Catpilot`, `feature.name` the hook or source,
`version` the `release`.

| `event` | `activity_id` | `status_id` | `status_detail` | `severity_id` |
| --- | --- | --- | --- | --- |
| `rules_delivered` | 3 Start | 1 Success | | 1 Informational |
| `rules_expired` | 3 Start | 2 Failure | `expired` | 2 Low |
| `policy_error` (session start or company-rules hook) | 99 Other (`Load`) | 2 Failure | `label` (`missing`, `malformed`, ...) | 3 Medium |

### 2.5 API Activity (6003)

`activity_id` 2 Read. `api.operation` is `tool`; `api.service.name` is `catpilot-guardrails-mcp`. `status_id` 1
Success when `error` is null, otherwise 2 Failure with `status_detail` the error code. `severity_id` 1. `actor`
and `src_endpoint` as §2.1 says.

## 3. ECS 8.11

| ECS field | Value |
| --- | --- |
| `@timestamp` | `ts`, in UTC with milliseconds |
| `ecs.version` | `8.11.0` |
| `event.id` | `event_id` |
| `event.action` | `event` |
| `event.provider` | `source` (the server for a line from before schema version 1) |
| `event.module`, `event.dataset` | `catpilot`, `catpilot.evidence` |
| `event.kind`, `event.category`, `event.type`, `event.outcome`, `event.severity` | the table below |
| `event.reason` | on `would_deny` with `exception_id`: `allowed by an expiring exception` |
| `observer` | `product` `Catpilot AI Guardrails`, `vendor` `Catpilot`, `type` `guardrail`, `version` the `release` |
| `rule.id`, `rule.name` | `rule_id` (company-rules hook); for a built-in check's finding, `rule.name` is `label` |
| `rule.ruleset` | `company-rules`, or the built-in hook's name |
| `rule.category` | `label`, on the four finding events |
| `error.code` | `label` on `policy_error`; the server's `error` on a failed `lookup` |
| `service.name` | `catpilot-guardrails-mcp`, on `lookup` |
| `catpilot` | the original line |

| `event` | `event.kind` | `event.category` | `event.type` | `event.outcome` | `event.severity` |
| --- | --- | --- | --- | --- | --- |
| `deny` | `alert` | `intrusion_detection` | `denied` | `success` | 3 |
| `ask` | `alert` | `intrusion_detection` | `info` | `unknown` | 2 |
| `would_deny` | `alert` | `intrusion_detection` | `allowed` | `success` | 1 |
| `input_error` | `event` | `intrusion_detection` | `denied` | `failure` | 2 |
| `policy_error` | `event` | `configuration` | `info` | `failure` | 3 |
| `rules_delivered` | `event` | `configuration` | `access` | `success` | 1 |
| `rules_expired` | `event` | `configuration` | `info` | `failure` | 2 |
| `lookup` | `event` | `configuration` | `access` | `success`, or `failure` when `error` is set | 1 |

Why: `intrusion_detection` is ECS's category for a control that detects and may block an action, and its
allowed types are exactly `allowed`, `denied` and `info`. `event.kind: alert` is for an event a detection rule
raised, which is what a rule match is. `event.outcome` is from the hook's side: a `deny` is the check
succeeding; an `input_error` is the hook failing to read its input, and blocking. `ask` is `unknown` because the
hook does not see the person's answer. The rules' state and the server's lookups read or report configuration,
so they are `configuration`, whose allowed types include `access` and `info` but not `error`; the failure is in
`event.outcome`.

There is no ECS field for the AI tool, the session or the policy hash; they stay under `catpilot.host`,
`catpilot.session_id` and `catpilot.policy_sha256`. Map them in an ingest pipeline if you want them elsewhere.

## 4. Changing the mapping

A change to a class, an id or a field here is a change to the converter and its golden files in the same pull
request. The golden input covers every event, a line from before schema version 1, an expiring exception and a
chained line. A new evidence event (a schema version change, [`EVIDENCE.md`](./EVIDENCE.md) §6) needs a row in
each table above before it ships; the tests fail until the converter knows it.
