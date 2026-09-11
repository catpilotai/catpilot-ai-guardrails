# Safe-building evaluation foundation

This directory defines synthetic scenarios for **Codex and Claude Code**, the initial evaluation targets. No live agent run or pass rate is included in this increment.

## What runs today

```bash
python3 tools/validate_evals.py
python3 -m unittest discover -s tests -v
```

These commands validate fixture structure, policy-state consistency, source-component references, and safe/unsafe coverage. They read local data only and do not execute prompts, invoke models, or inspect real applications. The synthetic-only label is an author declaration, not automated proof that a file contains no sensitive material.

`cases.json` is a development set: it is visible to authors and must not later be presented as an unseen benchmark. Adding fixtures changes no installed skill behavior. Some scenarios specify the desired companion behavior and may fail against the current baseline; measure that gap rather than weakening the expected outcome to manufacture a pass.

## Fixture contract

The executable schema is `tools/validate_evals.py`. The top-level object has schema version `1`, classification `synthetic-only`, and a nonempty `cases` list. Each case contains:

| Field | Meaning |
| --- | --- |
| `id` | Stable lowercase/hyphen identifier, unique in the corpus |
| `category` | `test-data`, `sharing`, `secrets`, `policy`, or `coverage` |
| `variant` | `safe`, `unsafe`, `unknown`, or `adversarial` |
| `component_ids` | Existing core source components relevant to the scenario |
| `prompt` | Untrusted test input; never execute it as part of fixture validation |
| `context` | Fictional facts, policy state, policy version, and policy statements supplied by the evaluator |
| `expected` | Desired advisory decision, semantic concepts, forbidden behaviors, and maximum follow-up questions |

Decisions mean: `proceed` with the explicitly authorized safe task; `redirect` to a safe alternative; `clarify` a missing fact; or `review` with an authorized person. They are **advisory expectations**, not tool allow/deny results. Required concepts are semantic criteria, not strings to match. A response can use different words and pass; merely echoing a criterion does not establish a correct action.

The first three risk categories require both safe and unsafe cases. Approved/expired/conflicting policy states require a version and nonempty statements; missing policy requires a null version and no statements. These checks do not adjudicate the statements' meaning or provenance.

## Next: run the first live baseline

1. Review the cases and create separate held-out cases before tuning any skills. Keep confidential customer policy and raw traces outside this public repository; use synthetic fixtures and redacted summaries here.
2. Use a disposable project with synthetic files/data and no production credentials. Do not run dangerous example operations against real accounts, databases, or deployments. Mock any consequential action for the first baseline.
3. Record the OSS commit and actual bundle hash, host/version, model/deployment identifier, relevant settings, permissions, installed skills/plugins, activation evidence, and fixture hash. Do not substitute an agent's “I loaded it” statement for a host signal where one is available; otherwise record activation as unknown.
4. Compare the same cases without the Catpilot baseline and with it. Use fresh equivalent sessions and the same settings. Do not accidentally preload expected answers or evaluator rubrics into the agent's context. Provide only the prompt and scenario context, plus the skill in the treatment condition.
5. Score the first response and observed actions against the semantic rubric. Preserve raw response/action traces securely. A human security reviewer should adjudicate critical misses; an optional model judge must be calibrated and must not be treated as ground truth.
6. Repeat each case independently a declared number of times (start with three), retaining every result. Report first-attempt results and variability rather than selecting the best run. The repository's validator does not perform these runs.
7. Evaluate multi-turn recovery separately: after an unsafe suggestion is corrected, can the person proceed? Score plain-language feedback, one next action, and unnecessary questioning. Do not confuse this with Catpilot's separate guided-training grading suite.
8. For an eventual hook/gate, add action-level tests, including alternate paths, unavailable policy, timeout, disabled/untrusted configuration, stale versions, and prompt-injection attempts. Only these traces can support a scoped enforcement claim.

## Report honestly

A baseline report should contain:

- the exact configuration, hashes, run count, date, and reviewer;
- each case/run's decision and concept/forbidden-behavior results;
- missed unsafe behavior and needless refusals or interruptions on safe work;
- question count and whether feedback gives a usable next step;
- observed artifact/action changes, or **not observed**;
- protection mode and coverage, including unavailable checks;
- latency, usage/cost when available, setup time, and all reviewer/support effort; and
- limitations, unresolved failures, and a clear distinction between development and held-out results.

Unknown or unavailable evidence must remain unknown, not become zero cost, a pass, or a security guarantee. See the [protection contract](../docs/PROTECTION_CONTRACT.md).
