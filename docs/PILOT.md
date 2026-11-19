# Running a pilot

A pilot answers two questions with your own people and your own rules:

1. **Does putting your company's rules in front of the AI tools change what people build, and at what cost?** That is, unsafe plans steered before code exists, reviews requested from the right person, and how often work stopped when it didn't need to.
2. **Does serving the rules through the server beat pasting the same rules into each tool?** This is the open question in the public benchmarks ([README](../README.md#what-the-benchmarks-show)). A pilot is the cheapest way to answer it for your company.

It takes two to four weeks, five to twenty people (include people who are not engineers), one security owner, and one person who can approve the rules.

## Pick a route

| Route | Tools covered | Who runs the server | Status |
| --- | --- | --- | --- |
| **Hosted (Catpilot Plus)** | Claude.ai, ChatGPT, Claude Code, Codex | Catpilot, per company, behind a company connector link | Runs in production at `guardrails.catpilot.ai`; the host results are in the [tested-runtimes table](REFERENCE.md#tested-runtimes) |
| **Self-hosted (this repository)** | Claude Code, Codex | You, on each machine, over stdio (nothing listens on the network) | The [15-minute quickstart](../README.md#company-rules-in-15-minutes), run end to end on 2026-10-28 |
| **Self-hosted, signed in (this repository)** | Claude.ai, ChatGPT | You, one server over HTTPS, checking tokens from your identity provider (`--auth oidc`) | Implemented and tested with locally generated keys; **not yet verified with Claude.ai or ChatGPT on a host** |

Claude.ai and ChatGPT reach a server only as a remote connector over HTTPS. The reference server now has an opt-in sign-in mode for that: it checks tokens from your own identity provider and a group claim picks the rules file ([`mcp-server/` README](../mcp-server/README.md#sign-in-for-claudeai-and-chatgpt---auth-oidc), [design note](spec/SERVER_AUTH.md)). Nobody has yet connected Claude.ai or ChatGPT to it on a real host, so whether either completes sign-in against your provider is unknown. For a pilot that needs those two tools working on day one, use the hosted route; if you try the signed-in route, plan time to verify it first.

## Week 0: set up (about a day)

1. **Write the rules.** Start from [`docs/spec/overlay.example.yaml`](spec/overlay.example.yaml): approved hosting and services, data classes, the sign-in rule, review triggers, and who to ask. Keep the file out of any public repository.
2. **Have a named person approve them.** Set `owner`, `reviewed_on`, and `expires_on`, then run `python tools/validate_overlay.py <file>`. The validator checks structure, expiry, and that nothing secret or incident-shaped is in the file; whether the listed items are really approved is the reviewer's call.
3. **Connect the tools.** For the hosted route, an admin connects the company link from Catpilot in each tool. For the self-hosted route, follow the quickstart's two `mcp add` commands on each participant's machine, or roll them out with [`docs/DEPLOY_ORG.md`](DEPLOY_ORG.md). On Claude Code and Codex, `deploy/org/install.sh --overlay <rules file>` also puts the rules in front of the model at every session start, with no lookup, and says when they have expired: advice, not enforcement, and not yet verified on a host ([details](DEPLOY_ORG.md#company-rules-at-session-start-on-claude-code)).
4. **Optional: turn on enforcement for Claude Code.** The three hooks block literal credentials in commands and file writes, and high-blast-radius commands. Deploy them through managed settings ([`docs/DEPLOY_ORG.md`](DEPLOY_ORG.md)). They are separate from the rules: they stop specific accidents and do not read your rules file. If your claude.ai organization also sets Claude Code managed settings, add `"managedSourcesBehavior": "merge"` there, or Claude Code skips the file and the hooks do not run ([details](DEPLOY_ORG.md#when-your-organization-also-uses-claudeai-managed-settings)). Run `/status` on one machine to check.
5. **Turn on the evidence log.** For self-hosted servers and hooks, set `CATPILOT_EVIDENCE_LOG` (the managed settings example writes to `~/.catpilot-guardrails/evidence.jsonl`). The hosted route records which tool was called, its outcome, and the topics involved. Neither records what people typed.
6. **Agree the measures and the exit criteria** below before anyone starts, and write them down.

## Weeks 1–3: run it

People build as they normally would. The assistant consults the rules when a plan touches data, access, hosting, sharing, or new services. Nobody should be asked to "test the guardrails"; that changes what they do.

Collect three things as you go:

- **Evidence-log counts.** Run `python tools/evidence_summary.py <log files>` weekly. It reports:
  - `check_plan` calls and their outcomes (`permitted`, `requires_review`, `prohibited`, `unknown`);
  - how often a person was asked to look (`ask_a_human`);
  - how often the rules had no answer (`unknown_policy`), which shows where your rules have gaps;
  - hook denials by kind.

  It contains counts and labels only.
- **Unnecessary stops.** Ask participants to report each time the assistant stopped or asked for a review when the work didn't need one. A one-line form is enough. This is the main cost of a guardrail, and the evidence log can't see it.
- **Escalations.** For each review request the assistant drafted, did it reach the right person, and what did they decide?

## The comparison: server versus pasted rules

The comparison runs offline, on your own tasks, with the repository's benchmark runner:

- **Condition D:** the activated skill plus your rules through the server, with an instruction to consult it.
- **Condition F:** the same company facts pasted as a checklist. Its text is the `company-checklist.md` that a private build of your rules writes.

```bash
python tools/bench.py --scenarios <your scenarios dir> --examples <your reference examples> \
  --host claude-code --arms D,F --overlay <your rules file> --runs 3 --out <outside any repository>
```

Write ten tasks the way your people actually ask, each with a trap your rules should catch, plus benign controls. [`evals/BENCHMARK.md`](../evals/BENCHMARK.md) sets the requirements:
- a self-check on reference examples before any model runs;
- at least one risk scenario and one benign control;
- Docker for the functional checks;
- hashes recorded for the scenarios, the rules and the skill.

Start with `--dry-run`, which makes no model calls. The scenarios, the rules and the results stay with you.

## Week 4: decide

Compare against the exit criteria you wrote down in week 0. For example:

- Unsafe plans were steered or escalated, and people found the escalations useful.
- Unnecessary stops stayed below the level you agreed, such as one in ten plans checked.
- The `unknown_policy` rate fell as you filled gaps in the rules.
- In the comparison, condition D did at least as well as F on unsafe acts and unnecessary stops. If it did not, a pasted checklist may be enough for you, and that is a useful answer.

Then expand, change the rules and run again, or stop.

## Ending the pilot

- **Self-hosted:** `claude mcp remove catpilot-guardrails -s user`, `codex mcp remove catpilot-guardrails`, and, if you deployed them centrally, `deploy/org/uninstall.sh`.
- **Hosted:** remove the company link from each tool.

Keep or delete the rules file and the evidence logs as your retention policy says; nothing was sent anywhere else.

## What a pilot does not show

- The rules **inform** the assistant; they do not block anything. Only the Claude Code hooks enforce, and only on their tool paths ([protection contract](PROTECTION_CONTRACT.md)).
- A few weeks with a few people is not a controlled study. The comparison is the controlled part, and it is still small.
- Evidence-log counts show what the tools did, not what people would have done without them.
