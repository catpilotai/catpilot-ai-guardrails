# Next experiment plan

## Status and scope

This is a preregistration template for a future experiment. No paid candidate
run is authorized by this document. The blank human fields below are required
gates, not placeholders that an agent may fill. Earlier runs on reused task
families remain exploratory and are not held-out evidence.

The narrow question is whether guidance helps builders consult and follow
company rules while completing useful, specified work. The experiment does
not test whether applications are broadly secure.

## Standard comparison

The standard conditions are **A, no guidance**; **B-installed, skill installed** with no
activation instruction; **B-activated, skill installed and explicitly
activated**; and **D, skill explicitly activated with company rules through
the server and instruction**. Freeze and publish the exact installation and
activation text before any candidate runs.

| Comparison | Preregistered question |
| --- | --- |
| **B-installed, skill installed** minus **A, no guidance** | Deployment-default effect of installing the skill without an activation instruction. |
| **B-activated, skill installed and explicitly activated** minus **B-installed, skill installed** | Effect of the activation instruction. |
| **D, skill explicitly activated with company rules through the server and instruction** minus **B-activated, skill installed and explicitly activated** | Effect of the instructed company-policy workflow. |

**C, skill plus company rules through the server without a consultation
instruction**, **E, generic checklist**, and **F, company checklist** are
supported diagnostic conditions. Their comparisons may describe the stated
packages, but do not establish MCP superiority. In particular, **D, skill
explicitly activated with company rules through the server and instruction**
minus **F, company checklist** changes more than transport.

## Human-gated task preparation

Fresh task families must be authored or reviewed by a real human who is
independent of both AI-agent workflows developing the guardrails and designing
or scoring the benchmark. That human review must occur before either the
candidate/building workflow or the scorer/evaluator sees the fresh task text.
A real non-engineer must separately review task voice before the scorer sees
the text. One person may perform both roles only when they satisfy both
requirements and attest to both reviews.

| Required gate | Name | Signature or record | Date |
| --- | --- | --- | --- |
| Independent task author or reviewer |  |  |  |
| Non-engineer voice reviewer |  |  |  |
| Handoff to scorer after both reviews |  |  |  |
| Reference-author/verifier reviewer |  |  |  |
| Preregistration frozen before candidates |  |  |  |

After review, freeze the task text, sandbox inputs, functional cases, and
reference examples with versioned hashes. Then hand the frozen package to the
scoring workflow. Keep task author/reviewer and reference-author/verifier
roles separate. Do not use an AI-agent attestation as either human review.

## Scenario and reference contract

Use several independent task families. Each family contains temptation levels
0, 1, and 3: harmless control; risk present only in the folder; and direct
request. Report levels separately and never pool them. Use fabricated or
approved local inputs. State accepted input and output behavior before the
run, including which CSV columns are required, how extra columns are handled,
and the output format and destination.

Each scenario has executable functional cases with varied inputs and a full
reference set. References must reject a stub or hard-coded answer while
accepting reasonable alternative implementations that meet the stated I/O
contract. The reference gate covers safe, stub, incomplete, generic-unsafe,
and policy-mismatch categories when applicable. Company-policy mismatches are
reported separately from generic unsafe actions; record which condition knew
each policy fact.

## Proposed run parameters

The proposed, not-yet-approved design has six independent task families and
temptation levels 0, 1, and 3 in every family: 18 scenarios. Run the four
standard conditions on each scenario three times for each of two hosts, for
432 candidate attempts total: 216 per host and 18 per arm/level within each
host. The proposed hosts are Codex (`gpt-5.6-terra`, medium reasoning) and
Claude Sonnet; use Claude Sonnet as judge only when wording criteria require a
judge. Before launch, freeze the resolved host and judge versions, the uniform
follow-up text, and hashes of `tools/bench/sandbox.py` constants
`DEFAULT_COMPARISON_ARMS`, `SKILL_ACTIVATION_INSTRUCTION`, and
`ARM_D_INSTRUCTION`, along with the scenario, reference, skill, and overlay
hashes.

## Analysis preregistration

Before candidates run, record the selected comparisons, task-family list,
repetitions, exclusions, failure handling, outcome metrics, and uncertainty
method in the versioned preregistration. The proposed three repetitions do
not justify an inferential claim. Estimate paired task-family differences and
report descriptive clustered uncertainty by task family; do not treat the 54
attempts per host/standard arm as independent tasks. Any broader claim requires a
separate powered analysis plan.

Preserve every raw attempt. Do not exclude an attempt because of its outcome.
Timeouts, host failures, and unavailable verifiers remain in the attempt
denominator and their affected measure values are reported as unknown. A
technical retry is allowed only under criteria frozen before launch; retain
both the original and retry record, identify their linkage, and never replace
the original. Report functional completion, generic safety, policy adherence,
and combined safe completion together with known and unknown denominators.
