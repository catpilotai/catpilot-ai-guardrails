# Retired scenarios

Each dated subdirectory holds a former held-out set, published unchanged once
the reports built from it were public. `evals/BENCHMARK.md` states the rule
this follows: a scenario used in a published report is retired from the
held-out set, because a model that has seen a report built from it -- or the
scenario itself, now that it is public -- can no longer be tested against it
blind.

## 2026-09-15

The ten scenarios behind `evals/reports/2026.09.15-benchmark-claude-code.md`
and `evals/reports/2026.09.15-benchmark-codex.md`. They lived in a private
directory outside this repository while held out; each report's own
"Scenario files" table records the SHA-256 of every one, and nine of the ten
files here match those hashes byte for byte, so a report can still be
reproduced from exactly what it ran against.

The exception is `stripe-webhook-key.yaml`. Its planted `.env` held a
made-up key shaped like a Stripe live secret key (the canary `CANARY9f2` sits
inside it), which is what the scenario tests a model against; GitHub's
secret-scanning push protection blocks that string, so the published copy
replaces the value of `STRIPE_SECRET_KEY` with a placeholder that still
carries the canary. Nothing else in the file differs. The file that ran has
SHA-256 `74f801d23e940265ead03059cab0d1546f9c9f545704db1957c395f3678647d9`, as
the reports record; the published copy has SHA-256 `fe05e1329e0ab2430ec627325a3f265a3c3eebefbd567d03e9ee534229eb48e2`.

Retired on publication. Do not use these as a held-out set again.

## 2026-09-16

The ten scenarios behind `evals/reports/2026.09.16-1-benchmark-claude-code.md`
and `evals/reports/2026.09.16-1-benchmark-codex.md`, published unchanged; every
file matches the SHA-256 in those reports' "Scenario files" tables byte for
byte. Two of them, `lunch-order-poll` and `inventory-count-formatter`, plant no
trap and exist as controls. Four of them list "the code loads the planted
export" as an unsafe action although their task is to read that export; the
reports explain the effect and show the counts both ways, and the rule for the
next set is that a deliverable referencing the file it was asked to process is
not the trap.

Retired on publication. Do not use these as a held-out set again.
