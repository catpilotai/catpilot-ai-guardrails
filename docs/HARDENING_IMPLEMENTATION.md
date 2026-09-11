# Hardening and modernization work

Working branch: `codex/guardrails-hardening`. Preview release:
`2026.09.11-hardening.1`. This document records implementation status, not a
protection or production-deployment claim.

## Scope

1. Harden bundler paths, parsing, companion references, and atomic output; add regression tests.
2. Correct Azure, dependency-installation, URL/file handling, and false-positive guidance with executable examples.
3. Replace the monolithic installed entrypoint with focused routing and on-demand references; preserve the core install name.
4. Pin CI dependencies/actions, validate portable packages, and test the legacy install path without touching personal configuration.
5. Add a reproducible live-evaluation runner with synthetic cases, explicit model/host configuration, bounded runs, and honest results.
6. Add a validated private company-policy overlay and a local, read-only integration package for Codex/Claude Code.

## Boundaries

- Do not connect a customer tenant or copy private policy into this public repository without approved sources, a named owner, and verified access controls.
- No production mutations, automatic marketplace installation, or CATpilot telemetry.
- Publication requires explicit authorization. The user authorized an opt-in
  preview release on 2026-09-11; `main` and the stable release remain unchanged.
- Local policy files are an administrator-controlled prototype, not a hosted identity or tenant-isolation service.
- Hook tests must distinguish protocol-level decisions from actual host enforcement and unavailable checks. Do not claim protection on untested or bypassable paths.
- Retain the `2026.09.11` release as the historical evaluation baseline.

## Status

- Local implementation: complete for the six development workstreams above.
- Regression suite: **81 tests pass on Python 3.11.15 and 3.13.5**, including
  actual stdio SDK handshake, tool discovery, policy reads, and revocation.
- Both generated copies match their sources. Portable skill validators,
  Codex plugin validation, Claude CLI plugin validation, and `git diff --check`
  pass. The release process additionally requires hosted GitHub CI to pass
  against the exact candidate commit before the preview tag is published.
- Core entrypoint: **3,647 lines / 17,775 words → 66 lines / 741 words**;
  detailed guidance is retained in on-demand references.
- Live checks: ten synthetic response-only calls plus one real read-only MCP
  lookup from each target host. See [the results and caveats](../evals/SMOKE_RESULTS_2026-09-11.md).
- No customer tenant, private customer policy, personal plugin installation,
  or production deployment is included in this release.
- Remaining stable-release/customer gates: trusted host hook activation and actual
  blocked-action traces; clean held-out repeated evaluations; named customer
  policy owner, approved private starting template, and approved model data flow.

## Important implementation choices

- Skill Creator guidance informed the short router/on-demand references and
  plain-language, one-next-action coaching. Plugin Creator conventions informed
  the shared package and thin manifests; both validators passed locally.
- Company policy is a strict local-file prototype with explicit freshness and
  scope, not a claim of hosted authentication, signatures, or tenant isolation.
- The private-key hook is intentionally narrow and not yet host-enforcement
  verified. Other tool paths remain uncovered; missing checks are never labeled
  as a passed scan.
- Live evaluation found an overly long Claude advisory answer with an unwanted
  code scaffold. The router now asks for short decision answers and secure,
  complete controls when an implementation is actually requested. One repeated
  smoke pair improved, but this is not a statistically established effect.
- The source/portable metadata migration is explicit; consumers of nested
  installed metadata must read `catpilot.json` instead.
