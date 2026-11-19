# Governance

How decisions are made in this repository. It is small and maintained by the **catpilotai** GitHub organization ([MAINTAINERS.md](./MAINTAINERS.md)).

## Decisions

- Changes land through pull requests. A maintainer reviews and merges; the evidence checklist in [CONTRIBUTING.md](./CONTRIBUTING.md) applies.
- A change to a stable surface ([docs/STABILITY.md](./docs/STABILITY.md)), a new rule kind, or a change to what a hook denies is decided in a public issue first, with the decision recorded there and linked from the pull request.
- Design notes in `docs/spec/` carry their status and the issue that approved them.
- When maintainers disagree, the maintainers named in MAINTAINERS.md decide; the reasoning goes in the issue.

## Becoming a maintainer

A contributor with a sustained record of reviewed, accepted changes can be invited by the existing maintainers. Maintainers who are inactive for a long period may be moved to emeritus status.

## Releases

Monthly stable release, patch releases as needed, and two stable releases' notice before a removal ([docs/STABILITY.md](./docs/STABILITY.md)). Release notes follow the template in [docs/RELEASE_NOTES_TEMPLATE.md](./docs/RELEASE_NOTES_TEMPLATE.md). Release archives carry build-provenance attestations ([SECURITY.md](./SECURITY.md)).

## Conduct

[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) applies in issues, pull requests and discussions.

## Scope

This repository is the open baseline: skills, hooks, validators, the reference server and the specs. Anything private to a company, including its rules file, stays out of it.
