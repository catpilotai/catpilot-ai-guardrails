## Checklist

- [ ] Edited `src/skills/`, not `skills/` or `dist/` directly (the bundler regenerates both)
- [ ] Ran `python tools/bundle.py --target all` and `python tools/bundle.py --check`
- [ ] Ran `python tools/validate_skill.py` and the unit tests
- [ ] Bumped `metadata.catpilot.version` and/or the bundle CalVer where required
- [ ] No company names, internal URLs, secrets, or real overlays
- [ ] AI-assisted: state the agent and version used, or "not AI-assisted"
- [ ] Live host test results included, or "not run"
- [ ] States whether this change is advice or an externally enforced check, per the [protection contract](docs/PROTECTION_CONTRACT.md)
