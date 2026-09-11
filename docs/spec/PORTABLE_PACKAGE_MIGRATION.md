# Progressive portable package migration

Applies to the opt-in `2026.09.11-hardening.1` preview bundle. The stable
`2026.09.11` repository tag still contains the older `2026.05.17` bundle.

The install name remains `catpilot-security-core`. Replace/reinstall the
**whole directory**; copying only `SKILL.md` loses the referenced guidance.

| Concern | Previous generated package | New generated package |
| --- | --- | --- |
| Entry point | Entire concatenated rulebook | Short router with conditional reference links |
| Component body | Embedded in `SKILL.md` | `references/<component>/REFERENCE.md` |
| Rich CATpilot metadata | Nested `metadata.catpilot` | `catpilot.json` sidecar |
| Portable metadata | Nested extension values | String-to-string `metadata`; `catpilot-manifest: catpilot.json` |
| Companion paths | Namespaced copies, links not relocated | Namespaced copies plus relative link rewriting |
| Plugin distribution | None | Generated copy of the same core, drift-checked in CI |

Source files under `src/skills/` retain their rich internal authoring format.
Do not install these individually and call them portable packages. External
consumers reading `metadata.catpilot.bundle` must migrate to
`catpilot.json["bundle"]`. This is an explicit metadata/layout breaking change
for those consumers even though the user-facing install name is unchanged.

Control mappings are inherited, illustrative, and not validated against every
current standard edition. A metadata mapping is not compliance evidence.
Do not create or imply new certified mappings in this migration.

Builders reject invalid names, duplicate YAML, malformed types, symlinks,
special files, duplicate tier output names, and companion collisions before
replacement. Work occurs in a temporary sibling directory and previous output
is restored on a failed replacement rename. These are trusted-maintainer
build tools, not a sandbox for concurrently attacker-modified directories.

`tools/validate_skill.py` checks portable metadata, the entrypoint size budget,
and local inline Markdown links. It does not validate all Markdown dialects,
run a scanner, or prove reference activation in a host. Hash-locked development
dependencies and action SHAs are reviewed inputs, not a vulnerability-free guarantee.

Run both generators and checks:

```bash
python tools/bundle.py
python tools/package_plugin.py
python tools/bundle.py --check
python tools/package_plugin.py --check
python tools/validate_skill.py skills/catpilot-security-core
```
