# Other ways to install

```bash
# Install globally so every project picks it up
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core --global

# Pick a specific agent (skills.sh defaults to detecting installed agents)
npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-safe-building --agent cursor

# List what's available without installing
npx skills add catpilotai/catpilot-ai-guardrails --list

# Or skip the CLI entirely: copy the skill in by hand
git clone https://github.com/catpilotai/catpilot-ai-guardrails.git
cp -r catpilot-ai-guardrails/skills/catpilot-security-core ~/.claude/skills/
cp -r catpilot-ai-guardrails/skills/catpilot-safe-building ~/.claude/skills/
```

## Hermes Agent

[Hermes Agent](https://hermes-agent.nousresearch.com) (Nous Research) has its own native skills system that reads from skills.sh. From inside Hermes:

```
/skills install catpilotai/catpilot-ai-guardrails/catpilot-security-core
```

Installation makes the instructions available to a host; it does not prove they were loaded, followed, or enforced. See the tested-runtimes table in `docs/REFERENCE.md`. Organization-wide deployment (managed settings, admin skill directories, workspace plugins): `docs/DEPLOY_ORG.md`.

## Claude Code plugin

The repository is also a Claude Code plugin (`.claude-plugin/plugin.json`, skills only): `/plugin marketplace add catpilotai/catpilot-ai-guardrails`, then `/plugin install catpilot-guardrails@catpilot`. The skills are then invoked as `/catpilot-guardrails:catpilot-safe-building` and `/catpilot-guardrails:catpilot-security-core`. The hooks and the reference server are not in the plugin; `hooks/README.md` and `mcp-server/README.md` cover those, and `docs/DEPLOY_ORG.md` covers enabling the plugin for an organization through managed settings.
