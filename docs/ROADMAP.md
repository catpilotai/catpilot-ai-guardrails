# Roadmap

The core content baseline is shipped and maintained. This quarter's work is the safe-building wedge and honest verification, not more frameworks.

| Item | Status |
|---|---|
| `catpilot-security-core` | shipped, nine components; maintained; no new components this quarter |
| `catpilot-safe-building` | shipped in `2026.09.13` |
| Per-host targets and the safe-building web page source | shipped in `2026.09.13`; the live `catpilot.ai/safe-ai-building` page ships with the site pass |
| README contract, tested-runtimes table, Claude Code hooks | shipped: the `Bash` credential hook in `2026.09.13`, the `Write`/`Edit` private-key hook in `2026.09.14` |
| Organization-overlay schema, validator, private builds | shipped in `2026.09.13` |
| Safe-building evaluation fixtures and with/without runner | shipped in `2026.09.16` (first reports for Claude Code and Codex; next run on a fresh scenario set with arm D and the follow-up turn) |
| Reference MCP server (`get_guidance`, `check_plan`, `get_template`, `list_approved`) | shipped as a self-hosted reference in `mcp-server/` and as a hosted generic-defaults endpoint at `mcp.catpilot.ai`; lookups verified from Claude Code and Codex on 2026-09-14; tenant-scoped, authenticated serving is the platform's work |
| ChatGPT and Claude.ai custom connectors against the hosted endpoint | not yet verified |
| Framework extensions (`catpilot-<framework>-security`) | content kept in `frameworks/`; no bundle promised this quarter |
| Agentic loop guidance for harnesses | reference text in `frameworks/agentic/` and the harness gate in `hooks/harness/`; packaging as a bundle deferred |
| `catpilot-security-advanced` | deferred |
| `tools/recommend.py` | deferred |
| HIPAA and GDPR mappings | deferred |
