# Contributing to AI Guardrails

You found the community scratching post.

## Quick Links

- **GitHub:** [catpilotai/catpilot-ai-guardrails](https://github.com/catpilotai/catpilot-ai-guardrails)
- **Website:** [catpilot.ai](https://catpilot.ai)

## How to Contribute

| What | How |
|------|-----|
| Found a dangerous pattern | Open an issue or PR |
| Bug in setup.sh | PR it! |
| New framework | Start with an issue to discuss |
| Typo/docs fix | Just PR it |
| Questions | Open a discussion |

## Before You PR

- [ ] Test with your AI assistant (does it follow the new rule?)
- [ ] Check file size: `wc -c copilot-instructions.md` (must be < 5KB)
- [ ] Keep PRs focused (one pattern per PR)
- [ ] Include before/after examples

## AI-Assisted PRs Welcome! 🤖

Built with Copilot, Claude, Cursor, or other AI tools? Perfect — this is literally a project about AI coding.

Just note in your PR:
- [ ] Mark as AI-assisted
- [ ] Confirm you tested it
- [ ] Confirm you understand what the code does

No judgment. We just want reviewers to know what to look for.

## What Makes a Good Pattern

```
✅ Specific    → "Don't use f-strings in SQL queries"
❌ Vague       → "Be careful with databases"

✅ Actionable  → Bad code → Good code examples
❌ Abstract    → "Follow best practices"

✅ Impactful   → Prevents outages, data loss, security holes
❌ Pedantic    → Style preferences
```

## File Size Budget

The whole point is staying small so we don't bloat the AI's context window:

| File | Budget |
|------|--------|
| `copilot-instructions.md` | < 5KB |
| Framework `condensed.md` | 600-800 bytes |
| `FULL_*.md` files | No limit (loaded on-demand) |

## Current Focus 🎯

- More framework patterns (Vue, Svelte, Go, Rust)
- Better setup.sh edge case handling  
- More cloud CLI patterns (GCP, AWS)
- Community-reported dangerous patterns

Check [Issues](https://github.com/catpilotai/catpilot-ai-guardrails/issues) for "good first issue" labels!

---

By contributing, you agree your work is licensed under MIT. Now go catch some bugs. 🐾
