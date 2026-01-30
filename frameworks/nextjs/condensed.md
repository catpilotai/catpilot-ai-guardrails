## 🔷 Next.js Security

| Risk | ❌ Never | ✅ Always |
|------|----------|----------|
| XSS | `dangerouslySetInnerHTML={{ __html: userInput }}` | `DOMPurify.sanitize(content)` |
| Secrets | `process.env.SECRET` in `'use client'` | Server Components only; `NEXT_PUBLIC_` for public |
| SSRF | `fetch(req.query.url)` | Allowlist: `['api.example.com'].includes(host)` |
| SQL | Template literals in queries | Prisma/Drizzle parameterized queries |
| Data leak | `return { props: { user } }` (full object) | Return only needed fields |

**Auth:** Always `getServerSession()` in API routes. Use middleware for `/dashboard/*` protection.

*Full reference: [FULL_NEXTJS.md](./FULL_NEXTJS.md)*
