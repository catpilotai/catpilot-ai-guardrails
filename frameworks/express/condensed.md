# Express.js Security Patterns

| Risk | Bad | Good |
|------|-----|------|
| SQL Injection | `` `SELECT * FROM users WHERE id=${id}` `` | `db.query("SELECT * FROM users WHERE id = $1", [id])` |
| XSS | `res.send(userInput)` without encoding | Use template engine escaping, `DOMPurify.sanitize()` |
| NoSQL Injection | `User.find({ name: req.body.name })` | `User.find({ name: String(req.body.name) })`, use mongoose schema |
| Path Traversal | `res.sendFile(req.params.file)` | `path.basename()` + resolve within allowed dir |
| Auth Bypass | No middleware on routes | `app.use('/api', authMiddleware)`, check on every route |
| Secrets | `const SECRET = "hardcoded"` | `process.env.SECRET`, use dotenv, never commit .env |
| CORS | `cors({ origin: '*', credentials: true })` | Explicit origin allowlist: `cors({ origin: ['https://myapp.com'] })` |

**Reference:** `FULL_EXPRESS.md` for helmet config, rate limiting, session security
