# Express.js Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides detailed security patterns for Express.js applications.

---

## Table of Contents

1. [SQL Injection](#sql-injection)
2. [NoSQL Injection](#nosql-injection)
3. [Cross-Site Scripting (XSS)](#cross-site-scripting-xss)
4. [Path Traversal](#path-traversal)
5. [Authentication & Authorization](#authentication--authorization)
6. [Secrets Management](#secrets-management)
7. [Security Headers (Helmet)](#security-headers-helmet)
8. [Rate Limiting](#rate-limiting)
9. [CORS Configuration](#cors-configuration)

---

## SQL Injection

### ❌ Vulnerable Patterns

```javascript
// String interpolation/concatenation
app.get('/users/:id', async (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;  // DANGEROUS
  const result = await db.query(query);
  res.json(result.rows);
});

// Template literals
const query = `SELECT * FROM users WHERE name = '${req.body.name}'`;  // DANGEROUS
```

### ✅ Safe Patterns

```javascript
// PostgreSQL (pg) - parameterized queries
app.get('/users/:id', async (req, res) => {
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await db.query(query, [req.params.id]);
  res.json(result.rows);
});

// MySQL - parameterized queries
const query = 'SELECT * FROM users WHERE id = ?';
const [rows] = await connection.execute(query, [req.params.id]);

// Multiple parameters
const query = 'SELECT * FROM users WHERE name = $1 AND email = $2';
const result = await db.query(query, [name, email]);

// With query builder (Knex.js)
const users = await knex('users')
  .where('id', req.params.id)
  .first();
```

---

## NoSQL Injection

### The Problem

MongoDB queries can be manipulated if user input is passed directly.

### ❌ Vulnerable Patterns

```javascript
// Direct object from request
app.post('/login', async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,  // Could be { $gt: "" }
    password: req.body.password   // Could be { $gt: "" }
  });
  // Attacker sends: { "username": {"$gt": ""}, "password": {"$gt": ""} }
  // This matches ANY user!
});

// Using $where with user input
User.find({ $where: `this.name == '${name}'` });  // DANGEROUS
```

### ✅ Safe Patterns

```javascript
// Explicitly cast/validate input types
app.post('/login', async (req, res) => {
  const username = String(req.body.username);  // Force string
  const password = String(req.body.password);
  
  const user = await User.findOne({ username, password });
});

// Use mongoose schema validation
const userSchema = new mongoose.Schema({
  username: { type: String, required: true },
  password: { type: String, required: true },
});

// Input validation with express-validator
const { body, validationResult } = require('express-validator');

app.post('/login', [
  body('username').isString().trim().notEmpty(),
  body('password').isString().notEmpty(),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  // Now safe to use
});

// mongo-sanitize package
const sanitize = require('mongo-sanitize');
const cleanUsername = sanitize(req.body.username);
```

---

## Cross-Site Scripting (XSS)

### ❌ Vulnerable Patterns

```javascript
// Sending user input directly
app.get('/search', (req, res) => {
  res.send(`<h1>Results for: ${req.query.q}</h1>`);  // DANGEROUS
});

// Setting innerHTML on client with unescaped data
// (API returns unsanitized user content)
```

### ✅ Safe Patterns

```javascript
// Use template engine with auto-escaping (EJS, Pug, Handlebars)
// EJS escapes by default with <%= %>
app.get('/search', (req, res) => {
  res.render('search', { query: req.query.q });  // Template escapes
});

// For APIs returning HTML, sanitize
const DOMPurify = require('isomorphic-dompurify');

app.get('/api/content/:id', async (req, res) => {
  const content = await Content.findById(req.params.id);
  res.json({
    ...content,
    html: DOMPurify.sanitize(content.html)
  });
});

// Escape utility for manual cases
const escapeHtml = require('escape-html');
res.send(`<h1>Results for: ${escapeHtml(req.query.q)}</h1>`);
```

---

## Path Traversal

### ❌ Vulnerable Patterns

```javascript
const path = require('path');

// Direct file access with user input
app.get('/files/:filename', (req, res) => {
  res.sendFile(`/uploads/${req.params.filename}`);  // DANGEROUS
  // Attacker: /files/../../../etc/passwd
});

// Even with path.join
app.get('/files/:filename', (req, res) => {
  const filePath = path.join(__dirname, 'uploads', req.params.filename);
  res.sendFile(filePath);  // Still vulnerable!
});
```

### ✅ Safe Patterns

```javascript
const path = require('path');

const UPLOADS_DIR = path.resolve(__dirname, 'uploads');

app.get('/files/:filename', (req, res) => {
  // Get only the filename, strip directory components
  const safeName = path.basename(req.params.filename);
  
  // Resolve full path
  const filePath = path.resolve(UPLOADS_DIR, safeName);
  
  // Verify it's within allowed directory
  if (!filePath.startsWith(UPLOADS_DIR)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Check file exists
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  res.sendFile(filePath);
});
```

---

## Authentication & Authorization

### JWT Authentication

```javascript
const jwt = require('jsonwebtoken');

// Middleware
const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token provided' });
  }
  
  const token = authHeader.split(' ')[1];
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
};

// Apply to routes
app.use('/api', authenticate);

// Or specific routes
app.get('/api/profile', authenticate, (req, res) => {
  res.json(req.user);
});
```

### Authorization

```javascript
// ❌ Missing authorization check
app.delete('/api/posts/:id', authenticate, async (req, res) => {
  await Post.deleteOne({ _id: req.params.id });  // Anyone can delete!
  res.json({ success: true });
});

// ✅ Check ownership
app.delete('/api/posts/:id', authenticate, async (req, res) => {
  const post = await Post.findById(req.params.id);
  
  if (!post) {
    return res.status(404).json({ error: 'Post not found' });
  }
  
  if (post.author.toString() !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  await post.deleteOne();
  res.json({ success: true });
});

// Role-based middleware
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    next();
  };
};

app.delete('/api/users/:id', authenticate, requireRole('admin'), async (req, res) => {
  // Only admins reach here
});
```

---

## Secrets Management

### ❌ Vulnerable Patterns

```javascript
// Hardcoded secrets
const JWT_SECRET = 'my-super-secret-key';
const DB_PASSWORD = 'password123';

// Committing .env
// (missing from .gitignore)
```

### ✅ Safe Patterns

```javascript
// Use environment variables
require('dotenv').config();  // Load .env in development

const config = {
  jwtSecret: process.env.JWT_SECRET,
  dbUrl: process.env.DATABASE_URL,
  port: process.env.PORT || 3000,
};

// Validate required env vars at startup
const required = ['JWT_SECRET', 'DATABASE_URL'];
for (const key of required) {
  if (!process.env[key]) {
    console.error(`Missing required env var: ${key}`);
    process.exit(1);
  }
}

// .env (never commit)
JWT_SECRET=your-256-bit-secret
DATABASE_URL=postgresql://user:pass@localhost/db

// .gitignore
.env
.env.*
!.env.example

// .env.example (commit this)
JWT_SECRET=
DATABASE_URL=
```

---

## Security Headers (Helmet)

```javascript
const helmet = require('helmet');

// Basic usage - applies sensible defaults
app.use(helmet());

// Customized
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],  // Avoid if possible
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: true,
  crossOriginResourcePolicy: { policy: "same-site" },
  dnsPrefetchControl: true,
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: { maxAge: 31536000, includeSubDomains: true },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true,
}));
```

---

## Rate Limiting

```javascript
const rateLimit = require('express-rate-limit');

// General API rate limit
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 100,  // 100 requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later' },
});

app.use('/api', apiLimiter);

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,  // 5 attempts per 15 minutes
  message: { error: 'Too many login attempts' },
});

app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// Skip rate limiting for trusted IPs (optional)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  skip: (req) => {
    const trustedIPs = ['127.0.0.1'];
    return trustedIPs.includes(req.ip);
  },
});
```

---

## CORS Configuration

### ❌ Vulnerable Patterns

```javascript
const cors = require('cors');

// Allow everything
app.use(cors());  // DANGEROUS in production

// Especially bad with credentials
app.use(cors({
  origin: '*',
  credentials: true,  // This combination is invalid and dangerous
}));
```

### ✅ Safe Patterns

```javascript
const cors = require('cors');

// Explicit allowlist
const allowedOrigins = [
  'https://myapp.com',
  'https://www.myapp.com',
];

if (process.env.NODE_ENV === 'development') {
  allowedOrigins.push('http://localhost:3000');
}

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));
```

---

## Quick Reference

| Vulnerability | Express Protection |
|---------------|-------------------|
| SQL Injection | Parameterized queries (`$1`, `?`) |
| NoSQL Injection | Type casting, mongo-sanitize |
| XSS | Template escaping, DOMPurify |
| Path Traversal | `path.basename()` + resolve check |
| Auth Bypass | Middleware on all routes |
| Secrets | `process.env`, dotenv |
| Headers | helmet middleware |

---

*Condensed version: [condensed.md](./condensed.md)*
