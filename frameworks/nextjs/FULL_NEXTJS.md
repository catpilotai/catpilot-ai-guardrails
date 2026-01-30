# Next.js Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides detailed security patterns for Next.js applications, covering the App Router, Pages Router, API Routes, Server Actions, and middleware.

---

## Table of Contents

1. [XSS Prevention](#xss-prevention)
2. [Environment Variables & Secrets](#environment-variables--secrets)
3. [API Route Security](#api-route-security)
4. [Server Actions Security](#server-actions-security)
5. [Authentication Patterns](#authentication-patterns)
6. [Database Security](#database-security)
7. [File Upload Security](#file-upload-security)
8. [CSRF Protection](#csrf-protection)
9. [Security Headers](#security-headers)

---

## XSS Prevention

### The Problem

Next.js JSX automatically escapes values, but several patterns bypass this protection.

### ❌ Vulnerable Patterns

```tsx
// 1. dangerouslySetInnerHTML without sanitization
function Comment({ content }: { content: string }) {
  // User submits: <img src=x onerror="alert(document.cookie)">
  return <div dangerouslySetInnerHTML={{ __html: content }} />
}

// 2. Rendering user input in script tags
function Analytics({ userId }: { userId: string }) {
  return (
    <script
      dangerouslySetInnerHTML={{
        __html: `analytics.identify("${userId}")`,  // Injection point!
      }}
    />
  )
}

// 3. href with javascript: protocol
function UserLink({ url }: { url: string }) {
  // User submits: javascript:alert(document.cookie)
  return <a href={url}>Click here</a>
}
```

### ✅ Safe Patterns

```tsx
// 1. Sanitize HTML before rendering
import DOMPurify from 'dompurify'

function Comment({ content }: { content: string }) {
  const sanitized = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'a', 'p'],
    ALLOWED_ATTR: ['href'],
  })
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />
}

// 2. Use JSON.stringify for data in scripts
function Analytics({ userId }: { userId: string }) {
  return (
    <script
      dangerouslySetInnerHTML={{
        __html: `analytics.identify(${JSON.stringify(userId)})`,
      }}
    />
  )
}

// 3. Validate URL protocols
function UserLink({ url }: { url: string }) {
  const isValidUrl = (u: string) => {
    try {
      const parsed = new URL(u)
      return ['http:', 'https:'].includes(parsed.protocol)
    } catch {
      return false
    }
  }
  
  if (!isValidUrl(url)) return null
  return <a href={url}>Click here</a>
}
```

---

## Environment Variables & Secrets

### The Problem

Next.js exposes `NEXT_PUBLIC_*` variables to the browser. Any other env var accessed in client code will be undefined or leak in build output.

### ❌ Vulnerable Patterns

```tsx
// Client Component trying to access secret
'use client'

export function PaymentForm() {
  // ❌ This will be undefined in browser, but may leak in build logs
  const stripeKey = process.env.STRIPE_SECRET_KEY
  
  // ❌ Or developers mistakenly use NEXT_PUBLIC_ for secrets
  const apiSecret = process.env.NEXT_PUBLIC_API_SECRET  // Exposed to browser!
}
```

### ✅ Safe Patterns

```tsx
// Server Component (default in App Router)
export async function PaymentProcessor() {
  // ✅ Safe — only runs on server
  const stripeKey = process.env.STRIPE_SECRET_KEY
  const stripe = new Stripe(stripeKey)
  // Process payment...
}

// Client Component using only public values
'use client'

export function PaymentForm() {
  // ✅ Safe — intentionally public
  const publishableKey = process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY
}

// API Route with secrets
export async function POST(request: Request) {
  // ✅ Safe — API routes run on server
  const apiKey = process.env.EXTERNAL_API_KEY
}
```

### Environment Variable Naming Convention

| Prefix | Visibility | Use For |
|--------|------------|---------|
| `NEXT_PUBLIC_*` | Client + Server | Public keys, feature flags, URLs |
| No prefix | Server only | API secrets, database URLs, tokens |

---

## API Route Security

### The Problem

API routes can be called by anyone. Without proper validation, they're vulnerable to injection, unauthorized access, and data exposure.

### ❌ Vulnerable Patterns

```tsx
// app/api/users/[id]/route.ts

// 1. No authentication
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const user = await db.user.findUnique({ where: { id: params.id } })
  return Response.json(user)  // Anyone can fetch any user!
}

// 2. SQL injection via template literals
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const name = searchParams.get('name')
  
  // ❌ Template literal is NOT parameterized
  const users = await sql`SELECT * FROM users WHERE name = '${name}'`
  return Response.json(users)
}

// 3. SSRF — fetching arbitrary URLs
export async function POST(request: Request) {
  const { url } = await request.json()
  const response = await fetch(url)  // Attacker controls destination!
  return Response.json(await response.json())
}
```

### ✅ Safe Patterns

```tsx
// app/api/users/[id]/route.ts
import { getServerSession } from 'next-auth'
import { z } from 'zod'

// 1. Authentication + Authorization
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const session = await getServerSession()
  if (!session) {
    return Response.json({ error: 'Unauthorized' }, { status: 401 })
  }
  
  // Only allow users to fetch their own data (or admins)
  if (session.user.id !== params.id && session.user.role !== 'admin') {
    return Response.json({ error: 'Forbidden' }, { status: 403 })
  }
  
  const user = await db.user.findUnique({ where: { id: params.id } })
  return Response.json(user)
}

// 2. Parameterized queries with Prisma
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url)
  const name = searchParams.get('name')
  
  // ✅ Prisma handles parameterization
  const users = await prisma.user.findMany({
    where: { name: { contains: name ?? '' } },
  })
  return Response.json(users)
}

// 3. SSRF prevention — allowlist URLs
const ALLOWED_HOSTS = ['api.stripe.com', 'api.github.com']

export async function POST(request: Request) {
  const { url } = await request.json()
  
  try {
    const parsed = new URL(url)
    if (!ALLOWED_HOSTS.includes(parsed.host)) {
      return Response.json({ error: 'URL not allowed' }, { status: 400 })
    }
    const response = await fetch(url)
    return Response.json(await response.json())
  } catch {
    return Response.json({ error: 'Invalid URL' }, { status: 400 })
  }
}
```

---

## Server Actions Security

### The Problem

Server Actions are exposed as POST endpoints. Without validation, they can be called with arbitrary data.

### ❌ Vulnerable Patterns

```tsx
// app/actions.ts
'use server'

// 1. No input validation
export async function updateProfile(formData: FormData) {
  const name = formData.get('name')
  const role = formData.get('role')  // Attacker adds role=admin!
  
  await db.user.update({
    where: { id: currentUser.id },
    data: { name, role },  // Privilege escalation!
  })
}

// 2. No authorization check
export async function deletePost(postId: string) {
  await db.post.delete({ where: { id: postId } })  // Anyone can delete any post!
}
```

### ✅ Safe Patterns

```tsx
// app/actions.ts
'use server'

import { z } from 'zod'
import { getServerSession } from 'next-auth'

// 1. Validate and sanitize input, ignore unauthorized fields
const updateProfileSchema = z.object({
  name: z.string().min(1).max(100),
  // Note: 'role' is NOT in schema — ignored even if submitted
})

export async function updateProfile(formData: FormData) {
  const session = await getServerSession()
  if (!session) throw new Error('Unauthorized')
  
  const validated = updateProfileSchema.parse({
    name: formData.get('name'),
  })
  
  await db.user.update({
    where: { id: session.user.id },
    data: validated,  // Only validated fields
  })
}

// 2. Authorization check
export async function deletePost(postId: string) {
  const session = await getServerSession()
  if (!session) throw new Error('Unauthorized')
  
  const post = await db.post.findUnique({ where: { id: postId } })
  if (post?.authorId !== session.user.id) {
    throw new Error('Forbidden')
  }
  
  await db.post.delete({ where: { id: postId } })
}
```

---

## Authentication Patterns

### NextAuth.js / Auth.js Secure Configuration

```tsx
// app/api/auth/[...nextauth]/route.ts
import NextAuth from 'next-auth'
import { PrismaAdapter } from '@auth/prisma-adapter'

const handler = NextAuth({
  adapter: PrismaAdapter(prisma),
  
  // ✅ Use secure session strategy
  session: {
    strategy: 'jwt',
    maxAge: 30 * 24 * 60 * 60, // 30 days
  },
  
  // ✅ Configure secure cookies
  cookies: {
    sessionToken: {
      name: `__Secure-next-auth.session-token`,
      options: {
        httpOnly: true,
        sameSite: 'lax',
        path: '/',
        secure: process.env.NODE_ENV === 'production',
      },
    },
  },
  
  callbacks: {
    // ✅ Control what goes in the JWT
    jwt: async ({ token, user }) => {
      if (user) {
        token.id = user.id
        token.role = user.role
      }
      return token
    },
    
    // ✅ Control what's exposed in session
    session: async ({ session, token }) => {
      session.user.id = token.id
      session.user.role = token.role
      return session
    },
  },
})

export { handler as GET, handler as POST }
```

### Middleware Protection

```tsx
// middleware.ts
import { NextResponse } from 'next/server'
import { getToken } from 'next-auth/jwt'

export async function middleware(request) {
  const token = await getToken({ req: request })
  
  // Protect dashboard routes
  if (request.nextUrl.pathname.startsWith('/dashboard')) {
    if (!token) {
      return NextResponse.redirect(new URL('/login', request.url))
    }
  }
  
  // Protect admin routes
  if (request.nextUrl.pathname.startsWith('/admin')) {
    if (!token || token.role !== 'admin') {
      return NextResponse.redirect(new URL('/unauthorized', request.url))
    }
  }
  
  return NextResponse.next()
}

export const config = {
  matcher: ['/dashboard/:path*', '/admin/:path*'],
}
```

---

## Database Security

### Prisma (Recommended)

```tsx
// ✅ Safe — Prisma handles parameterization
const user = await prisma.user.findUnique({
  where: { email: userInput },
})

// ✅ Safe — Prisma sanitizes
const users = await prisma.user.findMany({
  where: {
    OR: [
      { name: { contains: searchTerm } },
      { email: { contains: searchTerm } },
    ],
  },
})
```

### Raw SQL (When Necessary)

```tsx
// ❌ NEVER
await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${userId}'`)

// ✅ Use tagged template (Prisma parameterizes this)
await prisma.$queryRaw`SELECT * FROM users WHERE id = ${userId}`

// ✅ Or explicit parameterization
await prisma.$queryRaw(
  Prisma.sql`SELECT * FROM users WHERE id = ${Prisma.raw(userId)}`
)
```

---

## Security Headers

Add security headers via `next.config.js`:

```javascript
// next.config.js
const securityHeaders = [
  {
    key: 'X-DNS-Prefetch-Control',
    value: 'on',
  },
  {
    key: 'Strict-Transport-Security',
    value: 'max-age=63072000; includeSubDomains; preload',
  },
  {
    key: 'X-Frame-Options',
    value: 'SAMEORIGIN',
  },
  {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  },
  {
    key: 'Referrer-Policy',
    value: 'origin-when-cross-origin',
  },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
  },
]

module.exports = {
  async headers() {
    return [
      {
        source: '/:path*',
        headers: securityHeaders,
      },
    ]
  },
}
```

---

## Quick Reference Table

| Vulnerability | Next.js-Specific Risk | Prevention |
|---------------|----------------------|------------|
| XSS | `dangerouslySetInnerHTML`, `javascript:` hrefs | DOMPurify, URL validation |
| Secret Exposure | `NEXT_PUBLIC_*` misuse, client component access | Server-only env vars |
| SSRF | Unvalidated fetch in API routes | URL allowlisting |
| SQL Injection | Raw queries, template literals | Prisma, parameterized queries |
| CSRF | Server Actions without validation | Zod schemas, auth checks |
| Broken Auth | Missing middleware, no session checks | NextAuth + middleware |

---

*Condensed version: [condensed.md](./condensed.md)*
