# language-baseline

Component `language-baseline` · version 1.0.1 · severity high · category secure-coding.
Full text of one component of the `catpilot-security-core` bundle. The baseline rules are in `../SKILL.md`; this file has the rest: examples, remediation, and detection patterns.
## Baseline

**Applies when:** Writing or committing code that builds SQL from non-literal values, runs a subprocess/shell with non-literal arguments, writes input into the DOM/HTML, resolves a filesystem path from input, deserializes untrusted data, executes a string as code, bypasses type-system checks, or issues an outbound HTTP request to an input-derived URL.

**Always:**
- Route SQL values through driver parameter binding; never string concatenation, f-strings, template literals, or ORM raw-query helpers.
- Run subprocesses with an argv array and no shell (`shell=False`); the command name is a literal or from an allowlist, never derived from input.
- Write user-controlled values to the DOM/HTML only through escaping sinks (`textContent`, not `innerHTML`/`document.write`); sanitize with a vetted library when raw HTML is required.
- Normalize input-derived filesystem paths: strip to basename, join against a known-safe directory, resolve symlinks, and reject anything outside that directory.
- Deserialize untrusted data only with type-constrained formats (`json.loads`, `yaml.safe_load`); never `pickle.loads`, unsafe `yaml.load`, `Marshal.load`, `ObjectInputStream`, or `unserialize`.
- Never execute a string as code (`eval`, `new Function`, `setTimeout(stringArg)`) or bypass type-system checks (`as any`, `@ts-ignore`) on external input.
- Before an outbound HTTP request to an input-derived URL, check the host against an allowlist and reject internal/link-local IP ranges.

**Never:**
- SQL built by string concatenation, f-strings, or template literals with non-literal values.
- `subprocess`/`exec`/`system` invoked with a single shell-interpreted string containing non-literal elements.
- `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, or `{{ x | safe }}` fed with unsanitized user input.
- `pickle.loads`, `yaml.load`/`yaml.unsafe_load`, `Marshal.load`, or `unserialize` on external data.
- `eval`, `new Function`, or TypeScript `as any`/`@ts-ignore` used to bypass validation of external input.

Open the full component before acting: it has the examples, the remediation steps, and the detection patterns.

## Why

A small number of injection and arbitrary-code-execution patterns
account for most of the application-layer CVEs published every
year. The shape repeats across languages: **a value the program
did not produce reaches a context where it is interpreted as
code**.

- A user-supplied id reaches a SQL string by concatenation, and
  the database treats the trailing `'; DROP TABLE ...` as
  syntactically valid SQL. (SQL injection — CWE-89.)
- A search term reaches a shell command via
  `subprocess.call(..., shell=True)`, and the shell treats
  `$(curl evil)` as a substitution. (Command injection — CWE-78.)
- A user-supplied bio reaches the DOM via `innerHTML`, and the
  browser parses the embedded `<script>` tag. (XSS — CWE-79.)
- A user-supplied filename reaches `fs.readFile`, and the OS
  resolves `../../etc/passwd`. (Path traversal — CWE-22.)
- A user-supplied object reaches `pickle.loads`, and Python
  instantiates whatever class the byte stream names — including
  one whose `__reduce__` runs `os.system`. (Insecure
  deserialization — CWE-502.)
- A user-supplied URL reaches `requests.get`, and the server
  fetches `http://169.254.169.254/latest/meta-data/` from the
  cloud metadata service. (SSRF — CWE-918.)

The fix in every case has the same shape: **treat external input
as data, not as code**, by routing it through an API designed for
the context (parameterized query, argv-style exec, escaping
sink, allowlist).

This skill is not language-specific; the same six classes are
the same across Python, JavaScript/TypeScript, Ruby, Java, Go,
PHP, and C#. The language-specific shape of each fix changes;
the rule does not.

## When to apply

Apply this skill **before** the agent writes, recommends, or
commits any code that:

- Constructs a SQL query from values that are not literals in
  the source.
- Invokes a subprocess, shell, or system command with arguments
  that are not literals.
- Writes a value into the DOM, an HTML response body, or any
  HTML-template sink.
- Reads, writes, opens, deletes, or traverses a filesystem path
  derived from input.
- Deserializes data using a format that can construct arbitrary
  types (`pickle`, `yaml.load`, `Marshal`, `ObjectInputStream`,
  `unserialize`).
- Executes a string as code (`eval`, `new Function`,
  `setTimeout(string)`, `exec`).
- Bypasses the type system in a way that erases verification
  (`as any` in TypeScript, `@SuppressWarnings("unchecked")`
  in Java, `interface{}` casts in Go without runtime checks).
- Issues an outbound HTTP request to a URL the program did not
  fully construct.

This skill is the application-code counterpart to
`database-safety` (which governs the *operation* once the query
is correctly parameterized) and `secrets-management` (which
governs the credentials the application uses). All three apply
together.

## Rules

### Rule 1 — SQL is always parameterized; concatenation is prohibited

Values that are not source-literal constants reach SQL through
the driver's parameter-binding API, never through string
concatenation, f-strings, template literals, `printf`-style
formatting, or ORM raw-query helpers that bypass binding.

```python
# ✅ psycopg / sqlite3 / aiomysql — driver placeholders
cursor.execute(
    "SELECT * FROM users WHERE id = %s AND tenant_id = %s",
    (user_id, tenant_id),
)
```

```javascript
// ✅ pg / mysql2 / better-sqlite3 — numbered or `?` placeholders
await client.query(
  "SELECT * FROM users WHERE id = $1 AND tenant_id = $2",
  [userId, tenantId],
);
```

```java
// ✅ JDBC PreparedStatement
PreparedStatement ps = conn.prepareStatement(
    "SELECT * FROM users WHERE id = ? AND tenant_id = ?");
ps.setLong(1, userId);
ps.setLong(2, tenantId);
```

This rule overlaps `database-safety` Rule 5; it is restated here
because the failure mode (string concatenation in application
code) is a coding pattern, not a database operation.

### Rule 2 — Subprocess calls use argv arrays, never `shell=True` with input

When the program runs an external command:

- The arguments are passed as an array, not a single string.
- The shell is not invoked
  (`shell=False` in Python, no `sh -c` wrapper in Node).
- The command name is a literal or comes from an allowlist; it
  is not derived from input.

```python
# ✅ Python — argv array, no shell
subprocess.run(["grep", pattern, "file.txt"], check=True)
```

```javascript
// ✅ Node — execFile with argv, no shell
const { execFile } = require("node:child_process");
execFile("grep", [pattern, "file.txt"], (err, stdout) => { /* ... */ });
```

```ruby
# ✅ Ruby — argv form of system / exec / spawn
system("grep", pattern, "file.txt")
```

`exec`, `system`, `popen`, `subprocess.call`, `child_process.exec`,
and `Process.spawn` invoked with a single shell-interpreted
string are prohibited when any element of the string is not a
literal.

### Rule 3 — HTML output uses escaping sinks, never raw HTML sinks

User-controlled values reach the DOM or an HTML response body
through escaping sinks:

| Sink | Safe replacement |
|---|---|
| `element.innerHTML = x` | `element.textContent = x` |
| `document.write(x)` | DOM construction (`createElement`, `appendChild`) |
| `$('#x').html(v)` | `$('#x').text(v)` |
| `React: dangerouslySetInnerHTML` | Render `{v}` directly |
| Jinja `{{ x | safe }}` | Default `{{ x }}` |
| Handlebars `{{{ x }}}` | `{{ x }}` |

When HTML output is genuinely required (rendered Markdown,
rich-text editor), the value passes through a vetted sanitizer
(DOMPurify, bleach, sanitize-html, OWASP Java HTML Sanitizer)
with the allowlist tightened to the smallest required set of
tags and attributes. Sanitization is configured once, centrally,
and reused — not redefined per-call.

### Rule 4 — Filesystem paths from input are normalized, anchored, and bounded

When a path comes from input:

1. Extract the basename (strip directory components).
2. Join against a known-safe directory.
3. Resolve symlinks and re-check that the resolved path is still
   inside the safe directory.
4. Reject any path that fails any check; never "clean up" and
   continue.

```python
# ✅ Python
import os
from pathlib import Path
ALLOWED = Path("/var/app/uploads").resolve()

def safe_open(user_supplied: str):
    candidate = (ALLOWED / Path(user_supplied).name).resolve()
    if not str(candidate).startswith(str(ALLOWED) + os.sep):
        raise ValueError("path escape")
    return open(candidate, "rb")
```

```javascript
// ✅ Node
const path = require("node:path");
const fs = require("node:fs/promises");
const ALLOWED = path.resolve("/var/app/uploads");

async function safeRead(userSupplied) {
  const candidate = path.resolve(ALLOWED, path.basename(userSupplied));
  if (!candidate.startsWith(ALLOWED + path.sep)) {
    throw new Error("path escape");
  }
  return fs.readFile(candidate);
}
```

`open()`, `fs.readFile()`, `os.remove()`, `shutil.rmtree()`,
`fs.unlink()`, and analogous APIs invoked on an unvalidated
input path are prohibited.

### Rule 5 — Deserialization uses safe, type-constrained formats

The following deserializers can construct arbitrary types and
must not be invoked on data that did not originate inside the
program:

| Language | Unsafe | Safe replacement |
|---|---|---|
| Python | `pickle.loads`, `cPickle.loads`, `yaml.load`, `yaml.unsafe_load`, `marshal.loads`, `shelve` | `json.loads`, `yaml.safe_load`, `tomllib.loads` |
| JavaScript / Node | `eval`, `new Function`, `vm.runInThisContext` on input, `node-serialize.unserialize` | `JSON.parse` |
| Ruby | `Marshal.load`, `YAML.load` (pre-3.1) | `JSON.parse`, `YAML.safe_load` |
| Java | `ObjectInputStream.readObject`, `XMLDecoder`, `XStream` (default config) | Jackson `ObjectMapper` with `DefaultTyping=NONE`, Gson |
| PHP | `unserialize`, `wddx_deserialize` | `json_decode` |
| .NET | `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, `ObjectStateFormatter` | `System.Text.Json` |

The fix is to switch to a format that cannot instantiate arbitrary
types, then validate the parsed structure against a schema (Pydantic,
Zod, JSON Schema, Joi) before use.

### Rule 6 — `eval`-class APIs and type-system escapes are not used on input

The following are prohibited when their argument is, or contains,
input:

- `eval(...)` (every language).
- `new Function(...)`, `setTimeout(stringArg)`,
  `setInterval(stringArg)` in JavaScript.
- `exec(...)` of a string in Python (CPython byte-compile path).
- `instance_eval`, `class_eval`, `eval` in Ruby.
- TypeScript `as any`, `as unknown as T`, `// @ts-ignore`,
  `// @ts-expect-error` used to bypass a verification check on
  external input.
- Reflective construction (`Class.forName(...).newInstance()`,
  `Activator.CreateInstance(Type.GetType(...))`) where the type
  name is derived from input.

The fix is to express the dynamic logic through a constrained
mechanism — a routing table, a registry of allowed handlers, a
state machine, or a schema-validated dispatcher.

### Rule 7 — Outbound HTTP uses an allowlist of hosts and blocks internal targets

When the program issues an HTTP request to a URL derived from
input:

1. Parse the URL.
2. Check the host against an allowlist of expected hosts.
3. Resolve the host to IP addresses and reject any that fall
   inside RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`,
   `192.168.0.0/16`), loopback (`127.0.0.0/8`), link-local
   (`169.254.0.0/16` — includes cloud metadata), unique-local
   IPv6 (`fc00::/7`), or `::1`.
4. Re-resolve at request time to catch DNS rebinding (or use a
   library that pins the resolved IP).
5. Reject `file://`, `gopher://`, `dict://`, and any scheme that
   is not `http`/`https`.

```python
# ✅ Python — allowlist + internal-IP rejection
from ipaddress import ip_address, ip_network
import socket
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.stripe.com", "api.github.com"}
PRIVATE_RANGES = [
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
    ip_network("127.0.0.0/8"),
    ip_network("169.254.0.0/16"),
    ip_network("::1/128"),
    ip_network("fc00::/7"),
]

def safe_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("scheme")
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("host")
    for family, _, _, _, sockaddr in socket.getaddrinfo(parsed.hostname, None):
        ip = ip_address(sockaddr[0])
        if any(ip in net for net in PRIVATE_RANGES):
            raise ValueError("private ip")
    return url
```

`fetch(req.query.url)`, `requests.get(user_input)`,
`HttpClient.GetAsync(input)` invoked with no allowlist or
internal-IP check are prohibited.

## Negative examples

```python
# ❌ SQL injection — f-string into cursor.execute
cursor.execute(f"SELECT * FROM users WHERE email = '{email}'")
```

```javascript
// ❌ SQL injection — template literal
await client.query(`SELECT * FROM accounts WHERE id = ${id}`);
```

```python
# ❌ Command injection — shell=True with user input
subprocess.call(f"grep {pattern} log.txt", shell=True)
```

```javascript
// ❌ Command injection — exec with template literal
exec(`ls ${userInput}`);
```

```javascript
// ❌ XSS — raw innerHTML
element.innerHTML = userInput;
$('#div').html(userInput);
document.write(userInput);
```

```javascript
// ❌ Path traversal — input straight to fs
fs.readFile(req.query.filename, callback);
```

```python
# ❌ Insecure deserialization
import pickle, yaml
data = pickle.loads(request.body)
data = yaml.load(request.body)             # unsafe loader
data = yaml.unsafe_load(request.body)
```

```javascript
// ❌ eval and friends
eval(userInput);
new Function(userInput)();
setTimeout(userInput, 0);
```

```typescript
// ❌ TypeScript escape hatch used to silence a verification check
const validated = rawInput as any as User;       // bypasses runtime check
// @ts-ignore  -- on the line that validates the input
processUser(rawInput);
```

```javascript
// ❌ SSRF — fetch an arbitrary user-supplied URL
const res = await fetch(req.query.url);
```

```python
# ❌ Reflective instantiation from input
cls = globals()[request.json["class_name"]]
obj = cls()
```

## Remediation

### Centralized URL allowlist

```python
# ✅ Single safe_url() used by every outbound caller
ALLOWED_HOSTS = {"api.stripe.com", "api.github.com"}
# (see Rule 7 implementation above)

def call_stripe(path: str, payload: dict):
    url = safe_url(f"https://api.stripe.com{path}")
    return httpx.post(url, json=payload, timeout=10)
```

### Schema-validated deserialization

```python
# ✅ Parse, then validate against a schema before use
import json
from pydantic import BaseModel, EmailStr

class Signup(BaseModel):
    email: EmailStr
    plan: str

raw = json.loads(request.body)        # JSON, not pickle
signup = Signup.model_validate(raw)   # explicit typed validation
```

```typescript
// ✅ Zod-validated parse
import { z } from "zod";
const Signup = z.object({
  email: z.string().email(),
  plan: z.enum(["free", "pro"]),
});
const signup = Signup.parse(JSON.parse(req.body));
```

### Sanitized HTML where rich content is required

```javascript
// ✅ DOMPurify with a tight allowlist
import DOMPurify from "dompurify";
const ALLOWED = {
  ALLOWED_TAGS: ["p", "strong", "em", "ul", "ol", "li", "code", "pre", "a"],
  ALLOWED_ATTR: ["href"],
  ALLOWED_URI_REGEXP: /^https?:\/\//,
};
element.innerHTML = DOMPurify.sanitize(userMarkdownHtml, ALLOWED);
```

### Path validation reused across handlers

```python
# ✅ Reuse the same safe_open() from Rule 4 everywhere
@app.get("/uploads/{name}")
def get_upload(name: str):
    return FileResponse(safe_open(name).name)
```

### TypeScript runtime validation instead of `as any`

```typescript
// ✅ Replace cast with runtime parse
import { z } from "zod";
const User = z.object({ id: z.string(), tenantId: z.string() });
const user = User.parse(rawInput);     // throws on mismatch — never `as any`
```

### Dispatcher table replacing `eval`-like dispatch

```python
# ✅ Lookup table replacing dynamic class instantiation
HANDLERS = {
    "signup": handle_signup,
    "cancel": handle_cancel,
}

def dispatch(name: str, payload: dict):
    handler = HANDLERS.get(name)
    if handler is None:
        raise ValueError("unknown event")
    return handler(payload)
```

## Production detection heuristics

Treat the code context as production-class (escalating the
protocol) when **any** of these match:

- The file is on a path matching the production deployment of the
  service (the same heuristics `database-safety`,
  `cloud-cli-safety`, and `docker-safety` use).
- The function handles HTTP requests, message-queue messages,
  webhook deliveries, or any externally-reachable interface.
- The code path is part of an authentication, authorization,
  billing, or PII-handling flow (cross-references
  `pii-and-test-data` and `secrets-management`).
- The repository ships a library, SDK, or CLI other developers
  install.

If any signal matches, all seven rules apply without exception.
In particular, Rule 6 (no `eval`-class APIs on input) is enforced
even for "trusted" input — there is no trusted input on an
externally-reachable interface.

## References

- OWASP Top 10 (2021) — https://owasp.org/Top10/
- CWE-89 SQL Injection — https://cwe.mitre.org/data/definitions/89.html
- CWE-78 OS Command Injection — https://cwe.mitre.org/data/definitions/78.html
- CWE-79 Cross-site Scripting — https://cwe.mitre.org/data/definitions/79.html
- CWE-22 Path Traversal — https://cwe.mitre.org/data/definitions/22.html
- CWE-502 Insecure Deserialization — https://cwe.mitre.org/data/definitions/502.html
- CWE-918 SSRF — https://cwe.mitre.org/data/definitions/918.html
- OWASP Cheat Sheets — https://cheatsheetseries.owasp.org/
- Snyk Vulnerability DB — https://security.snyk.io/
