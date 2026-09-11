---
name: language-baseline
description: Block the language-agnostic classes of injection and arbitrary-code-execution failures — SQL via string concatenation, command injection via shell-true subprocess calls, XSS via `innerHTML`/`document.write`, path traversal via unvalidated filenames, insecure deserialization (`pickle`, unsafe `yaml.load`, PHP `unserialize`, Java `ObjectInputStream`, Ruby `Marshal`), dynamic code execution (`eval`, `Function`, `setTimeout(string)`), TypeScript `as any` escape hatches, and SSRF via unvalidated outbound URLs.
license: MIT
metadata:
  catpilot:
    id: language-baseline
    version: 1.0.1
    severity: high
    category: secure-coding
    applies_to:
      languages:
      - python
      - javascript
      - typescript
      - ruby
      - java
      - go
      - php
      - csharp
      - any
      frameworks:
      - any
      runtimes:
      - claude-code
      - cursor
      - openclaw
      - cline
      - aider
      - copilot
      - codex-cli
    control_mappings:
      soc2:
      - CC6.1
      - CC6.6
      - CC7.1
      - CC7.2
      pci_dss:
      - 6.2.4
      - 6.5.1
      - 6.5.4
      - 6.5.7
      iso_27001:
      - A.14.2.1
      - A.14.2.5
      - A.14.2.7
      - A.14.2.8
      nist_csf:
      - PR.IP-1
      - PR.IP-2
      - PR.IP-12
      - DE.CM-7
      owasp_top_10:
      - A01:2021
      - A03:2021
      - A05:2021
      - A06:2021
      - A08:2021
      - A10:2021
    provenance:
      origin: catpilot
      incident_derived: false
    maintainers:
    - team: catpilot-security
    references:
    - https://owasp.org/Top10/
    - https://cwe.mitre.org/data/definitions/89.html
    - https://cwe.mitre.org/data/definitions/78.html
    - https://cwe.mitre.org/data/definitions/79.html
    - https://cwe.mitre.org/data/definitions/22.html
    - https://cwe.mitre.org/data/definitions/502.html
    - https://cwe.mitre.org/data/definitions/918.html
---

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

1. For a single-file API, require a basename; reject directory components
   instead of silently stripping them.
2. Use a trusted, administrator-owned root and bound the bytes read.
3. Reject symlinks and non-regular files at open time. `path.resolve()`
   only normalizes text; it does not resolve filesystem symlinks.
4. Do not validate a path and later reopen it through a different API.

Use the tested POSIX examples in [safe_io.py](scripts/safe_io.py)
(`read_file_in_directory`) and [safe_files.cjs](scripts/safe_files.cjs)
(`safeRead`). The Python helper pins the directory descriptor; the Node
helper requires the root and its ancestors to remain administrator-owned
and unchanged. Neither is a general filesystem sandbox. They reject
unsupported platforms rather than silently dropping no-follow checks.
Use OS isolation for attacker-writable directory trees or arbitrary paths.

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
3. Resolve once and reject *any* non-public result, including IPv4-mapped
   IPv6, loopback, link-local, multicast, and shared-address space.
4. Connect to that validated numeric address, retaining TLS verification
   against the original hostname. Returning a "validated URL" to an HTTP
   library that resolves again does not prevent DNS rebinding.
5. Require HTTPS and an approved port. Disable redirects, or validate and
   pin every hop with the same policy. Bound response sizes and I/O timeouts.

See [safe_io.py](scripts/safe_io.py), `request_public_json`, for a tested
standard-library HTTPS GET example. It allows no caller credentials,
custom headers, redirects, or proxy environment settings. It is deliberately
not a general HTTP client: authenticated services should use an approved
SDK with controlled endpoints and network egress restrictions. Its socket
timeouts are not a total deadline (including DNS); enforce total deadlines
and rate limits at the service boundary.

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

Centralize destination policy in the client that makes the connection,
not a validator that merely returns a URL. Use the bundled HTTPS GET
helper only within its documented limits; keep secret-bearing requests
in an approved service-specific client.

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

Return the bounded bytes from `read_file_in_directory` through the
framework's byte-response API after checking the caller's authorization.
Do not use `FileResponse(handle.name)`: that reopens a path and discards
the protections on the original file descriptor. File-type, download
headers, and per-user access checks are separate requirements.

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
