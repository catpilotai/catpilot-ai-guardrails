# Core Python Security Guardrails — Full Reference

> **Version:** 1.0.0 | **Condensed:** [condensed.md](./condensed.md)

This document provides security patterns for general Python development, focusing on scripts, automation, and data processing beyond specific web frameworks (Django/FastAPI).

---

## Table of Contents

1. [Command Injection (Subprocess)](#command-injection-subprocess)
2. [Insecure Deserialization (Pickle)](#insecure-deserialization-pickle)
3. [Path Traversal & File Operations](#path-traversal--file-operations)
4. [HTTP Requests & SSRF](#http-requests--ssrf)
5. [XML Parsing](#xml-parsing)
6. [Secrets & Logging](#secrets--logging)
7. [Insecure Temporary Files](#insecure-temporary-files)

---

## Command Injection (Subprocess)

### The Problem
Using `shell=True` in `subprocess` calls allows attackers to execute arbitrary system commands via shell metacharacters (e.g., `; rm -rf /`).

### ❌ Vulnerable Patterns
```python
import subprocess

filename = "user_input.txt; rm -rf /"
# The shell interprets the semicolon as a command separator
subprocess.run(f"ls -l {filename}", shell=True)

# os.system is always a shell execution
os.system(f"ls -l {filename}")
```

### ✅ Secure Patterns
Always use `shell=False` (default) and pass arguments as a list.

```python
import subprocess

filename = "user_input.txt; rm -rf /"
# Safe: "user_input.txt; rm -rf /" is treated as a single filename argument
subprocess.run(["ls", "-l", filename], check=True)
```

If you MUST use shell features (pipes, redirection), use `shlex.quote`:

```python
import subprocess
import shlex

cmd = f"ls -l {shlex.quote(filename)}"
subprocess.run(cmd, shell=True, check=True)
```

---

## Insecure Deserialization (Pickle)

### The Problem
The `pickle` module is not secure. Loading untrusted data can execute arbitrary code.

### ❌ Vulnerable Patterns
```python
import pickle

# Attacker provides a malicious payload
token = b"cos\nsystem\n(S'rm -rf /'\ntR."
user_obj = pickle.loads(token)  # Executes code immediately
```

### ✅ Secure Patterns
Use safer serialization formats like JSON.

```python
import json

# Safe serialization
data = json.loads(json_string)
```

For complex objects, use **Pydantic** for schema validation:

```python
from pydantic import BaseModel

class User(BaseModel):
    id: int
    name: string

user = User.model_validate_json(json_string)
```

---

## Path Traversal & File Operations

### The Problem
Allowing user input to construct file paths can allow access to unauthorized files (e.g., `../../etc/passwd`).

### ❌ Vulnerable Patterns
```python
filename = "../../etc/passwd"
with open(f"/var/www/uploads/{filename}", "r") as f:
    print(f.read())
```

### ✅ Secure Patterns
Use `pathlib` to resolve and verify paths.

```python
from pathlib import Path

base_dir = Path("/var/www/uploads").resolve()
user_path = (base_dir / filename).resolve()

if not user_path.is_relative_to(base_dir):
    raise ValueError("Path traversal attempt detected")

with open(user_path, "r") as f:
    print(f.read())
```

---

## HTTP Requests & SSRF

### The Problem
1.  **DoS**: Requests without timeouts can hang indefinitely.
2.  **SSRF**: Fetching internal URLs (e.g., AWS metadata `169.254.169.254`) via user input.

### ❌ Vulnerable Patterns
```python
import requests

# HANS indefinitely if server is slow
requests.get("https://example.com")

# SSRF Vulnerability
url = request.args.get("url")
requests.get(url)  # Can hit internal services
```

### ✅ Secure Patterns
Always set a timeout and validate schemas.

```python
import requests

# 1. Always set timeout
try:
    requests.get("https://example.com", timeout=10)
except requests.Timeout:
    print("Request timed out")

# 2. SSRF Prevention (Basic)
from urllib.parse import urlparse

def is_safe_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        return False
    # Add allow-list logic here (e.g., deny private IPs)
    return True
```

---

## XML Parsing

### The Problem
Standard XML libraries (`xml.etree`, `minidom`) are vulnerable to XML Bomb (DoS) and External Entity Injection (XXE).

### ❌ Vulnerable Patterns
```python
from xml.etree import ElementTree
tree = ElementTree.parse("malicious.xml")
```

### ✅ Secure Patterns
Use `defusedxml`.

```python
from defusedxml.ElementTree import parse
tree = parse("safe.xml")
```

---

## Secrets & Logging

### The Problem
Accidentally printing secrets to stdout/logs or hardcoding them.

### ❌ Vulnerable Patterns
```python
api_key = "sk-12345"  # Hardcoded
print(f"Connecting with {api_key}")  # Leaked in logs
```

### ✅ Secure Patterns

```python
import os
import logging

# 1. Use Environment Variables
api_key = os.getenv("API_KEY")
if not api_key:
    raise ValueError("API_KEY not set")

# 2. Mask secrets in logs
class SecretFilter(logging.Filter):
    def filter(self, record):
        record.msg = record.msg.replace(api_key, "***")
        return True

logger = logging.getLogger(__name__)
logger.addFilter(SecretFilter())
```

---

## Insecure Temporary Files

### The Problem
Using predictable filenames in `/tmp` creates race conditions.

### ❌ Vulnerable Patterns
```python
path = "/tmp/my_temp_file"
with open(path, "w") as f:
    f.write("data")
```

### ✅ Secure Patterns
Use `tempfile` module.

```python
import tempfile
import os

fd, path = tempfile.mkstemp()
try:
    with os.fdopen(fd, 'w') as f:
        f.write("data")
finally:
    os.remove(path)
```
