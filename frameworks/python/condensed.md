# Python Security - Condensed Checklist

1.  **No `shell=True`**: Use `subprocess.run(["cmd", "arg"], shell=False)`. If shell is required, `shlex.quote()` inputs.
2.  **No `pickle`**: Use `json` or `pydantic` for serialization. Pickle allows RCE.
3.  **Path Validation**: Use `pathlib.Path.resolve().is_relative_to(base)` to prevent `..` traversal.
4.  **Network Timeouts**: Always set `timeout=10` (or similar) in `requests` calls. 
5.  **XML Security**: Use `defusedxml` instead of standard `xml` libraries.
6.  **Temp Files**: Use `tempfile.mkstemp()` instead of `/tmp/fixed_name`.
7.  **Secrets**: No hardcoded secrets. Use `os.getenv()`. Don't log sensitive variables.
