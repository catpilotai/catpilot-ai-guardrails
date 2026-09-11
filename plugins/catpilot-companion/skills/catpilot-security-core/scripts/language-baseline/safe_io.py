"""Bounded examples, not a general HTTP client or filesystem sandbox.

HTTPS GET only; exact trusted host allowlist; public destinations; no redirects,
credentials, or custom headers. TLS verifies the original hostname while the
connection uses the validated numeric address. Directory reads require a trusted,
non-attacker-writable root on POSIX. These helpers perform no work on import.
"""

import http.client
from ipaddress import ip_address
import json
import math
import os
import socket
import ssl
import stat
from urllib.parse import urlsplit


def resolve_public_https(url, allowed_hosts):
    if not isinstance(allowed_hosts, (set, frozenset, list, tuple)) or not allowed_hosts or not all(isinstance(h, str) and h and h == h.lower() for h in allowed_hosts):
        raise ValueError("explicit nonempty collection of lowercase allowed hosts required")
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
        raise ValueError("invalid URL")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("HTTPS without credentials or fragments required")
    if parsed.port not in (None, 443) or not parsed.hostname or '%' in parsed.hostname or parsed.hostname not in allowed_hosts:
        raise ValueError("unapproved host or port")
    addresses = []
    for _, _, _, _, address in socket.getaddrinfo(parsed.hostname, 443, type=socket.SOCK_STREAM):
        ip = ip_address(address[0].split('%', 1)[0])
        mapped = getattr(ip, 'ipv4_mapped', None)
        if mapped is not None:
            ip = mapped
        if not ip.is_global or ip.is_multicast or ip.is_unspecified:
            raise ValueError("non-public destination")
        addresses.append(str(ip))
    if not addresses:
        raise ValueError("no destination")
    return parsed.hostname, addresses[0], (parsed.path or '/') + ('?' + parsed.query if parsed.query else '')


def request_public_json(url, allowed_hosts, *, timeout=10, max_bytes=65536):
    """Fetch one small HTTPS JSON response; every failure is explicit."""
    if not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or not 0 < timeout <= 30:
        raise ValueError("timeout must be in (0, 30]")
    if type(max_bytes) is not int or not 0 < max_bytes <= 1_048_576:
        raise ValueError("invalid response limit")
    host, address, target = resolve_public_https(url, allowed_hosts)
    context = ssl.create_default_context()
    connection = http.client.HTTPSConnection(host, port=443, timeout=timeout, context=context)
    raw = socket.create_connection((address, 443), timeout=timeout)
    try:
        connection.sock = context.wrap_socket(raw, server_hostname=host)
        connection.request('GET', target, headers={'Accept': 'application/json'})
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError("non-success response; redirects are not followed")
        body = response.read(max_bytes + 1)
        if len(body) > max_bytes:
            raise ValueError("response too large")
        return json.loads(body)
    finally:
        connection.close()
        raw.close()


def read_file_in_directory(directory, filename, *, max_bytes=65536):
    """Read a basename via a pinned directory fd; reject symlinks and specials."""
    if not isinstance(filename, str) or not filename or filename in ('.', '..') or any(c in filename for c in ('/', '\\', '\x00')):
        raise ValueError("a single basename is required")
    if type(max_bytes) is not int or not 0 < max_bytes <= 1_048_576:
        raise ValueError("invalid file limit")
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise NotImplementedError("requires POSIX no-follow and directory-fd support")
    root = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        with os.fdopen(fd, 'rb') as source:
            if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
                raise ValueError("not a regular file")
            body = source.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise ValueError("file too large")
            return body
    finally:
        os.close(root)
