#!/usr/bin/env python3
"""In-harness gate for outbound URL fetches: block SSRF, internal IPs, and cloud metadata endpoints.

Scope, stated honestly:
  - Enforces outbound URL checks on the tool calls your harness routes through
    it. It cannot stop requests that do not pass through it or HTTP redirects
    followed after the gate unless your HTTP client disables redirects
    (`allow_redirects=False`).
  - Blocks non-HTTP(S) schemes, URLs with embedded credentials, cloud metadata
    hostnames (`169.254.169.254`, `metadata.google.internal`, `metadata.internal`,
    `100.100.100.200`), `localhost`, IP literals in private/loopback/link-local/
    reserved/multicast/unspecified ranges, and (when `resolve_dns=True`) any
    hostname that fails DNS resolution or resolves to a non-public IP address.
  - Optionally enforces an explicit hostname allowlist (`allowed_hosts`).
  - Returns a plain-language reason string on a blocked URL, or `None` when no
    rule matched. Never returns "allow". Fails closed on non-string input.

Standard library only. Python 3.8+.
"""
from __future__ import annotations

import ipaddress
import socket
import sys
from urllib.parse import urlparse

METADATA_HOSTS = {
    "169.254.169.254",
    "fd00:ec2::254",
    "metadata.google.internal",
    "metadata.internal",
    "metadata",
    "100.100.100.200",
    "localhost",
    "localhost.localdomain",
}


def _is_nonpublic_ip(ip_str: str) -> str | None:
    """Return a category label if ip_str is a non-public IP address, or None if public."""
    clean = ip_str.split("%", 1)[0]
    addr = ipaddress.ip_address(clean)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if str(addr) == "169.254.169.254" or str(addr) == "100.100.100.200":
        return "cloud metadata address"
    if addr.is_loopback:
        return "loopback address"
    if addr.is_link_local:
        return "link-local address"
    if addr.is_private:
        return "private network address"
    if addr.is_multicast:
        return "multicast address"
    if addr.is_unspecified:
        return "unspecified address"
    if addr.is_reserved:
        return "reserved address"
    if not addr.is_global:
        return "non-global address"
    return None


def gate_url_fetch(
    url: str,
    *,
    allowed_hosts: set[str] | list[str] | tuple[str, ...] | None = None,
    resolve_dns: bool = True,
) -> str | None:
    """Return a deny reason if `url` is unsafe for an agent tool to fetch, else None.

    Raises ValueError if `url` is not a string (fail-closed).
    """
    if not isinstance(url, str):
        raise ValueError("url must be a string")
    raw = url.strip()
    if not raw:
        return "Blocked URL fetch: URL is empty."
    try:
        parsed = urlparse(raw)
    except ValueError:
        return "Blocked URL fetch: malformed URL."

    if parsed.scheme.lower() not in ("http", "https"):
        return (
            f"Blocked URL fetch: scheme {parsed.scheme or '<missing>'!r} is not permitted; "
            "only 'http' and 'https' are allowed."
        )
    if parsed.username is not None or parsed.password is not None:
        return "Blocked URL fetch: URLs with embedded credentials (user:password@host) are not permitted."

    host = (parsed.hostname or "").strip().rstrip(".").lower()
    if not host:
        return "Blocked URL fetch: URL is missing a hostname."

    if host in METADATA_HOSTS or host.endswith(".internal") or host.endswith(".local"):
        return (
            f"Blocked URL fetch: host {host!r} is a local or cloud-metadata endpoint. "
            "Agents must not query internal or metadata services."
        )

    if allowed_hosts is not None:
        normalized_allow = {h.strip().rstrip(".").lower() for h in allowed_hosts if isinstance(h, str) and h.strip()}
        if host not in normalized_allow:
            return f"Blocked URL fetch: host {host!r} is not in the allowed_hosts list."

    # Check if host is directly an IP literal
    try:
        ipaddress.ip_address(host.split("%", 1)[0])
        is_ip_literal = True
    except ValueError:
        is_ip_literal = False

    if is_ip_literal:
        reason = _is_nonpublic_ip(host)
        if reason is not None:
            return f"Blocked URL fetch: host {host!r} is a {reason}."
        return None

    if resolve_dns:
        try:
            infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme.lower() == "https" else 80), proto=socket.IPPROTO_TCP)
        except OSError:
            return f"Blocked URL fetch: could not resolve hostname {host!r} (failing closed)."
        if not infos:
            return f"Blocked URL fetch: hostname {host!r} returned no addresses (failing closed)."
        for info in infos:
            sockaddr = info[4]
            if not sockaddr:
                continue
            resolved_ip = sockaddr[0]
            try:
                reason = _is_nonpublic_ip(resolved_ip)
            except ValueError:
                return f"Blocked URL fetch: hostname {host!r} resolved to unparseable address (failing closed)."
            if reason is not None:
                return f"Blocked URL fetch: hostname {host!r} resolves to a {reason} ({resolved_ip})."

    return None


def gate_url_tool_call(
    tool_name: str,
    tool_input: dict,
    field: str = "url",
    *,
    allowed_hosts: set[str] | list[str] | tuple[str, ...] | None = None,
    resolve_dns: bool = True,
) -> str | None:
    """Gate a tool call dictionary by checking `tool_input[field]` with `gate_url_fetch`."""
    if not isinstance(tool_input, dict):
        return f"Blocked {tool_name}: tool_input must be an object."
    value = tool_input.get(field)
    if not isinstance(value, str) or not value.strip():
        return f"Blocked {tool_name}: required string field {field!r} is missing or empty."
    return gate_url_fetch(value, allowed_hosts=allowed_hosts, resolve_dns=resolve_dns)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python hooks/harness/network_gate.py '<url>'", file=sys.stderr)
        sys.exit(2)
    verdict = gate_url_fetch(sys.argv[1])
    if verdict:
        print(verdict)
        sys.exit(1)
