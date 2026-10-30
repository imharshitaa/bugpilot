"""
ssrf_guard.py
-------------
Blocks scanner-issued HTTP requests (including redirect hops) from reaching
private, loopback, link-local, or other non-public network destinations
unless the target host was explicitly authorized (see core/scope.py).

This is the single place that decides whether a URL is safe for the scanner
to request. It is intentionally conservative: anything it cannot resolve or
classify is treated as unsafe (fail closed).
"""

import ipaddress
import socket
from urllib.parse import urlsplit

ALLOWED_SCHEMES = {"http", "https"}


def _is_unsafe_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def is_unsafe_host(hostname):
    """Resolve hostname and check every address for private/internal ranges.

    Returns (unsafe: bool, reason: str).
    """
    if not hostname:
        return True, "missing host"

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        return True, f"DNS resolution failed: {exc}"

    resolved_ips = {info[4][0] for info in addr_infos}
    if not resolved_ips:
        return True, "no addresses resolved"

    for ip_str in resolved_ips:
        if _is_unsafe_ip(ip_str):
            return True, f"resolves to non-public address {ip_str}"

    return False, ""


def validate_url(url, authorized_hosts=None, *, allow_private_for_authorized=True):
    """Decide whether the scanner may request `url`.

    Returns (allowed: bool, reason: str). `authorized_hosts` is a set of
    hostnames that were explicitly confirmed in scope (via --authorize /
    config/scope.txt) -- those hosts may resolve to private/loopback
    addresses (e.g. a local lab app) without being blocked.
    """
    authorized_hosts = authorized_hosts or set()

    try:
        parsed = urlsplit(url)
    except ValueError:
        return False, "unparseable URL"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ALLOWED_SCHEMES:
        return False, f"disallowed scheme: {scheme or '(none)'}"

    hostname = parsed.hostname
    if not hostname:
        return False, "missing host"

    if hostname in authorized_hosts and allow_private_for_authorized:
        return True, ""

    unsafe, reason = is_unsafe_host(hostname)
    if unsafe:
        return False, reason

    return True, ""
