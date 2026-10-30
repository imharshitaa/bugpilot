"""
scope.py
--------
Authorization/scope enforcement. config/scope.txt is treated as an explicit
allowlist of hosts the operator has confirmed they are authorized to test.
Any target host not already in that file must be confirmed either via the
--authorize flag (headless/CI) or an interactive y/n prompt -- never run
silently against an un-authorized host.
"""

import os
from urllib.parse import urlsplit


class AuthorizationError(Exception):
    """Raised when a target host is not authorized and cannot be confirmed."""


def _hostname(target):
    try:
        return urlsplit(target).hostname
    except ValueError:
        return None


def load_scope_hosts(path="config/scope.txt"):
    """Return the set of hostnames listed in the scope file."""
    hosts = set()
    if not os.path.exists(path):
        return hosts

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if not value or value.startswith("#"):
                continue
            host = _hostname(value) if value.startswith("http") else value
            if host:
                hosts.add(host)
    return hosts


def authorize_targets(targets, *, scope_path="config/scope.txt", confirm=False, interactive=False):
    """Return the set of authorized hostnames for `targets`.

    - Hosts already present in config/scope.txt are always authorized.
    - Hosts not in scope are authorized if `confirm=True` (e.g. --authorize
      passed in headless/CI mode).
    - Otherwise, if `interactive=True`, the operator is prompted y/n per host.
    - If a host is neither in scope, confirmed, nor accepted interactively,
      AuthorizationError is raised.
    """
    scope_hosts = load_scope_hosts(scope_path)
    authorized = set(scope_hosts)

    candidate_hosts = []
    for target in targets:
        host = _hostname(target)
        if host and host not in candidate_hosts:
            candidate_hosts.append(host)

    unauthorized = [host for host in candidate_hosts if host not in scope_hosts]

    for host in unauthorized:
        if confirm:
            authorized.add(host)
            continue

        if interactive:
            try:
                answer = input(
                    f"[?] '{host}' is not in config/scope.txt. "
                    f"Confirm you are authorized to test it (y/N): "
                ).strip().lower()
            except EOFError:
                raise AuthorizationError(
                    f"Host '{host}' is not authorized and no interactive input is "
                    f"available to confirm it. Add it to {scope_path} or pass --authorize."
                )
            if answer in ("y", "yes"):
                authorized.add(host)
                continue
            raise AuthorizationError(f"Authorization declined for host: {host}")

        raise AuthorizationError(
            f"Host '{host}' is not authorized. Add it to {scope_path}, pass "
            f"--authorize, or confirm interactively."
        )

    return authorized
