"""Tests for core/ssrf_guard.py: the single gate deciding whether a URL is
safe for the scanner to request."""

import socket

from core import ssrf_guard


def test_private_ip_literal_is_unsafe():
    unsafe, reason = ssrf_guard.is_unsafe_host("127.0.0.1")
    assert unsafe
    assert reason


def test_metadata_ip_literal_is_unsafe():
    unsafe, _ = ssrf_guard.is_unsafe_host("169.254.169.254")
    assert unsafe


def test_multicast_ip_literal_is_unsafe():
    unsafe, _ = ssrf_guard.is_unsafe_host("224.0.0.1")
    assert unsafe


def test_public_ip_literal_is_safe():
    unsafe, reason = ssrf_guard.is_unsafe_host("8.8.8.8")
    assert not unsafe
    assert reason == ""


def test_missing_hostname_is_unsafe():
    unsafe, _ = ssrf_guard.is_unsafe_host("")
    assert unsafe


def test_dns_resolution_failure_is_unsafe(monkeypatch):
    def _raise(*_args, **_kwargs):
        raise socket.gaierror("mocked failure")

    monkeypatch.setattr(socket, "getaddrinfo", _raise)
    unsafe, reason = ssrf_guard.is_unsafe_host("example.com")
    assert unsafe
    assert "DNS resolution failed" in reason


def test_hostname_resolving_to_private_ip_is_unsafe(monkeypatch):
    def _fake_getaddrinfo(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    unsafe, reason = ssrf_guard.is_unsafe_host("internal.example")
    assert unsafe
    assert "10.0.0.5" in reason


def test_hostname_resolving_to_public_ip_is_safe(monkeypatch):
    def _fake_getaddrinfo(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)
    unsafe, _ = ssrf_guard.is_unsafe_host("public.example")
    assert not unsafe


def test_validate_url_rejects_disallowed_scheme():
    allowed, reason = ssrf_guard.validate_url("ftp://127.0.0.1/", authorized_hosts=set())
    assert not allowed
    assert "scheme" in reason


def test_validate_url_rejects_unparseable_url():
    allowed, _ = ssrf_guard.validate_url("http://[::1", authorized_hosts=set())
    assert not allowed


def test_validate_url_rejects_missing_host():
    allowed, reason = ssrf_guard.validate_url("http:///path", authorized_hosts=set())
    assert not allowed
    assert "host" in reason


def test_validate_url_rejects_unauthorized_private_host():
    allowed, _ = ssrf_guard.validate_url("http://127.0.0.1:5000/", authorized_hosts=set())
    assert not allowed


def test_validate_url_allows_authorized_private_host():
    allowed, reason = ssrf_guard.validate_url("http://127.0.0.1:5000/", authorized_hosts={"127.0.0.1"})
    assert allowed
    assert reason == ""


def test_validate_url_authorized_host_still_blocked_when_override_disabled():
    allowed, _ = ssrf_guard.validate_url(
        "http://127.0.0.1:5000/",
        authorized_hosts={"127.0.0.1"},
        allow_private_for_authorized=False,
    )
    assert not allowed


def test_validate_url_allows_authorized_public_host():
    allowed, _ = ssrf_guard.validate_url("https://example.com/path", authorized_hosts={"example.com"})
    assert allowed
