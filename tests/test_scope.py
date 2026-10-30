"""Tests for core/scope.py: config/scope.txt parsing and authorization
confirm/interactive/reject paths."""

import pytest

from core.scope import AuthorizationError, authorize_targets, load_scope_hosts


def test_load_scope_hosts_parses_urls_bare_hosts_and_skips_comments(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("# comment\nhttps://example.com/path\ninternal.local\n\n")

    hosts = load_scope_hosts(str(scope_file))

    assert hosts == {"example.com", "internal.local"}


def test_load_scope_hosts_missing_file_returns_empty_set(tmp_path):
    hosts = load_scope_hosts(str(tmp_path / "missing.txt"))
    assert hosts == set()


def test_authorize_targets_host_already_in_scope_is_authorized(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("https://example.com\n")

    authorized = authorize_targets(["https://example.com/path"], scope_path=str(scope_file))

    assert authorized == {"example.com"}


def test_authorize_targets_confirm_flag_allows_out_of_scope_host(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("")

    authorized = authorize_targets(
        ["https://new.example"], scope_path=str(scope_file), confirm=True
    )

    assert "new.example" in authorized


def test_authorize_targets_raises_without_confirm_or_interactive(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("")

    with pytest.raises(AuthorizationError):
        authorize_targets(["https://new.example"], scope_path=str(scope_file))


def test_authorize_targets_interactive_accept(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("")
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    authorized = authorize_targets(
        ["https://new.example"], scope_path=str(scope_file), interactive=True
    )

    assert "new.example" in authorized


def test_authorize_targets_interactive_decline_raises(tmp_path, monkeypatch):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("")
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    with pytest.raises(AuthorizationError):
        authorize_targets(["https://new.example"], scope_path=str(scope_file), interactive=True)


def test_authorize_targets_interactive_eof_raises_authorization_error(tmp_path, monkeypatch):
    """Non-interactive stdin (e.g. closed/piped from /dev/null) must raise a
    clean AuthorizationError, not propagate a raw EOFError from input()."""
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("")

    def _raise_eof(prompt):
        raise EOFError

    monkeypatch.setattr("builtins.input", _raise_eof)

    with pytest.raises(AuthorizationError):
        authorize_targets(["https://new.example"], scope_path=str(scope_file), interactive=True)


def test_authorize_targets_mixes_in_scope_and_newly_confirmed_hosts(tmp_path):
    scope_file = tmp_path / "scope.txt"
    scope_file.write_text("https://known.example\n")

    authorized = authorize_targets(
        ["https://known.example", "https://new.example"],
        scope_path=str(scope_file),
        confirm=True,
    )

    assert authorized == {"known.example", "new.example"}
