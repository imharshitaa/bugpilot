"""Tests for Utils.http_request: SSRF gating, manual redirect re-validation,
retries, and response caching. All network I/O is mocked."""

from unittest.mock import MagicMock

from requests.exceptions import RequestException


def _authorize(utils, host="127.0.0.1"):
    utils.set_authorized_hosts({host})


def test_blocks_request_to_unauthorized_private_host(utils):
    result = utils.http_request("http://127.0.0.1:9/")
    assert result is None


def test_allows_request_to_authorized_host(utils, fake_response, monkeypatch):
    _authorize(utils)
    resp = fake_response(status_code=200, text="ok")
    monkeypatch.setattr(utils._session, "get", MagicMock(return_value=resp))

    result = utils.http_request("http://127.0.0.1:9/")

    assert result is resp
    assert result.history == []


def test_follows_redirect_and_builds_history(utils, fake_response, monkeypatch):
    _authorize(utils)
    hop1 = fake_response(status_code=302, headers={"Location": "/next"}, is_redirect=True)
    hop2 = fake_response(status_code=200, text="done")
    monkeypatch.setattr(utils._session, "get", MagicMock(side_effect=[hop1, hop2]))

    result = utils.http_request("http://127.0.0.1:9/start")

    assert result is hop2
    assert result.history == [hop1]


def test_blocks_redirect_to_unauthorized_host(utils, fake_response, monkeypatch):
    _authorize(utils, host="127.0.0.1")
    hop1 = fake_response(
        status_code=302,
        headers={"Location": "http://10.0.0.5/secret"},
        is_redirect=True,
    )
    monkeypatch.setattr(utils._session, "get", MagicMock(return_value=hop1))

    result = utils.http_request("http://127.0.0.1:9/start")

    assert result is hop1
    assert result.history == []


def test_stops_following_after_max_redirects(utils, fake_response, monkeypatch):
    _authorize(utils)
    utils.max_redirects = 1
    hop0 = fake_response(status_code=302, headers={"Location": "/a"}, is_redirect=True)
    hop1 = fake_response(status_code=302, headers={"Location": "/b"}, is_redirect=True)
    monkeypatch.setattr(utils._session, "get", MagicMock(side_effect=[hop0, hop1]))

    result = utils.http_request("http://127.0.0.1:9/start")

    assert result is hop1
    assert result.history == [hop0]


def test_no_location_header_returns_response_as_is(utils, fake_response, monkeypatch):
    _authorize(utils)
    resp = fake_response(status_code=302, headers={}, is_redirect=True)
    monkeypatch.setattr(utils._session, "get", MagicMock(return_value=resp))

    result = utils.http_request("http://127.0.0.1:9/start")

    assert result is resp
    assert result.history == []


def test_caches_get_responses(utils, fake_response, monkeypatch):
    _authorize(utils)
    resp = fake_response(status_code=200, text="cached")
    mock_get = MagicMock(return_value=resp)
    monkeypatch.setattr(utils._session, "get", mock_get)

    first = utils.http_request("http://127.0.0.1:9/same")
    second = utils.http_request("http://127.0.0.1:9/same")

    assert first is second
    assert mock_get.call_count == 1


def test_retries_then_succeeds(utils, fake_response, monkeypatch):
    _authorize(utils)
    utils.retries = 2
    good = fake_response(status_code=200, text="ok")
    monkeypatch.setattr(
        utils._session,
        "get",
        MagicMock(side_effect=[RequestException("boom"), good]),
    )

    result = utils.http_request("http://127.0.0.1:9/flaky")

    assert result is good


def test_returns_none_when_retries_exhausted(utils, monkeypatch):
    _authorize(utils)
    utils.retries = 2
    monkeypatch.setattr(
        utils._session,
        "get",
        MagicMock(side_effect=RequestException("boom")),
    )

    result = utils.http_request("http://127.0.0.1:9/down")

    assert result is None


def test_post_method_dispatches_via_session_post(utils, fake_response, monkeypatch):
    _authorize(utils)
    resp = fake_response(status_code=200, text="posted")
    monkeypatch.setattr(utils._session, "post", MagicMock(return_value=resp))

    result = utils.http_request("http://127.0.0.1:9/submit", method="POST", payload={"a": "1"})

    assert result is resp


def test_unsupported_method_returns_none(utils):
    _authorize(utils)
    result = utils.http_request("http://127.0.0.1:9/", method="DELETE")
    assert result is None
