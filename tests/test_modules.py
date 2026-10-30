"""Table-driven-ish tests for individual detection modules.

Each test monkeypatches `utils.http_request` directly rather than mocking
the underlying `requests.Session`, since these are unit tests of module
*logic* (not of the HTTP/SSRF layer, which is covered in
test_utils_http.py / test_ssrf_guard.py). Minimal, hand-built
`payload_rules` dicts are used instead of the full production
config/payload_rules.yaml so finding counts stay deterministic -- the
production file has many payloads per type, and modules only `break` their
innermost per-payload loop, so passing it directly would make exact
`len(findings)` assertions depend on YAML content rather than module logic.
"""

from modules import csrf, idor, misconfig, open_redirect, xss


def test_xss_detects_unescaped_reflection(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/search")
    payload = "<xss_test>"
    payload_rules = {"xss": {"payloads": [payload]}}

    def fake_http_request(url, **kwargs):
        if url == ep.url:
            return _resp(200, "no reflection here")
        return _resp(200, f"<p>Search results for: {payload}</p>")

    monkeypatch.setattr(utils, "http_request", fake_http_request)

    findings = xss.run([ep], utils, payload_rules)

    assert len(findings) == 1
    assert findings[0]["type"] == "xss"
    assert findings[0]["payload"] == payload


def test_xss_no_finding_when_payload_absent_from_baseline_too(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/search")
    payload = "<xss_test>"
    payload_rules = {"xss": {"payloads": [payload]}}

    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(200, "static page, no reflection"))

    findings = xss.run([ep], utils, payload_rules)

    assert findings == []


def test_xss_no_finding_when_payload_html_escaped(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/search")
    payload = "<xss_test>"
    payload_rules = {"xss": {"payloads": [payload]}}

    def fake_http_request(url, **kwargs):
        if url == ep.url:
            return _resp(200, "baseline")
        return _resp(200, "<p>Search results for: &lt;xss_test&gt;</p>")

    monkeypatch.setattr(utils, "http_request", fake_http_request)

    findings = xss.run([ep], utils, payload_rules)

    assert findings == []


def test_idor_detects_differing_response_for_incremented_id(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/item?id=5")
    payload_rules = {}

    def fake_http_request(url, **kwargs):
        if url == ep.url:
            return _resp(200, "Item 5: Blue Widget")
        return _resp(200, "Item 6: Red Widget")

    monkeypatch.setattr(utils, "http_request", fake_http_request)

    findings = idor.run([ep], utils, payload_rules)

    assert len(findings) == 1
    assert findings[0]["type"] == "idor"
    assert "5" in findings[0]["payload"] and "6" in findings[0]["payload"]


def test_idor_no_finding_when_baseline_not_200(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/item?id=5")
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(403, "forbidden"))

    findings = idor.run([ep], utils, {})

    assert findings == []


def test_idor_no_finding_when_response_identical(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/item?id=5")
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(200, "same body"))

    findings = idor.run([ep], utils, {})

    assert findings == []


def test_idor_never_mutates_host_or_port(utils, make_endpoint):
    ep = make_endpoint("http://127.0.0.1:8080/item?id=5")
    test_url, original_id, test_id = idor._build_test_url(ep.url)

    assert test_url.startswith("http://127.0.0.1:8080/")
    assert original_id == "5"
    assert test_id == "6"


def test_csrf_flags_post_form_without_recognized_token(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/login")
    body = (
        '<form method="post" action="/login">'
        '<input type="text" name="username">'
        '<input type="password" name="password">'
        "</form>"
    )
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(200, body))

    findings = csrf.run([ep], utils, {})

    assert len(findings) == 1
    assert findings[0]["type"] == "csrf"


def test_csrf_no_finding_when_broadened_token_field_present(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/login")
    body = (
        '<form method="post" action="/login">'
        '<input type="hidden" name="authenticity_token" value="abc">'
        '<input type="text" name="username">'
        "</form>"
    )
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(200, body))

    findings = csrf.run([ep], utils, {})

    assert findings == []


def test_csrf_no_finding_for_get_form(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/search")
    body = '<form method="get" action="/search"><input type="text" name="q"></form>'
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(200, body))

    findings = csrf.run([ep], utils, {})

    assert findings == []


def test_open_redirect_detects_redirect_to_attacker_domain(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/go")
    resp = _resp(200, "", url="https://example.org/")
    resp.history = [_resp(302, "", url=ep.url)]
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: resp)

    findings = open_redirect.run([ep], utils, {})

    assert len(findings) == 1
    assert findings[0]["type"] == "open_redirect"


def test_open_redirect_no_finding_without_redirect_history(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/go")
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(200, "no redirect"))

    findings = open_redirect.run([ep], utils, {})

    assert findings == []


def test_misconfig_flags_each_missing_header(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/")
    payload_rules = {
        "misconfig": {"headers_to_check": ["X-Frame-Options", "Content-Security-Policy"]}
    }
    monkeypatch.setattr(
        utils, "http_request", lambda url, **kw: _resp(200, "ok", headers={"X-Frame-Options": "DENY"})
    )

    findings = misconfig.run([ep], utils, payload_rules)

    assert len(findings) == 1
    assert "Content-Security-Policy" in findings[0]["evidence"]


def test_misconfig_skips_error_responses(utils, make_endpoint, monkeypatch):
    ep = make_endpoint("http://test.local/")
    payload_rules = {"misconfig": {"headers_to_check": ["X-Frame-Options"]}}
    monkeypatch.setattr(utils, "http_request", lambda url, **kw: _resp(404, "not found"))

    findings = misconfig.run([ep], utils, payload_rules)

    assert findings == []


def _resp(status_code, text, headers=None, url="http://test.local/"):
    from tests.conftest import FakeResponse

    return FakeResponse(status_code=status_code, headers=headers, text=text, url=url)
