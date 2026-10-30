"""End-to-end integration test: real crawl + real scan against the bundled
local labapp (never an external target).

Note: the open_redirect check below causes a single lightweight GET to
https://example.org -- the IANA-reserved domain the open_redirect module
itself uses as its test payload (see modules/open_redirect.py), and the
same domain labapp's own homepage links to. This is not "scanning" an
external target; it is the real redirect hop that must be followed to
confirm our own app's redirect behavior, exactly mirroring production use
of this detector.
"""

from core.crawler import Crawler
from core.scanner import Scanner
from core.utils import Utils
from core.validator import Validator
from models.endpoint_class import Endpoint
from modules import csrf as csrf_module
from modules import idor as idor_module


def _authorized_utils():
    utils = Utils()
    utils.retry_sleep_seconds = 0
    utils.set_authorized_hosts({"127.0.0.1"})
    return utils


def _discover(utils, labapp_server):
    crawler = Crawler(utils)
    urls = crawler.crawl(labapp_server + "/")
    return urls, [Endpoint(url=u) for u in urls]


def test_full_scan_against_labapp_finds_expected_vulnerability_types(labapp_server):
    utils = _authorized_utils()
    _, endpoints = _discover(utils, labapp_server)

    scanner = Scanner(utils, Validator())
    findings = scanner.run_modules(endpoints, selected_modules=None)

    normalized_types = {f["normalized_type"] for f in findings}
    assert "misconfig" in normalized_types
    assert "xss" in normalized_types
    assert "cors_misconfig" in normalized_types
    assert "open_redirect" in normalized_types


def test_idor_and_csrf_fire_at_module_level_but_are_suppressed_by_default_confidence_gate(
    labapp_server,
):
    """idor (confidence 0.5) and csrf (confidence 0.55) are both below the
    default scanner.min_confidence (0.6) in config/settings.yaml, so they
    are real, working detectors but intentionally absent from a default
    Scanner.run_modules() report -- documented behavior, not a bug."""
    utils = _authorized_utils()
    urls, _ = _discover(utils, labapp_server)

    item_endpoints = [Endpoint(url=u) for u in urls if "/item" in u]
    login_endpoints = [Endpoint(url=u) for u in urls if "/login" in u]
    assert item_endpoints and login_endpoints

    idor_findings = idor_module.run(item_endpoints, utils, {})
    csrf_findings = csrf_module.run(login_endpoints, utils, {})

    assert idor_findings and idor_findings[0]["confidence"] < 0.6
    assert csrf_findings and csrf_findings[0]["confidence"] < 0.6

    scanner = Scanner(utils, Validator())
    assert scanner.min_confidence == 0.6
