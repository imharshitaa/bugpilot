"""Tests for main.py's headless exit codes.

main.main() returns plain ints (0 clean, 2 for no-targets / authorization
failure / --fail-on-findings-with-findings) rather than calling sys.exit()
itself, so it can be called directly after monkeypatching sys.argv.

Scans run against either a closed local port (127.0.0.1:1 -- instant
connection-refused, never any real network I/O) or the bundled local
labapp fixture -- never an external target.
"""

import sys

import main as main_module
from core.reporter import Reporter
from core.utils import Utils


def _patch_reporter_output(monkeypatch, tmp_path):
    def fake_init(self, output_base=None):
        self.output_base = str(tmp_path)

    monkeypatch.setattr(Reporter, "__init__", fake_init)


def _disable_redirect_following(monkeypatch):
    """Prevents main()'s internal Utils() from auto-following redirects.

    labapp's homepage links to /go?redirect=https://example.org (to
    exercise the open_redirect detector); without this, ANY module that
    requests that discovered URL would follow the redirect and issue a
    real request to the external example.org domain. Tests that don't
    specifically need open_redirect detection disable following entirely
    to stay fully offline/local.
    """
    original_init = Utils.__init__

    def patched_init(self, settings_path="config/settings.yaml"):
        original_init(self, settings_path)
        self.follow_redirects = False

    monkeypatch.setattr(Utils, "__init__", patched_init)


def _patch_argv(monkeypatch, *args):
    monkeypatch.setattr(sys, "argv", ["main.py", *args])


def test_no_targets_returns_exit_code_2(monkeypatch, tmp_path):
    _patch_reporter_output(monkeypatch, tmp_path)
    monkeypatch.setattr(main_module, "load_scope", lambda path="config/scope.txt": [])
    _patch_argv(monkeypatch, "--headless", "--targets", "")

    assert main_module.main() == 2


def test_unauthorized_target_returns_exit_code_2(monkeypatch, tmp_path):
    _patch_reporter_output(monkeypatch, tmp_path)
    _patch_argv(monkeypatch, "--headless", "--targets", "http://127.0.0.1:1/")

    assert main_module.main() == 2


def test_authorized_clean_scan_against_unreachable_port_returns_0(monkeypatch, tmp_path):
    _patch_reporter_output(monkeypatch, tmp_path)
    monkeypatch.setattr("core.utils.time.sleep", lambda seconds: None)
    _patch_argv(
        monkeypatch,
        "--headless",
        "--authorize",
        "--targets",
        "http://127.0.0.1:1/",
        "--modules",
        "misconfig,xss,idor",
    )

    assert main_module.main() == 0


def test_fail_on_findings_returns_exit_code_2_when_labapp_has_findings(
    monkeypatch, tmp_path, labapp_server
):
    _patch_reporter_output(monkeypatch, tmp_path)
    _disable_redirect_following(monkeypatch)
    _patch_argv(
        monkeypatch,
        "--headless",
        "--authorize",
        "--fail-on-findings",
        "--targets",
        labapp_server + "/",
        "--modules",
        "misconfig,xss,cors_misconfig",
    )

    assert main_module.main() == 2
