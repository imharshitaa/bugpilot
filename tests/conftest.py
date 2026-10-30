"""Shared fixtures for the BugPilot test suite."""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


@pytest.fixture(autouse=True)
def _repo_root_cwd(monkeypatch):
    """All relative config paths (config/settings.yaml, etc.) assume cwd is
    the repo root, regardless of where `pytest` was invoked from."""
    monkeypatch.chdir(ROOT)


@pytest.fixture
def utils():
    from core.utils import Utils

    u = Utils()
    u.retry_sleep_seconds = 0
    return u


@pytest.fixture
def make_endpoint():
    from models.endpoint_class import Endpoint

    def _make(url, method="GET", params=None):
        return Endpoint(url, method=method, params=params)

    return _make


class FakeResponse:
    """Minimal stand-in for requests.Response used to mock HTTP calls."""

    def __init__(self, status_code=200, headers=None, text="", url="http://test.local/", is_redirect=False):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.url = url
        self.is_redirect = is_redirect
        self.history = []


@pytest.fixture
def fake_response():
    return FakeResponse


@pytest.fixture(scope="session")
def labapp_server():
    from labapp.app import run_in_thread

    server, thread, base_url = run_in_thread()
    yield base_url
    server.shutdown()
    thread.join(timeout=5)
