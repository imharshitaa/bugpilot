"""Utility functions used across the scanner."""

import json
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
import yaml


class Utils:
    def __init__(self, settings_path="config/settings.yaml"):
        self.settings = self.load_yaml(settings_path)

        self.timeout = self.settings["http"]["timeout"]
        self.retries = self.settings["http"]["retries"]
        self.retry_sleep_seconds = self.settings["http"].get("retry_sleep_seconds", 1)
        self.follow_redirects = self.settings["http"]["follow_redirects"]
        self.verify_tls = self.settings["http"].get("verify_tls", True)
        self.user_agent = self.settings["http"]["user_agent"]

        self.auth_enabled = self.settings["auth"]["enabled"]
        self.auth_header = self.settings["auth"]["header"]

        self.verbose = self.settings["debug"]["verbose"]

    def load_yaml(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def http_request(self, url, method="GET", payload=None, extra_headers=None):
        headers = {"User-Agent": self.user_agent}

        if self.auth_enabled and self.auth_header:
            headers["Authorization"] = self.auth_header

        if extra_headers:
            headers.update(extra_headers)

        for attempt in range(max(self.retries, 1)):
            try:
                if method == "GET":
                    return requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                        verify=self.verify_tls,
                    )

                if method == "POST":
                    return requests.post(
                        url,
                        headers=headers,
                        data=payload,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                        verify=self.verify_tls,
                    )

                return None
            except Exception as exc:
                if self.verbose:
                    print(f"[!] Request error ({attempt + 1}/{self.retries}): {exc}")
                time.sleep(self.retry_sleep_seconds)

        return None

    def add_query_params(self, url, params):
        """Safely merge/overwrite query parameters into a URL."""
        split = urlsplit(url)
        existing = dict(parse_qsl(split.query, keep_blank_values=True))
        for key, value in params.items():
            existing[str(key)] = str(value)

        query = urlencode(existing, doseq=True)
        return urlunsplit((split.scheme, split.netloc, split.path, query, split.fragment))

    def join_url(self, base, path):
        try:
            return urljoin(base, path)
        except Exception:
            return base

    def write_json(self, path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def log(self, message):
        if self.verbose:
            print(f"[DEBUG] {message}")


def load_yaml(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except FileNotFoundError as exc:
        raise FileNotFoundError(f"YAML file not found: {file_path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"Error parsing YAML file: {exc}") from exc
