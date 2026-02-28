"""
utils.py
---------
Utility functions used across the scanner.
"""

import json
import time
from urllib.parse import urljoin

import requests
import yaml


class Utils:
    def __init__(self, settings_path="config/settings.yaml"):
        self.settings = self.load_yaml(settings_path)

        self.timeout = self.settings["http"]["timeout"]
        self.retries = self.settings["http"]["retries"]
        self.follow_redirects = self.settings["http"]["follow_redirects"]
        self.user_agent = self.settings["http"]["user_agent"]

        self.auth_enabled = self.settings["auth"]["enabled"]
        self.auth_header = self.settings["auth"]["header"]

        self.verbose = self.settings["debug"]["verbose"]

    def load_yaml(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def http_request(self, url, method="GET", payload=None):
        headers = {"User-Agent": self.user_agent}

        if self.auth_enabled and self.auth_header:
            headers["Authorization"] = self.auth_header

        for attempt in range(self.retries):
            try:
                if method == "GET":
                    return requests.get(
                        url,
                        headers=headers,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                    )

                if method == "POST":
                    return requests.post(
                        url,
                        headers=headers,
                        data=payload,
                        timeout=self.timeout,
                        allow_redirects=self.follow_redirects,
                    )

                return None
            except Exception as exc:
                if self.verbose:
                    print(f"[!] Request error ({attempt + 1}/{self.retries}): {exc}")
                time.sleep(1)

        return None

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
