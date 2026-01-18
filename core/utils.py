"""
utils.py
---------
Utility functions used across the scanner: helper functions
- HTTP requests handler
- Config loader
- Logging system
- Text extraction helpers
"""

import requests
import yaml
import json
import time
from urllib.parse import urljoin

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

    # ----------------------------- #
    # YAML Loader
    # ----------------------------- #

    def load_yaml(path):
        with open(path, "r") as f:
            return yaml.safe_load(f)

    # ----------------------------- #
    # HTTP Request Handler
    # ----------------------------- #
    def http_request(self, url, method="GET", payload=None):
        """
        Sends an HTTP request and returns the response.
        Built with retry logic.
        """

        headers = {"User-Agent": self.user_agent}

        if self.auth_enabled and self.auth_header:
            headers["Authorization"] = self.auth_header

        for attempt in range(self.retries):
            try:
                if method == "GET":
                    resp = requests.get(url, headers=headers, timeout=self.timeout, allow_redirects=self.follow_redirects)

                elif method == "POST":
                    resp = requests.post(url, headers=headers, data=payload, timeout=self.timeout, allow_redirects=self.follow_redirects)

                else:
                    return None

                return resp

            except Exception as e:
                if self.verbose:
                    print(f"[!] Request error ({attempt+1}/{self.retries}): {e}")
                time.sleep(1)

        return None

    # ----------------------------- #
    # Join URL helper
    # ----------------------------- #
    def join_url(self, base, path):
        try:
            return urljoin(base, path)
        except:
            return base

    # ----------------------------- #
    # JSON Writer for scanning data
    # ----------------------------- #
    def write_json(self, path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    # ----------------------------- #
    # Log Helper
    # ----------------------------- #
    def log(self, message):
        if self.verbose:
            print(f"[DEBUG] {message}")

def load_yaml(file_path):
    """
    Load a YAML configuration file and return its contents as a dictionary
    """
    try:
        with open(file_path, "r") as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"YAML file not found: {file_path}")
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML file: {e}")

