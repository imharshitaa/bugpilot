"""Utility functions used across the scanner."""

import json
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests
from requests.exceptions import RequestException, Timeout
import yaml

from core.ssrf_guard import validate_url


class Utils:
    def __init__(self, settings_path="config/settings.yaml"):
        self.settings = self.load_yaml(settings_path)

        self.timeout = self.settings["http"]["timeout"]
        self.retries = self.settings["http"]["retries"]
        self.retry_sleep_seconds = self.settings["http"].get("retry_sleep_seconds", 1)
        self.follow_redirects = self.settings["http"]["follow_redirects"]
        self.max_redirects = int(self.settings["http"].get("max_redirects", 5))
        self.verify_tls = self.settings["http"].get("verify_tls", True)
        self.user_agent = self.settings["http"]["user_agent"]
        self.cache_enabled = self.settings["http"].get("cache_enabled", True)
        self._response_cache = {}

        self.block_private_targets = bool(
            self.settings.get("security", {}).get("block_private_targets", True)
        )
        self.authorized_hosts = set()

        self.auth_enabled = self.settings["auth"]["enabled"]
        self.auth_header = self.settings["auth"]["header"]

        self.verbose = self.settings["debug"]["verbose"]
        scanner_cfg = self.settings.get("scanner", {})
        self.runtime_log_max_per_module = int(
            scanner_cfg.get("runtime_log_max_per_module", 20)
        )
        self.active_module = None
        self.module_stats = {}
        self.request_event_callback = None
        self._request_log_counts = {}
        self._session = requests.Session()

    def load_yaml(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

    def set_authorized_hosts(self, hosts):
        """Hosts explicitly authorized via config/scope.txt or --authorize.

        Authorized hosts may resolve to private/loopback addresses (e.g. a
        local lab app) without being blocked by the SSRF guard.
        """
        self.authorized_hosts = set(hosts or [])

    def _validate_request_url(self, url):
        if not self.block_private_targets:
            return True, ""
        return validate_url(url, self.authorized_hosts)

    def _dispatch(self, url, method, payload, headers):
        if method == "GET":
            return self._session.get(
                url,
                headers=headers,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_tls,
            )
        if method == "POST":
            return self._session.post(
                url,
                headers=headers,
                data=payload,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_tls,
            )
        return None

    @staticmethod
    def _next_hop_method_and_payload(method, payload, status_code):
        # Mirrors browser/requests behavior: 301/302/303 after a POST
        # downgrade to a bodyless GET on the next hop; 307/308 preserve
        # method and body.
        if method == "POST" and status_code in (301, 302, 303):
            return "GET", None
        return method, payload

    def _send_with_redirects(self, url, method, payload, headers):
        """Dispatch the request, manually following redirects one hop at a
        time so each hop's destination can be re-validated against the SSRF
        guard before it is followed (requests' built-in allow_redirects=True
        does not re-check scope/SSRF rules on each hop)."""
        current_url = url
        current_method = method
        current_payload = payload
        history = []

        for hop in range(self.max_redirects + 1):
            response = self._dispatch(current_url, current_method, current_payload, headers)
            if response is None:
                return None

            if not self.follow_redirects or hop == self.max_redirects or not response.is_redirect:
                response.history = history
                return response

            location = response.headers.get("Location")
            if not location:
                response.history = history
                return response

            next_url = urljoin(current_url, location)
            allowed, reason = self._validate_request_url(next_url)
            if not allowed:
                self.log(f"Blocked redirect to {next_url}: {reason}")
                response.history = history
                return response

            history.append(response)
            current_method, current_payload = self._next_hop_method_and_payload(
                current_method, current_payload, response.status_code
            )
            current_url = next_url

        return response

    def http_request(self, url, method="GET", payload=None, extra_headers=None):
        headers = {"User-Agent": self.user_agent}

        if self.auth_enabled and self.auth_header:
            headers["Authorization"] = self.auth_header

        if extra_headers:
            headers.update(extra_headers)

        cache_key = None
        if self.cache_enabled and method == "GET":
            header_key = tuple(sorted(headers.items()))
            cache_key = (url, method, header_key)
            cached = self._response_cache.get(cache_key)
            if cached is not None:
                return cached

        allowed, reason = self._validate_request_url(url)
        if not allowed:
            self._record_blocked_stats()
            self.log(f"Blocked request to {url}: {reason}")
            self._emit_request_event(url, method, outcome="blocked")
            return None

        if method not in ("GET", "POST"):
            return None

        for attempt in range(max(self.retries, 1)):
            try:
                response = self._send_with_redirects(url, method, payload, headers)
                if response is None:
                    return None
                self._record_response_stats(response.status_code)
                self._emit_request_event(url, method, status_code=response.status_code)
                if cache_key:
                    self._response_cache[cache_key] = response
                return response
            except Timeout as exc:
                self._record_error_stats("timeout")
                if attempt == max(self.retries, 1) - 1:
                    self._emit_request_event(url, method, outcome="timeout")
                if self.verbose:
                    print(f"[!] Request timeout ({attempt + 1}/{self.retries}): {exc}")
                time.sleep(self.retry_sleep_seconds)
            except RequestException as exc:
                self._record_error_stats("request_error")
                if attempt == max(self.retries, 1) - 1:
                    self._emit_request_event(url, method, outcome="error")
                if self.verbose:
                    print(f"[!] Request error ({attempt + 1}/{self.retries}): {exc}")
                time.sleep(self.retry_sleep_seconds)
            except Exception as exc:
                self._record_error_stats("unknown_error")
                if attempt == max(self.retries, 1) - 1:
                    self._emit_request_event(url, method, outcome="error")
                if self.verbose:
                    print(f"[!] Request error ({attempt + 1}/{self.retries}): {exc}")
                time.sleep(self.retry_sleep_seconds)

        return None

    def set_active_module(self, module_name):
        self.active_module = module_name
        if module_name is None:
            return
        self._request_log_counts.setdefault(module_name, 0)
        self.module_stats.setdefault(
            module_name,
            {
                "requests": 0,
                "responses": 0,
                "blocked": 0,
                "timeouts": 0,
                "errors": 0,
                "server_errors": 0,
            },
        )

    def get_module_stats(self, module_name):
        return dict(self.module_stats.get(module_name, {}))

    def get_all_module_stats(self):
        return {name: dict(stats) for name, stats in self.module_stats.items()}

    def set_request_event_callback(self, callback):
        self.request_event_callback = callback

    def _record_response_stats(self, status_code):
        if not self.active_module:
            return
        stats = self.module_stats.setdefault(
            self.active_module,
            {"requests": 0, "responses": 0, "blocked": 0, "timeouts": 0, "errors": 0, "server_errors": 0},
        )
        stats["requests"] += 1
        stats["responses"] += 1
        if status_code in (401, 403, 406, 429):
            stats["blocked"] += 1
        if status_code >= 500:
            stats["server_errors"] += 1

    def _record_blocked_stats(self):
        if not self.active_module:
            return
        stats = self.module_stats.setdefault(
            self.active_module,
            {"requests": 0, "responses": 0, "blocked": 0, "timeouts": 0, "errors": 0, "server_errors": 0},
        )
        stats["requests"] += 1
        stats["blocked"] += 1

    def _record_error_stats(self, kind):
        if not self.active_module:
            return
        stats = self.module_stats.setdefault(
            self.active_module,
            {"requests": 0, "responses": 0, "blocked": 0, "timeouts": 0, "errors": 0, "server_errors": 0},
        )
        stats["requests"] += 1
        if kind == "timeout":
            stats["timeouts"] += 1
        else:
            stats["errors"] += 1

    def _emit_request_event(self, url, method, status_code=None, outcome="response"):
        if not self.request_event_callback or not self.active_module:
            return

        count = self._request_log_counts.get(self.active_module, 0)
        if count >= self.runtime_log_max_per_module:
            return

        self._request_log_counts[self.active_module] = count + 1
        blocked = status_code in (401, 403, 406, 429) if status_code is not None else False

        self.request_event_callback(
            {
                "module": self.active_module,
                "url": url,
                "method": method,
                "status_code": status_code,
                "outcome": outcome,
                "blocked": blocked,
            }
        )

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
