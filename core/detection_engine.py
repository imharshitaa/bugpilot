"""Shared detection helpers to improve signal quality and reduce false positives."""

import html
from urllib.parse import parse_qsl, urlsplit

from models.false_positive import is_false_positive


class DetectionEngine:
    def __init__(self, utils):
        self.utils = utils
        scanner_cfg = self.utils.settings.get("scanner", {})
        self.fast_mode = bool(scanner_cfg.get("fast_mode", True))
        self.max_params_fast = int(scanner_cfg.get("max_params_per_test_fast", 2))
        self.max_params_full = int(scanner_cfg.get("max_params_per_test_full", 4))

    def query_params(self, url):
        split = urlsplit(url)
        return [key for key, _ in parse_qsl(split.query, keep_blank_values=True)]

    def candidate_params(self, url, preferred_params=None):
        preferred_params = preferred_params or []
        existing = self.query_params(url)
        merged = []
        for key in existing + preferred_params:
            if key and key not in merged:
                merged.append(key)
        return merged or ["id"]

    def build_test_urls(self, url, payload, preferred_params=None, max_params=None):
        if max_params is None:
            max_params = self.max_params_fast if self.fast_mode else self.max_params_full
        params = self.candidate_params(url, preferred_params)[: max(1, int(max_params))]
        return [self.utils.add_query_params(url, {param: payload}) for param in params]

    def has_new_indicator(self, baseline_text, test_text, indicators):
        baseline = str(baseline_text or "").lower()
        test = str(test_text or "").lower()
        for indicator in indicators:
            marker = str(indicator).lower()
            if marker in test and marker not in baseline:
                return True
        return False

    def reflected_unescaped(self, payload, test_text):
        text = str(test_text or "")
        payload = str(payload or "")
        if payload not in text:
            return False
        escaped = html.escape(payload, quote=True)
        return escaped not in text

    def likely_false_positive(self, evidence):
        return is_false_positive(str(evidence or ""))

    def status_or_body_changed(self, baseline_resp, test_resp, min_len_delta=25):
        if not baseline_resp or not test_resp:
            return False
        if baseline_resp.status_code != test_resp.status_code:
            return True
        return abs(len(baseline_resp.text) - len(test_resp.text)) >= min_len_delta
