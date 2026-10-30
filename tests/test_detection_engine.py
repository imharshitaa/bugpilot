"""Tests for core/detection_engine.py: the shared signal-quality helpers
used by multiple modules to reduce false positives."""

from core.detection_engine import DetectionEngine


def test_candidate_params_merges_existing_and_preferred_dedup(utils):
    engine = DetectionEngine(utils)
    params = engine.candidate_params("http://test.local/?id=1&q=2", preferred_params=["id", "extra"])
    assert params == ["id", "q", "extra"]


def test_candidate_params_defaults_to_id_when_none_found(utils):
    engine = DetectionEngine(utils)
    params = engine.candidate_params("http://test.local/")
    assert params == ["id"]


def test_build_test_urls_caps_at_max_params_fast(utils):
    engine = DetectionEngine(utils)
    engine.fast_mode = True
    engine.max_params_fast = 2
    urls = engine.build_test_urls("http://test.local/?a=1&b=2&c=3", "PAYLOAD")
    assert len(urls) == 2
    assert all("PAYLOAD" in u for u in urls)


def test_build_test_urls_respects_explicit_max_params_override(utils):
    engine = DetectionEngine(utils)
    urls = engine.build_test_urls("http://test.local/?a=1&b=2&c=3", "PAYLOAD", max_params=1)
    assert len(urls) == 1


def test_has_new_indicator_true_when_marker_only_in_test(utils):
    engine = DetectionEngine(utils)
    assert engine.has_new_indicator("baseline text", "test has ERROR marker", ["error"])


def test_has_new_indicator_false_when_marker_in_baseline_too(utils):
    engine = DetectionEngine(utils)
    assert not engine.has_new_indicator("baseline has error", "test has error", ["error"])


def test_has_new_indicator_false_when_marker_absent(utils):
    engine = DetectionEngine(utils)
    assert not engine.has_new_indicator("baseline", "test", ["error"])


def test_reflected_unescaped_true_for_raw_payload(utils):
    engine = DetectionEngine(utils)
    assert engine.reflected_unescaped("<script>", "<p><script></p>")


def test_reflected_unescaped_false_when_html_escaped(utils):
    engine = DetectionEngine(utils)
    assert not engine.reflected_unescaped("<script>", "<p>&lt;script&gt;</p>")


def test_reflected_unescaped_false_when_payload_absent(utils):
    engine = DetectionEngine(utils)
    assert not engine.reflected_unescaped("<script>", "<p>no payload here</p>")


def test_likely_false_positive_delegates_to_model(utils):
    engine = DetectionEngine(utils)
    assert engine.likely_false_positive("404 page not found")
    assert not engine.likely_false_positive("real evidence of a bug")


def test_status_or_body_changed_true_on_status_diff(utils, fake_response):
    engine = DetectionEngine(utils)
    baseline = fake_response(status_code=200, text="same length body")
    test = fake_response(status_code=500, text="same length bodX")
    assert engine.status_or_body_changed(baseline, test)


def test_status_or_body_changed_true_on_large_length_delta(utils, fake_response):
    engine = DetectionEngine(utils)
    baseline = fake_response(status_code=200, text="short")
    test = fake_response(status_code=200, text="x" * 100)
    assert engine.status_or_body_changed(baseline, test, min_len_delta=25)


def test_status_or_body_changed_false_when_similar(utils, fake_response):
    engine = DetectionEngine(utils)
    baseline = fake_response(status_code=200, text="hello world")
    test = fake_response(status_code=200, text="hello worlD")
    assert not engine.status_or_body_changed(baseline, test, min_len_delta=25)


def test_status_or_body_changed_false_when_either_response_missing(utils, fake_response):
    engine = DetectionEngine(utils)
    baseline = fake_response(status_code=200, text="hello")
    assert not engine.status_or_body_changed(baseline, None)
    assert not engine.status_or_body_changed(None, baseline)
