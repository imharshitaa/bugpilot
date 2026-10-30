# BugPilot Technical Blueprint

## 1) System Intent

BugPilot is a command-orchestrated application-security testing framework designed to:
- enforce explicit authorization/scope before any request is sent,
- guard against SSRF (including via redirects) for any non-authorized target,
- run a reproducible recon -> crawl -> module-dispatch -> risk-score -> report pipeline,
- support an extensible plugin/module system,
- produce machine- and human-consumable artifacts (Markdown, JSON, SARIF),
- integrate into CI/CD as a real, verifiable security gate.

## 2) End-to-End Execution Flow

1. User invokes CLI command (`bugpilot scan|crawl|recon|test|exploit`).
2. `core/scope.py`'s `authorize_targets()` checks each target host against `config/scope.txt`;
   unauthorized hosts require `--authorize` (headless) or an interactive y/n confirmation, else
   `AuthorizationError` aborts before any request is made.
3. `Utils.set_authorized_hosts()` stores the authorized set; every subsequent
   `Utils.http_request()` call (and every redirect hop it follows) is revalidated through
   `core/ssrf_guard.py` against that set.
4. `core/recon.py` and `core/crawler.py` establish target context and endpoint inventory.
5. `core/scanner.py` dispatches enabled modules (via `core/plugin_manager.py`) against discovered
   endpoints, filters findings below `min_confidence`, enriches them with risk scores
   (`core/risk_scorer.py`) and deduplicates (`core/validator.py`).
6. `core/reporter.py` writes run artifacts to a versioned output directory.
7. Optional differential (`core/diff_scan.py`) and replay logic compare or reproduce prior runs.

## 3) Folder and File Significance

### Root runtime entry points
- `bugpilot_cli.py`: CLI command routing, export handling, and the `-authorize`/`--authorize`
  flag for `recon`/`crawl` (which run in-process); `scan`/`test`/`exploit` shell out to `main.py`.
- `main.py`: orchestration entry for interactive/headless execution; owns the `--headless`,
  `--authorize`, `--targets`, `--modules`, `--formats`, `--fail-on-findings`, and related flags.
- `pyproject.toml`: package metadata, console script registration, and the `test`/`demo` optional
  dependency groups (`pip install -e .[test,demo]`).
- `requirements.txt`: secondary/legacy dependency list, kept in sync with `pyproject.toml`.

### Core engine (`core/`)
- `core/scope.py`: scope-file parsing and `authorize_targets()`/`AuthorizationError`.
- `core/ssrf_guard.py`: hostname resolution and private/loopback/link-local/metadata/
  multicast/reserved IP rejection for non-authorized hosts.
- `core/utils.py`: the single HTTP chokepoint (`Utils.http_request()`) — SSRF validation, manual
  bounded redirect-following with per-hop revalidation, retries, response caching.
- `core/workflow.py`: interactive prompt flow for collecting scan intent/test case selection.
- `core/scanner.py`: scan loop, module dispatch, confidence gating.
- `core/crawler.py`: URL endpoint discovery and crawl constraints.
- `core/recon.py`: target header/intelligence collection.
- `core/plugin_manager.py`: built-in/external plugin loading and execution contract.
- `core/detection_engine.py`: shared finding-detection heuristics (reflected-value checks,
  response-diffing, false-positive delegation).
- `core/risk_scorer.py`: risk score/rating derivation (severity + confidence + evidence length +
  sensitive-endpoint keyword boost).
- `core/validator.py`: finding deduplication and evidence trimming.
- `core/diff_scan.py`: baseline-vs-current finding comparison.
- `core/reporter.py`: markdown/json/sarif artifact generation.
- `core/lab_validator.py`: guidance text for manually reproducing a finding in a controlled lab.

### Test modules (`modules/`)
- One file per vulnerability category; each `run(endpoints, utils, payload_rules)` returns a list
  of finding dicts. Every module sets its own `confidence` based on how certain its detection
  method is — see README.md's "Detection confidence" table for which modules are heuristic-only
  and therefore filtered out by the default `min_confidence`.
- Module enablement/metadata is controlled via `config/modules.yaml`.

### Models (`models/`)
- `models/endpoint_class.py`: the `Endpoint` data contract passed between crawler/scanner/modules.
- `models/false_positive.py`: shared `is_false_positive()` heuristic used by several modules to
  filter weak evidence before reporting.

### Configuration (`config/`)
- `settings.yaml`: scanner profile (`min_confidence`, `max_redirects`, timeouts, retries, caching).
- `scope.txt`: pre-authorized target allowlist (real allowlist, enforced by `core/scope.py`).
- `modules.yaml`: built-in module registry.
- `plugins.yaml`: external plugin registry.
- `test_cases.yaml`: higher-level test category map.
- `payload_rules.yaml`: payload selection and detection hints.

### Reporting (`reports/`)
- Persisted run outputs under timestamped directories: markdown narrative plus
  machine-readable JSON/SARIF for automation.

### Bundled lab app (`labapp/`)
- A small Flask app with intentional, well-understood vulnerabilities, used by the test suite and
  CI as a real, local, safe scan target. Run standalone with `python -m labapp.app [port]`.

### Tests (`tests/`)
- Full pytest suite: SSRF guard, scope/authorization, HTTP/redirect handling, each module, risk
  scoring, deduplication, diff scanning, plugin loading, reporting, CLI exit codes, and a real
  end-to-end scan against `labapp`.

### Demo and deployment files
- `demo/index.html`: terminal-style demo UI with a persistent banner stating that, without a
  configured backend, every command is a scripted simulation and makes no real network requests.
- `demo/terminal-config.json`: demo terminal backend config (optional `backend_ws_url`).
- `.github/workflows/ci.yml`: installs the project, runs `pytest`, then runs a real authorized
  headless scan against `labapp` with `--fail-on-findings`, and uploads `findings.json`/
  `results.sarif` as artifacts.
- `.github/workflows/pages.yml`: GitHub Pages deployment for the demo page.
- `backend/server.py`: optional WebSocket bridge for the demo page's live mode.

## 4) Command Semantics

- `scan`: full module run with markdown/json/sarif output.
- `crawl`: endpoint/API surface mapping.
- `recon`: target header/metadata collection.
- `test`: same module run as `scan`, with `--validate-findings none`.
- `exploit`: same module run as `scan`, json-only output, `--validate-findings all`.
- `expoit`: alias for `exploit`.

Export semantics:
- `-export` writes JSON output to a default `reports/output/` path.
- `-export <path>` writes JSON output to an explicit path.

## 5) Data Contracts (Findings)

A finding dict includes:
- `type`, `normalized_type`, `module`
- `severity`, `confidence`
- `endpoint`, `payload`, `evidence`
- `risk_score`, `risk_rating`, `risk`, `mitigation`, `references`
- `vulnerability_point`, `target_response` (status/content-type/server/length snapshot)
- `lab_validation` (guidance text for manual reproduction)

## 6) Quality and False-Positive Controls

- `min_confidence` gating in `config/settings.yaml` (default `0.6`) — genuinely filters output,
  since every module now sets a calibrated `confidence` value. See README.md for the full table.
- Several modules additionally filter through `models/false_positive.py` before reporting.
- Differential scan support (`core/diff_scan.py`) against a baseline `findings.json` for
  regression visibility.
- Replayable sessions (`--replay-session`) for reproducibility.
- No module reports a finding from a keyword/string match alone — detection requires an observed
  behavioral difference (reflection, status/body diff, redirect target, missing header, etc.).

## 7) CI/CD

`.github/workflows/ci.yml` (the only workflow besides `pages.yml`):
1. `pip install -e .[test,demo]`
2. `pytest -q`
3. Start `labapp` locally on an ephemeral/fixed port.
4. Run a real authorized headless scan against it with `--fail-on-findings`, treating exit code
   `2` (findings detected — expected, since `labapp` is intentionally vulnerable) as success and
   any other non-zero code as a real failure.
5. Upload `findings.json`/`results.sarif` as build artifacts.

Equivalent local run:

```bash
python -m labapp.app &
python3 main.py --headless --authorize \
  --targets http://127.0.0.1:5000/ \
  --modules all \
  --formats json,sarif \
  --fail-on-findings
```

## 8) GitHub Pages Demo Access

- Public URL: `https://imharshitaa.github.io/bugpilot/demo/`
- Default mode has no backend connected and is a scripted simulation only (see the banner on the
  page itself).
- Local preview:
```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory .
```
Then open `http://127.0.0.1:8080`.

## 9) Project Setup Steps (Canonical)

```bash
git clone https://github.com/imharshitaa/bugpilot.git
cd bugpilot
python3 -m venv venv
source venv/bin/activate
pip install -e .[test,demo]
```

## 10) Security and Governance Note

BugPilot enforces an authorization/scope check and an SSRF guard before any request is sent, but
these are safety rails against *accidental* out-of-scope testing — they are not a substitute for
having real, explicit authorization to test a target. Only run BugPilot against systems you are
authorized to test.
