# BugPilot

BugPilot is a modular application-security testing CLI for **authorized** web/API testing. It
runs recon -> crawl -> module-based vulnerability checks -> risk scoring -> reporting, and ships
with an authorization/scope guard, SSRF protection, and a bundled local vulnerable app so you can
try it safely without touching any external target.

This is a personal, independent open-source project. It is not affiliated with, and shares no
code or architecture with, any employer or proprietary codebase.

## What's actually implemented

- A scope allowlist (`config/scope.txt`) and an `--authorize` flag/interactive confirmation
  prompt, enforced before any request is sent (`core/scope.py`).
- An SSRF guard (`core/ssrf_guard.py`) that resolves every hostname and rejects
  private/loopback/link-local/metadata/multicast/reserved IPs for targets that haven't been
  explicitly authorized, including on every redirect hop, not just the initial request
  (`core/utils.py`).
- A plugin-based module system (`core/plugin_manager.py`) with built-in detectors for XSS, SQLi,
  IDOR, CSRF, CORS misconfiguration, open redirect, missing security headers, path traversal,
  SSRF, XXE, JWT weaknesses, insecure deserialization, rate limiting, business logic abuse,
  GraphQL introspection, and file upload handling (`modules/`).
- Confidence-aware filtering: `Scanner.run_modules()` drops any finding below
  `config/settings.yaml`'s `min_confidence` (default `0.6`). See "Detection confidence" below —
  some modules are intentionally heuristic and suppressed by default.
- Risk scoring (`core/risk_scorer.py`), deduplication/evidence trimming (`core/validator.py`),
  differential scan comparison against a baseline (`core/diff_scan.py`).
- Markdown, JSON, and SARIF report output (`core/reporter.py`).
- A headless mode for CI (`main.py --headless`) with a real, working GitHub Actions workflow
  (`.github/workflows/ci.yml`) that runs the test suite and a real authorized scan against the
  bundled local vulnerable app.
- A pytest suite (`tests/`) covering the SSRF guard, scope/authorization logic, HTTP/redirect
  handling, every detection module, risk scoring, deduplication, diff scanning, plugin loading,
  reporting, CLI exit codes, and a real end-to-end scan against the bundled lab app.

## What's aspirational / not implemented

- `exploit` / `test` are thinner than their names suggest: they run the same module set as `scan`
  with different default output formats, not a distinct exploitation engine.
- There is no authentication/session-handling layer (login flows, cookie jars across requests) —
  every module tests unauthenticated or single-request behavior.
- `--lab-auto-docker` exists as a flag but depends on a local Docker daemon being available; it is
  not exercised by the test suite or CI.

If you find other gaps, please open an issue — this list is meant to be honest, not exhaustive.

## The bundled vulnerable app (`labapp/`)

`labapp/` is a small Flask app with intentional, well-understood vulnerabilities (reflected XSS,
sequential-ID IDOR, permissive CORS, open redirect, missing security headers, a login form with no
CSRF token). It exists so you — and the test suite, and CI — have a real, local, safe target to
scan without ever touching a third-party site.

```bash
python -m labapp.app          # serves on http://127.0.0.1:5000
python -m labapp.app 8080     # or a custom port
```

## Quick start

```bash
git clone https://github.com/imharshitaa/bugpilot.git
cd bugpilot
python3 -m venv venv
source venv/bin/activate
pip install -e .[test,demo]
```

`requirements.txt` is kept in sync as a secondary install path, but `pip install -e .[test,demo]`
(from `pyproject.toml`) is the preferred way to get the CLI, test suite, and demo backend
dependencies together.

## Authorization and scope

BugPilot refuses to send a single request to a target it hasn't been authorized for.

- Hosts listed in `config/scope.txt` are pre-authorized.
- Any other host requires either:
  - an explicit `--authorize` flag (required in headless/CI mode), or
  - a `y` answer to an interactive confirmation prompt (interactive mode).
- Unauthorized targets raise `AuthorizationError` and the command exits non-zero without making
  any network request.
- Once a host is authorized, the SSRF guard still allows private/loopback addresses only for that
  authorized host — this is what lets you scan `127.0.0.1`/`labapp` locally while still blocking
  an *unauthorized* target's redirect from pivoting to internal/metadata addresses.

Try it against the bundled lab app (safe, local, no external traffic):

```bash
python -m labapp.app &
bugpilot scan http://127.0.0.1:5000 --authorize
```

## Command reference

```bash
bugpilot scan <url> [--authorize] [-export [path]]
bugpilot crawl <url> [-authorize] [-export [path]]
bugpilot recon <url> [-authorize] [-export [path]]
bugpilot test <url> [--authorize] [-export [path]]
bugpilot exploit <url> [--authorize] [-export [path]]
bugpilot expoit <url>   # alias for exploit
```

- `scan`/`test`/`exploit` shell out to `main.py --headless` under the hood, so `--authorize` and
  any other `main.py` flag (see below) can be passed straight through.
- `recon`/`crawl` run in-process and take their own `-authorize`/`--authorize` flag.
- `-export` writes a JSON copy of findings/results to `reports/output/`.

## Headless / CI mode

```bash
python3 main.py --headless \
  --targets http://127.0.0.1:5000/ \
  --authorize \
  --modules all \
  --formats json,sarif \
  --fail-on-findings
```

`main.py` returns `0` on a clean run, `2` if no targets were provided, if authorization failed, or
if `--fail-on-findings` is set and findings were detected. Other flags:
`--baseline-findings <path>` (differential scan), `--replay-session <path>`, `--lab-auto-docker`,
`--validate-findings none|all|1,2,3`.

## Detection confidence — read this before trusting a "clean" scan

Findings below `config/settings.yaml`'s `min_confidence` (default `0.6`) are filtered out of the
default report. The following modules are **heuristic by design** and score below that threshold,
so they will not appear unless you lower `min_confidence`:

| Module | Confidence | Why it's heuristic |
|---|---|---|
| `idor` | 0.5 | A differing response for a sequential ID is suggestive, not proof of an authorization flaw. |
| `csrf` | 0.55 | Absence of a recognized token field name doesn't rule out other CSRF defenses (e.g. SameSite cookies). |
| `auth_bypass` | 0.4 | Based on response-shape comparison, not a confirmed bypass. |
| `business_logic_abuse` | 0.5 | Value echoing alone is weak evidence of a real logic flaw. |
| `rate_limit_bruteforce` | 0.55 | Behavioral/statistical; can't rule out app-level controls like CAPTCHA. |
| `file_upload_testing` | 0.4 | Missing a client-side `accept` attribute is not itself a server-side control. |

Everything else (`misconfig`, `xss`, `sqli`, `open_redirect`, `cors_misconfig`,
`path_traversal`, `ssrf`, `xxe`, `jwt_validation_weaknesses`, `insecure_deserialization`,
`graphql_specific_testing`, `file_inclusion_indicator`) scores at or above `0.6` and shows up by
default. `tests/test_lab_integration.py` asserts this split explicitly against the bundled lab app.

No module reports a finding from a keyword match alone — each requires an observed behavioral
difference (reflected payload, differing status/body, redirect to an attacker-controlled host,
missing header, etc.), and several additionally run through `models/false_positive.py` before
being reported. Still, treat every finding as a lead to verify manually, not a confirmed
vulnerability.

## Output artifacts

Each run writes to `reports/output/run_<timestamp>/`:
`report.md`, `findings.json`, `context.json`, `endpoints.json`, `session.json`, plus
`results.sarif` and/or `differential_scan.json`/`lab_validation_results.json` when those features
are enabled.

## Running the tests

```bash
pytest -q
```

104 tests cover the SSRF guard, scope/authorization, HTTP/redirect handling, every module, risk
scoring, deduplication, diff scanning, plugin loading, reporting, CLI exit codes, and a real
end-to-end scan/detection-confidence check against `labapp`. CI (`.github/workflows/ci.yml`) runs
the same suite plus a live authorized scan against `labapp` on every push/PR.

No linting, formatting, or type-checking tooling (flake8/ruff/mypy/black/etc.) is currently
configured in this repository.

## Configuration

- `config/settings.yaml` — scanner profile (`min_confidence`, `max_redirects`, timeouts, retries).
- `config/scope.txt` — pre-authorized target allowlist.
- `config/modules.yaml` / `config/plugins.yaml` — built-in/external module registry.
- `config/payload_rules.yaml` — payload and indicator definitions.

## Demo page

`demo/index.html` (served at `https://imharshitaa.github.io/bugpilot/demo/`) is a terminal-style
UI for showing the CLI's shape. **By default it has no backend connected and every command is a
scripted simulation** — it does not scan, crawl, or make any network request. A persistent banner
on the page states this. For a real scan, run the CLI locally as shown above.

Local preview:

```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory .
```

## Authorization notice

Only use BugPilot against systems you are explicitly authorized to test. The scope guard and SSRF
protection exist to make accidental out-of-scope testing hard, not to make unauthorized testing
easy — they are not a substitute for having real authorization.
