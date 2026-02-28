# BugPilot Developer Reference

## 1) Overview
BugPilot is a security testing orchestrator for authorized web/API targets.

It supports:
- Interactive and headless (CI/CD) scanning
- Plugin-based module execution
- Risk scoring per finding
- Output formats: Markdown, JSON, SARIF
- Isolated lab validation (native HTTP and optional Docker transport)
- Replayable scan sessions
- Differential scanning (baseline vs current)

---

## 2) Execution Modes

### Interactive mode
```bash
python3 main.py
```

### Headless CI/CD mode
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json,sarif \
  --validate-findings none
```

Useful headless flags:
- `--fail-on-findings`
- `--baseline-findings <path_to_findings.json>`
- `--replay-session <path_to_session.json>`
- `--lab-auto-docker`

---

## 3) High-Level Runtime Flow

1. Parse CLI args (`main.py`) and decide interactive vs headless mode.
2. Build run context from:
   - user prompts (`core/workflow.py`) OR
   - CLI flags OR
   - replay session file.
3. Run recon (`core/recon.py`) + crawl (`core/crawler.py`).
4. Convert URLs to `Endpoint` models (`models/endpoint_class.py`).
5. Execute selected plugins/modules via `core/scanner.py` + `core/plugin_manager.py`.
6. Enrich findings with:
   - normalized type
   - severity
   - risk score/rating/text
   - mitigation/reference/lab guidance
   - target response snapshot
7. Optional lab validation (`core/lab_validator.py`).
8. Optional differential compare (`core/diff_scan.py`).
9. Write outputs (`core/reporter.py`) in selected formats.

---

## 4) Architecture and File Roles

### `main.py`
Primary orchestrator.
- Handles CLI args (`--headless`, `--formats`, `--baseline-findings`, etc.)
- Drives workflow, scan execution, optional validation/diff
- Prints terminal UI and output artifact paths

### `core/`
- `workflow.py`
  - Interactive prompts for target/module/lab/output format selection.
- `scanner.py`
  - Core scan engine.
  - Uses plugin manager to load modules.
  - Applies endpoint filtering and enrichment.
- `plugin_manager.py`
  - Loads builtin plugins from `modules/` and optional file-based plugins from `config/plugins.yaml`.
- `risk_scorer.py`
  - Computes `risk_score` (0-100), `risk_rating`, and risk narrative.
- `lab_validator.py`
  - Safe replay validation in isolated environment.
  - Supports optional Docker-backed request transport.
- `diff_scan.py`
  - Compares baseline and current findings (new/resolved/persisting).
- `reporter.py`
  - Writes Markdown/JSON/SARIF and session artifact.
- `crawler.py`
  - Same-host crawling with depth/link caps.
- `recon.py`
  - Basic header reconnaissance.
- `utils.py`
  - HTTP client, request caching, URL param merging, YAML/JSON helpers.
- `validator.py`
  - Deduplication and evidence trimming helpers.

### `models/`
- `endpoint_class.py` - endpoint representation + serialization.
- `severity.py` - default severity map by vulnerability category.
- `prompts.py` - mitigation, exploitation-method notes, references.
- `false_positive.py` - simple false-positive text filters.

### `modules/`
Each module exposes:
```python
run(endpoints, utils, payload_rules) -> list[dict]
```

Current builtins include:
- xss, sqli, ssrf, auth_bypass, misconfig, idor, open_redirect
- path_traversal, file_inclusion_indicator, cors_misconfig, csrf
- rate_limit_bruteforce
- jwt_validation_weaknesses
- insecure_deserialization
- business_logic_abuse
- graphql_specific_testing
- file_upload_testing
- xxe

### `config/`
- `modules.yaml` - builtin module registry + enabled states.
- `plugins.yaml` - external/file-based plugin registry.
- `test_cases.yaml` - attack methods, scripts, tools, commands metadata.
- `payload_rules.yaml` - shared payload/signature rules.
- `settings.yaml` - HTTP/scanner/crawler/report/CI/lab behavior.
- `scope.txt` - fallback targets.

### `payloads/`
Reference payload text files per category (developer reference artifacts).

### `reports/output/run_<timestamp>/`
Per-run output directory.

---

## 5) Plugin Architecture

### Builtin plugins
- Declared in `config/modules.yaml`.
- Implemented as Python modules under `modules/`.

### External plugins
- Declared in `config/plugins.yaml`.
- Currently supported source: `python_file`.

Example plugin entry:
```yaml
plugins:
  custom_module:
    enabled: true
    description: Custom validation
    source: python_file
    path: plugins/custom_module.py
```

Plugin contract:
- Must provide `run(endpoints, utils, payload_rules)`.
- Return list of finding dictionaries.

---

## 6) Finding Contract and Enrichment

### Module output (minimum recommended)
- `type`
- `endpoint`
- `payload`
- `evidence`
- `cwe`
- `severity` (optional)

### Scanner enrichment adds
- `normalized_type`
- `module`
- `severity` (if missing)
- `risk_score`
- `risk_rating`
- `risk`
- `vulnerability_point`
- `target_response`
- `lab_validation`

---

## 7) Risk Scoring

Implemented in `core/risk_scorer.py`.

Inputs:
- base severity
- confidence (if provided)
- evidence length
- endpoint keyword boost (auth/admin/payment-like)

Outputs:
- `risk_score` (0-100)
- `risk_rating` (`low|medium|high|critical`)
- risk explanation text

---

## 8) Output Formats

Selectable with:
- interactive prompt: output formats
- headless: `--formats markdown,json,sarif`

Artifacts (depending on selected formats/features):
- `report.md`
- `findings.json`
- `results.sarif`
- `context.json`
- `endpoints.json`
- `session.json`
- `lab_validation_results.json` (if lab validation run)
- `differential_scan.json` (if baseline comparison run)

---

## 9) Lab Validation

Lab validation is safe replay only; it is not destructive exploitation.

Trigger:
- interactive: prompt after findings table
- headless: `--validate-findings all|1,2,3|none`

Transport options:
- default native HTTP requests
- Docker-backed (`--lab-auto-docker`) via ephemeral curl container

Results include:
- status (`validated` or `inconclusive`)
- source target, lab target
- proof text
- evidence preview
- transport used

---

## 10) Replayable Sessions

Each run writes `session.json` containing reusable scan context.

Replay command:
```bash
python3 main.py --headless --replay-session reports/output/run_<timestamp>/session.json
```

Replay restores:
- target type
- targets
- selected modules
- lab environment
- output formats

---

## 11) Differential Scanning

Provide baseline findings:
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json \
  --baseline-findings /path/to/baseline/findings.json
```

Output:
- `differential_scan.json` with counts and lists:
  - `new_findings`
  - `resolved_findings`
  - `persisting_findings`

---

## 12) Adding a New Category (Developer Checklist)

1. Add module file under `modules/<name>.py` with `run(...)`.
2. Add entry to `config/modules.yaml`.
3. Add test metadata to `config/test_cases.yaml`.
4. Add payload/signature rules to `config/payload_rules.yaml` if needed.
5. Add severity to `models/severity.py`.
6. Add mitigation/method/reference in `models/prompts.py`.
7. Run headless smoke test and verify output artifacts.

---

## 13) Quick Dev Commands

Setup:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Interactive run:
```bash
python3 main.py
```

Headless + SARIF:
```bash
python3 main.py --headless --targets https://example.com --modules all --formats json,sarif
```

Compile check:
```bash
PYTHONPYCACHEPREFIX=.pycache python3 -m py_compile main.py core/*.py models/*.py modules/*.py
```
