# BugPilot Developer Reference

## 1) What This Repository Does
BugPilot is an interactive security testing orchestrator for authorized web/API targets.

At runtime, it:
1. Collects target + module selections from prompts.
2. Performs lightweight recon.
3. Crawls endpoints.
4. Runs selected vulnerability modules.
5. Enriches findings with severity/risk/mitigation metadata.
6. Writes run artifacts under `reports/output/run_<timestamp>/`.

---

## 2) High-Level Execution Flow

`main.py` is the entrypoint and wires everything together.

Flow:
1. Initialize core services (`Utils`, `Validator`, `Crawler`, `Scanner`, `Recon`, `Reporter`, `Workflow`).
2. Load fallback targets from `config/scope.txt`.
3. `Workflow.collect()` asks:
   - target type
   - target URLs
   - modules to run
   - lab environment
4. For each target:
   - `Recon.analyze_headers()`
   - `Crawler.crawl()`
5. Convert discovered URLs to `Endpoint` objects.
6. `Scanner.run_modules()` dynamically imports and runs each selected module.
7. `Reporter.write()` writes markdown + JSON output files.
8. Summary is printed to terminal.

---

## 3) Directory Structure and Purpose

### `config/`
- `modules.yaml`
  - Module registry, `enabled` toggle, and module descriptions.
  - Controls what appears in module selection prompt.
- `test_cases.yaml`
  - Per-category attack method metadata.
  - Lists custom scripts, tool names, and example commands.
  - Used by `Workflow.build_test_plan()` for report context.
- `payload_rules.yaml`
  - Shared payloads/signatures consumed by modules (currently xss/sqli/ssrf/auth_bypass/misconfig sections).
- `settings.yaml`
  - HTTP behavior, auth header support, scanner/crawler settings, report settings, debug flags.
- `scope.txt`
  - Fallback target list when user leaves target prompt blank.

### `core/`
- `workflow.py`
  - Interactive input pipeline.
  - Builds `run_context` object with selected modules and test plan metadata.
- `utils.py`
  - Shared helpers:
    - YAML loading
    - HTTP requests/retries/TLS verify handling
    - query param URL merging (`add_query_params`)
    - JSON writer
- `recon.py`
  - Header-based reconnaissance per target.
- `crawler.py`
  - Safe same-host link discovery and depth-limited crawling.
- `scanner.py`
  - Dynamic module loader (`importlib.import_module("modules.<name>")`).
  - Runs modules, enriches findings (normalized type, severity, risk, mitigation, references, lab validation, response snapshot), and deduplicates via validator.
- `validator.py`
  - Finding deduplication and evidence trimming helper.
- `reporter.py`
  - Creates run folder and writes:
    - `report.md`
    - `findings.json`
    - `context.json`
    - `endpoints.json`

### `models/`
- `endpoint_class.py`
  - Endpoint model (`url`, `method`, `params`) and serializer.
- `severity.py`
  - Default severity mapping per vulnerability category.
- `prompts.py`
  - Mitigations, safe exploitation-method notes, references per category.
- `false_positive.py`
  - Simple text pattern filter for likely false positives.

### `modules/`
Each file exposes `run(endpoints, utils, payload_rules) -> list[dict]`.

- `xss.py`
- `sqli.py`
- `ssrf.py`
- `auth_bypass.py`
- `misconfig.py`
- `idor.py`
- `open_redirect.py`
- `path_traversal.py`
- `file_inclusion_indicator.py`
- `cors_misconfig.py`
- `csrf.py`

Module outputs are normalized/enriched in `core/scanner.py` before reporting.

### `reports/`
- Runtime outputs go to `reports/output/run_<timestamp>/...`
- `reports/target_report.md` is a legacy configured path and not the primary current output path.

### `payloads/`, `data/`, `sample/`
- `payloads/*.txt`: reference payload lists (not directly wired into active runtime logic).
- `data/`: static sample files.
- `sample/dvwa.md`: example content/reference.

---

## 4) File Connection Map (Who Calls What)

Entrypoint chain:
- `main.py`
  - imports from `core/*` and `models/endpoint_class.py`
  - calls `Workflow.collect()`
  - calls `Recon.analyze_headers()`
  - calls `Crawler.crawl()`
  - calls `Scanner.run_modules()`
  - calls `Reporter.write()`

Scanner chain:
- `core/scanner.py`
  - reads `config/modules.yaml`
  - reads `config/payload_rules.yaml`
  - dynamically imports `modules/<module_name>.py`
  - enriches using `models/severity.py` + `models/prompts.py`
  - deduplicates via `core/validator.py`

Workflow chain:
- `core/workflow.py`
  - reads `config/modules.yaml` and `config/test_cases.yaml`
  - builds report-facing test plan metadata

HTTP behavior chain:
- All network calls go through `core/utils.py::http_request()`
  - used by recon, crawler, and modules
  - controlled by `config/settings.yaml`

---

## 5) Finding Object Contract

Modules should return dictionaries with at least:
- `type`
- `endpoint`
- `severity` (optional; scanner can default it)
- `payload`
- `evidence`
- `cwe`
- `mitigation` (optional; scanner can default it)
- `references` (optional; scanner can default it)

Scanner adds:
- `normalized_type`
- `module`
- `risk`
- `vulnerability_point`
- `target_response`
- `lab_validation`

---

## 6) How to Add a New Test Category

1. Create new module file in `modules/<new_category>.py` with `run(...)`.
2. Add it in `config/modules.yaml` with `enabled` + description.
3. Add metadata in `config/test_cases.yaml` (`attack_method`, `custom_scripts`, `tools`, `commands`).
4. Add severity in `models/severity.py`.
5. Add mitigation/method/reference entries in `models/prompts.py`.
6. If payload/signature driven, add rules in `config/payload_rules.yaml`.
7. Run `python3 main.py`, select the module, verify output in `reports/output/...`.

---

## 7) Runtime Artifacts You Should Check While Developing

Per run folder:
- `report.md`: human-readable report.
- `findings.json`: raw enriched findings.
- `context.json`: run context + selected module plan.
- `endpoints.json`: scanned endpoint inventory.

If module behavior looks wrong, inspect `findings.json` first, then trace:
1. module output
2. scanner enrichment
3. reporter rendering

---

## 8) Practical Dev Notes

- Only `config/modules.yaml` controls active module availability.
- `config/test_cases.yaml` commands are informational metadata for the report/test plan; scanner execution is done via Python module imports.
- Crawler is same-host only by design in `core/crawler.py`.
- TLS verification is controlled by `config/settings.yaml -> http.verify_tls`.
- Keep module `type` names consistent with keys in `models/severity.py` and `models/prompts.py` for clean enrichment.

---

## 9) Quick Start

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 main.py
```

