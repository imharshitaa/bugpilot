# BugPilot

BugPilot is an interactive security testing orchestrator for authorized bug bounty workflows.

It now supports:
- Target type intake (web app, API, mobile backend, other)
- Target URL intake at runtime
- Test-case/module selection at runtime
- Module execution with structured findings
- Target response snapshot capture per finding
- Risk, mitigation, vulnerability point, and lab validation notes
- Report persistence in `reports/output/<run_id>/`

## Project flow
1. Ask target type
2. Ask target URLs
3. Ask which test cases/modules to run
4. Crawl and discover endpoints
5. Execute selected modules
6. Enrich findings with risk + response details
7. Save Markdown and JSON reports

## Install
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Run
```bash
python3 main.py
```

If you leave targets blank during prompts, BugPilot falls back to `config/scope.txt`.

## Headless CI/CD mode
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json,sarif \
  --validate-findings none
```

Useful flags:
- `--fail-on-findings`: exit non-zero when findings exist.
- `--baseline-findings <path>`: differential scan against a baseline findings JSON.
- `--replay-session <path>`: replay previous run context from `session.json`.
- `--lab-auto-docker`: run isolated lab validation requests via Docker curl container when available.

## Output
Each run writes to a unique folder:
- `reports/output/run_<timestamp>/report.md`
- `reports/output/run_<timestamp>/findings.json`
- `reports/output/run_<timestamp>/context.json`
- `reports/output/run_<timestamp>/endpoints.json`
- `reports/output/run_<timestamp>/session.json`
- `reports/output/run_<timestamp>/results.sarif` (if `sarif` format selected)
- `reports/output/run_<timestamp>/lab_validation_results.json` (if lab validation executed)
- `reports/output/run_<timestamp>/differential_scan.json` (if baseline provided)

## Config files
- `config/modules.yaml`: module registry and enabled state
- `config/test_cases.yaml`: attack method, scripts, tools, and commands metadata
- `config/payload_rules.yaml`: payload and indicator rules

## Important
Use BugPilot only on systems you are explicitly authorized to test.
