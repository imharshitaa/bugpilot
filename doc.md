# BugPilot Technical Reference

## Purpose
BugPilot provides a command-driven security testing pipeline that is extensible, automatable, and risk-oriented.

## Functional Domains
- Surface Discovery: crawl and endpoint collection.
- Target Intelligence: recon metadata (host, headers, DNS/IP, TLS summary).
- Vulnerability Testing: category-based checks and payload execution.
- Evidence Validation: controlled exploit flow for proof capture.
- Reporting: markdown + machine-readable outputs for integration.

## Command Contract
- `bugpilot scan <url>`: orchestrated scan flow.
- `bugpilot crawl <url>`: URL/API/sub-surface discovery.
- `bugpilot recon <url>`: target intelligence collection.
- `bugpilot test <url>`: vulnerability test category execution.
- `bugpilot exploit <url>`: evidence validation mode.
- `bugpilot expoit <url>`: alias to `exploit`.

Optional export flag:
- `-export`
- `-export /path/to/output.json`

## Runtime Architecture
1. CLI routing (`bugpilot_cli.py`).
2. Orchestration engine (`main.py`).
3. Recon layer (`core/recon.py`).
4. Crawl layer (`core/crawler.py`).
5. Scan layer (`core/scanner.py`).
6. Plugin loading (`core/plugin_manager.py`).
7. Detection helpers (`core/detection_engine.py`).
8. Risk scoring (`core/risk_scorer.py`).
9. Artifact writer (`core/reporter.py`).

## Plugin Architecture
Builtin plugins:
- Source: `modules/*.py`
- Registration: `config/modules.yaml`

External plugins:
- Registration: `config/plugins.yaml`
- Loader supports python-file plugins.

Expected plugin function:
```python
run(endpoints, utils, payload_rules) -> list[dict]
```

## Risk and Triage Model
- Findings are normalized to consistent severity/type fields.
- Risk scoring maps technical evidence into prioritization signals.
- Confidence controls reduce false positives in fast scans.
- Differential scan compares current run to baseline findings.

## CI/CD and Governance
Recommended security gate pattern:
1. Run headless scan in pipeline.
2. Export JSON/SARIF artifacts.
3. Fail build on policy threshold (`--fail-on-findings`).
4. Track findings trend with baseline comparisons.

Headless example:
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json,sarif \
  --fail-on-findings
```

## Output Specification
Run directory: `reports/output/run_<timestamp>/`

Standard artifacts:
- `report.md`
- `findings.json`
- `context.json`
- `endpoints.json`
- `session.json`

Optional artifacts:
- `results.sarif`
- `lab_validation_results.json`
- `differential_scan.json`

## Business-Level Mapping
- Engineering Productivity: standardized commands reduce ad-hoc scripts.
- Risk Transparency: severity-scored findings improve prioritization.
- Audit Readiness: reproducible artifacts support compliance reporting.
- Remediation Confidence: replay + differential scans verify fixes.

## Key Configuration Files
- `config/settings.yaml`
- `config/modules.yaml`
- `config/plugins.yaml`
- `config/test_cases.yaml`
- `config/payload_rules.yaml`

## Local Developer Setup
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

Quick usage:
```bash
bugpilot scan https://example.com
bugpilot test https://example.com -export
```

## Demo UI Note
The `docs/` terminal UI is for demonstration. Operational usage should rely on CLI/headless workflows.
