# BugPilot

BugPilot is a security testing orchestration tool for authorized targets. It is designed for developer workflows, security engineering operations, and business-level risk visibility.

## Why BugPilot
- Standardizes security testing into repeatable command flows.
- Produces actionable findings with severity, evidence, and risk scoring.
- Supports local engineering usage and headless CI/CD execution.
- Reduces time from detection to validation and reporting.

## Core Capabilities
- Command-based operations: `scan`, `crawl`, `recon`, `test`, `exploit`.
- Plugin architecture for built-in and external test modules.
- Risk scoring and confidence-aware triage.
- Replayable sessions and differential scans (baseline comparison).
- Multi-format outputs: Markdown, JSON, SARIF.
- Optional isolated lab validation and evidence capture.

## Value By Persona
### Developers
- Fast local scanning against feature branches and staging targets.
- JSON artifacts for automation and regression checks.
- Differential scan support to validate patch impact.

### Security Engineers
- Structured recon, crawling, testing, and evidence workflows.
- Plugin-driven extensibility for category-specific test logic.
- Session replay and deterministic output paths for investigations.

### Business / Program Owners
- Risk-prioritized findings with clear severity context.
- Consistent artifacts for audits, tracking, and reporting.
- CI/CD integration to enforce policy gates (`--fail-on-findings`).

## Installation
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

## Primary Commands
```bash
bugpilot scan <url>
bugpilot crawl <url>
bugpilot recon <url>
bugpilot test <url>
bugpilot exploit <url>
```

Alias:
```bash
bugpilot expoit <url>
```

Export structured JSON logs:
```bash
bugpilot scan <url> -export
bugpilot test <url> -export /custom/path/results.json
```

If package install is not used:
```bash
./bugpilot scan <url>
```

## Command Functions
- `bugpilot scan`: end-to-end scanning workflow with vulnerability summary.
- `bugpilot crawl`: endpoint and API surface discovery.
- `bugpilot recon`: target intelligence (headers, DNS/IP, TLS summary).
- `bugpilot test`: vulnerability category execution profile.
- `bugpilot exploit`: controlled evidence validation flow.

## Headless CI/CD
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json,sarif \
  --validate-findings none
```

Useful flags:
- `--fail-on-findings`
- `--baseline-findings <path>`
- `--replay-session <path>`
- `--lab-auto-docker`

## Output Artifacts
Per run:
- `reports/output/run_<timestamp>/report.md`
- `reports/output/run_<timestamp>/findings.json`
- `reports/output/run_<timestamp>/context.json`
- `reports/output/run_<timestamp>/endpoints.json`
- `reports/output/run_<timestamp>/session.json`
- `reports/output/run_<timestamp>/results.sarif` (when enabled)
- `reports/output/run_<timestamp>/lab_validation_results.json` (when enabled)
- `reports/output/run_<timestamp>/differential_scan.json` (when baseline is provided)

## Architecture (High-Level)
1. CLI entry (`bugpilot_cli.py`) parses command and options.
2. Orchestration (`main.py`) executes recon, crawl, scan/test workflows.
3. Plugin manager (`core/plugin_manager.py`) loads enabled modules.
4. Detection/risk layers normalize findings and assign risk signals.
5. Reporter persists markdown + machine-readable artifacts.

## Configuration
- `config/settings.yaml`: runtime/system settings.
- `config/modules.yaml`: module registry and enabled state.
- `config/plugins.yaml`: external plugin definitions.
- `config/test_cases.yaml`: test category metadata.
- `config/payload_rules.yaml`: payload and detection indicators.

## Minimal Pages Demo Note
A GitHub Pages terminal exists for demonstration only. Real-world testing is intended through local/CI execution of the CLI commands above.

## Authorization Requirement
Use BugPilot only on systems you are explicitly authorized to test.
