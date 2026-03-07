# BugPilot

BugPilot is a modular offensive-security orchestration platform for authorized application testing.
It is built to support developer self-testing, security engineering workflows, and business-grade risk reporting.

## Project Overview
- Standardized CLI-driven testing lifecycle: recon -> crawl -> test -> exploit validation -> report.
- Plugin-based module system for test category expansion.
- Risk scoring and confidence-aware triage to reduce false positives.
- Output contracts for engineers and tooling: Markdown, JSON, SARIF.
- CI/CD-ready headless mode for security gates.

## GitHub Demo Page
- Live demo URL: `https://imharshitaa.github.io/bugpilot/demo/`
- Demo is a shell-style terminal UI for product showcase.
- Production/real testing should be run locally or in CI using the CLI.

## Quick Start (Default Developer Setup)
1. Clone repository
```bash
git clone https://github.com/imharshitaa/bugpilot.git
cd bugpilot
```

2. Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

4. Run primary commands
```bash
bugpilot scan <url>
bugpilot crawl <url>
bugpilot recon <url>
bugpilot test <url>
bugpilot exploit <url>
```

## Command Reference
- `bugpilot scan <url>`: full workflow with vulnerability summary.
- `bugpilot crawl <url>`: endpoint/API surface enumeration.
- `bugpilot recon <url>`: host/header/network intelligence collection.
- `bugpilot test <url>`: vulnerability category execution profile.
- `bugpilot exploit <url>`: controlled validation and evidence mode.
- `bugpilot expoit <url>`: alias to `exploit`.

JSON export support:
```bash
bugpilot scan <url> -export
bugpilot test <url> -export /tmp/bugpilot-findings.json
```

## Headless CI/CD Mode
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json,sarif \
  --fail-on-findings
```

Useful pipeline flags:
- `--fail-on-findings`
- `--baseline-findings <path>`
- `--replay-session <path>`
- `--lab-auto-docker`

## Output Artifacts
Each run generates a folder in:
- `reports/output/run_<timestamp>/`

Typical files:
- `report.md`
- `findings.json`
- `context.json`
- `endpoints.json`
- `session.json`
- `results.sarif` (if enabled)
- `lab_validation_results.json` (if enabled)
- `differential_scan.json` (if baseline provided)

## Business and Engineering Value
- Engineering velocity: reusable commands and deterministic output paths.
- Security operations: category-specific tests with evidence-oriented reporting.
- Leadership visibility: risk-prioritized findings for planning and governance.
- Compliance posture: repeatable artifacts for audit and tracking.

## Configuration Surface
- `config/settings.yaml`: runtime controls, scanner profile, web terminal settings.
- `config/modules.yaml`: built-in module registry.
- `config/plugins.yaml`: external plugin registry.
- `config/test_cases.yaml`: categorized test metadata.
- `config/payload_rules.yaml`: payload and indicator definitions.

## Local Preview for Demo UI
```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory .
```
Open:
- `http://127.0.0.1:8080`

## Authorization Notice
Use BugPilot only against systems you are explicitly authorized to test.
