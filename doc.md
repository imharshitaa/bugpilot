# BugPilot Technical Blueprint

## 1) System Intent
BugPilot is a command-orchestrated security testing framework designed to:
- provide reproducible offensive-security workflows,
- support extensible module/plugin testing,
- produce machine- and human-consumable artifacts,
- integrate into local developer loops and CI/CD gates.

## 2) End-to-End Execution Flow
1. User invokes CLI command (`bugpilot scan|crawl|recon|test|exploit`).
2. CLI parser normalizes command flags and mode.
3. Workflow engine loads configuration and enabled modules.
4. Recon and crawler establish target context and endpoint inventory.
5. Scanner dispatches module/plugin checks by category.
6. Findings are normalized, risk-scored, and enriched with evidence fields.
7. Reporter writes run artifacts to versioned output directory.
8. Optional differential and replay logic compare or reproduce prior states.

## 3) Folder and File Significance

### Root runtime entry points
- `bugpilot`: shell launcher for command execution.
- `bugpilot_cli.py`: main CLI command contract, command routing, export handling.
- `main.py`: orchestration entry for interactive/headless execution.
- `pyproject.toml`: package metadata and console script registration.
- `requirements.txt`: Python dependency list.

### Core engine (`core/`)
- `core/workflow.py`: high-level workflow helpers and command-mode control.
- `core/scanner.py`: scan loop, module dispatch, confidence/fast-mode controls.
- `core/crawler.py`: URL endpoint discovery and crawl constraints.
- `core/recon.py`: target intelligence collection (headers, DNS/IP, TLS summary).
- `core/plugin_manager.py`: built-in/external plugin loading and execution contract.
- `core/detection_engine.py`: shared finding detection heuristics.
- `core/risk_scorer.py`: risk score/rating derivation logic.
- `core/reporter.py`: markdown/json/sarif artifact generation.
- `core/lab_validator.py`: isolated validation logic for selected finding categories.
- `core/utils.py`: shared utility helpers (I/O, parsing, config helpers).

### Test modules (`modules/`)
- Category implementations for web/API vulnerabilities.
- Each module returns structured finding dictionaries consumed by scanner/reporter.
- Module enablement and metadata controlled via `config/modules.yaml`.

### Models (`models/`)
- Prompt/data contracts and typed structures used across the workflow.

### Payloads (`payloads/`)
- Curated payload and pattern files for category-specific testing.

### Configuration (`config/`)
- `settings.yaml`: scanner/runtime/web-terminal defaults.
- `modules.yaml`: module definitions, state, descriptions.
- `plugins.yaml`: external plugin declarations.
- `test_cases.yaml`: higher-level test category map.
- `payload_rules.yaml`: payload selection and detection hints.

### Reporting (`reports/`)
- Persisted run outputs under timestamped directories.
- Contains markdown narrative + machine-readable data for automation.

### Demo and deployment files
- `docs/index.html`: shell-style demo terminal UI.
- `docs/terminal-config.json`: demo terminal backend config.
- `.github/workflows/pages.yml`: GitHub Pages deployment workflow.
- `backend/server.py`: optional WebSocket runner for remote command execution.

## 4) Command Semantics
- `scan`: complete testing lifecycle with consolidated findings.
- `crawl`: endpoint and API surface mapping.
- `recon`: target metadata and technical fingerprinting.
- `test`: vulnerability-category execution profile.
- `exploit`: controlled exploit/lab validation path for evidence.
- `expoit`: compatibility alias to `exploit`.

Export semantics:
- `-export` writes JSON output using default path.
- `-export <path>` writes JSON output to explicit path.

## 5) Data Contracts (Findings)
A finding is expected to include fields such as:
- `type`
- `severity`
- `title`/`description`
- `evidence`
- `endpoint`/`source`
- `risk_score` and/or `risk_rating`
- optional validation metadata

## 6) Quality and False-Positive Controls
- Minimum confidence gating in scanner profile.
- Fast-mode payload/parameter caps to balance speed and signal.
- Differential scan support against baselines for regression visibility.
- Replayable sessions for reproducibility and investigation.

## 7) CI/CD Integration Blueprint
Recommended pipeline pattern:
1. Install project and dependencies.
2. Run headless scan with JSON/SARIF outputs.
3. Enforce policy via `--fail-on-findings`.
4. Archive run artifacts.
5. Compare against baseline where needed.

Example:
```bash
python3 main.py --headless \
  --targets https://target \
  --modules all \
  --formats json,sarif \
  --fail-on-findings
```

## 8) GitHub Pages Demo Access
- Public URL: `https://imharshitaa.github.io/bugpilot/`
- Local preview:
```bash
python3 -m http.server 8080 --bind 127.0.0.1 --directory .
```
Then open:
- `http://127.0.0.1:8080`

## 9) Project Setup Steps (Canonical)
```bash
git clone https://github.com/imharshitaa/bugpilot.git
cd bugpilot
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## 10) Security and Governance Note
BugPilot must only be executed against explicitly authorized assets.
