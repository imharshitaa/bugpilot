"""
main.py
---------
BugPilot Master Controller
"""

import os
import datetime
from models.endpoint_class import Endpoint
from core.utils import Utils
from core.crawler import Crawler
from core.recon import Recon
from core.scanner import Scanner
from core.validator import Validator
from core.utils import load_yaml   # ensure this import exists


# ------------------------------------------------
# LOAD SCOPE
# ------------------------------------------------
def load_scope(path="config/scope.txt"):
    targets = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line.startswith("http"):
                targets.append(line)
    return targets


# ------------------------------------------------
# CONVERT URLS → ENDPOINTS
# ------------------------------------------------
def convert_to_endpoints(urls):
    return [Endpoint(url=u) for u in urls]


# ------------------------------------------------
# FINDINGS → MARKDOWN BLOCK
# ------------------------------------------------
def build_findings_block(findings):
    block = ""

    for f in findings:
        block += f"""
## 🚨 {f['type'].upper()} ({f['severity'].upper()})

**CWE:** {f['cwe']}  
**Endpoint:** `{f['endpoint']}`  
**Payload Used:** `{f['payload']}`  

### 🧾 Evidence:
{f['evidence']}

### 🛡 Mitigation:
{f['mitigation']}

### 🧨 Exploitation Methods (Safe Explanation):
{f['exploitation_methods']}

### 📚 References:
{f['references']}

---
"""
    return block


# ------------------------------------------------
# LOAD TEMPLATE
# ------------------------------------------------
def load_template():
    with open("reports/target_report.md", "r") as f:
        return f.read()


# ------------------------------------------------
# SAVE FINAL REPORT
# ------------------------------------------------
def save_report(rendered_text):
    os.makedirs("reports/output", exist_ok=True)

    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    path = f"reports/output/report_{ts}.md"

    with open(path, "w") as f:
        f.write(rendered_text)

    print(f"\n[+] Report generated: {path}")
    return path


# ------------------------------------------------
# PRINT SUMMARY FOR ACTIONS
# ------------------------------------------------
def print_summary(findings):
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for f in findings:
        sev = f["severity"]
        if sev in severities:
            severities[sev] += 1

    print("\n====== BUGPILOT SUMMARY ======")
    print(f"Total Findings: {len(findings)}")
    print(f"🔥 Critical: {severities['critical']}")
    print(f"🔴 High:     {severities['high']}")
    print(f"🟡 Medium:   {severities['medium']}")
    print(f"🟢 Low:      {severities['low']}\n")


# ------------------------------------------------
# MAIN ENGINE
# ------------------------------------------------
def main():

    print("""
===========================================
              BugPilot Scanner
      Automated Web Security Testing Suite
===========================================
""")

    utils = Utils()
    validator = Validator()
    crawler = Crawler(utils)
    scanner = Scanner(utils, validator)

    # --------------------------------------------
    # LOAD MODULE CONFIG + APPLY SINGLE MODULE MODE
    # --------------------------------------------
    modules = load_yaml("config/modules.yaml")

    ENABLED_MODULE = os.getenv("ENABLED_MODULE", None)

    if ENABLED_MODULE:
        print(f"[+] Workflow override → Running only: {ENABLED_MODULE}")
        for module_name in modules.keys():
            modules[module_name]["enabled"] = (module_name == ENABLED_MODULE)

    scanner.modules = modules  # pass updated modules to scanner

    # --------------------------------------------
    # LOAD SCOPE
    # --------------------------------------------
    targets = load_scope()
    print(f"[+] Loaded {len(targets)} targets")

    all_endpoints = []

    # Crawl each target
    for t in targets:
        print(f"[+] Crawling: {t}")
        crawled = crawler.crawl(t)
        print(f"    Found: {len(crawled)}")
        all_endpoints.extend(convert_to_endpoints(crawled))

    print(f"\n[+] Total endpoints discovered: {len(all_endpoints)}")

    # --------------------------------------------
    # RUN ALL ENABLED MODULES
    # --------------------------------------------
    print("\n[+] Running modules...")
    findings = scanner.run_modules(all_endpoints)
    print(f"[+] Modules completed → {len(findings)} findings")

    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        if f["severity"] in severity_counts:
            severity_counts[f["severity"]] += 1

    # Load template
    template = load_template()

    # Build findings block
    fb = build_findings_block(findings)

    # Fill placeholders
    rendered = template
    rendered = rendered.replace("{{SCAN_DATE}}", str(datetime.datetime.now()))
    rendered = rendered.replace("{{TARGET}}", ", ".join(targets))
    rendered = rendered.replace("{{ENDPOINT_COUNT}}", str(len(all_endpoints)))
    rendered = rendered.replace("{{FINDING_COUNT}}", str(len(findings)))
    rendered = rendered.replace("{{CRITICAL_COUNT}}", str(severity_counts["critical"]))
    rendered = rendered.replace("{{HIGH_COUNT}}", str(severity_counts["high"]))
    rendered = rendered.replace("{{MEDIUM_COUNT}}", str(severity_counts["medium"]))
    rendered = rendered.replace("{{LOW_COUNT}}", str(severity_counts["low"]))
    rendered = rendered.replace("{{FINDINGS_BLOCK}}", fb)

    # Save output report
    save_report(rendered)

    # Summary for GitHub Actions logs
    print_summary(findings)


# ------------------------------------------------
# ENTRY POINT
# ------------------------------------------------
if __name__ == "__main__":
    main()
