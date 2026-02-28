"""
main.py
---------
BugPilot interactive controller.
"""

import os

from core.crawler import Crawler
from core.recon import Recon
from core.reporter import Reporter
from core.scanner import Scanner
from core.utils import Utils
from core.validator import Validator
from core.workflow import Workflow
from models.endpoint_class import Endpoint


def load_scope(path="config/scope.txt"):
    targets = []
    if not os.path.exists(path):
        return targets

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            value = line.strip()
            if value.startswith("http"):
                targets.append(value)
    return targets


def convert_to_endpoints(urls):
    return [Endpoint(url=url) for url in urls]


def print_summary(findings):
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0}

    for finding in findings:
        sev = str(finding.get("severity", "low")).lower()
        if sev in severities:
            severities[sev] += 1

    print("\n====== BUGPILOT SUMMARY ======")
    print(f"Total Findings: {len(findings)}")
    print(f"Critical: {severities['critical']}")
    print(f"High:     {severities['high']}")
    print(f"Medium:   {severities['medium']}")
    print(f"Low:      {severities['low']}")


def main():
    print(
        """
===========================================
              BugPilot Scanner
===========================================
"""
    )

    utils = Utils()
    validator = Validator()
    crawler = Crawler(utils)
    scanner = Scanner(utils, validator)
    recon = Recon(utils)
    reporter = Reporter()
    workflow = Workflow()

    fallback_targets = load_scope()
    run_context = workflow.collect(fallback_targets=fallback_targets)

    targets = run_context["targets"]
    if not targets:
        print("[!] No targets found. Add URLs in config/scope.txt or enter them when prompted.")
        return

    print(f"\n[+] Target type: {run_context['target_type']}")
    print(f"[+] Targets loaded: {len(targets)}")
    print(f"[+] Selected test cases: {', '.join(run_context['selected_modules'])}")
    print(f"[+] Exploitation policy: {run_context['exploitation_policy']}")
    print(f"[+] Lab validation env: {run_context['lab_environment']}")

    all_endpoints = []
    recon_data = {}

    for target in targets:
        print(f"\n[+] Recon: {target}")
        recon_data[target] = recon.analyze_headers(target)

        print(f"[+] Crawling: {target}")
        crawled = crawler.crawl(target)

        if not crawled:
            crawled = [target]

        print(f"    Endpoints found: {len(crawled)}")
        all_endpoints.extend(convert_to_endpoints(crawled))

    deduped = {}
    for endpoint in all_endpoints:
        deduped[endpoint.url] = endpoint
    all_endpoints = list(deduped.values())

    print(f"\n[+] Total unique endpoints discovered: {len(all_endpoints)}")
    print("[+] Running selected test cases...")

    findings = scanner.run_modules(
        all_endpoints, selected_modules=run_context["selected_modules"]
    )

    run_context["recon"] = recon_data
    outputs = reporter.write(run_context, all_endpoints, findings, utils)

    print_summary(findings)
    print("\n[+] Output files")
    print(f"- Report:        {outputs['markdown']}")
    print(f"- Findings JSON: {outputs['findings_json']}")
    print(f"- Context JSON:  {outputs['context_json']}")
    print(f"- Endpoints:     {outputs['endpoints_json']}")


if __name__ == "__main__":
    main()
