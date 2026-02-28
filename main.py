"""
main.py
---------
BugPilot interactive controller.
"""

import os

from core.crawler import Crawler
from core.lab_validator import LabValidator
from core.recon import Recon
from core.reporter import Reporter
from core.scanner import Scanner
from core.utils import Utils
from core.validator import Validator
from core.workflow import Workflow
from models.endpoint_class import Endpoint

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


console = Console() if RICH_AVAILABLE else None


def severity_style(severity):
    sev = str(severity).lower()
    styles = {
        "critical": "[bold red]CRITICAL[/bold red]",
        "high": "[bold orange3]HIGH[/bold orange3]",
        "medium": "[bold yellow]MEDIUM[/bold yellow]",
        "low": "[bold bright_green]LOW[/bold bright_green]",
    }
    return styles.get(sev, f"[cyan]{sev.upper()}[/cyan]")


def status_style(status):
    st = str(status).lower()
    if st == "validated":
        return "[bold bright_green]VALIDATED[/bold bright_green]"
    if st == "inconclusive":
        return "[bold yellow]INCONCLUSIVE[/bold yellow]"
    return f"[cyan]{st.upper()}[/cyan]"


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

    if RICH_AVAILABLE:
        table = Table(title="Scan Summary", style="green")
        table.add_column("Metric", style="bright_green")
        table.add_column("Value", justify="right", style="cyan")
        table.add_row("Total Findings", str(len(findings)))
        table.add_row("[bold red]Critical[/bold red]", str(severities["critical"]))
        table.add_row("[bold orange3]High[/bold orange3]", str(severities["high"]))
        table.add_row("[bold yellow]Medium[/bold yellow]", str(severities["medium"]))
        table.add_row("[bold bright_green]Low[/bold bright_green]", str(severities["low"]))
        console.print(table)
        return

    print("\n====== BUGPILOT SUMMARY ======")
    print(f"Total Findings: {len(findings)}")
    print(f"Critical: {severities['critical']}")
    print(f"High:     {severities['high']}")
    print(f"Medium:   {severities['medium']}")
    print(f"Low:      {severities['low']}")


def print_findings_preview(findings):
    if RICH_AVAILABLE:
        if not findings:
            console.print(
                Panel(
                    "[yellow]No vulnerabilities detected in this run.[/yellow]",
                    title="[bold cyan]Findings Preview[/bold cyan]",
                    border_style="cyan",
                )
            )
            return

        table = Table(title="[bold cyan]Findings Preview[/bold cyan]", style="green")
        table.add_column("#", style="bright_green", justify="right")
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="white")
        table.add_column("Source Target", style="green")
        table.add_column("Module", style="cyan")
        table.add_column("CWE", style="green")

        for idx, finding in enumerate(findings, start=1):
            table.add_row(
                str(idx),
                str(finding.get("type", "unknown")),
                severity_style(finding.get("severity", "low")),
                str(finding.get("endpoint", "N/A")),
                str(finding.get("module", "unknown")),
                str(finding.get("cwe", "N/A")),
                style="dim" if idx % 2 == 0 else "",
            )
        console.print(table)
        return

    if not findings:
        print("\n[+] Findings Preview: no vulnerabilities detected in this run.")
        return

    print("\n[+] Findings Preview")
    for idx, finding in enumerate(findings, start=1):
        print(
            f"{idx}. type={finding.get('type', 'unknown')} "
            f"severity={str(finding.get('severity', 'low')).upper()} "
            f"source={finding.get('endpoint', 'N/A')} "
            f"module={finding.get('module', 'unknown')} "
            f"cwe={finding.get('cwe', 'N/A')}"
        )


def select_findings_for_lab_validation(findings):
    if not findings:
        return []

    prompt = (
        "Choose finding numbers to validate in isolated lab "
        "(comma-separated), 'all', or press Enter to skip: "
    )
    raw = input(prompt).strip().lower()
    if not raw:
        return []
    if raw == "all":
        return list(range(len(findings)))

    selected = []
    for token in [part.strip() for part in raw.split(",") if part.strip()]:
        if token.isdigit():
            idx = int(token) - 1
            if 0 <= idx < len(findings):
                selected.append(idx)
    return sorted(set(selected))


def print_lab_validation_results(results):
    if RICH_AVAILABLE:
        table = Table(title="[bold magenta]Isolated Lab Validation Results[/bold magenta]", style="green")
        table.add_column("#", style="bright_green", justify="right")
        table.add_column("Type", style="cyan")
        table.add_column("Severity", style="white")
        table.add_column("Status", style="white")
        table.add_column("Source Target", style="cyan")
        table.add_column("Lab Target", style="green")
        table.add_column("Proof", style="bright_green")
        for idx, result in enumerate(results, start=1):
            table.add_row(
                str(idx),
                str(result.get("vulnerability_type", "unknown")),
                severity_style(result.get("severity", "low")),
                status_style(result.get("status", "inconclusive")),
                str(result.get("source_target", "N/A")),
                str(result.get("lab_target", "N/A")),
                str(result.get("proof", "")),
                style="dim" if idx % 2 == 0 else "",
            )
        console.print(table)
        return

    print("\n[+] Isolated Lab Validation Results")
    for idx, result in enumerate(results, start=1):
        print(
            f"{idx}. type={result.get('vulnerability_type', 'unknown')} "
            f"severity={str(result.get('severity', 'low')).upper()} "
            f"status={result.get('status', 'inconclusive')} "
            f"source={result.get('source_target', 'N/A')} "
            f"lab={result.get('lab_target', 'N/A')} "
            f"proof={result.get('proof', '')}"
        )


def main():
    if RICH_AVAILABLE:
        console.print(
            Panel(
                "[bold bright_green]BugPilot Scanner[/bold bright_green]\n"
                "[green]Authorized Security Testing Workflow[/green]",
                border_style="green",
            )
        )
    else:
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
    lab_validator = LabValidator(utils, scanner.payload_rules)
    recon = Recon(utils)
    reporter = Reporter()
    workflow = Workflow()

    fallback_targets = load_scope()
    run_context = workflow.collect(fallback_targets=fallback_targets)

    targets = run_context["targets"]
    if not targets:
        if RICH_AVAILABLE:
            console.print(
                "[bold red][!][/bold red] No targets found. "
                "Add URLs in config/scope.txt or enter them when prompted."
            )
        else:
            print("[!] No targets found. Add URLs in config/scope.txt or enter them when prompted.")
        return

    if RICH_AVAILABLE:
        context_table = Table(title="Run Context", style="green")
        context_table.add_column("Field", style="bright_green")
        context_table.add_column("Value", style="cyan")
        context_table.add_row("Target type", run_context["target_type"])
        context_table.add_row("Targets loaded", str(len(targets)))
        context_table.add_row("Selected test cases", ", ".join(run_context["selected_modules"]))
        context_table.add_row("Exploitation policy", run_context["exploitation_policy"])
        context_table.add_row("Lab validation env", run_context["lab_environment"])
        console.print(context_table)
    else:
        print(f"\n[+] Target type: {run_context['target_type']}")
        print(f"[+] Targets loaded: {len(targets)}")
        print(f"[+] Selected test cases: {', '.join(run_context['selected_modules'])}")
        print(f"[+] Exploitation policy: {run_context['exploitation_policy']}")
        print(f"[+] Lab validation env: {run_context['lab_environment']}")

    all_endpoints = []
    recon_data = {}

    for target in targets:
        if RICH_AVAILABLE:
            console.print(f"\n[bold green][+][/bold green] Recon: [cyan]{target}[/cyan]")
        else:
            print(f"\n[+] Recon: {target}")
        recon_data[target] = recon.analyze_headers(target)

        if RICH_AVAILABLE:
            console.print(f"[bold green][+][/bold green] Crawling: [cyan]{target}[/cyan]")
        else:
            print(f"[+] Crawling: {target}")
        crawled = crawler.crawl(target)

        if not crawled:
            crawled = [target]

        if RICH_AVAILABLE:
            console.print(f"    [green]Endpoints found:[/green] [cyan]{len(crawled)}[/cyan]")
        else:
            print(f"    Endpoints found: {len(crawled)}")
        all_endpoints.extend(convert_to_endpoints(crawled))

    deduped = {}
    for endpoint in all_endpoints:
        deduped[endpoint.url] = endpoint
    all_endpoints = list(deduped.values())

    if RICH_AVAILABLE:
        console.print(
            f"\n[bold green][+][/bold green] Total unique endpoints discovered: "
            f"[cyan]{len(all_endpoints)}[/cyan]"
        )
        console.print("[bold green][+][/bold green] Running selected test cases...")
    else:
        print(f"\n[+] Total unique endpoints discovered: {len(all_endpoints)}")
        print("[+] Running selected test cases...")

    findings = scanner.run_modules(
        all_endpoints, selected_modules=run_context["selected_modules"]
    )

    run_context["recon"] = recon_data
    outputs = reporter.write(run_context, all_endpoints, findings, utils)

    print_summary(findings)
    print_findings_preview(findings)

    lab_results = []
    selected_indices = select_findings_for_lab_validation(findings)
    if selected_indices:
        if RICH_AVAILABLE:
            console.print(
                Panel(
                    f"[green]Running isolated lab validation for findings:[/green] [bold cyan]{', '.join(str(i + 1) for i in selected_indices)}[/bold cyan]",
                    border_style="magenta",
                )
            )
        for idx in selected_indices:
            result = lab_validator.validate(findings[idx], run_context["lab_environment"])
            result["finding_number"] = idx + 1
            lab_results.append(result)
        print_lab_validation_results(lab_results)

        lab_results_path = os.path.join(outputs["run_path"], "lab_validation_results.json")
        utils.write_json(lab_results_path, lab_results)
        outputs["lab_validation_json"] = lab_results_path

    if RICH_AVAILABLE:
        output_table = Table(title="Output Files", style="green")
        output_table.add_column("Artifact", style="bright_green")
        output_table.add_column("Path", style="cyan")
        output_table.add_row("Report", outputs["markdown"])
        output_table.add_row("Findings JSON", outputs["findings_json"])
        output_table.add_row("Context JSON", outputs["context_json"])
        output_table.add_row("Endpoints JSON", outputs["endpoints_json"])
        if "lab_validation_json" in outputs:
            output_table.add_row("Lab Validation JSON", outputs["lab_validation_json"])
        console.print(output_table)
    else:
        print("\n[+] Output files")
        print(f"- Report:        {outputs['markdown']}")
        print(f"- Findings JSON: {outputs['findings_json']}")
        print(f"- Context JSON:  {outputs['context_json']}")
        print(f"- Endpoints:     {outputs['endpoints_json']}")
        if "lab_validation_json" in outputs:
            print(f"- Lab Validation:{outputs['lab_validation_json']}")


if __name__ == "__main__":
    main()
