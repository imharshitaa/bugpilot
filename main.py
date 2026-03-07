"""
main.py
---------
BugPilot interactive controller.
"""

import argparse
import json
import os
import sys
from urllib.parse import urlsplit

from core.crawler import Crawler
from core.diff_scan import compare_findings
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


def parse_csv(raw):
    if not raw:
        return []
    return [item.strip() for item in str(raw).split(",") if item.strip()]


def load_replay_session(path):
    if not path:
        return None
    if not os.path.exists(path):
        raise FileNotFoundError(f"Replay session file not found: {path}")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_args():
    parser = argparse.ArgumentParser(description="BugPilot scanner")
    parser.add_argument("--headless", action="store_true", help="Run in CI/CD non-interactive mode.")
    parser.add_argument("--target-type", default="web_app", help="Target type for headless mode.")
    parser.add_argument("--targets", default="", help="Comma separated targets for headless mode.")
    parser.add_argument("--modules", default="all", help="Comma separated modules or 'all'.")
    parser.add_argument("--lab-environment", default="local-lab", help="Lab environment name or URL.")
    parser.add_argument(
        "--formats",
        default="markdown,json",
        help="Output formats: markdown,json,sarif (comma separated).",
    )
    parser.add_argument(
        "--validate-findings",
        default="none",
        help="Lab validation selection in headless mode: none|all|1,2,3",
    )
    parser.add_argument(
        "--baseline-findings",
        default="",
        help="Path to baseline findings.json for differential scanning.",
    )
    parser.add_argument(
        "--replay-session",
        default="",
        help="Path to prior session/context json to replay.",
    )
    parser.add_argument(
        "--lab-auto-docker",
        action="store_true",
        help="Run lab validation via ephemeral docker curl container when possible.",
    )
    parser.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit non-zero in headless mode if findings are detected.",
    )
    return parser.parse_args()


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


def select_findings_for_lab_validation_headless(findings, selector):
    if not findings:
        return []
    raw = str(selector or "none").strip().lower()
    if raw in ("", "none", "skip"):
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


def print_differential_summary(diff_result):
    if not diff_result:
        return

    if RICH_AVAILABLE:
        table = Table(title="[bold blue]Differential Scan Summary[/bold blue]", style="blue")
        table.add_column("Metric", style="bright_blue")
        table.add_column("Value", justify="right", style="cyan")
        table.add_row("Baseline Findings", str(diff_result.get("baseline_count", 0)))
        table.add_row("Current Findings", str(diff_result.get("current_count", 0)))
        table.add_row("New", str(diff_result.get("new_count", 0)))
        table.add_row("Resolved", str(diff_result.get("resolved_count", 0)))
        table.add_row("Persisting", str(diff_result.get("persisting_count", 0)))
        console.print(table)
        return

    print("\n[+] Differential Scan Summary")
    print(f"Baseline:  {diff_result.get('baseline_count', 0)}")
    print(f"Current:   {diff_result.get('current_count', 0)}")
    print(f"New:       {diff_result.get('new_count', 0)}")
    print(f"Resolved:  {diff_result.get('resolved_count', 0)}")
    print(f"Persisting:{diff_result.get('persisting_count', 0)}")


def print_module_progress(event, data):
    module = data.get("module", "unknown")
    if not RICH_AVAILABLE:
        if event == "start":
            print(f"[~] Running module: {module}")
        elif event == "done":
            stats = data.get("stats", {})
            print(
                f"[+] {module}: completed | findings={data.get('findings', 0)} "
                f"blocked={stats.get('blocked', 0)} timeouts={stats.get('timeouts', 0)} errors={stats.get('errors', 0)}"
            )
        elif event == "error":
            print(f"[!] {module}: failed | {data.get('error', 'unknown error')}")
        return

    if event == "start":
        mode = "FAST" if data.get("fast_mode") else "FULL"
        console.print(
            f"[bold cyan][~][/bold cyan] [cyan]{module}[/cyan] "
            f"started ({mode} mode, endpoints={data.get('endpoints', 0)})"
        )
    elif event == "done":
        stats = data.get("stats", {})
        console.print(
            f"[bold bright_green][+][/bold bright_green] [cyan]{module}[/cyan] done | "
            f"findings={data.get('findings', 0)} blocked={stats.get('blocked', 0)} "
            f"timeouts={stats.get('timeouts', 0)} errors={stats.get('errors', 0)}"
        )
    elif event == "error":
        console.print(
            f"[bold red][!][/bold red] [cyan]{module}[/cyan] failed | "
            f"{data.get('error', 'unknown error')}"
        )


def _short_url(url, max_len=90):
    value = str(url or "")
    if len(value) <= max_len:
        return value
    parsed = urlsplit(value)
    compact = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    if len(compact) <= max_len:
        return compact
    return value[: max_len - 3] + "..."


def print_request_event(event):
    module = event.get("module", "unknown")
    method = str(event.get("method", "GET")).upper()
    url = _short_url(event.get("url", ""))
    status_code = event.get("status_code")
    outcome = event.get("outcome", "response")
    blocked = bool(event.get("blocked", False))

    if not RICH_AVAILABLE:
        if outcome == "response":
            block_tag = " BLOCKED" if blocked else ""
            print(f"    [{module}] {method} {url} -> {status_code}{block_tag}")
        elif outcome == "timeout":
            print(f"    [{module}] {method} {url} -> TIMEOUT")
        else:
            print(f"    [{module}] {method} {url} -> ERROR")
        return

    if outcome == "timeout":
        console.print(
            f"    [bold magenta][TIMEOUT][/bold magenta] "
            f"[dim]{module}[/dim] [cyan]{method}[/cyan] [white]{url}[/white]"
        )
        return
    if outcome == "error":
        console.print(
            f"    [bold red][ERROR][/bold red] "
            f"[dim]{module}[/dim] [cyan]{method}[/cyan] [white]{url}[/white]"
        )
        return

    code = int(status_code) if status_code is not None else 0
    if code >= 500:
        code_style = "[bold red]"
    elif code >= 400:
        code_style = "[bold yellow]"
    elif code >= 300:
        code_style = "[bold blue]"
    else:
        code_style = "[bold bright_green]"

    block_flag = " [bold red]BLOCKED[/bold red]" if blocked else ""
    console.print(
        f"    [dim]{module}[/dim] [cyan]{method}[/cyan] [white]{url}[/white] -> "
        f"{code_style}{code}[/]{block_flag}"
    )


def print_module_status_table(module_stats, findings):
    finding_count_by_module = {}
    for finding in findings:
        module = finding.get("module", "unknown")
        finding_count_by_module[module] = finding_count_by_module.get(module, 0) + 1

    if RICH_AVAILABLE:
        table = Table(title="[bold green]Module Execution Status[/bold green]", style="green")
        table.add_column("Module", style="cyan")
        table.add_column("Requests", justify="right", style="green")
        table.add_column("Blocked", justify="right", style="yellow")
        table.add_column("Timeouts", justify="right", style="magenta")
        table.add_column("Errors", justify="right", style="red")
        table.add_column("Findings", justify="right", style="bright_green")
        table.add_column("Status", style="white")

        for module, stats in sorted(module_stats.items()):
            status = "[bright_green]OK[/bright_green]"
            if stats.get("errors", 0) > 0 or stats.get("timeouts", 0) > 0:
                status = "[yellow]DEGRADED[/yellow]"
            if stats.get("requests", 0) == 0:
                status = "[red]NO RESPONSE[/red]"

            table.add_row(
                module,
                str(stats.get("requests", 0)),
                str(stats.get("blocked", 0)),
                str(stats.get("timeouts", 0)),
                str(stats.get("errors", 0)),
                str(finding_count_by_module.get(module, 0)),
                status,
            )
        console.print(table)
        return

    print("\n[+] Module Execution Status")
    for module, stats in sorted(module_stats.items()):
        status = "OK"
        if stats.get("errors", 0) > 0 or stats.get("timeouts", 0) > 0:
            status = "DEGRADED"
        if stats.get("requests", 0) == 0:
            status = "NO RESPONSE"
        print(
            f"- {module}: req={stats.get('requests', 0)} blocked={stats.get('blocked', 0)} "
            f"timeouts={stats.get('timeouts', 0)} errors={stats.get('errors', 0)} "
            f"findings={finding_count_by_module.get(module, 0)} status={status}"
        )


def main():
    args = parse_args()

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
    utils.set_request_event_callback(print_request_event)
    validator = Validator()
    crawler = Crawler(utils)
    scanner = Scanner(utils, validator)
    lab_validator = LabValidator(
        utils,
        scanner.payload_rules,
        docker_auto_validation=args.lab_auto_docker,
    )
    recon = Recon(utils)
    reporter = Reporter()
    workflow = Workflow()

    fallback_targets = load_scope()
    replay_data = load_replay_session(args.replay_session) if args.replay_session else None

    if args.headless:
        all_modules = list(scanner.available_modules().keys())
        selected_modules = all_modules
        if args.modules.lower() != "all":
            selected_modules = [m for m in parse_csv(args.modules) if m in all_modules]
            selected_modules = selected_modules or all_modules

        run_context = {
            "target_type": args.target_type,
            "targets": parse_csv(args.targets) or fallback_targets,
            "selected_modules": selected_modules,
            "test_plan": workflow.build_test_plan(selected_modules),
            "exploitation_policy": "Detect on target, validate exploitability only in controlled lab",
            "lab_environment": args.lab_environment,
            "output_formats": parse_csv(args.formats) or ["markdown", "json"],
            "execution_mode": "headless",
            "baseline_findings": args.baseline_findings or None,
        }

        if replay_data:
            run_context.update(
                {
                    "target_type": replay_data.get("target_type", run_context["target_type"]),
                    "targets": replay_data.get("targets", run_context["targets"]),
                    "selected_modules": replay_data.get(
                        "selected_modules", run_context["selected_modules"]
                    ),
                    "lab_environment": replay_data.get(
                        "lab_environment", run_context["lab_environment"]
                    ),
                    "output_formats": replay_data.get(
                        "output_formats", run_context["output_formats"]
                    ),
                }
            )
            run_context["test_plan"] = workflow.build_test_plan(run_context["selected_modules"])
            run_context["replay_source_run_id"] = replay_data.get("replay_source_run_id")
    else:
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

    if RICH_AVAILABLE and not args.headless:
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
        all_endpoints,
        selected_modules=run_context["selected_modules"],
        progress_callback=print_module_progress,
    )

    run_context["recon"] = recon_data
    outputs = reporter.write(run_context, all_endpoints, findings, utils)

    print_summary(findings)
    print_module_status_table(utils.get_all_module_stats(), findings)
    print_findings_preview(findings)

    lab_results = []
    if args.headless:
        selected_indices = select_findings_for_lab_validation_headless(
            findings, args.validate_findings
        )
    else:
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

    diff_result = None
    baseline_path = run_context.get("baseline_findings") or args.baseline_findings
    if baseline_path and os.path.exists(baseline_path):
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_payload = json.load(f)
        baseline_findings = (
            baseline_payload if isinstance(baseline_payload, list) else baseline_payload.get("findings", [])
        )
        diff_result = compare_findings(baseline_findings, findings)
        print_differential_summary(diff_result)
        diff_path = os.path.join(outputs["run_path"], "differential_scan.json")
        utils.write_json(diff_path, diff_result)
        outputs["differential_json"] = diff_path

    if RICH_AVAILABLE:
        output_table = Table(title="Output Files", style="green")
        output_table.add_column("Artifact", style="bright_green")
        output_table.add_column("Path", style="cyan")
        for label, key in [
            ("Report", "markdown"),
            ("Findings JSON", "findings_json"),
            ("SARIF", "sarif"),
            ("Context JSON", "context_json"),
            ("Endpoints JSON", "endpoints_json"),
            ("Session JSON", "session_json"),
            ("Lab Validation JSON", "lab_validation_json"),
            ("Differential JSON", "differential_json"),
        ]:
            if key in outputs:
                output_table.add_row(label, outputs[key])
        console.print(output_table)
    else:
        print("\n[+] Output files")
        for label, key in [
            ("Report", "markdown"),
            ("Findings JSON", "findings_json"),
            ("SARIF", "sarif"),
            ("Context JSON", "context_json"),
            ("Endpoints", "endpoints_json"),
            ("Session", "session_json"),
            ("Lab Validation", "lab_validation_json"),
            ("Differential", "differential_json"),
        ]:
            if key in outputs:
                print(f"- {label}: {outputs[key]}")

    if args.headless and args.fail_on_findings and findings:
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
