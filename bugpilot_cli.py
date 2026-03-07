"""Command-line entrypoint for BugPilot."""

import argparse
import datetime
import json
import os
import shlex
import subprocess
import sys

from core.crawler import Crawler
from core.recon import Recon
from core.utils import Utils


PROJECT_NAME = "BugPilot"
PROJECT_LINK = "https://github.com/imharshitaa/bugpilot"


def _run_main_with_args(extra_args):
    root = os.path.dirname(os.path.abspath(__file__))
    main_py = os.path.join(root, "main.py")
    cmd = [sys.executable, main_py] + list(extra_args)
    return subprocess.call(cmd)


def _print_banner():
    print(f"{PROJECT_NAME}")
    print(f"GitHub: {PROJECT_LINK}")
    print("")
    print("Quick Start:")
    print("1) bugpilot scan https://target")
    print("2) bugpilot test https://target -export")
    print("3) bugpilot --help")


def _sanitize_target(target):
    value = str(target or "").strip()
    return value if value.startswith(("http://", "https://")) else ""


def _latest_run_dir(root):
    output_dir = os.path.join(root, "reports", "output")
    if not os.path.isdir(output_dir):
        return None
    runs = [
        os.path.join(output_dir, d)
        for d in os.listdir(output_dir)
        if d.startswith("run_") and os.path.isdir(os.path.join(output_dir, d))
    ]
    if not runs:
        return None
    return max(runs, key=os.path.getmtime)


def _write_export(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _export_path(command, target, export_arg):
    if export_arg and export_arg not in ("true", "1", "yes"):
        return export_arg
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = (
        target.replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(":", "_")
    )
    return os.path.join("reports", "output", f"{command}_{safe_target}_{ts}.json")


def _extract_export(args):
    tokens = list(args or [])
    export_enabled = False
    export_value = ""

    i = 0
    cleaned = []
    while i < len(tokens):
        token = tokens[i]
        if token in ("-export", "--export"):
            export_enabled = True
            if i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                export_value = tokens[i + 1]
                i += 2
                continue
            i += 1
            continue
        cleaned.append(token)
        i += 1
    return cleaned, export_enabled, export_value


def _scan_command(scan_args):
    root = os.path.dirname(os.path.abspath(__file__))
    args, export_enabled, export_value = _extract_export(scan_args)

    forwarded = list(args)
    target = ""
    if forwarded and forwarded[0].startswith(("http://", "https://")):
        target = forwarded.pop(0)
        forwarded = [
            "--headless",
            "--targets",
            target,
            "--modules",
            "all",
            "--formats",
            "markdown,json,sarif",
        ] + forwarded

    if export_enabled:
        if "--formats" not in forwarded:
            forwarded += ["--formats", "json"]
        elif "json" not in " ".join(forwarded):
            forwarded += ["--formats", "json"]

    code = _run_main_with_args(forwarded)

    if export_enabled:
        run_dir = _latest_run_dir(root)
        if run_dir:
            findings = os.path.join(run_dir, "findings.json")
            if os.path.exists(findings):
                with open(findings, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                path = _export_path("scan", target or "manual", export_value)
                _write_export(path, {"command": "scan", "target": target, "findings": payload})
                print(f"[+] Exported JSON: {path}")

    return code


def _recon_command(target, export_value=""):
    target = _sanitize_target(target)
    if not target:
        print("[!] recon requires a valid target URL.")
        return 1

    utils = Utils()
    recon = Recon(utils)
    result = recon.analyze_headers(target)
    if not result:
        print("[!] No recon response received.")
        return 1
    print("[+] Recon result")
    print(json.dumps(result, indent=2))

    if export_value is not None:
        path = _export_path("recon", target, export_value)
        _write_export(path, {"command": "recon", "target": target, "result": result})
        print(f"[+] Exported JSON: {path}")
    return 0


def _crawl_command(target, export_value=""):
    target = _sanitize_target(target)
    if not target:
        print("[!] crawl requires a valid target URL.")
        return 1

    utils = Utils()
    crawler = Crawler(utils)
    urls = crawler.crawl(target)
    print(f"[+] Endpoints discovered: {len(urls)}")
    for url in urls:
        print(url)

    if export_value is not None:
        path = _export_path("crawl", target, export_value)
        _write_export(path, {"command": "crawl", "target": target, "endpoints": urls})
        print(f"[+] Exported JSON: {path}")
    return 0


def _test_like_command(command, target, extra_args, export_enabled=False, export_value=""):
    target = _sanitize_target(target)
    if not target:
        print(f"[!] {command} requires a valid target URL.")
        return 1

    extra, extra_export, extra_export_value = _extract_export(extra_args)
    export_enabled = export_enabled or extra_export
    export_value = export_value or extra_export_value

    if command == "test":
        forwarded = [
            "--headless",
            "--targets",
            target,
            "--modules",
            "all",
            "--formats",
            "markdown,json,sarif",
            "--validate-findings",
            "none",
        ] + extra
    else:
        # exploit = safe evidence/validation mode.
        forwarded = [
            "--headless",
            "--targets",
            target,
            "--modules",
            "all",
            "--formats",
            "json",
            "--validate-findings",
            "all",
        ] + extra

    if export_enabled and "--formats" not in forwarded:
        forwarded += ["--formats", "json"]

    code = _run_main_with_args(forwarded)
    if export_enabled:
        root = os.path.dirname(os.path.abspath(__file__))
        run_dir = _latest_run_dir(root)
        if run_dir:
            findings = os.path.join(run_dir, "findings.json")
            if os.path.exists(findings):
                with open(findings, "r", encoding="utf-8") as f:
                    payload = json.load(f)
                path = _export_path(command, target, export_value)
                _write_export(path, {"command": command, "target": target, "findings": payload})
                print(f"[+] Exported JSON: {path}")
    return code


def cli():
    parser = argparse.ArgumentParser(prog="bugpilot", description="BugPilot CLI")
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run BugPilot scanner")
    scan_parser.add_argument("args", nargs=argparse.REMAINDER, help="Scan args (supports URL shortcut and -export).")

    recon_parser = subparsers.add_parser("recon", help="Run recon on target URL")
    recon_parser.add_argument("target", help="Target URL")
    recon_parser.add_argument("-export", dest="export", nargs="?", const="true", default=None, help="Export JSON (optional file path)")

    crawl_parser = subparsers.add_parser("crawl", help="Run crawler on target URL")
    crawl_parser.add_argument("target", help="Target URL")
    crawl_parser.add_argument("-export", dest="export", nargs="?", const="true", default=None, help="Export JSON (optional file path)")

    test_parser = subparsers.add_parser("test", help="Test target for vulnerabilities")
    test_parser.add_argument("target", help="Target URL")
    test_parser.add_argument("args", nargs=argparse.REMAINDER, help="Extra args for main.py (supports -export)")

    exploit_parser = subparsers.add_parser("exploit", help="Run safe evidence validation mode")
    exploit_parser.add_argument("target", help="Target URL")
    exploit_parser.add_argument("args", nargs=argparse.REMAINDER, help="Extra args for main.py (supports -export)")

    expoit_parser = subparsers.add_parser("expoit", help="Alias of exploit")
    expoit_parser.add_argument("target", help="Target URL")
    expoit_parser.add_argument("args", nargs=argparse.REMAINDER, help="Extra args for main.py (supports -export)")

    info_parser = subparsers.add_parser("info", help="Show project info and quick-start")
    info_parser.add_argument("args", nargs=argparse.REMAINDER)

    if len(sys.argv) == 1:
        _print_banner()
        parser.print_help()
        return 0

    parsed = parser.parse_args()
    if parsed.command == "info":
        _print_banner()
        return 0
    if parsed.command == "scan":
        return _scan_command(parsed.args)
    if parsed.command == "recon":
        return _recon_command(parsed.target, parsed.export)
    if parsed.command == "crawl":
        return _crawl_command(parsed.target, parsed.export)
    if parsed.command == "test":
        args, export_enabled, export_value = _extract_export(parsed.args)
        return _test_like_command("test", parsed.target, args, export_enabled, export_value)
    if parsed.command in ("exploit", "expoit"):
        args, export_enabled, export_value = _extract_export(parsed.args)
        return _test_like_command("exploit", parsed.target, args, export_enabled, export_value)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
