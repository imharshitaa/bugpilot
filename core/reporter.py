"""
reporter.py
------------
Writes structured outputs (JSON + Markdown) under reports/output.
"""

import datetime
import os


class Reporter:
    def __init__(self, output_base="reports/output"):
        self.output_base = output_base

    def _run_dir(self):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        run_id = f"run_{timestamp}"
        path = os.path.join(self.output_base, run_id)
        os.makedirs(path, exist_ok=True)
        return run_id, path

    def _severity_counts(self, findings):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            sev = str(finding.get("severity", "low")).lower()
            if sev in counts:
                counts[sev] += 1
        return counts

    def _build_markdown(self, run_context, endpoints, findings):
        counts = self._severity_counts(findings)
        now = datetime.datetime.now().isoformat()

        lines = [
            "# BugPilot Findings Report",
            "",
            "## Scan Context",
            f"- Scan Date: {now}",
            f"- Target Type: {run_context.get('target_type')}",
            f"- Targets: {', '.join(run_context.get('targets', []))}",
            f"- Exploitation Policy: {run_context.get('exploitation_policy')}",
            f"- Lab Validation Environment: {run_context.get('lab_environment')}",
            f"- Endpoints Discovered: {len(endpoints)}",
            f"- Findings: {len(findings)}",
            "",
            "## Severity Summary",
            f"- Critical: {counts['critical']}",
            f"- High: {counts['high']}",
            f"- Medium: {counts['medium']}",
            f"- Low: {counts['low']}",
            "",
            "## Selected Test Cases",
        ]

        for module, plan in run_context.get("test_plan", {}).items():
            lines.extend(
                [
                    f"### {module}",
                    f"- Attack Method: {plan.get('attack_method')}",
                    f"- Custom Scripts: {', '.join(plan.get('custom_scripts', []))}",
                    f"- Kali Tools: {', '.join(plan.get('tools', {}).get('kali', []))}",
                    f"- Open Source Tools: {', '.join(plan.get('tools', {}).get('opensource', []))}",
                    f"- Commands: {', '.join(plan.get('commands', []))}",
                    "",
                ]
            )

        lines.append("## Detailed Findings")
        lines.append("")

        if not findings:
            lines.append("No findings detected in this run.")
            lines.append("")

        for idx, finding in enumerate(findings, start=1):
            target_response = finding.get("target_response", {})
            lines.extend(
                [
                    f"### {idx}. {finding.get('type', 'unknown').upper()} ({finding.get('severity', 'low').upper()})",
                    f"- Module/Test Case: {finding.get('module', 'unknown')}",
                    f"- CWE: {finding.get('cwe', 'N/A')}",
                    f"- Vulnerability Point: {finding.get('vulnerability_point', 'N/A')}",
                    f"- Endpoint: {finding.get('endpoint', 'N/A')}",
                    f"- Payload/Test Input: {finding.get('payload', 'N/A')}",
                    f"- Evidence: {finding.get('evidence', 'N/A')}",
                    f"- Risk: {finding.get('risk', 'N/A')}",
                    f"- Mitigation: {finding.get('mitigation', 'N/A')}",
                    f"- References: {finding.get('references', 'N/A')}",
                    f"- Lab Validation (controlled environment): {finding.get('lab_validation', 'N/A')}",
                    "- Target Response Snapshot:",
                    f"  - status_code: {target_response.get('status_code')}",
                    f"  - content_type: {target_response.get('content_type')}",
                    f"  - server: {target_response.get('server')}",
                    f"  - content_length: {target_response.get('content_length')}",
                    "",
                ]
            )

        return "\n".join(lines)

    def write(self, run_context, endpoints, findings, utils):
        run_id, run_path = self._run_dir()

        markdown = self._build_markdown(run_context, endpoints, findings)
        md_path = os.path.join(run_path, "report.md")
        json_path = os.path.join(run_path, "findings.json")
        context_path = os.path.join(run_path, "context.json")
        endpoints_path = os.path.join(run_path, "endpoints.json")

        with open(md_path, "w", encoding="utf-8") as f:
            f.write(markdown)

        utils.write_json(json_path, findings)
        utils.write_json(context_path, run_context)
        utils.write_json(endpoints_path, [endpoint.serialize() for endpoint in endpoints])

        return {
            "run_id": run_id,
            "run_path": run_path,
            "markdown": md_path,
            "findings_json": json_path,
            "context_json": context_path,
            "endpoints_json": endpoints_path,
        }
