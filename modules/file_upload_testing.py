"""File upload testing indicators from forms and handler responses."""

from bs4 import BeautifulSoup

from models.prompts import EXPLOIT_METHODS, MITIGATIONS, REFERENCES
from models.severity import get_severity


def run(endpoints, utils, payload_rules):
    findings = []

    for ep in endpoints:
        resp = utils.http_request(ep.url)
        if not resp:
            continue

        soup = BeautifulSoup(resp.text, "html.parser")
        forms = soup.find_all("form")

        for form in forms:
            file_input = form.find("input", {"type": "file"})
            if not file_input:
                continue

            accept = (file_input.get("accept") or "").strip()
            if not accept:
                findings.append(
                    {
                        "type": "file_upload_testing",
                        "cwe": "CWE-434",
                        "severity": get_severity("file_upload_testing"),
                        "endpoint": ep.url,
                        "payload": "multipart/form-data with unrestricted file type",
                        "evidence": "File upload input found without explicit accept/type restrictions.",
                        "mitigation": MITIGATIONS["file_upload_testing"],
                        "exploitation_methods": "\n- " + "\n- ".join(EXPLOIT_METHODS["file_upload_testing"]),
                        "references": REFERENCES["file_upload_testing"],
                    }
                )
                break

    return findings
