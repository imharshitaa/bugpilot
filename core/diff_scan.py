"""Differential scan helpers (before/after comparison)."""


def finding_key(finding):
    return (
        str(finding.get("normalized_type") or finding.get("type", "unknown")).lower(),
        str(finding.get("endpoint", "")),
        str(finding.get("payload", "N/A")),
    )


def compare_findings(baseline_findings, current_findings):
    baseline_map = {finding_key(f): f for f in baseline_findings}
    current_map = {finding_key(f): f for f in current_findings}

    baseline_keys = set(baseline_map.keys())
    current_keys = set(current_map.keys())

    new_keys = sorted(current_keys - baseline_keys)
    resolved_keys = sorted(baseline_keys - current_keys)
    persisting_keys = sorted(current_keys & baseline_keys)

    return {
        "baseline_count": len(baseline_findings),
        "current_count": len(current_findings),
        "new_count": len(new_keys),
        "resolved_count": len(resolved_keys),
        "persisting_count": len(persisting_keys),
        "new_findings": [current_map[k] for k in new_keys],
        "resolved_findings": [baseline_map[k] for k in resolved_keys],
        "persisting_findings": [current_map[k] for k in persisting_keys],
    }
