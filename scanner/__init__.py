from __future__ import annotations

from .deps_auditor import scan_requirements_file
from .pth_auditor import Finding, scan_pth_directory
from .storage import ScanStore

SEVERITY_WEIGHTS = {
    "CRITICAL": 55,
    "HIGH": 35,
    "MEDIUM": 20,
    "LOW": 10,
}


def evaluate_findings(findings: list[Finding]) -> tuple[str, int]:
    if not findings:
        return "PASS", 0
    score = min(100, sum(SEVERITY_WEIGHTS.get(f.severity, 10) for f in findings))
    if any(f.severity == "CRITICAL" for f in findings) or score >= 60:
        return "CRITICAL", score
    return "WARN", score


__all__ = [
    "Finding",
    "ScanStore",
    "evaluate_findings",
    "scan_pth_directory",
    "scan_requirements_file",
]
