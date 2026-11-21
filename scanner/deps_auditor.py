from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Dict, List, Set

from .pth_auditor import Finding

POPULAR_PACKAGES: Set[str] = {
    "requests",
    "fastapi",
    "uvicorn",
    "flask",
    "django",
    "numpy",
    "pandas",
    "pydantic",
    "sqlalchemy",
    "pytest",
    "httpx",
    "jinja2",
    "openai",
    "anthropic",
    "agent-framework",
    "langchain",
    "ollama",
}

COMPROMISED_ADVISORIES: Dict[str, Set[str]] = {
    "agent-framework": {"1.26.1", "1.26.2"},
}

REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|>|<)?\s*([A-Za-z0-9_.-]+)?"
)


def scan_requirements_file(req_path: str | Path) -> List[Finding]:
    path = Path(req_path)
    if not path.exists() or not path.is_file():
        return []

    findings: List[Finding] = []
    for line_no, raw_line in enumerate(
        path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1
    ):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue

        match = REQ_LINE_RE.match(line)
        if not match:
            continue

        pkg_name = match.group(1).lower().replace("_", "-")
        operator = match.group(2) or ""
        version = match.group(3) or ""

        if pkg_name in COMPROMISED_ADVISORIES and version in COMPROMISED_ADVISORIES[pkg_name]:
            findings.append(
                Finding(
                    rule_id="DEP-001",
                    severity="CRITICAL",
                    category="compromised_release",
                    target=f"{pkg_name}=={version} (line {line_no})",
                    message=f"Known compromised PyPI release detected: {pkg_name} {version}.",
                    remediation="Pin to a verified safe version (e.g., 1.26.0 for agent-framework) and rotate secrets.",
                )
            )

        if operator != "==":
            findings.append(
                Finding(
                    rule_id="DEP-002",
                    severity="MEDIUM",
                    category="unpinned_dependency",
                    target=f"{pkg_name} (line {line_no})",
                    message=f"Dependency '{line}' is not strictly pinned with '=='.",
                    remediation="Pin exact tested versions (e.g., package==1.2.3) to block unexpected upstream updates.",
                )
            )

        if pkg_name not in POPULAR_PACKAGES:
            close = difflib.get_close_matches(pkg_name, POPULAR_PACKAGES, n=1, cutoff=0.80)
            if close:
                findings.append(
                    Finding(
                        rule_id="DEP-003",
                        severity="HIGH",
                        category="typosquat_suspect",
                        target=f"{pkg_name} (line {line_no})",
                        message=f"Package '{pkg_name}' closely resembles popular package '{close[0]}'.",
                        remediation=f"Verify spelling in requirements.txt; did you mean '{close[0]}'?",
                    )
                )

    return findings
