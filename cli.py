from __future__ import annotations

import argparse
import json
import sys

from scanner import evaluate_findings, scan_pth_directory, scan_requirements_file


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Python .pth & PyPI Supply-Chain Security Scanner"
    )
    parser.add_argument(
        "--site-packages", help="Path to site-packages directory to audit .pth hooks"
    )
    parser.add_argument(
        "--requirements", help="Path to requirements.txt to audit dependencies"
    )
    args = parser.parse_args()

    findings = []
    if args.site_packages:
        findings.extend(scan_pth_directory(args.site_packages))
    if args.requirements:
        findings.extend(scan_requirements_file(args.requirements))

    status, risk_score = evaluate_findings(findings)
    print(
        json.dumps(
            {
                "status": status,
                "risk_score": risk_score,
                "findings_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        )
    )
    return 2 if status == "CRITICAL" else 0


if __name__ == "__main__":
    sys.exit(main())
