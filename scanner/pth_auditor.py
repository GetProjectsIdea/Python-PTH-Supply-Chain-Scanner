from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import List

SUSPICIOUS_INDICATORS = (
    "os.environ",
    "169.254.169.254",
    "webhook.site",
    "git-credentials",
    "azure",
    "zlib.compress",
    "b64encode",
)


@dataclass
class Finding:
    rule_id: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    category: str
    target: str
    message: str
    remediation: str

    def to_dict(self) -> dict:
        return asdict(self)


def _inspect_python_module_ast(py_file: Path) -> List[str]:
    hits: List[str] = []
    try:
        source = py_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return hits

    lowered = source.lower()
    for marker in SUSPICIOUS_INDICATORS:
        if marker in lowered:
            hits.append(f"literal:{marker}")

    try:
        tree = ast.parse(source, filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in {"exec", "eval"}:
                    hits.append(f"call:{node.func.id}")
                elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                    "urlopen",
                    "post",
                    "system",
                    "Popen",
                }:
                    hits.append(f"attr:{node.func.attr}")
    except SyntaxError:
        hits.append("syntax_error_obfuscated")

    return sorted(set(hits))


def scan_pth_directory(site_packages_dir: str | Path) -> List[Finding]:
    root = Path(site_packages_dir)
    if not root.exists() or not root.is_dir():
        return []

    findings: List[Finding] = []
    for pth_file in sorted(root.glob("*.pth")):
        try:
            lines = pth_file.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for line_no, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            if (
                line.startswith("import ")
                or "exec(" in line
                or "eval(" in line
                or "__import__" in line
            ):
                findings.append(
                    Finding(
                        rule_id="PTH-001",
                        severity="CRITICAL",
                        category="pth_startup_hook",
                        target=f"{pth_file.name}:{line_no}",
                        message=f"Executable Python code found in .pth startup file: {line[:80]}",
                        remediation="Inspect the owning package, remove the .pth file, and rotate environment credentials.",
                    )
                )

                if line.startswith("import "):
                    mod_name = line.replace("import ", "", 1).split(";")[0].split()[0].strip()
                    candidate_py = root / f"{mod_name}.py"
                    if candidate_py.exists():
                        ast_hits = _inspect_python_module_ast(candidate_py)
                        if ast_hits:
                            findings.append(
                                Finding(
                                    rule_id="PTH-002",
                                    severity="CRITICAL",
                                    category="credential_stealer_ast",
                                    target=candidate_py.name,
                                    message=f"Startup-imported module contains suspicious indicators: {', '.join(ast_hits)}",
                                    remediation="Isolate host immediately, pin safe package versions, and audit outbound network logs.",
                                )
                            )

    return findings
