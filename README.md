# Python .pth & PyPI Supply-Chain Security Scanner

> A defensive security auditor built with FastAPI, SQLite, and Python's AST module to detect malicious `site-packages` startup hooks, typosquats, and compromised PyPI releases.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## 📌 Overview

Python provides a startup feature via `.pth` files in `site-packages`. While designed to add directory paths to `sys.path`, lines beginning with `import ` execute arbitrary Python statements every time the interpreter launches. Threat actors have actively abused this vector (such as the November 2026 compromise of Microsoft's `agent-framework` package) to drop persistence hooks and exfiltrate secrets.

This repository provides:
1. **`.pth` Startup Hook Auditor (`scanner/pth_auditor.py`):** Scans virtual environments for executable lines (`PTH-001`) and uses Abstract Syntax Tree (AST) inspection to flag credential harvesting and exfiltration markers (`PTH-002`).
2. **PyPI Dependency Auditor (`scanner/deps_auditor.py`):** Checks `requirements.txt` against known compromised package releases (`DEP-001`), warns on unpinned dependencies (`DEP-002`), and identifies typosquatted names using sequence matching (`DEP-003`).
3. **SQLite Persistence (`scanner/storage.py`):** Stores scan history, findings count, and computes a weighted 0–100 risk score.
4. **FastAPI Web Dashboard (`app.py` & `templates/dashboard.html`):** Interactive dark-mode dashboard displaying KPI metrics and live scan runners.
5. **CI/CD Terminal Runner (`cli.py`):** Returns exit code `2` on `CRITICAL` findings for automated pipeline gating.

---

## 🚀 Quickstart

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/GetProjectsIdea/Python-PTH-Supply-Chain-Scanner.git
cd Python-PTH-Supply-Chain-Scanner
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run Automated Unit Tests

```bash
python -m unittest discover -s tests -v
```

### 3. Run CLI Scanner

```bash
# Scan a requirements file
python cli.py --requirements requirements.txt

# Scan a site-packages directory
python cli.py --site-packages .venv/lib/python3.11/site-packages
```

### 4. Launch the Web Dashboard

```bash
python app.py
```
Open [http://127.0.0.1:5060](http://127.0.0.1:5060) in your browser.

---

## 🛡️ Detection Rules

| Rule ID | Severity | Category | Description |
|---|---|---|---|
| `PTH-001` | `CRITICAL` | `pth_startup_hook` | Executable `import`, `exec()`, or `eval()` statement inside a `.pth` file |
| `PTH-002` | `CRITICAL` | `credential_stealer_ast` | Startup-imported module references `os.environ`, cloud metadata (`169.254.169.254`), or outbound HTTP exfiltration |
| `DEP-001` | `CRITICAL` | `compromised_release` | Package matches known compromised releases (e.g. `agent-framework==1.26.1`/`1.26.2`) |
| `DEP-002` | `MEDIUM` | `unpinned_dependency` | Dependency does not enforce strict equality (`==`) |
| `DEP-003` | `HIGH` | `typosquat_suspect` | Package name closely matches a popular package (e.g. `reqeusts` vs `requests`) |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
