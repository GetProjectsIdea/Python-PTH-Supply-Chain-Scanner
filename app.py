from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from scanner import (
    ScanStore,
    evaluate_findings,
    scan_pth_directory,
    scan_requirements_file,
)

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"


class ScanPayload(BaseModel):
    site_packages_dir: Optional[str] = None
    requirements_path: Optional[str] = None


def create_app(db_path: str | None = None) -> FastAPI:
    app = FastAPI(title="Python .pth & PyPI Supply-Chain Scanner", version="1.0.0")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    store = ScanStore(db_path or os.getenv("SCANNER_DB_PATH", "supply_chain_scans.db"))

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return templates.TemplateResponse(
            request,
            "dashboard.html",
            {"stats": store.stats(), "reports": store.recent_reports(limit=15)},
        )

    @app.get("/api/stats")
    def api_stats() -> Dict[str, Any]:
        return store.stats()

    @app.get("/api/reports")
    def api_reports(limit: int = 20) -> Dict[str, Any]:
        return {"reports": store.recent_reports(limit=max(1, min(limit, 100)))}

    @app.post("/api/scan")
    def run_scan(payload: ScanPayload) -> Dict[str, Any]:
        findings = []
        labels = []
        if payload.site_packages_dir:
            labels.append(f"pth:{payload.site_packages_dir}")
            findings.extend(scan_pth_directory(payload.site_packages_dir))
        if payload.requirements_path:
            labels.append(f"req:{payload.requirements_path}")
            findings.extend(scan_requirements_file(payload.requirements_path))

        status, risk_score = evaluate_findings(findings)
        serialized = [f.to_dict() for f in findings]
        report_id = store.save_report(
            target_label=" | ".join(labels) or "empty_target",
            status=status,
            risk_score=risk_score,
            findings=serialized,
        )
        return {
            "report_id": report_id,
            "status": status,
            "risk_score": risk_score,
            "findings_count": len(serialized),
            "findings": serialized,
        }

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=5060, reload=False)
