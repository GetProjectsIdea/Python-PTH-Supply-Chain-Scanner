from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


class ScanStore:
    def __init__(self, db_path: str | Path = "supply_chain_scans.db") -> None:
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    target_label TEXT NOT NULL,
                    status TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    findings_count INTEGER NOT NULL,
                    findings_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def save_report(
        self,
        *,
        target_label: str,
        status: str,
        risk_score: int,
        findings: List[Dict[str, Any]],
    ) -> int:
        created_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO scan_reports (
                    created_at, target_label, status, risk_score, findings_count, findings_json
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    created_at,
                    target_label,
                    status,
                    risk_score,
                    len(findings),
                    json.dumps(findings),
                ),
            )
            conn.commit()
            return int(cur.lastrowid)

    def recent_reports(self, limit: int = 20) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_reports ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            out = []
            for row in rows:
                item = dict(row)
                item["findings"] = json.loads(item["findings_json"])
                out.append(item)
            return out

    def stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_scans,
                    SUM(CASE WHEN status = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_scans,
                    SUM(CASE WHEN status = 'WARN' THEN 1 ELSE 0 END) AS warn_scans,
                    SUM(CASE WHEN status = 'PASS' THEN 1 ELSE 0 END) AS pass_scans
                FROM scan_reports
                """
            ).fetchone()
            return {
                "total_scans": row["total_scans"] or 0,
                "critical_scans": row["critical_scans"] or 0,
                "warn_scans": row["warn_scans"] or 0,
                "pass_scans": row["pass_scans"] or 0,
            }
