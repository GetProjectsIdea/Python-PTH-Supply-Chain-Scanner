import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from app import create_app
from scanner import scan_pth_directory, scan_requirements_file


class SupplyChainScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)
        self.db_path = self.root / "test_scans.db"
        self.app = create_app(db_path=str(self.db_path))
        self.client = TestClient(self.app)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_safe_pth_file_passes(self) -> None:
        sp = self.root / "site-packages"
        sp.mkdir()
        (sp / "editable_pkg.pth").write_text("/opt/my_project/src\n", encoding="utf-8")
        findings = scan_pth_directory(sp)
        self.assertEqual(findings, [])

    def test_malicious_pth_and_stealer_module_detected(self) -> None:
        sp = self.root / "site-packages"
        sp.mkdir()
        (sp / "agent_framework_meta.pth").write_text(
            "import agent_framework_meta\n", encoding="utf-8"
        )
        (sp / "agent_framework_meta.py").write_text(
            "import os, urllib.request\nurl = 'https://webhook.site/test'\nenv = os.environ\n",
            encoding="utf-8",
        )
        findings = scan_pth_directory(sp)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("PTH-001", rule_ids)
        self.assertIn("PTH-002", rule_ids)

    def test_compromised_agent_framework_version_flagged(self) -> None:
        req = self.root / "requirements.txt"
        req.write_text("agent-framework==1.26.2\nfastapi==0.115.0\n", encoding="utf-8")
        findings = scan_requirements_file(req)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "DEP-001")
        self.assertEqual(findings[0].severity, "CRITICAL")

    def test_typosquat_and_unpinned_dependency_detected(self) -> None:
        req = self.root / "requirements.txt"
        req.write_text("reqeusts==2.31.0\nfastapi>=0.115.0\n", encoding="utf-8")
        findings = scan_requirements_file(req)
        rule_ids = {f.rule_id for f in findings}
        self.assertIn("DEP-002", rule_ids)
        self.assertIn("DEP-003", rule_ids)

    def test_api_scan_persists_to_sqlite_and_updates_stats(self) -> None:
        sp = self.root / "site-packages"
        sp.mkdir()
        (sp / "evil.pth").write_text("import evil_hook\n", encoding="utf-8")

        resp = self.client.post("/api/scan", json={"site_packages_dir": str(sp)})
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "CRITICAL")
        self.assertEqual(data["findings_count"], 1)

        stats = self.client.get("/api/stats").json()
        self.assertEqual(stats["total_scans"], 1)
        self.assertEqual(stats["critical_scans"], 1)

    def test_dashboard_renders(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Supply-Chain Security Scanner", resp.text)


if __name__ == "__main__":
    unittest.main()
