"""
End-to-end test for the IncidentResponder.AI orchestrator.

This test runs the full workflow against a sample GuardDuty finding to ensure
that every agent executes successfully and that the final report is generated.
"""

import os
import sys
import json
import glob
import unittest
import shutil
from pathlib import Path

# Ensure project root is on path when tests run from repo root
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from orchestrator.orchestrator import IncidentOrchestrator  # noqa: E402


class TestOrchestratorFlow(unittest.TestCase):
    """Validates the orchestrator end-to-end workflow."""

    SAMPLE_FILE = os.path.join("data", "sample_guardduty_1.json")

    def setUp(self):
        """Ensure a clean slate for the database and reports output."""
        self.reports_dir = Path("reports_test")
        self.db_path = Path("incident_reports_test.db")

        self._prev_reports_env = os.environ.get("REPORTS_DIR")
        self._prev_db_env = os.environ.get("INCIDENT_DB_PATH")
        os.environ["REPORTS_DIR"] = str(self.reports_dir)
        os.environ["INCIDENT_DB_PATH"] = str(self.db_path)

        if self.db_path.exists():
            self.db_path.unlink()

        if self.reports_dir.exists():
            shutil.rmtree(self.reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        """Clean up any artifacts generated during the test."""
        if self.db_path.exists():
            self.db_path.unlink()

        if self.reports_dir.exists():
            shutil.rmtree(self.reports_dir)

        # Restore environment variables
        if self._prev_reports_env is not None:
            os.environ["REPORTS_DIR"] = self._prev_reports_env
        else:
            os.environ.pop("REPORTS_DIR", None)

        if self._prev_db_env is not None:
            os.environ["INCIDENT_DB_PATH"] = self._prev_db_env
        else:
            os.environ.pop("INCIDENT_DB_PATH", None)

    def test_process_sample_guardduty_finding(self):
        """Runs orchestrator on a sample finding and validates the output."""
        orchestrator = IncidentOrchestrator(use_openai=False)
        report = orchestrator.process_incident(self.SAMPLE_FILE)

        # Validate that the report includes the critical sections
        self.assertIn("alert", report)
        self.assertIn("mitre_mapping", report)
        self.assertIn("recommended_actions", report)
        self.assertGreater(len(report["recommended_actions"]), 0)

        # Confirm a JSON report was written to disk
        generated_reports = glob.glob(str(self.reports_dir / "*_report.json"))
        self.assertEqual(len(generated_reports), 1, "Expected exactly one report file")

        with open(generated_reports[0], "r", encoding="utf-8") as handle:
            saved_report = json.load(handle)
            self.assertEqual(saved_report["alert"], report["alert"])
            self.assertEqual(saved_report["mitre_mapping"]["primary_technique"],
                             report["mitre_mapping"]["primary_technique"])


if __name__ == "__main__":
    unittest.main()

