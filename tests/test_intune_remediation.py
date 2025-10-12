"""Tests for Intune remediation guidance."""
from __future__ import annotations

from pathlib import Path
import re
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]


class IntuneRemediationTests(unittest.TestCase):
    """Validate remediation guidance for the Intune PushLaunch heuristic."""

    def setUp(self) -> None:
        self.heuristic_path = REPO_ROOT / "Analyzers" / "Heuristics" / "Intune.ps1"
        self.assertTrue(
            self.heuristic_path.exists(),
            msg=f"Heuristic file not found: {self.heuristic_path}",
        )
        self.content = self.heuristic_path.read_text(encoding="utf-8")

    def test_remediation_script_uses_enterprisemgmt_path(self) -> None:
        """Ensure the remediation script references the EnterpriseMgmt path."""
        start_token = "function Invoke-IntuneHeuristic-INTUNE-003"
        end_token = "function Invoke-IntuneHeuristic-INTUNE-002"
        try:
            start_index = self.content.index(start_token)
        except ValueError as exc:
            self.fail(f"Unable to locate INTUNE-003 function definition: {exc}")

        try:
            end_index = self.content.index(end_token, start_index + len(start_token))
        except ValueError:
            end_index = len(self.content)

        function_body = self.content[start_index:end_index]
        self.assertIn(
            "\\Microsoft\\Windows\\EnterpriseMgmt\\{EnrollmentGUID}\\PushLaunch",
            function_body,
            "Remediation default path must reference the EnterpriseMgmt PushLaunch task.",
        )
        self.assertIn(
            "schtasks /Change /TN",
            function_body,
            "Remediation should include a schtasks change command for PushLaunch.",
        )
        self.assertIn(
            "schtasks /Run /TN",
            function_body,
            "Remediation should include a schtasks run command for PushLaunch.",
        )
        self.assertIn(
            "$taskPath",
            function_body,
            "Remediation should inject the resolved task path into schtasks commands.",
        )
        self.assertNotIn(
            "PushToInstall",
            function_body,
            "Remediation script should no longer reference the legacy PushToInstall path.",
        )

    def test_pushlaunch_task_path_placeholder_is_documented(self) -> None:
        """Verify guidance references the EnterpriseMgmt enrollment GUID path."""
        self.assertIn(
            "\\Microsoft\\Windows\\EnterpriseMgmt\\{EnrollmentGUID}\\",
            self.content,
            "Technicians should be directed to the EnterpriseMgmt enrollment GUID path.",
        )


if __name__ == "__main__":
    unittest.main()
