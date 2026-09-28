"""Read-only tests only: never initialize, format, attach, or mount a disk."""
from __future__ import annotations

import json
from pathlib import Path
import platform
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "vm" / "prepare_transfer_disk.ps1"
POWERSHELL = (shutil.which("pwsh") or shutil.which("powershell")) if platform.system() == "Windows" else None


@unittest.skipUnless(POWERSHELL, "Read-only PowerShell checks require PowerShell on Windows")
class TransferPlanTests(unittest.TestCase):
    def test_default_is_read_only_plan(self):
        result = subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-File", str(SCRIPT)],
            cwd=ROOT, text=True, capture_output=True, check=False, timeout=30,
        )
        if result.returncode and "UnauthorizedAccess" in result.stderr:
            self.skipTest("Host execution policy blocked file execution; no policy was changed")
        self.assertEqual(result.returncode, 0, result.stderr)
        plan = json.loads(result.stdout)
        self.assertEqual(plan["status"], "PLAN_ONLY_NO_CHANGES")
        self.assertEqual(plan["disk_capacity_bytes"], 1024 ** 3)
        self.assertEqual(plan["file_system"], "FAT32")
        self.assertEqual(plan["vm_name"], "ORAN-Security-Lab")
        self.assertEqual(Path(plan["transfer_vhdx"]), ROOT / ".vm-local" / "transfer" / "ORAN-TRANSFER.vhdx")
        self.assertIn("Collect never formats; it mounts read-only and preserves all originals.", plan["constraints"])

    def test_powershell_syntax(self):
        # Relative path in a fixed command avoids interpolating personal paths.
        command = (
            "$parseTokens=$null; $parseErrors=$null; "
            "[System.Management.Automation.Language.Parser]::ParseFile("
            "(Join-Path (Get-Location) 'scripts/vm/prepare_transfer_disk.ps1'), "
            "[ref]$parseTokens, [ref]$parseErrors) | Out-Null; "
            "if (@($parseErrors).Count -ne 0) { $parseErrors | Out-String | Write-Output; exit 1 }"
        )
        subprocess.run(
            [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=ROOT, text=True, capture_output=True, check=True, timeout=30,
        )


if __name__ == "__main__":
    unittest.main()
