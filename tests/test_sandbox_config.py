from __future__ import annotations

from pathlib import Path


def test_sandbox_launcher_defines_hardened_settings_and_mappings() -> None:
    script = Path('sandbox/Launch-FileGuardianSandbox.ps1').read_text(encoding='utf-8')
    for token in ["@('VGpu','Disable')", "@('Networking','Disable')", "@('ProtectedClient','Enable')", "@('ClipboardRedirection','Disable')"]:
        assert token in script
    assert "C:\\FileGuardian\\Runtime" in script
    assert "C:\\FileGuardian\\Input" in script
    assert "C:\\FileGuardian\\Output" in script
    assert "C:\\FileGuardian\\State" in script
    assert "System.Xml.XmlDocument" in script
    assert "Start-Process" in script


def test_sandbox_bootstrap_uses_packaged_runtime_and_reports() -> None:
    script = Path('sandbox/Start-FileGuardianInSandbox.ps1').read_text(encoding='utf-8')
    assert "FILE_GUARDIAN_EXECUTION_ENVIRONMENT" in script
    assert "C:\\FileGuardian\\Runtime\\FileGuardian.exe" in script
    assert "--recursive" in script and "--gui" in script
    assert "file_guardian_report.json" in script
    assert "file_guardian_report.csv" in script
    assert "C:\\FileGuardian\\State" in script and "tags.json" in script
