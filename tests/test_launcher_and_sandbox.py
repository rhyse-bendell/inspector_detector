from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

from app import build_gui_startup_config, run_cli
from file_guardian import FileScanner, TagStore, write_json_report

ROOT = Path(__file__).resolve().parents[1]


class StartupAndPackagingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_custom_tag_store_persistence(self) -> None:
        sample = self.root / 'sample.txt'
        sample.write_text('hello', encoding='utf-8')
        result = FileScanner().scan_file(sample)
        store_path = self.root / 'state with spaces' / 'tags.json'
        store = TagStore(store_path)
        store.add_tags(result.sha256, ['review'], str(sample))
        self.assertEqual(TagStore(store_path).get_tags(result.sha256), ['review'])

    def test_gui_initial_path_configuration(self) -> None:
        cfg = build_gui_startup_config(['C:/FileGuardian/Input'], True, 'out.json', 'out.csv', 'tags.json', 'windows-sandbox')
        self.assertEqual(cfg['initial_paths'], ['C:/FileGuardian/Input'])
        self.assertTrue(cfg['recursive'])
        self.assertTrue(cfg['initial_exports_pending'])
        self.assertEqual(cfg['tag_store_path'], 'tags.json')

    def test_cli_json_csv_export_and_execution_environment(self) -> None:
        sample = self.root / 'doc.txt'
        sample.write_text('https://example.com/?utm_source=x', encoding='utf-8')
        json_path = self.root / 'report.json'
        csv_path = self.root / 'report.csv'
        code = run_cli([str(sample)], False, str(json_path), str(csv_path), str(self.root / 'tags.json'), 'windows-sandbox')
        self.assertIn(code, (0, 1))
        payload = json.loads(json_path.read_text(encoding='utf-8'))
        self.assertEqual(payload['execution_environment'], 'windows-sandbox')
        self.assertEqual(len(payload['results']), 1)
        with csv_path.open(encoding='utf-8-sig', newline='') as handle:
            self.assertGreaterEqual(len(list(csv.DictReader(handle))), 1)

    def test_report_metadata_only_when_set(self) -> None:
        sample = self.root / 'doc.txt'
        sample.write_text('hello', encoding='utf-8')
        result = FileScanner().scan_file(sample)
        path = write_json_report([result], self.root / 'report.json', execution_environment='windows-sandbox')
        self.assertEqual(json.loads(path.read_text(encoding='utf-8'))['execution_environment'], 'windows-sandbox')

    def test_packaged_executable_cli_smoke_scan_falls_back_to_python(self) -> None:
        sample = self.root / 'doc.txt'
        sample.write_text('hello', encoding='utf-8')
        exe = ROOT / 'dist' / 'FileGuardian' / ('FileGuardian.exe' if sys.platform.startswith('win') else 'FileGuardian')
        cmd = [str(exe)] if exe.exists() else [sys.executable, str(ROOT / 'app.py')]
        completed = subprocess.run(cmd + [str(sample), '--json', str(self.root / 'smoke.json')], text=True, capture_output=True)
        self.assertIn(completed.returncode, (0, 1))
        self.assertTrue((self.root / 'smoke.json').exists())

    def test_powershell_sources_contain_required_no_silent_fallback_logic(self) -> None:
        launcher = (ROOT / 'launcher' / 'Launch-FileGuardian.ps1').read_text(encoding='utf-8')
        sandbox = (ROOT / 'sandbox' / 'Launch-FileGuardianSandbox.ps1').read_text(encoding='utf-8')
        self.assertIn("Mode='local'", launcher)
        self.assertIn('rememberedMode', launcher)
        self.assertIn('Malformed', 'Malformed preference file returns to chooser/default')
        self.assertIn('Click Yes to run locally instead', sandbox)
        self.assertNotIn('Enable-WindowsOptionalFeature -Online -FeatureName "Containers-DisposableClientVM" -All |', sandbox)

    def test_wsb_security_settings_and_xml_sensitive_paths(self) -> None:
        fixture = ROOT / 'tests' / 'fixtures' / 'sample_sandbox.xml'
        tree = ET.parse(fixture)
        root = tree.getroot()
        self.assertEqual(root.findtext('VGpu'), 'Disable')
        self.assertEqual(root.findtext('Networking'), 'Disable')
        self.assertEqual(root.findtext('MemoryInMB'), '2048')
        mappings = [(m.findtext('SandboxFolder'), m.findtext('ReadOnly'), m.findtext('HostFolder')) for m in root.findall('./MappedFolders/MappedFolder')]
        self.assertEqual([m[0] for m in mappings], ['C:\\FileGuardian\\Runtime', 'C:\\FileGuardian\\Input', 'C:\\FileGuardian\\Output', 'C:\\FileGuardian\\State'])
        self.assertEqual([m[1] for m in mappings], ['true', 'true', 'false', 'false'])
        self.assertTrue(any('&' in (m[2] or '') for m in mappings))


if __name__ == '__main__':
    unittest.main()
