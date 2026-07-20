from __future__ import annotations

import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from file_guardian import FileScanner, TagStore, write_csv_report, write_json_report


class FileGuardianTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.scanner = FileScanner()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_plain_text_tracking_url(self) -> None:
        path = self.root / "message.txt"
        path.write_text(
            "Review https://example.org/report?utm_source=email&recipient=abc123",
            encoding="utf-8",
        )
        result = self.scanner.scan_file(path)
        titles = {finding.title for finding in result.findings}
        self.assertIn("Tracking-style or recipient-identifying URL", titles)
        self.assertIn(result.highest_severity, {"MEDIUM", "HIGH"})

    def test_html_tracking_pixel(self) -> None:
        path = self.root / "mail.html"
        path.write_text(
            '<html><body><img src="https://tracker.example/pixel?id=abc" width="1" height="1"></body></html>',
            encoding="utf-8",
        )
        result = self.scanner.scan_file(path)
        self.assertTrue(any("tracking-pixel" in finding.title.lower() for finding in result.findings))
        self.assertEqual(result.highest_severity, "HIGH")

    def test_ooxml_remote_template(self) -> None:
        path = self.root / "remote_template.docx"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "[Content_Types].xml",
                '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>',
            )
            archive.writestr(
                "word/_rels/settings.xml.rels",
                '''<?xml version="1.0" encoding="UTF-8"?>
                <Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
                  <Relationship Id="rId1"
                    Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
                    Target="https://example.org/template.dotm?uid=user123"
                    TargetMode="External"/>
                </Relationships>''',
            )
            archive.writestr("word/document.xml", "<document/>")
        result = self.scanner.scan_file(path)
        self.assertEqual(result.detected_type, "Office Open XML document")
        self.assertTrue(any(finding.title == "Remote attached template" for finding in result.findings))
        self.assertEqual(result.highest_severity, "HIGH")

    def test_raw_pdf_active_tokens(self) -> None:
        path = self.root / "active.pdf"
        path.write_bytes(
            b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
            b"2 0 obj << /S /JavaScript /JS (app.alert('test')) >> endobj\n%%EOF"
        )
        result = self.scanner.scan_file(path)
        self.assertTrue(any("JavaScript" in finding.title for finding in result.findings))
        self.assertIn(result.highest_severity, {"HIGH", "MEDIUM"})

    def test_local_tag_store_does_not_modify_source(self) -> None:
        path = self.root / "document.txt"
        path.write_text("content", encoding="utf-8")
        before = path.read_bytes()
        result = self.scanner.scan_file(path)
        tag_store = TagStore(self.root / "tags.json")
        tags = tag_store.add_tags(result.sha256, ["UCF", "needs-review"], str(path))
        self.assertEqual(set(tags), {"UCF", "needs-review"})
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(set(tag_store.get_tags(result.sha256)), {"UCF", "needs-review"})
        remaining = tag_store.remove_tags(result.sha256, ["needs-review"])
        self.assertEqual(remaining, ["UCF"])

    def test_report_writers(self) -> None:
        path = self.root / "document.txt"
        path.write_text("https://example.com/?gclid=123", encoding="utf-8")
        result = self.scanner.scan_file(path)
        json_path = write_json_report([result], self.root / "report.json")
        csv_path = write_csv_report([result], self.root / "report.csv")
        payload = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["application"], "File Guardian")
        self.assertEqual(len(payload["results"]), 1)
        self.assertTrue(csv_path.exists())
        self.assertGreater(csv_path.stat().st_size, 0)


if __name__ == "__main__":
    unittest.main()

class FileGuardianSandboxFeatureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.scanner = FileScanner()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_custom_tag_store_persists_and_source_unchanged(self) -> None:
        doc = self.root / "source.txt"
        doc.write_text("hello", encoding="utf-8")
        before = doc.read_bytes()
        result = self.scanner.scan_file(doc)
        store_path = self.root / "state" / "custom-tags.json"
        first = TagStore(store_path)
        first.add_tags(result.sha256, ["review"], str(doc))
        second = TagStore(store_path)
        self.assertEqual(second.get_tags(result.sha256), ["review"])
        second.remove_tags(result.sha256, ["review"])
        self.assertEqual(doc.read_bytes(), before)
        self.assertEqual(TagStore(store_path).get_tags(result.sha256), [])

    def test_malformed_tag_store_fails_safely_without_touching_source(self) -> None:
        doc = self.root / "source.txt"
        doc.write_text("hello", encoding="utf-8")
        before = doc.read_bytes()
        store_path = self.root / "bad-tags.json"
        store_path.write_text("{not json", encoding="utf-8")
        result = self.scanner.scan_file(doc)
        store = TagStore(store_path)
        self.assertEqual(store.get_tags(result.sha256), [])
        self.assertEqual(doc.read_bytes(), before)

    def test_execution_environment_json_metadata(self) -> None:
        import os
        doc = self.root / "source.txt"
        doc.write_text("hello", encoding="utf-8")
        old = os.environ.get("FILE_GUARDIAN_EXECUTION_ENVIRONMENT")
        os.environ["FILE_GUARDIAN_EXECUTION_ENVIRONMENT"] = "windows-sandbox"
        try:
            report = write_json_report([self.scanner.scan_file(doc)], self.root / "report.json")
        finally:
            if old is None:
                os.environ.pop("FILE_GUARDIAN_EXECUTION_ENVIRONMENT", None)
            else:
                os.environ["FILE_GUARDIAN_EXECUTION_ENVIRONMENT"] = old
        self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["execution_environment"], "windows-sandbox")

    def test_gui_argument_parsing_records_initial_scan_options(self) -> None:
        from app import build_parser
        args = build_parser().parse_args(["C:/Input", "--recursive", "--gui", "--json", "out.json", "--csv", "out.csv", "--tag-store", "tags.json"])
        self.assertTrue(args.gui)
        self.assertTrue(args.recursive)
        self.assertEqual(args.paths, ["C:/Input"])
        self.assertEqual(args.json_path, "out.json")
        self.assertEqual(args.csv_path, "out.csv")
        self.assertEqual(args.tag_store_path, "tags.json")
