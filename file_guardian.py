from __future__ import annotations

import csv
import ctypes
import hashlib
import html
import io
import json
import os
import platform
import re
import tarfile
import tempfile
import threading
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import policy as email_policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
import xml.etree.ElementTree as ET

try:
    from defusedxml.ElementTree import fromstring as safe_xml_fromstring  # type: ignore
except ImportError:
    safe_xml_fromstring = ET.fromstring

APP_NAME = "File Guardian"
VERSION = "0.1.0"

SEVERITY_RANK = {
    "NONE": -1,
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}

RISK_WEIGHTS = {
    "INFO": 0,
    "LOW": 5,
    "MEDIUM": 15,
    "HIGH": 35,
    "CRITICAL": 60,
}

TRACKER_HOST_PATTERNS = (
    "google-analytics.com",
    "googletagmanager.com",
    "doubleclick.net",
    "facebook.com/tr",
    "connect.facebook.net",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "hotjar.com",
    "clarity.ms",
    "amplitude.com",
    "newrelic.com",
    "nr-data.net",
    "sentry.io",
    "plausible.io",
    "matomo",
    "piwik",
    "adobe-analytics.com",
    "omtrdc.net",
    "app-measurement.com",
    "mailchimp.com",
    "list-manage.com",
    "mandrillapp.com",
    "sendgrid.net",
    "hubspot.com",
    "hs-analytics.net",
    "marketo.net",
    "pardot.com",
)

TRACKING_QUERY_KEYS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "utm_id",
    "gclid",
    "dclid",
    "fbclid",
    "msclkid",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "vero_id",
    "wickedid",
    "yclid",
    "rb_clickid",
    "s_cid",
    "campaignid",
    "adgroupid",
    "creative",
    "tracking",
    "track",
    "tracker",
    "pixel",
    "beacon",
    "recipient",
    "subscriber",
    "contactid",
    "contact_id",
    "user_id",
    "userid",
    "uid",
    "email",
    "token",
    "signature",
    "sig",
    "auth",
    "key",
}

SENSITIVE_QUERY_HINTS = (
    "token",
    "auth",
    "key",
    "secret",
    "sig",
    "email",
    "user",
    "uid",
    "recipient",
    "subscriber",
    "contact",
    "session",
    "id",
)

URL_RE = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s<>\"'\]\[(){}]+",
    re.MULTILINE,
)

UNC_RE = re.compile(r"(?i)(?:\\\\[^\s\\/]+\\[^\s<>\"']+|file://[^\s<>\"']+)")

TEXT_EXTENSIONS = {
    ".txt",
    ".csv",
    ".tsv",
    ".md",
    ".markdown",
    ".json",
    ".xml",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".log",
    ".py",
    ".r",
    ".js",
    ".css",
    ".sql",
    ".ps1",
    ".bat",
    ".cmd",
    ".sh",
}

HTML_EXTENSIONS = {".html", ".htm", ".xhtml", ".svg", ".mht", ".mhtml", ".eml"}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tif", ".tiff", ".webp", ".gif", ".bmp", ".heic"}
OFFICE_ZIP_EXTENSIONS = {
    ".docx",
    ".docm",
    ".dotx",
    ".dotm",
    ".xlsx",
    ".xlsm",
    ".xltx",
    ".xltm",
    ".xlsb",
    ".pptx",
    ".pptm",
    ".potx",
    ".potm",
    ".ppsx",
    ".ppsm",
}
LEGACY_OFFICE_EXTENSIONS = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".pub", ".msg"}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"}
ACTIVE_ARCHIVE_EXTENSIONS = {
    ".exe",
    ".dll",
    ".scr",
    ".com",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
    ".wsf",
    ".hta",
    ".lnk",
    ".url",
    ".reg",
    ".chm",
    ".jar",
}


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    def __post_init__(self) -> None:
        self.severity = self.severity.upper()
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"Unknown severity: {self.severity}")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    path: str
    size_bytes: int = 0
    sha256: str = ""
    extension: str = ""
    detected_type: str = "Unknown"
    scanned_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "NONE"
        return max(self.findings, key=lambda finding: SEVERITY_RANK[finding.severity]).severity

    @property
    def risk_score(self) -> int:
        score = sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in self.findings)
        return min(score, 100)

    @property
    def issue_count(self) -> int:
        return sum(1 for finding in self.findings if finding.severity != "INFO")

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def deduplicate(self) -> None:
        seen: set[tuple[str, str, str, str]] = set()
        unique: list[Finding] = []
        for finding in self.findings:
            key = (
                finding.severity,
                finding.category,
                finding.title,
                finding.evidence,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        unique.sort(key=lambda item: (-SEVERITY_RANK[item.severity], item.category, item.title))
        self.findings = unique

    def as_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "extension": self.extension,
            "detected_type": self.detected_type,
            "scanned_at": self.scanned_at,
            "highest_severity": self.highest_severity,
            "risk_score": self.risk_score,
            "issue_count": self.issue_count,
            "tags": list(self.tags),
            "notes": list(self.notes),
            "error": self.error,
            "findings": [finding.as_dict() for finding in self.findings],
        }


@dataclass
class ScanPolicy:
    max_raw_scan_bytes: int = 25 * 1024 * 1024
    max_deep_parse_bytes: int = 250 * 1024 * 1024
    max_zip_entries: int = 20_000
    max_zip_member_bytes: int = 30 * 1024 * 1024
    max_zip_total_uncompressed: int = 750 * 1024 * 1024
    max_zip_ratio: float = 250.0
    max_urls_per_file: int = 100
    max_pdf_objects: int = 50_000
    max_pdf_depth: int = 30
    follow_symlinks: bool = False


def user_data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home()))
        return base / "FileGuardian"
    if platform.system() == "Darwin":
        return Path.home() / "Library" / "Application Support" / "FileGuardian"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "fileguardian"


class TagStore:
    """Local labels keyed by file hash. Source files are never modified."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path or (user_data_dir() / "tags.json")
        self._lock = threading.Lock()
        self._data: dict[str, Any] = {"version": 1, "files": {}}
        self._load()

    def _load(self) -> None:
        try:
            if self.path.exists():
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict) and isinstance(loaded.get("files"), dict):
                    self._data = loaded
        except Exception:
            self._data = {"version": 1, "files": {}}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._data, indent=2, ensure_ascii=False)
        fd, temp_name = tempfile.mkstemp(prefix="tags_", suffix=".json", dir=self.path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def get_tags(self, sha256: str) -> list[str]:
        if not sha256:
            return []
        with self._lock:
            record = self._data["files"].get(sha256, {})
            tags = record.get("tags", [])
            return sorted({str(tag) for tag in tags if str(tag).strip()}, key=str.lower)

    def add_tags(self, sha256: str, tags: Iterable[str], path: str = "") -> list[str]:
        cleaned = {str(tag).strip() for tag in tags if str(tag).strip()}
        if not sha256 or not cleaned:
            return self.get_tags(sha256)
        with self._lock:
            record = self._data["files"].setdefault(
                sha256,
                {"tags": [], "paths": [], "first_seen": datetime.now(timezone.utc).isoformat()},
            )
            record["tags"] = sorted(set(record.get("tags", [])) | cleaned, key=str.lower)
            if path:
                record["paths"] = sorted(set(record.get("paths", [])) | {path})
            record["last_seen"] = datetime.now(timezone.utc).isoformat()
            self._save()
            return list(record["tags"])

    def remove_tags(self, sha256: str, tags: Iterable[str]) -> list[str]:
        cleaned = {str(tag).strip().lower() for tag in tags if str(tag).strip()}
        if not sha256 or not cleaned:
            return self.get_tags(sha256)
        with self._lock:
            record = self._data["files"].get(sha256)
            if not record:
                return []
            record["tags"] = [tag for tag in record.get("tags", []) if str(tag).lower() not in cleaned]
            record["last_seen"] = datetime.now(timezone.utc).isoformat()
            self._save()
            return list(record["tags"])


def clean_url_candidate(url: str) -> str:
    return url.rstrip(".,;:!?)]}>\"'")


def extract_urls(text: str, limit: int = 100) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for match in URL_RE.finditer(text):
        url = clean_url_candidate(match.group(0))
        if url and url not in seen:
            found.append(url)
            seen.add(url)
        if len(found) >= limit:
            break
    return found


def redact_url(url: str) -> str:
    """Retain enough structure for review without copying tokens into reports."""
    try:
        parts = urlsplit(url)
        redacted_query: list[tuple[str, str]] = []
        for key, value in parse_qsl(parts.query, keep_blank_values=True):
            lowered = key.lower()
            should_redact = (
                lowered in TRACKING_QUERY_KEYS
                or lowered.startswith("utm_")
                or any(hint in lowered for hint in SENSITIVE_QUERY_HINTS)
                or len(value) > 24
            )
            redacted_query.append((key, "<redacted>" if should_redact else value))
        return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted_query), ""))
    except Exception:
        return url[:500]


def tracker_characteristics(url: str) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    try:
        parts = urlsplit(url)
        host_and_path = f"{parts.netloc}{parts.path}".lower()
        if any(pattern in host_and_path for pattern in TRACKER_HOST_PATTERNS):
            reasons.append("known analytics/telemetry host pattern")
        keys = {key.lower() for key, _ in parse_qsl(parts.query, keep_blank_values=True)}
        matched_keys = sorted(
            key for key in keys if key in TRACKING_QUERY_KEYS or key.startswith("utm_")
        )
        if matched_keys:
            reasons.append("tracking or recipient-identifying query parameters: " + ", ".join(matched_keys[:8]))
    except Exception:
        pass
    return bool(reasons), reasons


def is_remote_target(target: str) -> bool:
    lowered = target.strip().lower()
    return lowered.startswith(("http://", "https://", "ftp://", "file://", "mailto:")) or lowered.startswith("\\\\")


def read_limited(path: Path, limit: int) -> tuple[bytes, bool]:
    with path.open("rb") as handle:
        data = handle.read(limit + 1)
    truncated = len(data) > limit
    return data[:limit], truncated


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def decode_bytes(data: bytes) -> str:
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16", errors="replace")
        except Exception:
            pass
    for encoding in ("utf-8-sig", "utf-8", "utf-16-le", "latin-1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace")


def xml_local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def safe_snippet(value: Any, max_length: int = 240) -> str:
    text = re.sub(r"\s+", " ", str(value)).strip()
    return text[:max_length] + ("…" if len(text) > max_length else "")


def windows_alternate_streams(path: Path) -> list[tuple[str, int]]:
    if os.name != "nt":
        return []

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    find_first = kernel32.FindFirstStreamW
    find_first.argtypes = [ctypes.c_wchar_p, ctypes.c_int, ctypes.POINTER(WIN32_FIND_STREAM_DATA), ctypes.c_uint]
    find_first.restype = ctypes.c_void_p
    find_next = kernel32.FindNextStreamW
    find_next.argtypes = [ctypes.c_void_p, ctypes.POINTER(WIN32_FIND_STREAM_DATA)]
    find_next.restype = ctypes.c_int
    find_close = kernel32.FindClose
    find_close.argtypes = [ctypes.c_void_p]
    find_close.restype = ctypes.c_int

    data = WIN32_FIND_STREAM_DATA()
    invalid_handle = ctypes.c_void_p(-1).value
    handle = find_first(str(path), 0, ctypes.byref(data), 0)
    if handle == invalid_handle:
        return []

    streams: list[tuple[str, int]] = []
    try:
        while True:
            name = data.cStreamName
            if name and name != "::$DATA":
                streams.append((name, int(data.StreamSize)))
            if not find_next(handle, ctypes.byref(data)):
                break
    finally:
        find_close(handle)
    return streams


def read_windows_stream(path: Path, stream_name: str, limit: int = 64 * 1024) -> str:
    logical_name = stream_name
    if logical_name.startswith(":"):
        logical_name = logical_name[1:]
    if logical_name.endswith(":$DATA"):
        logical_name = logical_name[: -len(":$DATA")]
    try:
        with open(f"{path}:{logical_name}", "rb") as handle:
            return decode_bytes(handle.read(limit))
    except Exception:
        return ""


class _TrackingHTMLParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.references: list[dict[str, Any]] = []
        self.inline_scripts: list[str] = []
        self.event_handlers: list[str] = []
        self._inside_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        attr_map = {key.lower(): (value or "") for key, value in attrs}
        lowered_tag = tag.lower()
        for key, value in attr_map.items():
            if key.startswith("on") and value.strip():
                self.event_handlers.append(f"{lowered_tag}.{key}: {safe_snippet(value)}")
        if "style" in attr_map:
            for url in extract_urls(attr_map["style"]):
                self.references.append({"tag": lowered_tag, "attribute": "style", "url": url, "attrs": attr_map})

        candidate_attributes = {
            "script": ["src"],
            "img": ["src", "srcset"],
            "iframe": ["src"],
            "frame": ["src"],
            "object": ["data"],
            "embed": ["src"],
            "link": ["href"],
            "a": ["href"],
            "form": ["action"],
            "source": ["src", "srcset"],
            "video": ["src", "poster"],
            "audio": ["src"],
            "input": ["src"],
            "image": ["href", "xlink:href"],
            "use": ["href", "xlink:href"],
        }
        for attribute in candidate_attributes.get(lowered_tag, []):
            value = attr_map.get(attribute, "")
            if not value:
                continue
            urls = extract_urls(value)
            if not urls and is_remote_target(value):
                urls = [value]
            for url in urls:
                self.references.append({"tag": lowered_tag, "attribute": attribute, "url": url, "attrs": attr_map})

        if lowered_tag == "meta" and attr_map.get("http-equiv", "").lower() == "refresh":
            content = attr_map.get("content", "")
            for url in extract_urls(content):
                self.references.append({"tag": "meta-refresh", "attribute": "content", "url": url, "attrs": attr_map})

        if lowered_tag == "script":
            self._inside_script = True
            self._script_chunks = []

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script" and self._inside_script:
            self.inline_scripts.append("".join(self._script_chunks))
            self._inside_script = False
            self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._inside_script:
            self._script_chunks.append(data)


class FileScanner:
    def __init__(self, policy: Optional[ScanPolicy] = None) -> None:
        self.policy = policy or ScanPolicy()

    def iter_input_files(self, inputs: Iterable[str | Path], recursive: bool = True) -> Iterator[Path]:
        seen: set[str] = set()
        for raw_path in inputs:
            path = Path(raw_path).expanduser()
            if path.is_file() or path.is_symlink():
                normalized = str(path.absolute())
                if normalized not in seen:
                    seen.add(normalized)
                    yield path
                continue
            if not path.is_dir():
                continue
            iterator = path.rglob("*") if recursive else path.iterdir()
            for child in iterator:
                try:
                    if child.is_file() or child.is_symlink():
                        normalized = str(child.absolute())
                        if normalized not in seen:
                            seen.add(normalized)
                            yield child
                except OSError:
                    continue

    def scan_file(self, raw_path: str | Path) -> ScanResult:
        path = Path(raw_path)
        result = ScanResult(path=str(path), extension=path.suffix.lower())
        try:
            stat = path.lstat()
            result.size_bytes = stat.st_size
            if path.is_symlink():
                target = os.readlink(path)
                result.add(
                    Finding(
                        "MEDIUM",
                        "Filesystem",
                        "Symbolic link",
                        "The selected path is a symbolic link. Scanning a link can inspect a different file than its displayed location suggests.",
                        evidence=f"Target: {target}",
                        remediation="Verify the target path before trusting or sharing the file.",
                    )
                )
                if not self.policy.follow_symlinks:
                    result.detected_type = "Symbolic link"
                    result.notes.append("Content was not followed because follow_symlinks is disabled.")
                    result.deduplicate()
                    return result

            if not path.is_file():
                raise ValueError("Path is not a regular file")

            result.sha256 = sha256_file(path)
            head, _ = read_limited(path, 4096)
            detected = self._detect_type(path, head)
            result.detected_type = detected
            self._scan_filesystem_metadata(path, result)
            self._check_extension_mismatch(path, head, detected, result)

            if detected == "Portable Executable" or result.extension in {".exe", ".dll", ".scr", ".com"}:
                result.add(
                    Finding(
                        "CRITICAL",
                        "Executable content",
                        "Executable program content",
                        "This file can execute code. It should not be treated as a passive document.",
                        evidence=f"Detected type: {detected}; extension: {result.extension or '(none)'}",
                        remediation="Do not run it. Analyze in an isolated malware-analysis environment if its origin is uncertain.",
                    )
                )
                self._scan_generic_content(path, result, context="binary")
            elif detected == "PDF document":
                self._scan_pdf(path, result)
            elif detected == "ZIP archive" or result.extension in OFFICE_ZIP_EXTENSIONS:
                self._scan_zip_or_ooxml(path, result)
            elif detected == "OLE Compound File" or result.extension in LEGACY_OFFICE_EXTENSIONS:
                self._scan_legacy_office(path, result)
            elif detected == "RTF document" or result.extension == ".rtf":
                self._scan_rtf(path, result)
            elif result.extension in HTML_EXTENSIONS:
                self._scan_html_email_svg(path, result)
            elif result.extension in IMAGE_EXTENSIONS or detected.startswith("Image"):
                self._scan_image(path, result)
            elif result.extension in ARCHIVE_EXTENSIONS:
                self._scan_archive(path, result)
            elif result.extension in TEXT_EXTENSIONS or detected == "Text-like file":
                self._scan_text(path, result)
            else:
                self._scan_generic_content(path, result, context="binary")

        except PermissionError as exc:
            result.error = f"Permission denied: {exc}"
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "File could not be read",
                    "The scanner did not have permission to inspect this file.",
                    evidence=str(exc),
                    remediation="Copy the file to a readable analysis folder or run with appropriate permissions.",
                )
            )
        except Exception as exc:
            result.error = f"{type(exc).__name__}: {exc}"
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "Inspection error",
                    "The file could not be fully inspected. A parser error is not evidence that the file is safe or malicious.",
                    evidence=result.error,
                    remediation="Review the file type, try a current scanner version, and use an isolated environment for high-risk material.",
                )
            )
        result.deduplicate()
        return result

    def _detect_type(self, path: Path, head: bytes) -> str:
        if head.startswith(b"%PDF-"):
            return "PDF document"
        if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08"):
            return "ZIP archive"
        if head.startswith(bytes.fromhex("D0CF11E0A1B11AE1")):
            return "OLE Compound File"
        if head.startswith(b"{\\rtf"):
            return "RTF document"
        if head.startswith(b"MZ"):
            return "Portable Executable"
        if head.startswith(b"\x89PNG\r\n\x1a\n"):
            return "Image: PNG"
        if head.startswith(b"\xff\xd8\xff"):
            return "Image: JPEG"
        if head.startswith((b"GIF87a", b"GIF89a")):
            return "Image: GIF"
        if head.startswith((b"II*\x00", b"MM\x00*")):
            return "Image: TIFF"
        if len(head) >= 12 and head[0:4] == b"RIFF" and head[8:12] == b"WEBP":
            return "Image: WebP"
        if head.startswith(b"\x7fELF"):
            return "ELF executable"
        extension = path.suffix.lower()
        if extension in TEXT_EXTENSIONS | HTML_EXTENSIONS:
            return "Text-like file"
        sample = head[:2048]
        if sample:
            null_ratio = sample.count(b"\x00") / len(sample)
            printable_ratio = sum(1 for byte in sample if byte in b"\t\r\n" or 32 <= byte <= 126) / len(sample)
            if null_ratio < 0.02 and printable_ratio > 0.80:
                return "Text-like file"
        return "Unknown binary"

    def _check_extension_mismatch(self, path: Path, head: bytes, detected: str, result: ScanResult) -> None:
        extension = result.extension
        expected: dict[str, set[str]] = {
            "PDF document": {".pdf"},
            "Portable Executable": {".exe", ".dll", ".scr", ".com", ".cpl", ".sys"},
            "RTF document": {".rtf"},
            "OLE Compound File": LEGACY_OFFICE_EXTENSIONS | {".docm", ".xlsm", ".pptm"},
        }
        if detected in expected and extension and extension not in expected[detected]:
            severity = "HIGH" if detected == "Portable Executable" else "MEDIUM"
            result.add(
                Finding(
                    severity,
                    "File identity",
                    "Extension does not match file content",
                    "The filename extension does not match the detected content signature. This can be accidental or used to disguise active content.",
                    evidence=f"Extension {extension}; detected {detected}",
                    remediation="Verify the original source and rename only after confirming the actual format.",
                )
            )
        if extension in OFFICE_ZIP_EXTENSIONS and not head.startswith(b"PK"):
            result.add(
                Finding(
                    "MEDIUM",
                    "File identity",
                    "Office filename without an Office ZIP signature",
                    "Modern Office documents normally use an Open XML ZIP container, but this file does not have that signature.",
                    evidence=f"Extension: {extension}; detected: {detected}",
                    remediation="Treat the file as malformed or mislabeled until independently verified.",
                )
            )

    def _scan_filesystem_metadata(self, path: Path, result: ScanResult) -> None:
        if os.name == "nt":
            try:
                streams = windows_alternate_streams(path)
                for stream_name, size in streams:
                    stream_text = read_windows_stream(path, stream_name)
                    if "Zone.Identifier" in stream_name:
                        urls = extract_urls(stream_text, 10)
                        evidence = f"Stream {stream_name}, {size} bytes"
                        if urls:
                            evidence += "; origin/referrer: " + ", ".join(redact_url(url) for url in urls)
                        result.add(
                            Finding(
                                "INFO",
                                "Filesystem metadata",
                                "Windows Mark-of-the-Web metadata",
                                "Windows stored download-zone metadata in an NTFS alternate data stream. This is not an active tracker, but it can disclose download provenance and affect how Windows opens the file.",
                                evidence=evidence,
                                remediation="Retain it for provenance unless policy requires removal. Do not remove it merely to bypass Windows security warnings.",
                            )
                        )
                    else:
                        result.add(
                            Finding(
                                "MEDIUM",
                                "Filesystem metadata",
                                "NTFS alternate data stream",
                                "The file has a non-default alternate data stream. Such streams can hold hidden metadata or content not visible in the normal file size.",
                                evidence=f"Stream {stream_name}, {size} bytes",
                                remediation="Review the stream with approved forensic tools before copying or sharing the file.",
                            )
                        )
            except Exception as exc:
                result.notes.append(f"Alternate-data-stream check failed: {exc}")
        elif hasattr(os, "listxattr"):
            try:
                attrs = [name for name in os.listxattr(path) if name]
                privacy_attrs = [
                    name
                    for name in attrs
                    if any(term in name.lower() for term in ("quarantine", "origin", "download", "wherefrom", "metadata"))
                ]
                if privacy_attrs:
                    result.add(
                        Finding(
                            "INFO",
                            "Filesystem metadata",
                            "Extended provenance metadata",
                            "The filesystem has extended attributes that may record download origin or quarantine state.",
                            evidence=", ".join(privacy_attrs[:20]),
                            remediation="Retain for provenance unless your data-handling policy directs otherwise.",
                        )
                    )
            except Exception:
                pass

    def _scan_zip_or_ooxml(self, path: Path, result: ScanResult) -> None:
        try:
            with zipfile.ZipFile(path) as archive:
                names = archive.namelist()
                is_ooxml = "[Content_Types].xml" in names or result.extension in OFFICE_ZIP_EXTENSIONS
                if is_ooxml:
                    result.detected_type = "Office Open XML document"
                    self._scan_ooxml_archive(path, archive, result)
                else:
                    result.detected_type = "ZIP archive"
                    self._scan_zip_inventory(archive, result)
        except zipfile.BadZipFile as exc:
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "Invalid or damaged ZIP container",
                    "The file has a ZIP-like signature or Office extension but could not be parsed as a valid ZIP archive.",
                    evidence=str(exc),
                    remediation="Obtain a fresh copy and do not trust a partial scan.",
                )
            )
            self._scan_generic_content(path, result, context="binary")

    def _validate_zip(self, archive: zipfile.ZipFile, result: ScanResult) -> bool:
        infos = archive.infolist()
        if len(infos) > self.policy.max_zip_entries:
            result.add(
                Finding(
                    "HIGH",
                    "Archive safety",
                    "Excessive archive entry count",
                    "The archive contains more entries than the safe inspection limit and may be designed to exhaust resources.",
                    evidence=f"Entries: {len(infos):,}; limit: {self.policy.max_zip_entries:,}",
                    remediation="Analyze in an isolated environment with archive-bomb protections.",
                )
            )
            return False
        total_uncompressed = sum(info.file_size for info in infos)
        total_compressed = sum(max(info.compress_size, 1) for info in infos)
        ratio = total_uncompressed / total_compressed if total_compressed else float("inf")
        if total_uncompressed > self.policy.max_zip_total_uncompressed or ratio > self.policy.max_zip_ratio:
            result.add(
                Finding(
                    "HIGH",
                    "Archive safety",
                    "Possible decompression bomb",
                    "The archive's expanded size or compression ratio exceeds the safe inspection policy.",
                    evidence=(
                        f"Expanded size: {total_uncompressed:,} bytes; compressed size: {total_compressed:,} bytes; "
                        f"ratio: {ratio:.1f}"
                    ),
                    remediation="Do not extract normally. Analyze in an isolated environment with strict resource limits.",
                )
            )
            return False
        dangerous_paths: list[str] = []
        for info in infos:
            normalized = info.filename.replace("\\", "/")
            parts = [part for part in normalized.split("/") if part not in ("", ".")]
            if normalized.startswith(("/", "\\")) or any(part == ".." for part in parts) or re.match(r"^[A-Za-z]:", normalized):
                dangerous_paths.append(info.filename)
        if dangerous_paths:
            result.add(
                Finding(
                    "HIGH",
                    "Archive safety",
                    "Archive path-traversal entries",
                    "The archive contains absolute or parent-directory paths that could write outside the intended extraction folder.",
                    evidence=", ".join(dangerous_paths[:30]),
                    remediation="Do not extract with a normal archive tool. Use an isolated safe extractor that rejects traversal paths.",
                )
            )

        encrypted = [info.filename for info in infos if info.flag_bits & 0x1]
        if encrypted:
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "Encrypted archive members",
                    "Some archive members are encrypted and could not be inspected.",
                    evidence=", ".join(encrypted[:20]),
                    remediation="Obtain the password through an approved channel and rescan after controlled extraction.",
                )
            )
        return True

    def _scan_zip_inventory(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        if not self._validate_zip(archive, result):
            return
        active_entries = []
        nested_documents = []
        for info in archive.infolist():
            suffix = Path(info.filename).suffix.lower()
            if suffix in ACTIVE_ARCHIVE_EXTENSIONS:
                active_entries.append(info.filename)
            if suffix in OFFICE_ZIP_EXTENSIONS | LEGACY_OFFICE_EXTENSIONS | {".pdf", ".rtf", ".html", ".eml"}:
                nested_documents.append(info.filename)
        if active_entries:
            result.add(
                Finding(
                    "HIGH",
                    "Archive content",
                    "Executable or script-like files inside archive",
                    "The archive contains entries capable of executing code or redirecting users.",
                    evidence=", ".join(active_entries[:30]),
                    remediation="Do not execute these entries. Extract only in an isolated analysis environment if review is necessary.",
                )
            )
        if nested_documents:
            result.add(
                Finding(
                    "INFO",
                    "Inspection completeness",
                    "Documents inside archive require separate scans",
                    "This version inventories archive contents but does not recursively parse every nested document.",
                    evidence=", ".join(nested_documents[:30]),
                    remediation="Extract to an isolated folder and scan the extracted files individually.",
                )
            )

    def _scan_ooxml_archive(self, path: Path, archive: zipfile.ZipFile, result: ScanResult) -> None:
        if not self._validate_zip(archive, result):
            return
        infos = archive.infolist()
        names = [info.filename for info in infos]
        lowered_names = [name.lower() for name in names]

        def matching(fragment: str) -> list[str]:
            return [names[index] for index, value in enumerate(lowered_names) if fragment in value]

        macros = matching("vbaproject.bin")
        if macros:
            result.add(
                Finding(
                    "HIGH",
                    "Office active content",
                    "VBA macro project",
                    "The Office document contains VBA macro code. Macros can access files, launch programs, and make network requests when enabled.",
                    evidence=", ".join(macros[:10]),
                    remediation="Do not enable macros. Review the macro source with approved analysis tools in an isolated environment.",
                )
            )

        active_x = matching("/activex/")
        if active_x:
            result.add(
                Finding(
                    "HIGH",
                    "Office active content",
                    "ActiveX controls",
                    "The document contains ActiveX controls, which can provide executable behavior beyond ordinary document content.",
                    evidence=", ".join(active_x[:20]),
                    remediation="Open only in Protected View or an isolated environment and validate why the controls are required.",
                )
            )

        web_extensions = matching("webextensions") + matching("taskpanes")
        if web_extensions:
            result.add(
                Finding(
                    "HIGH",
                    "Office active content",
                    "Office web add-in content",
                    "The document contains web-extension or task-pane components that may load web-hosted code or content.",
                    evidence=", ".join(sorted(set(web_extensions))[:20]),
                    remediation="Verify the add-in identity and approved host before opening the document outside an isolated environment.",
                )
            )

        embedded = matching("/embeddings/")
        if embedded:
            result.add(
                Finding(
                    "MEDIUM",
                    "Embedded content",
                    "Embedded files or OLE objects",
                    "The document contains embedded objects or files. Embedded content can conceal additional documents or executable components.",
                    evidence=", ".join(embedded[:30]),
                    remediation="Inventory and separately scan embedded objects before trusting the document.",
                )
            )

        external_links = matching("/externallinks/")
        if external_links:
            result.add(
                Finding(
                    "MEDIUM",
                    "External references",
                    "Office external-link components",
                    "The document contains external-link components, commonly used for linked workbooks, data sources, or other outside content.",
                    evidence=", ".join(external_links[:20]),
                    remediation="Review and remove unnecessary external links, especially links to network shares or remote hosts.",
                )
            )

        custom_ui = matching("customui")
        if custom_ui:
            result.add(
                Finding(
                    "MEDIUM",
                    "Office active content",
                    "Custom Office ribbon/interface content",
                    "The document contains custom Office UI definitions. These are not automatically malicious but can be associated with macros or add-ins.",
                    evidence=", ".join(custom_ui[:20]),
                    remediation="Confirm the customization is expected and review related macros or callbacks.",
                )
            )

        comments = [name for name in names if re.search(r"(?i)(comments|people\.xml|person\.xml)", name)]
        if comments:
            result.add(
                Finding(
                    "INFO",
                    "Privacy metadata",
                    "Comments or reviewer identity data",
                    "The document contains comment/reviewer components that may disclose names, identities, or revision context.",
                    evidence=", ".join(comments[:20]),
                    remediation="Review comments and document-inspector results before external sharing.",
                )
            )

        custom_xml = matching("customxml/")
        if custom_xml:
            result.add(
                Finding(
                    "INFO",
                    "Privacy metadata",
                    "Custom XML data",
                    "The Office package contains custom XML parts. These may store application-specific identifiers or data not visible in the document body.",
                    evidence=f"{len(custom_xml)} custom XML part(s)",
                    remediation="Review the package metadata or use Office Document Inspector before external release.",
                )
            )

        signatures = matching("_xmlsignatures")
        if signatures:
            result.add(
                Finding(
                    "INFO",
                    "Authenticity metadata",
                    "Digital-signature components",
                    "The package contains digital-signature components. This is generally a provenance feature, not a tracker.",
                    evidence=", ".join(signatures[:20]),
                    remediation="Preserve signatures when authenticity matters; verify them in an approved Office environment.",
                )
            )

        self._scan_ooxml_properties(archive, result)
        self._scan_ooxml_relationships(archive, result)
        self._scan_ooxml_xml_content(archive, result)

        if macros or result.extension in {".docm", ".dotm", ".xlsm", ".xltm", ".pptm", ".potm", ".ppsm", ".xlsb"}:
            self._scan_vba_with_oletools(path, result)

    def _scan_ooxml_properties(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        metadata_values: list[str] = []
        custom_names: list[str] = []
        sensitivity_names: list[str] = []
        for member in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
            try:
                info = archive.getinfo(member)
            except KeyError:
                continue
            if info.file_size > self.policy.max_zip_member_bytes:
                result.notes.append(f"Skipped oversized metadata member: {member}")
                continue
            try:
                root = safe_xml_fromstring(archive.read(member))
            except Exception as exc:
                result.notes.append(f"Could not parse {member}: {exc}")
                continue
            if member.endswith("custom.xml"):
                for prop in root.iter():
                    if xml_local_name(prop.tag).lower() == "property":
                        name = prop.attrib.get("name", "").strip()
                        if name:
                            custom_names.append(name)
                            if any(term in name.lower() for term in ("sensitivity", "classification", "label", "mip")):
                                sensitivity_names.append(name)
            else:
                allowed = {
                    "creator",
                    "lastmodifiedby",
                    "created",
                    "modified",
                    "revision",
                    "identifier",
                    "application",
                    "appversion",
                    "company",
                    "manager",
                    "template",
                    "totaltime",
                }
                for element in root.iter():
                    name = xml_local_name(element.tag)
                    value = (element.text or "").strip()
                    if value and name.lower() in allowed:
                        metadata_values.append(f"{name}={safe_snippet(value, 100)}")
        if metadata_values:
            result.add(
                Finding(
                    "INFO",
                    "Privacy metadata",
                    "Office document properties",
                    "Document properties may disclose authorship, organization, software, template, and editing timestamps. They are not active trackers but can identify the file's provenance.",
                    evidence="; ".join(metadata_values[:20]),
                    remediation="Review and remove unnecessary properties before external release.",
                )
            )
        if custom_names:
            result.add(
                Finding(
                    "INFO",
                    "Privacy metadata",
                    "Custom Office properties",
                    "The document has application-defined custom properties that may persist across copies.",
                    evidence=", ".join(sorted(set(custom_names))[:30]),
                    remediation="Review custom properties before sharing outside the intended environment.",
                )
            )
        if sensitivity_names:
            result.add(
                Finding(
                    "INFO",
                    "Classification metadata",
                    "Sensitivity or classification properties",
                    "The document contains properties that appear related to sensitivity labels or classification. This may indicate handling restrictions even if no tracker is present.",
                    evidence=", ".join(sorted(set(sensitivity_names))[:20]),
                    remediation="Follow the applicable organizational data-handling policy before copying or uploading the file.",
                )
            )

    def _scan_ooxml_relationships(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        for info in archive.infolist():
            if not info.filename.lower().endswith(".rels"):
                continue
            if info.file_size > self.policy.max_zip_member_bytes:
                result.notes.append(f"Skipped oversized relationship member: {info.filename}")
                continue
            try:
                root = safe_xml_fromstring(archive.read(info.filename))
            except Exception as exc:
                result.notes.append(f"Could not parse {info.filename}: {exc}")
                continue
            for relationship in root.iter():
                if xml_local_name(relationship.tag).lower() != "relationship":
                    continue
                rel_type = relationship.attrib.get("Type", "")
                rel_kind = rel_type.rsplit("/", 1)[-1] if rel_type else "unknown"
                target = relationship.attrib.get("Target", "")
                mode = relationship.attrib.get("TargetMode", "")
                external = mode.lower() == "external" or is_remote_target(target)
                if not external:
                    continue
                lowered_kind = rel_kind.lower()
                lower_target = target.lower()
                tracker, reasons = tracker_characteristics(target)
                auto_load = lowered_kind in {
                    "attachedtemplate",
                    "image",
                    "audio",
                    "video",
                    "oleobject",
                    "externallinkpath",
                    "externaldata",
                    "webextension",
                    "control",
                    "package",
                }
                if target.startswith("\\\\") or lower_target.startswith("file://"):
                    severity = "HIGH"
                    title = "External file or network-share relationship"
                    detail = (
                        "The document references a file path or network share. Office applications may attempt to resolve such references, "
                        "which can disclose workstation/network authentication information or retrieve untrusted content."
                    )
                elif lowered_kind == "hyperlink":
                    severity = "MEDIUM" if tracker else "LOW"
                    title = "External hyperlink with tracking characteristics" if tracker else "External hyperlink"
                    detail = "The document contains an external hyperlink. A hyperlink normally contacts the destination only when a user activates it."
                elif lowered_kind == "attachedtemplate":
                    severity = "HIGH"
                    title = "Remote attached template"
                    detail = "The document is linked to an external template. Office may retrieve templates during document opening or editing."
                elif lowered_kind in {"image", "audio", "video"}:
                    severity = "HIGH" if tracker else "MEDIUM"
                    title = "Remote media with tracking characteristics" if tracker else "Remote media reference"
                    detail = "The document contains externally hosted media that may be fetched when rendered or refreshed."
                elif lowered_kind in {"oleobject", "externaldata", "externallinkpath", "package", "control", "webextension"}:
                    severity = "HIGH" if tracker or auto_load else "MEDIUM"
                    title = "External active/data relationship"
                    detail = "The document links to external active content, data, or an embedded-object source."
                else:
                    severity = "HIGH" if tracker and auto_load else "MEDIUM"
                    title = "External Office relationship"
                    detail = "The Office package contains an external relationship that may contact or retrieve content outside the file."
                reason_text = f" Tracker indicators: {'; '.join(reasons)}." if reasons else ""
                result.add(
                    Finding(
                        severity,
                        "External references",
                        title,
                        detail + reason_text,
                        evidence=(
                            f"Part: {info.filename}; relationship type: {rel_kind}; "
                            f"target: {redact_url(target) if '://' in target else safe_snippet(target, 400)}"
                        ),
                        remediation="Confirm the destination is expected and approved; remove or break the link if it is unnecessary.",
                    )
                )

    def _scan_ooxml_xml_content(self, archive: zipfile.ZipFile, result: ScanResult) -> None:
        urls_seen: set[str] = set()
        for info in archive.infolist():
            name = info.filename.lower()
            if not name.endswith((".xml", ".rels", ".vml")):
                continue
            if info.file_size > self.policy.max_zip_member_bytes:
                continue
            try:
                text = decode_bytes(archive.read(info.filename))
            except Exception:
                continue
            upper = text.upper()
            if "DDEAUTO" in upper or re.search(r"\bDDE\b", upper):
                result.add(
                    Finding(
                        "HIGH",
                        "Office active content",
                        "DDE field or instruction",
                        "The document contains a Dynamic Data Exchange instruction. DDE fields can invoke external applications or retrieve data.",
                        evidence=f"Part: {info.filename}",
                        remediation="Do not update fields. Remove the DDE instruction unless it is explicitly required and approved.",
                    )
                )
            if "INCLUDEPICTURE" in upper or "INCLUDETEXT" in upper:
                references = extract_urls(text, 20) + UNC_RE.findall(text)
                result.add(
                    Finding(
                        "MEDIUM" if not references else "HIGH",
                        "External references",
                        "External include field",
                        "The document contains INCLUDEPICTURE or INCLUDETEXT field instructions that can retrieve external content when fields are updated.",
                        evidence=f"Part: {info.filename}; references: " + ", ".join(redact_url(item) for item in references[:10]),
                        remediation="Unlink or remove the field unless the external source is required and trusted.",
                    )
                )
            for url in extract_urls(text, self.policy.max_urls_per_file):
                if url in urls_seen:
                    continue
                urls_seen.add(url)
                tracker, reasons = tracker_characteristics(url)
                if not tracker:
                    continue
                result.add(
                    Finding(
                        "MEDIUM",
                        "Tracking indicators",
                        "Tracking-style URL in Office package",
                        "A URL embedded in the Office package matches common analytics or recipient-tracking characteristics.",
                        evidence=f"Part: {info.filename}; URL: {redact_url(url)}; reasons: {'; '.join(reasons)}",
                        remediation="Determine whether the URL is visible content, a hyperlink, or an automatically loaded resource; remove it if unnecessary.",
                    )
                )

    def _scan_vba_with_oletools(self, path: Path, result: ScanResult) -> None:
        try:
            from oletools.olevba import VBA_Parser  # type: ignore
        except ImportError:
            result.notes.append("oletools is not installed; VBA source-level analysis was skipped.")
            return
        parser = None
        try:
            parser = VBA_Parser(str(path))
            if not parser.detect_vba_macros():
                return
            categories: dict[str, list[str]] = {}
            for item in parser.analyze_macros():
                if len(item) < 3:
                    continue
                kind, keyword, description = item[0], item[1], item[2]
                categories.setdefault(str(kind), []).append(f"{keyword}: {description}")
            autoexec = categories.get("AutoExec", [])
            suspicious = categories.get("Suspicious", [])
            iocs = categories.get("IOC", [])
            if autoexec:
                result.add(
                    Finding(
                        "HIGH",
                        "Office macros",
                        "Auto-executing macro triggers",
                        "The VBA project contains triggers that may run automatically when the document is opened, closed, or otherwise activated.",
                        evidence="; ".join(autoexec[:20]),
                        remediation="Do not enable macros; review the full VBA source in an isolated environment.",
                    )
                )
            if suspicious:
                result.add(
                    Finding(
                        "HIGH",
                        "Office macros",
                        "Suspicious VBA capabilities",
                        "Static macro analysis found capabilities commonly associated with process execution, file access, obfuscation, or network activity.",
                        evidence="; ".join(suspicious[:30]),
                        remediation="Have the macro code reviewed before opening the file with macros enabled.",
                    )
                )
            if iocs:
                result.add(
                    Finding(
                        "MEDIUM",
                        "Office macros",
                        "Macro indicators of compromise or external references",
                        "Static macro analysis extracted URLs, paths, executable names, or other indicators that warrant review.",
                        evidence="; ".join(iocs[:30]),
                        remediation="Validate each indicator and compare file hashes with approved security tooling.",
                    )
                )
        except Exception as exc:
            result.notes.append(f"oletools VBA analysis failed: {type(exc).__name__}: {exc}")
        finally:
            try:
                if parser is not None:
                    parser.close()
            except Exception:
                pass

    def _scan_legacy_office(self, path: Path, result: ScanResult) -> None:
        result.detected_type = "Legacy Office/OLE document"
        if result.extension in OFFICE_ZIP_EXTENSIONS:
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "Possible encrypted modern Office document",
                    "A modern Office filename is stored in an OLE container rather than the expected Open XML ZIP container. This commonly occurs when an Office file is password-encrypted, so its internal content could not be inspected.",
                    evidence=f"Extension: {result.extension}; container: OLE Compound File",
                    remediation="Obtain the password through an approved channel and inspect a controlled decrypted copy.",
                )
            )
        result.add(
            Finding(
                "MEDIUM",
                "Inspection completeness",
                "Legacy binary Office format",
                "Legacy OLE Office files are more difficult to inspect completely than Open XML packages and may contain macros, embedded objects, or linked content.",
                evidence=f"Extension: {result.extension or '(none)'}",
                remediation="Convert only in an isolated, patched Office environment after macro and embedded-object review.",
            )
        )
        self._scan_vba_with_oletools(path, result)
        self._scan_generic_content(path, result, context="legacy-office")

    def _scan_rtf(self, path: Path, result: ScanResult) -> None:
        result.detected_type = "RTF document"
        data, truncated = read_limited(path, self.policy.max_raw_scan_bytes)
        text = decode_bytes(data)
        upper = text.upper()
        if "\\OBJECT" in upper or "\\OBJDATA" in upper:
            result.add(
                Finding(
                    "HIGH",
                    "Embedded content",
                    "RTF embedded object data",
                    "The RTF contains an embedded object or object-data block. Embedded OLE content can carry active or concealed payloads.",
                    evidence="RTF control word \\object or \\objdata",
                    remediation="Do not open in Word outside an isolated environment; extract and inspect the object separately.",
                )
            )
        if "DDEAUTO" in upper or re.search(r"\bDDE\b", upper):
            result.add(
                Finding(
                    "HIGH",
                    "Active content",
                    "RTF DDE instruction",
                    "The RTF contains a DDE field or instruction that can invoke external applications or data sources.",
                    evidence="DDE/DDEAUTO text found",
                    remediation="Remove the field and do not update linked content.",
                )
            )
        if "INCLUDEPICTURE" in upper or "INCLUDETEXT" in upper:
            result.add(
                Finding(
                    "MEDIUM",
                    "External references",
                    "RTF external include field",
                    "The RTF may retrieve external text or images when fields are updated.",
                    evidence="INCLUDEPICTURE or INCLUDETEXT text found",
                    remediation="Remove or unlink the field unless the source is trusted and necessary.",
                )
            )
        self._add_url_findings(text, result, context="rtf", auto_load=False)
        if truncated:
            result.notes.append("RTF raw scan was truncated at the configured byte limit.")

    def _scan_pdf(self, path: Path, result: ScanResult) -> None:
        result.detected_type = "PDF document"
        parser_available = True
        try:
            from pypdf import PdfReader  # type: ignore
            from pypdf.generic import IndirectObject  # type: ignore
        except ImportError:
            parser_available = False
            result.notes.append("pypdf is not installed; only a raw PDF indicator scan was performed.")

        parser_failed = False
        if parser_available and result.size_bytes <= self.policy.max_deep_parse_bytes:
            try:
                reader = PdfReader(str(path), strict=False)
                if getattr(reader, "is_encrypted", False):
                    result.add(
                        Finding(
                            "MEDIUM",
                            "Inspection completeness",
                            "Encrypted PDF",
                            "The PDF is encrypted. The scanner cannot reliably inspect protected objects without an approved password.",
                            remediation="Obtain the password through an approved channel and rescan in a controlled environment.",
                        )
                    )
                else:
                    metadata = getattr(reader, "metadata", None)
                    if metadata:
                        values = []
                        for key in ("/Author", "/Creator", "/Producer", "/CreationDate", "/ModDate", "/Title", "/Subject"):
                            value = metadata.get(key) if hasattr(metadata, "get") else None
                            if value:
                                values.append(f"{key.lstrip('/')}={safe_snippet(value, 120)}")
                        if values:
                            result.add(
                                Finding(
                                    "INFO",
                                    "Privacy metadata",
                                    "PDF document properties",
                                    "PDF properties may disclose author, software, title, and timestamps. They are not active trackers but can identify provenance.",
                                    evidence="; ".join(values[:20]),
                                    remediation="Review and remove unnecessary metadata before external release.",
                                )
                            )
                    attachment_names: list[str] = []
                    try:
                        attachment_list = getattr(reader, "attachment_list", None)
                        if attachment_list is not None:
                            for attachment in attachment_list:
                                name = getattr(attachment, "name", None) or getattr(attachment, "filename", None) or str(attachment)
                                attachment_names.append(safe_snippet(name, 150))
                        else:
                            attachments = getattr(reader, "attachments", {})
                            if hasattr(attachments, "keys"):
                                attachment_names.extend(str(name) for name in attachments.keys())
                    except Exception as exc:
                        result.notes.append(f"PDF attachment inventory failed: {exc}")
                    if attachment_names:
                        result.add(
                            Finding(
                                "MEDIUM",
                                "Embedded content",
                                "PDF embedded files",
                                "The PDF contains embedded attachments that require separate inspection.",
                                evidence=", ".join(attachment_names[:30]),
                                remediation="Extract only in an isolated folder and scan each attachment separately.",
                            )
                        )

                    visited: set[tuple[int, int]] = set()
                    counters = {"objects": 0}

                    def get_text(value: Any) -> str:
                        try:
                            if hasattr(value, "get_data"):
                                return decode_bytes(value.get_data()[:1_000_000])
                        except Exception:
                            return ""
                        return str(value)

                    def add_action(action: str, trail: str) -> None:
                        action_map = {
                            "/JavaScript": ("HIGH", "PDF JavaScript action", "The PDF contains JavaScript that may run in a capable PDF viewer."),
                            "/Launch": ("HIGH", "PDF launch action", "The PDF contains an action that can launch a file or external application."),
                            "/SubmitForm": ("HIGH", "PDF form-submission action", "The PDF can submit form data to an external destination."),
                            "/ImportData": ("MEDIUM", "PDF import-data action", "The PDF contains an action to import external data."),
                            "/GoToR": ("MEDIUM", "PDF remote-document action", "The PDF contains an action that navigates to an external document."),
                            "/Rendition": ("MEDIUM", "PDF rendition action", "The PDF contains multimedia/rendition behavior."),
                            "/Sound": ("MEDIUM", "PDF sound action", "The PDF contains a sound action."),
                            "/Movie": ("MEDIUM", "PDF movie action", "The PDF contains a movie action."),
                        }
                        if action in action_map:
                            severity, title, detail = action_map[action]
                            result.add(
                                Finding(
                                    severity,
                                    "PDF active content",
                                    title,
                                    detail,
                                    evidence=f"Object path: {trail}; action: {action}",
                                    remediation="Open only in a hardened viewer with JavaScript, launch actions, and external content disabled.",
                                )
                            )

                    def walk(obj: Any, trail: str = "/Root", depth: int = 0) -> None:
                        if depth > self.policy.max_pdf_depth or counters["objects"] >= self.policy.max_pdf_objects:
                            return
                        try:
                            if isinstance(obj, IndirectObject):
                                key = (int(obj.idnum), int(obj.generation))
                                if key in visited:
                                    return
                                visited.add(key)
                                obj = obj.get_object()
                            counters["objects"] += 1
                            if isinstance(obj, dict):
                                action = str(obj.get("/S", ""))
                                add_action(action, trail)
                                if "/URI" in obj:
                                    uri = get_text(obj.get("/URI"))
                                    tracker, reasons = tracker_characteristics(uri)
                                    result.add(
                                        Finding(
                                            "MEDIUM" if tracker else "LOW",
                                            "External references",
                                            "PDF external URI with tracking characteristics" if tracker else "PDF external URI",
                                            "The PDF contains a URI action or link. It contacts the destination only if the viewer or user activates it, unless combined with another automatic action.",
                                            evidence=f"{redact_url(uri)}" + (f"; reasons: {'; '.join(reasons)}" if reasons else ""),
                                            remediation="Verify the destination and remove unnecessary links or actions.",
                                        )
                                    )
                                if "/OpenAction" in obj:
                                    result.add(
                                        Finding(
                                            "MEDIUM",
                                            "PDF active content",
                                            "PDF open action",
                                            "The PDF defines an action to run or navigate when opened. The action type requires review.",
                                            evidence=f"Object path: {trail}/OpenAction",
                                            remediation="Review the referenced action and remove it if it is unnecessary.",
                                        )
                                    )
                                if "/AA" in obj:
                                    result.add(
                                        Finding(
                                            "MEDIUM",
                                            "PDF active content",
                                            "PDF additional actions",
                                            "The PDF defines event-triggered additional actions on a document, page, field, or annotation.",
                                            evidence=f"Object path: {trail}/AA",
                                            remediation="Review each trigger and action in a hardened analysis environment.",
                                        )
                                    )
                                if "/JS" in obj:
                                    script = get_text(obj.get("/JS"))
                                    network_terms = [
                                        term
                                        for term in ("submitForm", "getURL", "launchURL", "SOAP", "Net.HTTP", "URL")
                                        if term.lower() in script.lower()
                                    ]
                                    result.add(
                                        Finding(
                                            "HIGH",
                                            "PDF active content",
                                            "Embedded PDF JavaScript",
                                            "The PDF contains JavaScript source or a JavaScript stream.",
                                            evidence=(
                                                f"Object path: {trail}/JS; network-related terms: {', '.join(network_terms) if network_terms else 'none identified'}; "
                                                f"snippet: {safe_snippet(script, 200)}"
                                            ),
                                            remediation="Disable PDF JavaScript and review the script in an isolated environment.",
                                        )
                                    )
                                special_keys = {
                                    "/EmbeddedFiles": ("MEDIUM", "PDF embedded-file name tree"),
                                    "/XFA": ("MEDIUM", "PDF XFA forms"),
                                    "/RichMedia": ("HIGH", "PDF rich-media content"),
                                    "/RichMediaContent": ("HIGH", "PDF rich-media content"),
                                    "/AcroForm": ("INFO", "Interactive PDF form"),
                                    "/3D": ("MEDIUM", "PDF 3D content"),
                                    "/Movie": ("MEDIUM", "PDF movie content"),
                                    "/Sound": ("MEDIUM", "PDF sound content"),
                                }
                                for key, (severity, title) in special_keys.items():
                                    if key in obj:
                                        result.add(
                                            Finding(
                                                severity,
                                                "PDF content",
                                                title,
                                                "This PDF feature can contain interactive, embedded, or externally connected content that warrants review.",
                                                evidence=f"Object path: {trail}{key}",
                                                remediation="Confirm the feature is expected and use a viewer with active content disabled.",
                                            )
                                        )
                                for key, value in list(obj.items()):
                                    walk(value, f"{trail}/{str(key).lstrip('/')}", depth + 1)
                            elif isinstance(obj, (list, tuple)):
                                for index, value in enumerate(obj):
                                    walk(value, f"{trail}[{index}]", depth + 1)
                        except Exception:
                            return

                    root = reader.trailer.get("/Root") if hasattr(reader, "trailer") else None
                    if root is not None:
                        walk(root)
                    if counters["objects"] >= self.policy.max_pdf_objects:
                        result.notes.append("PDF object traversal reached the configured object limit.")
            except Exception as exc:
                parser_failed = True
                result.notes.append(f"pypdf parsing failed: {type(exc).__name__}: {exc}")
        elif parser_available:
            result.notes.append("PDF exceeded the deep-parse size limit; only raw indicators were scanned.")

        self._scan_pdf_raw(path, result, parser_failed=parser_failed or not parser_available)

    def _scan_pdf_raw(self, path: Path, result: ScanResult, parser_failed: bool = False) -> None:
        data, truncated = read_limited(path, self.policy.max_raw_scan_bytes)
        text = decode_bytes(data)
        token_findings = {
            "/JavaScript": ("HIGH", "Raw PDF JavaScript token"),
            "/Launch": ("HIGH", "Raw PDF launch-action token"),
            "/SubmitForm": ("HIGH", "Raw PDF form-submission token"),
            "/OpenAction": ("MEDIUM", "Raw PDF open-action token"),
            "/AA": ("MEDIUM", "Raw PDF additional-action token"),
            "/GoToR": ("MEDIUM", "Raw PDF remote-document token"),
            "/EmbeddedFile": ("MEDIUM", "Raw PDF embedded-file token"),
            "/RichMedia": ("HIGH", "Raw PDF rich-media token"),
            "/XFA": ("MEDIUM", "Raw PDF XFA token"),
        }
        for token, (severity, title) in token_findings.items():
            if token in text:
                result.add(
                    Finding(
                        severity if parser_failed else ("LOW" if severity == "MEDIUM" else "MEDIUM"),
                        "PDF raw indicators",
                        title,
                        "The token appears in raw PDF bytes. Raw matching can produce false positives, but it is useful when structured parsing is incomplete.",
                        evidence=token,
                        remediation="Confirm the object structure with an independent PDF-analysis tool.",
                    )
                )
        self._add_url_findings(text, result, context="pdf-raw", auto_load=False)
        if truncated:
            result.notes.append("Raw PDF scan was truncated at the configured byte limit.")

    def _scan_html_email_svg(self, path: Path, result: ScanResult) -> None:
        data, truncated = read_limited(path, self.policy.max_raw_scan_bytes)
        extension = result.extension
        if extension == ".eml":
            result.detected_type = "Email message"
            try:
                message = BytesParser(policy=email_policy.default).parsebytes(data)
                html_parts: list[str] = []
                attachments: list[str] = []
                if message.is_multipart():
                    for part in message.walk():
                        content_type = part.get_content_type()
                        disposition = part.get_content_disposition()
                        filename = part.get_filename()
                        if disposition == "attachment" or filename:
                            attachments.append(filename or f"unnamed {content_type}")
                        elif content_type == "text/html":
                            try:
                                html_parts.append(part.get_content())
                            except Exception:
                                payload = part.get_payload(decode=True) or b""
                                html_parts.append(decode_bytes(payload))
                elif message.get_content_type() == "text/html":
                    try:
                        html_parts.append(message.get_content())
                    except Exception:
                        html_parts.append(decode_bytes(message.get_payload(decode=True) or b""))
                if attachments:
                    active = [name for name in attachments if Path(name).suffix.lower() in ACTIVE_ARCHIVE_EXTENSIONS]
                    result.add(
                        Finding(
                            "HIGH" if active else "INFO",
                            "Email content",
                            "Email attachments",
                            "The message contains attachments that require separate scanning.",
                            evidence=", ".join(attachments[:30]),
                            remediation="Save attachments to an isolated folder and scan each one before opening.",
                        )
                    )
                for html_part in html_parts:
                    self._scan_html_text(html_part, result, source="email HTML body")
                message_id = message.get("Message-ID")
                if message_id:
                    result.add(
                        Finding(
                            "INFO",
                            "Privacy metadata",
                            "Email message identifier",
                            "The message contains a unique Message-ID used for mail routing and threading. It is not an active tracker by itself but can identify the message instance.",
                            evidence=safe_snippet(message_id, 200),
                            remediation="Preserve it for evidence or remove headers only when creating an approved sanitized copy.",
                        )
                    )
            except Exception as exc:
                result.notes.append(f"Email parsing failed: {exc}")
                self._scan_html_text(decode_bytes(data), result, source="raw email")
        else:
            result.detected_type = "HTML/SVG document" if extension in {".html", ".htm", ".xhtml", ".svg"} else "Web archive"
            self._scan_html_text(decode_bytes(data), result, source=extension or "web content")
        if truncated:
            result.notes.append("HTML/email scan was truncated at the configured byte limit.")

    def _scan_html_text(self, text: str, result: ScanResult, source: str) -> None:
        parser = _TrackingHTMLParser()
        try:
            parser.feed(text)
        except Exception as exc:
            result.notes.append(f"HTML parsing warning: {exc}")

        for reference in parser.references[: self.policy.max_urls_per_file]:
            tag = reference["tag"]
            attribute = reference["attribute"]
            url = reference["url"]
            attrs = reference["attrs"]
            tracker, reasons = tracker_characteristics(url)
            width = str(attrs.get("width", "")).strip().lower().replace("px", "")
            height = str(attrs.get("height", "")).strip().lower().replace("px", "")
            tiny = width in {"0", "1"} and height in {"0", "1"}
            if tag == "img" and (tiny or tracker):
                severity = "HIGH" if tiny or tracker else "MEDIUM"
                title = "Remote tracking-pixel candidate" if tiny else "Remote image with tracking characteristics"
                detail = "The HTML/email can automatically request a remote image. The request can reveal that the content was opened, along with network and client information available to the server."
            elif tag in {"script", "iframe", "frame", "object", "embed"}:
                severity = "HIGH"
                title = "Remote executable or embedded web content"
                detail = "The document references remote script, frame, or embedded content that may execute or load when opened in a browser-capable viewer."
            elif tag == "form":
                severity = "MEDIUM"
                title = "External form submission destination"
                detail = "The document contains a form that can send entered data to an external server."
            elif tag == "a":
                severity = "MEDIUM" if tracker else "LOW"
                title = "Hyperlink with tracking characteristics" if tracker else "External hyperlink"
                detail = "The link contacts its destination when selected by a user."
            elif tag == "meta-refresh":
                severity = "MEDIUM"
                title = "Automatic redirect"
                detail = "The content contains a meta-refresh redirect that may navigate automatically."
            else:
                severity = "HIGH" if tracker and tag in {"img", "source", "video", "audio", "link", "input", "image", "use"} else "MEDIUM"
                title = "Remote resource with tracking characteristics" if tracker else "Remote web resource"
                detail = "The content references a remote resource that may be retrieved automatically, depending on the viewer."
            result.add(
                Finding(
                    severity,
                    "Web tracking/active content",
                    title,
                    detail + (f" Tracker indicators: {'; '.join(reasons)}." if reasons else ""),
                    evidence=f"Source: {source}; <{tag}> {attribute}={redact_url(url)}",
                    remediation="Block remote content by default and remove unnecessary external references before sharing.",
                )
            )

        if parser.event_handlers:
            result.add(
                Finding(
                    "HIGH",
                    "Web active content",
                    "Inline event-handler code",
                    "The HTML/SVG contains event attributes such as onload or onclick that can execute script in a browser-capable viewer.",
                    evidence="; ".join(parser.event_handlers[:20]),
                    remediation="Remove event handlers or review them in an isolated browser environment.",
                )
            )

        script_text = "\n".join(parser.inline_scripts)
        network_apis = [
            term
            for term in ("sendBeacon", "fetch(", "XMLHttpRequest", "WebSocket", "Image()", "navigator.sendBeacon", "document.cookie")
            if term.lower() in script_text.lower()
        ]
        if network_apis:
            result.add(
                Finding(
                    "HIGH",
                    "Web active content",
                    "Inline script with network or tracking APIs",
                    "Inline JavaScript contains APIs that can transmit data, load remote resources, or access browser state.",
                    evidence=", ".join(network_apis),
                    remediation="Do not open in a normal browser; review the script in an isolated environment and remove it if unnecessary.",
                )
            )
        self._add_url_findings(script_text, result, context="inline-script", auto_load=True)

    def _scan_text(self, path: Path, result: ScanResult) -> None:
        result.detected_type = "Text-like file"
        data, truncated = read_limited(path, self.policy.max_raw_scan_bytes)
        text = decode_bytes(data)
        self._add_url_findings(text, result, context="plain-text", auto_load=False)
        extension = result.extension
        if extension in {".js", ".py", ".ps1", ".bat", ".cmd", ".sh", ".r"}:
            network_terms = [
                term
                for term in (
                    "requests.get",
                    "requests.post",
                    "urllib",
                    "Invoke-WebRequest",
                    "Invoke-RestMethod",
                    "curl ",
                    "wget ",
                    "fetch(",
                    "XMLHttpRequest",
                    "sendBeacon",
                    "WebClient",
                    "HttpClient",
                    "socket.",
                )
                if term.lower() in text.lower()
            ]
            if network_terms:
                result.add(
                    Finding(
                        "MEDIUM",
                        "Script behavior",
                        "Script contains network-access code",
                        "The selected file is executable script source and contains network-related APIs or commands. Static presence does not prove the code runs, but it warrants review.",
                        evidence=", ".join(network_terms[:20]),
                        remediation="Review the script before executing it and run only in an environment with appropriate network controls.",
                    )
                )
        if truncated:
            result.notes.append("Text scan was truncated at the configured byte limit.")

    def _scan_image(self, path: Path, result: ScanResult) -> None:
        try:
            from PIL import ExifTags, Image  # type: ignore
        except ImportError:
            result.notes.append("Pillow is not installed; image metadata analysis was skipped.")
            self._scan_generic_content(path, result, context="image")
            return
        try:
            with Image.open(path) as image:
                result.detected_type = f"Image: {image.format or 'unknown'}"
                width, height = image.size
                if width <= 2 and height <= 2:
                    result.add(
                        Finding(
                            "INFO",
                            "Image characteristics",
                            "Very small image",
                            "A tiny image can be used as a tracking pixel when referenced remotely from HTML or email. A standalone local image is not an active tracker by itself.",
                            evidence=f"Dimensions: {width}×{height}",
                            remediation="Inspect the context in which the image is referenced.",
                        )
                    )
                exif = image.getexif()
                metadata: list[str] = []
                gps_present = False
                if exif:
                    tag_names = getattr(ExifTags, "TAGS", {})
                    privacy_keys = {
                        "Artist",
                        "Copyright",
                        "CameraOwnerName",
                        "BodySerialNumber",
                        "LensSerialNumber",
                        "ImageUniqueID",
                        "UserComment",
                        "XPAuthor",
                        "XPComment",
                        "XPKeywords",
                        "Software",
                        "DateTime",
                        "DateTimeOriginal",
                    }
                    for key, value in exif.items():
                        name = tag_names.get(key, str(key))
                        if name in privacy_keys and value not in (None, "", b""):
                            metadata.append(f"{name}={safe_snippet(value, 120)}")
                    try:
                        gps = exif.get_ifd(0x8825)
                        gps_present = bool(gps)
                    except Exception:
                        gps_present = any(tag_names.get(key) == "GPSInfo" for key in exif.keys())
                info_keys = []
                for key, value in image.info.items():
                    if key.lower() in {"author", "artist", "comment", "description", "software", "xml", "xmp", "exif"}:
                        info_keys.append(key)
                        if isinstance(value, str):
                            metadata.append(f"{key}={safe_snippet(value, 120)}")
                if gps_present:
                    result.add(
                        Finding(
                            "MEDIUM",
                            "Privacy metadata",
                            "Image GPS metadata",
                            "The image contains GPS-related EXIF metadata that may reveal a capture location.",
                            remediation="Create an approved metadata-stripped copy before external sharing if location disclosure is not intended.",
                        )
                    )
                if metadata or info_keys:
                    result.add(
                        Finding(
                            "INFO",
                            "Privacy metadata",
                            "Image identity or editing metadata",
                            "The image contains metadata that may disclose author, device, serial number, software, comments, or timestamps.",
                            evidence="; ".join(metadata[:25]) if metadata else ", ".join(info_keys),
                            remediation="Review and strip unnecessary metadata from a copy before external release.",
                        )
                    )
        except Exception as exc:
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "Image parsing failed",
                    "The image metadata parser could not inspect the file completely.",
                    evidence=f"{type(exc).__name__}: {exc}",
                    remediation="Obtain a fresh copy or inspect with an independent image-forensics tool.",
                )
            )

    def _scan_archive(self, path: Path, result: ScanResult) -> None:
        extension = result.extension
        try:
            if extension == ".zip" or zipfile.is_zipfile(path):
                with zipfile.ZipFile(path) as archive:
                    result.detected_type = "ZIP archive"
                    self._scan_zip_inventory(archive, result)
                return
            if extension in {".tar", ".tgz", ".gz", ".bz2", ".xz"} and tarfile.is_tarfile(path):
                result.detected_type = "TAR archive"
                active_entries: list[str] = []
                nested_documents: list[str] = []
                with tarfile.open(path, mode="r:*") as archive:
                    members = archive.getmembers()
                    if len(members) > self.policy.max_zip_entries:
                        result.add(
                            Finding(
                                "HIGH",
                                "Archive safety",
                                "Excessive archive entry count",
                                "The archive contains more entries than the configured safe inspection limit.",
                                evidence=f"Entries: {len(members):,}",
                                remediation="Analyze with strict resource limits in an isolated environment.",
                            )
                        )
                        return
                    for member in members:
                        suffix = Path(member.name).suffix.lower()
                        if member.issym() or member.islnk():
                            result.add(
                                Finding(
                                    "MEDIUM",
                                    "Archive safety",
                                    "Archive link entry",
                                    "The archive contains a symbolic or hard link that can redirect extraction to an unexpected path.",
                                    evidence=member.name,
                                    remediation="Use a safe extractor that blocks path traversal and link escapes.",
                                )
                            )
                        if suffix in ACTIVE_ARCHIVE_EXTENSIONS:
                            active_entries.append(member.name)
                        if suffix in OFFICE_ZIP_EXTENSIONS | LEGACY_OFFICE_EXTENSIONS | {".pdf", ".rtf", ".html", ".eml"}:
                            nested_documents.append(member.name)
                if active_entries:
                    result.add(
                        Finding(
                            "HIGH",
                            "Archive content",
                            "Executable or script-like archive entries",
                            "The archive contains code-capable files.",
                            evidence=", ".join(active_entries[:30]),
                            remediation="Do not execute these entries; inspect in isolation.",
                        )
                    )
                if nested_documents:
                    result.add(
                        Finding(
                            "INFO",
                            "Inspection completeness",
                            "Nested documents require separate scans",
                            "This version inventories but does not deeply parse every file inside TAR archives.",
                            evidence=", ".join(nested_documents[:30]),
                            remediation="Extract safely to an isolated directory and scan the files individually.",
                        )
                    )
                return
        except Exception as exc:
            result.add(
                Finding(
                    "MEDIUM",
                    "Inspection completeness",
                    "Archive parsing failed",
                    "The archive could not be inventoried completely.",
                    evidence=f"{type(exc).__name__}: {exc}",
                    remediation="Use an isolated archive-analysis tool and do not extract directly into sensitive directories.",
                )
            )
            return
        self._scan_generic_content(path, result, context="archive")

    def _scan_generic_content(self, path: Path, result: ScanResult, context: str) -> None:
        data, truncated = read_limited(path, self.policy.max_raw_scan_bytes)
        text = decode_bytes(data)
        self._add_url_findings(text, result, context=context, auto_load=False)
        extension = result.extension
        if extension in {".lnk", ".url", ".chm", ".hta", ".js", ".vbs", ".ps1", ".bat", ".cmd"}:
            result.add(
                Finding(
                    "HIGH",
                    "Active content",
                    "File type can execute or redirect",
                    "This file type can execute commands, scripts, compiled help content, or external shortcuts rather than acting as a passive document.",
                    evidence=f"Extension: {extension}",
                    remediation="Do not activate the file. Review it as code or shortcut data in an isolated environment.",
                )
            )
        if truncated:
            result.notes.append("Generic raw scan was truncated at the configured byte limit.")

    def _add_url_findings(self, text: str, result: ScanResult, context: str, auto_load: bool) -> None:
        for url in extract_urls(text, self.policy.max_urls_per_file):
            tracker, reasons = tracker_characteristics(url)
            if tracker:
                severity = "HIGH" if auto_load else "MEDIUM"
                result.add(
                    Finding(
                        severity,
                        "Tracking indicators",
                        "Tracking-style or recipient-identifying URL",
                        "The file contains a URL with common analytics, campaign, recipient, or telemetry characteristics. Static presence does not prove it is contacted automatically.",
                        evidence=f"Context: {context}; URL: {redact_url(url)}; reasons: {'; '.join(reasons)}",
                        remediation="Determine whether the URL is automatically loaded, user-activated, or merely visible text; remove it if unnecessary.",
                    )
                )
            elif context in {"binary", "legacy-office", "pdf-raw", "rtf"}:
                result.add(
                    Finding(
                        "LOW",
                        "External references",
                        "External URL embedded in file",
                        "An external URL was found in a format where its role is not fully determined by the raw scan.",
                        evidence=f"Context: {context}; URL: {redact_url(url)}",
                        remediation="Confirm whether the URL is a normal citation, a hyperlink, or an automatically loaded resource.",
                    )
                )


def write_json_report(results: Iterable[ScanResult], destination: str | Path) -> Path:
    destination = Path(destination)
    payload = {
        "application": APP_NAME,
        "version": VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "limitations": (
            "Static inspection cannot prove a file is safe. Encrypted, obfuscated, malformed, server-side, viewer-level, "
            "cloud-platform, DRM, and exploit-based behavior may not be detected."
        ),
        "results": [result.as_dict() for result in results],
    }
    destination.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return destination


def write_csv_report(results: Iterable[ScanResult], destination: str | Path) -> Path:
    destination = Path(destination)
    fields = [
        "path",
        "sha256",
        "detected_type",
        "size_bytes",
        "highest_severity",
        "risk_score",
        "tags",
        "severity",
        "category",
        "title",
        "detail",
        "evidence",
        "remediation",
        "notes",
        "error",
    ]
    with destination.open("w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for result in results:
            findings = result.findings or [Finding("INFO", "Scan result", "No recognized indicators", "No recognized indicators were found by this scanner version.")]
            for finding in findings:
                writer.writerow(
                    {
                        "path": result.path,
                        "sha256": result.sha256,
                        "detected_type": result.detected_type,
                        "size_bytes": result.size_bytes,
                        "highest_severity": result.highest_severity,
                        "risk_score": result.risk_score,
                        "tags": ", ".join(result.tags),
                        "severity": finding.severity,
                        "category": finding.category,
                        "title": finding.title,
                        "detail": finding.detail,
                        "evidence": finding.evidence,
                        "remediation": finding.remediation,
                        "notes": " | ".join(result.notes),
                        "error": result.error,
                    }
                )
    return destination


def format_result_text(result: ScanResult) -> str:
    lines = [
        f"File: {result.path}",
        f"Type: {result.detected_type}",
        f"Size: {result.size_bytes:,} bytes",
        f"SHA-256: {result.sha256 or '(not calculated)'}",
        f"Risk: {result.highest_severity} (score {result.risk_score}/100)",
        f"Local tags: {', '.join(result.tags) if result.tags else '(none)'}",
        "",
    ]
    if result.error:
        lines.extend([f"Inspection error: {result.error}", ""])
    if not result.findings:
        lines.extend(
            [
                "No recognized tracking, active-content, or privacy indicators were found by this scanner version.",
                "This is not a guarantee that the file is safe or authorized to share.",
            ]
        )
    else:
        lines.append(f"Findings ({len(result.findings)}):")
        for index, finding in enumerate(result.findings, start=1):
            lines.extend(
                [
                    "",
                    f"{index}. [{finding.severity}] {finding.title}",
                    f"   Category: {finding.category}",
                    f"   {finding.detail}",
                ]
            )
            if finding.evidence:
                lines.append(f"   Evidence: {finding.evidence}")
            if finding.remediation:
                lines.append(f"   Recommended action: {finding.remediation}")
    if result.notes:
        lines.extend(["", "Inspection notes:"])
        lines.extend(f"- {note}" for note in result.notes)
    lines.extend(
        [
            "",
            "Boundary: this is static, offline inspection. It cannot detect every form of tracking, viewer telemetry, cloud-service logging, DRM callbacks, hidden exploits, or server-side behavior.",
        ]
    )
    return "\n".join(lines)
