# File Guardian 0.1

File Guardian is a local, read-only Python application for inspecting documents and related files before you open or share them. It looks for indicators that a file may contact an external service, execute active content, contain hidden/embedded material, or disclose metadata.

It does **not** upload files or make network requests. The scanner reads source files without modifying them. Local tags are stored separately in the user's application-data directory and keyed by SHA-256 hash.

## Quick start on Windows

1. Install a current 64-bit Python 3 release from Python's official installer. During installation, enable **Add Python to PATH** or ensure the `py` launcher is installed.
2. Extract this folder to a location you control.
3. Double-click **`Install_and_Run.bat`** the first time. It creates an isolated `.venv`, installs the optional parsing libraries, and opens the GUI.
4. On later runs, double-click **`Run_File_Guardian.bat`**.
5. Choose **Scan Files…** or **Scan Folder…**. Select a result to see evidence and recommended follow-up.
6. Use **Export Report…** to save JSON or CSV results.

The application should also start in a reduced-capability mode with only the Python standard library. Installing the requirements enables deeper PDF, image-metadata, and Office macro analysis.

## What version 0.1 inspects

### Modern Microsoft Office files

Supported Open XML containers include DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, templates, and related variants. Checks include:

- external relationships and remote templates;
- remote images/media, linked data, hyperlinks, network shares, and file URLs;
- VBA projects, ActiveX, web add-ins/task panes, custom ribbons, and embedded OLE objects;
- DDE, INCLUDEPICTURE, and INCLUDETEXT field indicators;
- document properties, custom properties, comments/reviewer data, custom XML, classification-style property names, and digital-signature components;
- ZIP encryption, excessive expansion, and archive-bomb characteristics.

### Legacy Office and RTF

- legacy OLE Office formats are marked as requiring more cautious review;
- `oletools`, when installed, performs source-level VBA indicator analysis without executing macros;
- RTF object data, DDE, external include fields, and external URLs are flagged.

### PDF

- JavaScript, launch actions, open actions, event-triggered actions, form submission, remote-document actions, XFA, rich media, 3D/media features, external URIs, and embedded attachments;
- author/creator/producer and timestamp metadata;
- raw token scanning when structured parsing is unavailable or incomplete.

### HTML, SVG, email, and web archives

- remote scripts, iframes, objects, forms, images, styles, media, and redirects;
- remote 1×1/0×0 image references and analytics-style hosts or query parameters;
- inline script network APIs such as `sendBeacon`, `fetch`, `XMLHttpRequest`, and WebSocket;
- inline event handlers such as `onload`;
- email attachments and Message-ID metadata.

### Images

- EXIF GPS data;
- author, owner, device serial, unique ID, software, comments, and timestamp metadata;
- tiny-image characteristics, while clearly distinguishing a standalone image from a remotely referenced tracking pixel.

### Archives, filesystems, and generic files

- executable/script/shortcut content inside ZIP and TAR archives;
- Windows NTFS alternate data streams, including Mark-of-the-Web provenance metadata;
- selected extended provenance attributes on macOS/Linux;
- executable signatures and misleading filename extensions;
- tracking-style URLs in text, script, and otherwise opaque file content.

## Local tags

Tags are intentionally **not embedded into the source document**. They are stored in:

- Windows: `%APPDATA%\FileGuardian\tags.json`
- macOS: `~/Library/Application Support/FileGuardian/tags.json`
- Linux: `$XDG_DATA_HOME/fileguardian/tags.json` or `~/.local/share/fileguardian/tags.json`

They are keyed by the file's SHA-256 hash, so tags can follow an identical copy of a file even if it is moved. Example labels might include `UCF`, `needs-PI-review`, `approved-to-share`, `CUI-review-required`, or `sanitized-copy`.

A tag is only an organizational label. It does not establish authorization, classification, or compliance.

## Important boundaries

Static inspection cannot prove that a file is safe. File Guardian does not reliably detect every possible:

- encrypted or password-protected payload;
- obfuscated macro or script;
- exploit for an Office, PDF, image, archive, or operating-system parser;
- DRM/licensing callback;
- telemetry performed by Microsoft Office, Adobe, a browser, a cloud viewer, SharePoint, OneDrive, Google Drive, or another application rather than by the file itself;
- server-side logging after a normal-looking URL redirects;
- steganographic content;
- tracking that depends on a specific institutional account, plugin, policy, or network environment.

“No recognized indicators” therefore means only that this scanner version did not find an indicator it knows how to detect.

For highly untrusted files, use a disposable virtual machine or Windows Sandbox, disconnect unnecessary network access, and do not double-click the source file. Parsing libraries themselves can have vulnerabilities, so an isolated environment remains appropriate for hostile samples.

## University and controlled-data warning

A tracker scan and a sharing authorization review are different tasks. A file can contain no tracker and still be restricted by CUI/FCI, export-control, sponsor, privacy, contract, IRB, or university policy. Do not upload or share a university file merely because File Guardian reports no findings. Check its markings, project rules, data owner, and approved systems first.

Reports may contain local paths, hashes, metadata, hostnames, and redacted URL structures. Treat reports according to the sensitivity of the inspected files.

## Command-line use

The GUI opens when no paths are supplied:

```bat
.venv\Scripts\python.exe app.py
```

Scan one file and save JSON:

```bat
.venv\Scripts\python.exe app.py "C:\Research\document.docx" --json "C:\Research\document_scan.json"
```

Scan a folder recursively and save JSON and CSV:

```bat
.venv\Scripts\python.exe app.py "C:\Research\Incoming" --recursive --json report.json --csv report.csv
```

CLI exit codes are:

- `0`: scan completed with no HIGH/CRITICAL file result;
- `1`: scan completed and at least one file had a HIGH/CRITICAL result;
- `2`: no files were found or the application could not start.

## Run the tests

```bat
.venv\Scripts\python.exe -m unittest discover -s tests -v
```

## Source layout

- `app.py` — GUI and command-line entry point.
- `file_guardian.py` — scanner, parsers, tag store, and report writers.
- `requirements.txt` — optional parsing dependencies.
- `tests/` — regression tests using synthetic files.
- `Install_and_Run.bat` — first-run setup and launcher.
- `Run_File_Guardian.bat` — normal Windows launcher.
- `run_file_guardian.sh` — macOS/Linux setup and launcher.

## Planned next steps

The architecture is ready for later additions such as:

- policy profiles for UCF/Knight Shield or other projects;
- controlled creation of sanitized copies with before/after hashes;
- recursive extraction in a restricted temporary workspace;
- password-assisted scans without storing passwords;
- signature and certificate validation;
- YARA integration;
- comparison of original and sanitized files;
- signed manifests, chain-of-custody records, and role-based approval tags.

Do not add “tracking tags” to documents themselves without a separate design and authorization review. Version 0.1 provides non-invasive local classification tags only.
