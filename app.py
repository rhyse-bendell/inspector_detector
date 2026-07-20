from __future__ import annotations

import argparse
import queue
import sys
import threading
from pathlib import Path
from typing import Iterable

from file_guardian import (
    APP_NAME,
    VERSION,
    FileScanner,
    ScanResult,
    TagStore,
    format_result_text,
    write_csv_report,
    write_json_report,
)


def run_cli(paths: Iterable[str], recursive: bool, json_path: str | None, csv_path: str | None) -> int:
    scanner = FileScanner()
    tag_store = TagStore()
    input_files = list(scanner.iter_input_files(paths, recursive=recursive))
    if not input_files:
        print("No readable files were found.", file=sys.stderr)
        return 2

    results: list[ScanResult] = []
    for index, path in enumerate(input_files, start=1):
        print(f"[{index}/{len(input_files)}] Scanning {path}")
        result = scanner.scan_file(path)
        result.tags = tag_store.get_tags(result.sha256)
        results.append(result)
        print(
            f"  {result.highest_severity:>6}  score={result.risk_score:>3}  "
            f"findings={len(result.findings):>2}  {result.detected_type}"
        )

    if json_path:
        destination = write_json_report(results, json_path)
        print(f"JSON report: {destination}")
    if csv_path:
        destination = write_csv_report(results, csv_path)
        print(f"CSV report: {destination}")

    high_count = sum(1 for result in results if result.highest_severity in {"HIGH", "CRITICAL"})
    print(f"Completed: {len(results)} file(s); {high_count} high/critical result(s).")
    return 1 if high_count else 0


def run_gui() -> int:
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print("Tkinter is not available in this Python installation.", file=sys.stderr)
        return 2

    class GuardianApp(tk.Tk):
        def __init__(self) -> None:
            super().__init__()
            self.title(f"{APP_NAME} {VERSION}")
            self.geometry("1240x760")
            self.minsize(980, 620)

            self.scanner = FileScanner()
            self.tag_store = TagStore()
            self.results: list[ScanResult] = []
            self.result_by_iid: dict[str, ScanResult] = {}
            self.worker_queue: queue.Queue[tuple[str, object]] = queue.Queue()
            self.cancel_event = threading.Event()
            self.worker: threading.Thread | None = None

            self.recursive_var = tk.BooleanVar(value=True)
            self.status_var = tk.StringVar(value="Ready. Files are inspected locally; the scanner makes no network requests.")
            self.tag_var = tk.StringVar()

            self._build_ui(ttk, tk, filedialog, messagebox)
            self.after(100, self._poll_worker)

        def _build_ui(self, ttk, tk, filedialog, messagebox) -> None:
            self._filedialog = filedialog
            self._messagebox = messagebox

            top = ttk.Frame(self, padding=10)
            top.pack(fill="x")

            title = ttk.Label(top, text="File Guardian", font=("Segoe UI", 20, "bold"))
            title.grid(row=0, column=0, sticky="w")
            subtitle = ttk.Label(
                top,
                text=(
                    "Offline static inspection for remote references, tracking-style URLs, active content, embedded objects, "
                    "privacy metadata, and incomplete inspection conditions."
                ),
                wraplength=940,
            )
            subtitle.grid(row=1, column=0, columnspan=8, sticky="w", pady=(2, 8))

            self.files_button = ttk.Button(top, text="Scan Files…", command=self._choose_files)
            self.files_button.grid(row=2, column=0, padx=(0, 6), sticky="w")
            self.folder_button = ttk.Button(top, text="Scan Folder…", command=self._choose_folder)
            self.folder_button.grid(row=2, column=1, padx=6, sticky="w")
            ttk.Checkbutton(top, text="Include subfolders", variable=self.recursive_var).grid(
                row=2, column=2, padx=12, sticky="w"
            )
            self.cancel_button = ttk.Button(top, text="Cancel", command=self._cancel_scan, state="disabled")
            self.cancel_button.grid(row=2, column=3, padx=6, sticky="w")
            ttk.Button(top, text="Clear", command=self._clear_results).grid(row=2, column=4, padx=6, sticky="w")
            ttk.Button(top, text="Export Report…", command=self._export_report).grid(row=2, column=5, padx=6, sticky="w")

            warning = ttk.Label(
                top,
                text=(
                    "A clean scan is not proof that a file is safe or authorized to share. Encrypted content, obfuscation, "
                    "viewer telemetry, cloud logging, DRM callbacks, and exploits may remain undetected."
                ),
                wraplength=1120,
            )
            warning.grid(row=3, column=0, columnspan=8, sticky="w", pady=(10, 0))
            top.columnconfigure(7, weight=1)

            main = ttk.Panedwindow(self, orient="horizontal")
            main.pack(fill="both", expand=True, padx=10, pady=(0, 8))

            left = ttk.Frame(main)
            right = ttk.Frame(main)
            main.add(left, weight=3)
            main.add(right, weight=4)

            columns = ("risk", "score", "type", "findings", "tags", "path")
            self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="extended")
            headings = {
                "risk": "Risk",
                "score": "Score",
                "type": "Detected type",
                "findings": "Findings",
                "tags": "Local tags",
                "path": "File",
            }
            widths = {"risk": 80, "score": 60, "type": 180, "findings": 70, "tags": 150, "path": 390}
            for column in columns:
                self.tree.heading(column, text=headings[column])
                self.tree.column(column, width=widths[column], anchor="w", stretch=column in {"type", "tags", "path"})
            tree_scroll_y = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
            tree_scroll_x = ttk.Scrollbar(left, orient="horizontal", command=self.tree.xview)
            self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
            self.tree.grid(row=0, column=0, sticky="nsew")
            tree_scroll_y.grid(row=0, column=1, sticky="ns")
            tree_scroll_x.grid(row=1, column=0, sticky="ew")
            left.rowconfigure(0, weight=1)
            left.columnconfigure(0, weight=1)
            self.tree.bind("<<TreeviewSelect>>", self._show_selected_result)

            details_label = ttk.Label(right, text="Inspection details", font=("Segoe UI", 11, "bold"))
            details_label.pack(anchor="w", pady=(0, 4))
            text_frame = ttk.Frame(right)
            text_frame.pack(fill="both", expand=True)
            self.details = tk.Text(text_frame, wrap="word", state="disabled", font=("Consolas", 9))
            detail_scroll = ttk.Scrollbar(text_frame, orient="vertical", command=self.details.yview)
            self.details.configure(yscrollcommand=detail_scroll.set)
            self.details.pack(side="left", fill="both", expand=True)
            detail_scroll.pack(side="right", fill="y")

            tag_frame = ttk.LabelFrame(right, text="Local tags (stored outside the source file)", padding=8)
            tag_frame.pack(fill="x", pady=(8, 0))
            ttk.Label(tag_frame, text="Comma-separated tags:").grid(row=0, column=0, sticky="w")
            tag_entry = ttk.Entry(tag_frame, textvariable=self.tag_var)
            tag_entry.grid(row=0, column=1, sticky="ew", padx=6)
            ttk.Button(tag_frame, text="Add to selected", command=self._add_tags).grid(row=0, column=2, padx=4)
            ttk.Button(tag_frame, text="Remove from selected", command=self._remove_tags).grid(row=0, column=3, padx=4)
            ttk.Button(tag_frame, text="Copy details", command=self._copy_details).grid(row=0, column=4, padx=(12, 0))
            tag_frame.columnconfigure(1, weight=1)

            status = ttk.Label(self, textvariable=self.status_var, relief="sunken", anchor="w", padding=(8, 4))
            status.pack(fill="x", side="bottom")

        def _choose_files(self) -> None:
            paths = self._filedialog.askopenfilenames(title="Select files to inspect")
            if paths:
                self._start_scan(list(paths), recursive=False)

        def _choose_folder(self) -> None:
            folder = self._filedialog.askdirectory(title="Select folder to inspect")
            if folder:
                self._start_scan([folder], recursive=self.recursive_var.get())

        def _start_scan(self, inputs: list[str], recursive: bool) -> None:
            if self.worker and self.worker.is_alive():
                self._messagebox.showinfo(APP_NAME, "A scan is already running.")
                return
            self.cancel_event.clear()
            self.files_button.configure(state="disabled")
            self.folder_button.configure(state="disabled")
            self.cancel_button.configure(state="normal")
            self.status_var.set("Enumerating files…")

            def worker() -> None:
                try:
                    files = list(self.scanner.iter_input_files(inputs, recursive=recursive))
                    self.worker_queue.put(("count", len(files)))
                    for index, path in enumerate(files, start=1):
                        if self.cancel_event.is_set():
                            break
                        self.worker_queue.put(("progress", (index, len(files), str(path))))
                        result = self.scanner.scan_file(path)
                        result.tags = self.tag_store.get_tags(result.sha256)
                        self.worker_queue.put(("result", result))
                    self.worker_queue.put(("done", self.cancel_event.is_set()))
                except Exception as exc:
                    self.worker_queue.put(("fatal", f"{type(exc).__name__}: {exc}"))

            self.worker = threading.Thread(target=worker, daemon=True)
            self.worker.start()

        def _poll_worker(self) -> None:
            try:
                while True:
                    kind, payload = self.worker_queue.get_nowait()
                    if kind == "count":
                        count = int(payload)
                        self.status_var.set(f"Found {count} file(s).")
                    elif kind == "progress":
                        index, total, path = payload  # type: ignore[misc]
                        self.status_var.set(f"Scanning {index}/{total}: {path}")
                    elif kind == "result":
                        self._insert_result(payload)  # type: ignore[arg-type]
                    elif kind == "done":
                        cancelled = bool(payload)
                        self._scan_finished(cancelled)
                    elif kind == "fatal":
                        self._scan_finished(False)
                        self._messagebox.showerror(APP_NAME, f"Scan failed:\n{payload}")
            except queue.Empty:
                pass
            self.after(100, self._poll_worker)

        def _insert_result(self, result: ScanResult) -> None:
            self.results.append(result)
            iid = self.tree.insert(
                "",
                "end",
                values=(
                    result.highest_severity,
                    result.risk_score,
                    result.detected_type,
                    len(result.findings),
                    ", ".join(result.tags),
                    result.path,
                ),
            )
            self.result_by_iid[iid] = result
            if len(self.results) == 1:
                self.tree.selection_set(iid)
                self.tree.focus(iid)
                self._display_result(result)

        def _scan_finished(self, cancelled: bool) -> None:
            self.files_button.configure(state="normal")
            self.folder_button.configure(state="normal")
            self.cancel_button.configure(state="disabled")
            if cancelled:
                self.status_var.set(f"Scan cancelled. {len(self.results)} result(s) currently listed.")
            else:
                high = sum(1 for result in self.results if result.highest_severity in {"HIGH", "CRITICAL"})
                self.status_var.set(f"Scan complete. {len(self.results)} result(s); {high} high/critical.")

        def _cancel_scan(self) -> None:
            self.cancel_event.set()
            self.status_var.set("Cancelling after the current file…")

        def _clear_results(self) -> None:
            if self.worker and self.worker.is_alive():
                self._messagebox.showinfo(APP_NAME, "Cancel the active scan before clearing results.")
                return
            self.results.clear()
            self.result_by_iid.clear()
            for item in self.tree.get_children():
                self.tree.delete(item)
            self._set_details("")
            self.status_var.set("Results cleared.")

        def _show_selected_result(self, _event=None) -> None:
            selection = self.tree.selection()
            if not selection:
                return
            result = self.result_by_iid.get(selection[0])
            if result:
                self._display_result(result)

        def _display_result(self, result: ScanResult) -> None:
            self._set_details(format_result_text(result))

        def _set_details(self, text: str) -> None:
            self.details.configure(state="normal")
            self.details.delete("1.0", "end")
            self.details.insert("1.0", text)
            self.details.configure(state="disabled")

        def _selected_results(self) -> list[tuple[str, ScanResult]]:
            selected: list[tuple[str, ScanResult]] = []
            for iid in self.tree.selection():
                result = self.result_by_iid.get(iid)
                if result:
                    selected.append((iid, result))
            return selected

        def _parse_tags(self) -> list[str]:
            return [item.strip() for item in self.tag_var.get().split(",") if item.strip()]

        def _add_tags(self) -> None:
            tags = self._parse_tags()
            selected = self._selected_results()
            if not tags or not selected:
                self._messagebox.showinfo(APP_NAME, "Select one or more results and enter at least one tag.")
                return
            for iid, result in selected:
                result.tags = self.tag_store.add_tags(result.sha256, tags, path=result.path)
                values = list(self.tree.item(iid, "values"))
                values[4] = ", ".join(result.tags)
                self.tree.item(iid, values=values)
            self._display_result(selected[0][1])
            self.status_var.set(f"Added tags to {len(selected)} file(s). Source files were not modified.")

        def _remove_tags(self) -> None:
            tags = self._parse_tags()
            selected = self._selected_results()
            if not tags or not selected:
                self._messagebox.showinfo(APP_NAME, "Select one or more results and enter at least one tag.")
                return
            for iid, result in selected:
                result.tags = self.tag_store.remove_tags(result.sha256, tags)
                values = list(self.tree.item(iid, "values"))
                values[4] = ", ".join(result.tags)
                self.tree.item(iid, values=values)
            self._display_result(selected[0][1])
            self.status_var.set(f"Removed tags from {len(selected)} file(s). Source files were not modified.")

        def _copy_details(self) -> None:
            text = self.details.get("1.0", "end-1c")
            if not text:
                return
            self.clipboard_clear()
            self.clipboard_append(text)
            self.status_var.set("Inspection details copied to the clipboard.")

        def _export_report(self) -> None:
            if not self.results:
                self._messagebox.showinfo(APP_NAME, "There are no results to export.")
                return
            destination = self._filedialog.asksaveasfilename(
                title="Export File Guardian report",
                defaultextension=".json",
                filetypes=[("JSON report", "*.json"), ("CSV report", "*.csv")],
            )
            if not destination:
                return
            try:
                if Path(destination).suffix.lower() == ".csv":
                    write_csv_report(self.results, destination)
                else:
                    write_json_report(self.results, destination)
                self.status_var.set(f"Report saved: {destination}")
            except Exception as exc:
                self._messagebox.showerror(APP_NAME, f"Could not save report:\n{type(exc).__name__}: {exc}")

    app = GuardianApp()
    app.mainloop()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Offline static inspection of documents and related files for tracking and active-content indicators."
    )
    parser.add_argument("paths", nargs="*", help="Files or folders to scan. If omitted, the GUI opens.")
    parser.add_argument("--recursive", action="store_true", help="Include subfolders for folder inputs.")
    parser.add_argument("--json", dest="json_path", help="Write a JSON report to this path.")
    parser.add_argument("--csv", dest="csv_path", help="Write a CSV report to this path.")
    parser.add_argument("--gui", action="store_true", help="Open the GUI even when paths are supplied.")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION}")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.gui or not args.paths:
        return run_gui()
    return run_cli(args.paths, recursive=args.recursive, json_path=args.json_path, csv_path=args.csv_path)


if __name__ == "__main__":
    raise SystemExit(main())
