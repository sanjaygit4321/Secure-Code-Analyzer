#!/usr/bin/env python3
"""
SCA GUI - Local Desktop Interface for Secure Code Analyzer

Cross-platform GUI (Tkinter) to run the existing CLI analyses locally on
Windows, macOS, and Linux. No web server required.

Usage:
  - Run: python gui.py
  - Windows (double-click): sca_gui.bat
  - macOS (double-click): run_gui.command
"""

import os
import sys
import json
import threading
import re
import copy
from datetime import datetime

# Tkinter is part of the standard library, but on macOS
# your Python must be built with Tcl/Tk support.
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
except ModuleNotFoundError:
    print(
        "Tkinter is not available in this Python.\n"
        "On macOS, install Python from python.org (includes Tk), or\n"
        "brew install tcl-tk and reinstall Python with Tk support via pyenv.\n"
        "After that, re-create your venv and run: python gui.py"
    )
    sys.exit(1)

# Ensure local imports resolve when double-clicking scripts
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if SCRIPT_DIR not in sys.path:
    sys.path.insert(0, SCRIPT_DIR)

# Import analysis functions from main
try:
    import main as sca_main
except Exception as e:
    message = (
        f"Failed to import analyzer: {e}\n\n"
        "Ensure you are running gui.py from the project folder, and that dependencies are installed."
    )
    raise SystemExit(message)


class SCAGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SCA - Secure Code Analyzer (GUI)")
        self.geometry("980x700")
        self.minsize(900, 620)

        # State (must be after super().__init__())
        self.mode = tk.StringVar(value="analyze")  # analyze | scan
        self.path = tk.StringVar()
        self.recursive = tk.BooleanVar(value=True)
        self.extensions = tk.StringVar(value=".js,.mjs,.jsx,.ts,.tsx,.php,.java,.py")
        self.save_results = tk.BooleanVar(value=False)
        self.output_path = tk.StringVar(value="")  # file for analyze, directory for scan
        self.display_mode = tk.StringVar(value="json")  # json | tabular
        self.severity_filter = tk.StringVar(value="All")

        # Build UI
        self._build_header()
        self._build_controls()
        self._build_results()

    # UI sections
    def _build_header(self):
        header = ttk.Frame(self)
        header.pack(fill=tk.X, padx=14, pady=(12, 6))

        title = ttk.Label(header, text="Secure Code Analyzer", font=("Segoe UI", 16, "bold"))
        subtitle = ttk.Label(header, text="Analyze JavaScript, PHP, Java, or Python files or scan directories")
        title.grid(row=0, column=0, sticky="w")
        subtitle.grid(row=1, column=0, sticky="w")

    def _build_controls(self):
        controls = ttk.LabelFrame(self, text="Input & Options")
        controls.pack(fill=tk.X, padx=14, pady=6)

        # Mode
        mode_frame = ttk.Frame(controls)
        mode_frame.grid(row=0, column=0, columnspan=3, sticky="w", pady=(8, 6))
        ttk.Radiobutton(mode_frame, text="Analyze File", value="analyze", variable=self.mode, command=self._on_mode_change).pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Scan Directory", value="scan", variable=self.mode, command=self._on_mode_change).pack(side=tk.LEFT, padx=(16, 0))
        ttk.Radiobutton(mode_frame, text="Scan Zip", value="scan_zip", variable=self.mode, command=self._on_mode_change).pack(side=tk.LEFT, padx=(16, 0))

        # Path picker
        ttk.Label(controls, text="Path:").grid(row=1, column=0, sticky="e", padx=(8, 6))
        self.path_entry = ttk.Entry(controls, textvariable=self.path)
        self.path_entry.grid(row=1, column=1, sticky="ew", padx=(0, 6))
        browse_btn = ttk.Button(controls, text="Browse...", command=self._browse_path)
        browse_btn.grid(row=1, column=2, sticky="w")

        # Scan-only options
        self.scan_opts = ttk.Frame(controls)
        self.scan_opts.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(6, 0))
        self.scan_opts.columnconfigure(1, weight=1)
        ttk.Checkbutton(self.scan_opts, text="Recursive", variable=self.recursive).grid(row=0, column=0, sticky="w")
        ttk.Label(self.scan_opts, text="Extensions:").grid(row=0, column=1, sticky="e", padx=(8, 6))
        ttk.Entry(self.scan_opts, textvariable=self.extensions).grid(row=0, column=2, sticky="ew")

        # Output options
        out_opts = ttk.Frame(controls)
        out_opts.grid(row=3, column=0, columnspan=3, sticky="ew", pady=(6, 8))
        out_opts.columnconfigure(1, weight=1)
        ttk.Checkbutton(out_opts, text="Save results to JSON", variable=self.save_results, command=self._toggle_output).grid(row=0, column=0, sticky="w")
        ttk.Entry(out_opts, textvariable=self.output_path, state="disabled").grid(row=0, column=1, sticky="ew", padx=(8, 6))
        self.output_browse = ttk.Button(out_opts, text="Choose...", state="disabled", command=self._browse_output)
        self.output_browse.grid(row=0, column=2, sticky="w")

        # Run controls
        run_frame = ttk.Frame(controls)
        run_frame.grid(row=4, column=0, columnspan=3, sticky="ew")
        self.run_btn = ttk.Button(run_frame, text="Run Analysis", command=self._run)
        self.run_btn.pack(side=tk.LEFT)
        self.progress = ttk.Progressbar(run_frame, mode="indeterminate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(12, 0))

        # Grid weights
        controls.columnconfigure(1, weight=1)

        # Initial state
        self._on_mode_change()

    def _build_results(self):
        results_frame = ttk.LabelFrame(self, text="Results")
        results_frame.pack(fill=tk.BOTH, expand=True, padx=14, pady=(6, 14))

        # Summary labels
        summary = ttk.Frame(results_frame)
        summary.pack(fill=tk.X, padx=8, pady=6)
        self.summary_label = ttk.Label(summary, text="Awaiting analysis…")
        self.summary_label.pack(side=tk.LEFT)

        # Severity and Language filter dropdowns
        filter_frame = ttk.Frame(results_frame)
        filter_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        ttk.Label(filter_frame, text="Severity filter:").pack(side=tk.LEFT)
        severity_options = ["All", "Critical", "Medium", "Low", "Info"]
        severity_menu = ttk.OptionMenu(filter_frame, self.severity_filter, "All", *severity_options, command=lambda _: self._refresh_results())
        severity_menu.pack(side=tk.LEFT)

        # Language filter
        self.language_filter = tk.StringVar(value="All")
        ttk.Label(filter_frame, text="Language filter:").pack(side=tk.LEFT, padx=(16, 0))
        language_options = ["All", "JavaScript", "PHP", "Java", "Python"]
        language_menu = ttk.OptionMenu(filter_frame, self.language_filter, "All", *language_options, command=lambda _: self._refresh_results())
        language_menu.pack(side=tk.LEFT)

        # Display mode toggle
        mode_frame = ttk.Frame(results_frame)
        mode_frame.pack(fill=tk.X, padx=8, pady=(0, 4))
        ttk.Label(mode_frame, text="Display mode:").pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="JSON", value="json", variable=self.display_mode, command=self._refresh_results).pack(side=tk.LEFT)
        ttk.Radiobutton(mode_frame, text="Tabular", value="tabular", variable=self.display_mode, command=self._refresh_results).pack(side=tk.LEFT)

        # Result text area (for JSON)
        self.text_frame = ttk.Frame(results_frame)
        self.text_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.text = tk.Text(self.text_frame, wrap="none", height=20)
        self.text.pack(fill=tk.BOTH, expand=True)
        vs = ttk.Scrollbar(self.text_frame, orient="vertical", command=self.text.yview)
        hs = ttk.Scrollbar(self.text_frame, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        hs.pack(side=tk.BOTTOM, fill=tk.X)

        # Tabular frame (for Treeview tables) inside a Canvas for global scrolling
        self.tabular_canvas = tk.Canvas(results_frame, borderwidth=0, background="#f8f8f8")
        self.tabular_scroll = ttk.Scrollbar(results_frame, orient="vertical", command=self.tabular_canvas.yview)
        self.tabular_hscroll = ttk.Scrollbar(results_frame, orient="horizontal", command=self.tabular_canvas.xview)
        self.tabular_canvas.configure(yscrollcommand=self.tabular_scroll.set, xscrollcommand=self.tabular_hscroll.set)
        self.tabular_frame = ttk.Frame(self.tabular_canvas)
        self.tabular_canvas.create_window((0, 0), window=self.tabular_frame, anchor="nw")
        self.tabular_tables = []
        self.tabular_frame.bind("<Configure>", lambda e: self.tabular_canvas.configure(scrollregion=self.tabular_canvas.bbox("all")))
        # Mouse wheel scrolling
        self.tabular_canvas.bind_all("<MouseWheel>", self._on_tabular_mousewheel)

        # Utility buttons
        util = ttk.Frame(results_frame)
        util.pack(fill=tk.X, padx=8, pady=(0, 8))
        ttk.Button(util, text="Copy JSON", command=self._copy_json).pack(side=tk.LEFT)

    # Event handlers
    def _on_mode_change(self):
        is_scan = self.mode.get() == "scan"
        # Toggle scan-only options
        for child in self.scan_opts.winfo_children():
            child.configure(state="normal" if is_scan else "disabled")
        # Clear output path when switching modes to avoid confusion
        self.output_path.set("")

    def _toggle_output(self):
        enabled = self.save_results.get()
        state = "normal" if enabled else "disabled"
        # Locate the output entry by walking up from browse button
        out_entry = None
        parent = self.output_browse.master
        for child in parent.winfo_children():
            if isinstance(child, ttk.Entry):
                out_entry = child
                break
        if out_entry:
            out_entry.configure(state=state)
        self.output_browse.configure(state=state)

    def _browse_path(self):
        mode = self.mode.get()
        if mode == "analyze":
            # Allow file or zip selection
            code_patterns = "*.js *.mjs *.jsx *.ts *.tsx *.php *.java *.py *.zip"
            path = filedialog.askopenfilename(
                title="Select file to analyze (JS, PHP, Java, Python, or ZIP)",
                filetypes=[
                    ("Code/Zip files", code_patterns),
                    ("JavaScript", "*.js *.mjs *.jsx *.ts *.tsx"),
                    ("PHP", "*.php"),
                    ("Java", "*.java"),
                    ("Python", "*.py"),
                    ("Zip", "*.zip"),
                    ("All files", "*.*"),
                ],
            )
        elif mode == "scan_zip":
            path = filedialog.askopenfilename(
                title="Select zip file to scan",
                filetypes=[("Zip files", "*.zip")],
            )
        else:
            path = filedialog.askdirectory(title="Select directory to scan")
        if path:
            self.path.set(path)

    def _browse_output(self):
        if self.mode.get() == "analyze":
            # Choose file path to save JSON
            default = f"sca_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            path = filedialog.asksaveasfilename(
                title="Save results JSON",
                defaultextension=".json",
                initialfile=default,
                filetypes=[("JSON", "*.json")],
            )
        else:
            # Choose directory to save per-file and combined results
            path = filedialog.askdirectory(title="Choose output directory")
        if path:
            self.output_path.set(path)

    def _copy_json(self):
        data = self.text.get("1.0", tk.END).strip()
        if not data:
            return
        self.clipboard_clear()
        self.clipboard_append(data)
        messagebox.showinfo("Copied", "Results JSON copied to clipboard.")

    def _run(self):
        self.run_btn.configure(state="disabled")
        self.progress.start()
        # Clear previous results
        self.summary_label.configure(text="Running analysis...")
        self.text.delete("1.0", tk.END)
        # Run in background
        threading.Thread(target=self._run_worker, daemon=True).start()

    def _run_worker(self):
        try:
            input_path = self.path.get()
            import main as sca_main
            mode = self.mode.get()
            def extract_json_from_output(output):
                # Extract the largest valid JSON object from output using regex
                matches = re.findall(r'({[\s\S]*})', output)
                best = None
                for m in matches:
                    try:
                        obj = json.loads(m)
                        if best is None or len(m) > len(best):
                            best = m
                    except Exception:
                        continue
                if best:
                    return json.loads(best)
                return None
            if mode == "analyze":
                    results = sca_main.run_all_sca_analyses(input_path, show_progress=False)
                    print(f"[DEBUG] Findings for {input_path}: {json.dumps(results.get('findings', {}), indent=2) if isinstance(results, dict) else results}")
                    if self.save_results.get():
                        out = self.output_path.get().strip() or None
                        sca_main.save_json_results(results, out)
                    self._update_results(results)
            elif mode == "scan_zip":
                print(f"[DEBUG] Scan Zip mode selected. Path: {input_path}")
                from click.testing import CliRunner
                runner = CliRunner()
                result = runner.invoke(sca_main.bulk_analyze, [input_path, '--format', 'json'])
                print(f"[DEBUG] bulk_analyze result output: {result.output}")
                results = extract_json_from_output(result.output)
                if results is None:
                    print(f"[DEBUG] Error: Could not extract valid JSON from bulk_analyze output.")
                self._update_results(results)
            else:
                print(f"[DEBUG] Scan directory mode selected. Path: {input_path}")
                from click.testing import CliRunner
                runner = CliRunner()
                result = runner.invoke(sca_main.bulk_analyze, [input_path, '--format', 'json'])
                print(f"[DEBUG] bulk_analyze result output: {result.output}")
                results = extract_json_from_output(result.output)
                if results is None:
                    print(f"[DEBUG] Error: Could not extract valid JSON from bulk_analyze output.")
                self._update_results(results)
        except Exception as e:
            self._update_error(str(e))
        finally:
            self.after(0, self._finish_run)

    def _finish_run(self):
        self.progress.stop()
        self.run_btn.configure(state="normal")

    def _update_error(self, error_msg: str):
        def apply():
            self.summary_label.configure(text=f"Error: {error_msg}")
            self.text.delete("1.0", tk.END)
            self.text.insert(tk.END, json.dumps({"error": error_msg}, indent=2))
        self.after(0, apply)

    def _update_results(self, results: dict):
        print(f"[DEBUG] _update_results called with results: {json.dumps(results, indent=2, ensure_ascii=False)}")
        self._original_results = copy.deepcopy(results)  # Store a deep copy of the original, unfiltered results
        self._last_results = results
        self._refresh_results()

    def _refresh_results(self):
        # Always filter from a deep copy of the original results
        results = copy.deepcopy(getattr(self, '_original_results', None))
        if results is None:
            return
        severity = self.severity_filter.get().lower()
        language = self.language_filter.get().lower()
        def filter_findings(findings, file_language=None):
            filtered = {}
            for module, items in findings.items():
                filtered_items = items
                if severity != "all":
                    filtered_items = [f for f in filtered_items if f.get("Severity", "").lower() == severity]
                if language != "all":
                    # Try to filter by language field in finding, fallback to file_language if present
                    filtered_items = [f for f in filtered_items if f.get("Language", "").lower() == language or (file_language and file_language.lower() == language)]
                filtered[module] = filtered_items
            return filtered
        # Normalize severity value for OptionMenu
        severity = severity.lower()
        if severity == "critical":
            severity = "critical"
        elif severity == "high":
            severity = "high"
        elif severity == "medium":
            severity = "medium"
        elif severity == "low":
            severity = "low"
        elif severity == "info":
            severity = "info"
        def apply():
            # Summary text
            if "file" in results:
                # Single file analysis
                total = results.get("total_findings", 0)
                file_name = results.get("file", "(unknown)")
                lang = results.get("language", "")
                self.summary_label.configure(
                    text=f"File: {file_name} | Language: {lang} | Total findings: {total}"
                )
            elif "scan_summary" in results:
                s = results["scan_summary"]
                self.summary_label.configure(
                    text=f"Scan: {s.get('directory')} | Files: {s.get('total_files')} | Findings: {s.get('total_findings')}"
                )
            else:
                self.summary_label.configure(text="Analysis completed.")

            # Hide/show text and tabular frames
            if self.display_mode.get() == "json":
                self.text_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
                self.tabular_canvas.pack_forget()
                self.tabular_scroll.pack_forget()
                self.text.delete("1.0", tk.END)
                try:
                    filtered_results = results.copy()
                    if "findings" in filtered_results:
                        filtered_results["findings"] = filter_findings(filtered_results["findings"], results.get("language"))
                    elif "file_results" in filtered_results:
                        for fr in filtered_results["file_results"]:
                            if "findings" in fr:
                                fr["findings"] = filter_findings(fr["findings"], fr.get("language"))
                    self.text.insert(tk.END, json.dumps(filtered_results, indent=2, ensure_ascii=False))
                except TypeError:
                    self.text.insert(tk.END, str(results))
            else:
                self.text_frame.pack_forget()
                self.tabular_canvas.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
                self.tabular_scroll.pack(side=tk.RIGHT, fill=tk.Y)
                self.tabular_hscroll.pack(side=tk.BOTTOM, fill=tk.X)
                # Clear previous tables
                for widget in self.tabular_frame.winfo_children():
                    widget.destroy()
                self.tabular_tables = []
                filtered_results = results.copy()
                if "findings" in filtered_results:
                    filtered_results["findings"] = filter_findings(filtered_results["findings"], results.get("language"))
                elif "file_results" in filtered_results:
                    for fr in filtered_results["file_results"]:
                        if "findings" in fr:
                            filtered = filter_findings(fr["findings"], fr.get("language"))
                            # Ensure all modules are present, even if empty after filtering
                            for mod in fr["findings"]:
                                if mod not in filtered:
                                    filtered[mod] = []
                            fr["findings"] = filtered
                self._show_tabular_tables(filtered_results)
        self.after(0, apply)

    def _on_tabular_mousewheel(self, event):
        # Windows uses event.delta, Linux uses event.num
        if event.delta:
            self.tabular_canvas.yview_scroll(int(-1*(event.delta/120)), "units")
        elif event.num == 4:
            self.tabular_canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self.tabular_canvas.yview_scroll(1, "units")

    def _show_tabular_tables(self, results):
        # Support combined results for bulk/scan (file_results)
        if "file_results" in results:
            if not results["file_results"]:
                label = ttk.Label(self.tabular_frame, text="No files found for analysis.", font=("Segoe UI", 11, "italic"))
                label.pack(pady=12)
                return
            for idx, file_result in enumerate(results["file_results"]):
                file_name = file_result.get("file", "Unknown file")
                findings = file_result.get("findings", {})
                print(f"[DEBUG] Showing tabular tables for file: {file_name}, findings: {json.dumps(findings, indent=2, ensure_ascii=False)}")
                file_label = ttk.Label(self.tabular_frame, text=f"File: {file_name}", font=("Segoe UI", 11, "bold"))
                file_label.pack(anchor="w", pady=(18 if idx > 0 else 12, 2))
                if not any(findings.values()):
                    label = ttk.Label(self.tabular_frame, text="No findings for this file.", font=("Segoe UI", 11, "italic"))
                    label.pack(pady=12)
                else:
                    self._show_module_tables(findings)
        elif "findings" in results:
            findings = results["findings"]
            print(f"[DEBUG] Showing tabular tables for single file findings: {json.dumps(findings, indent=2, ensure_ascii=False)}")
            if not any(findings.values()):
                label = ttk.Label(self.tabular_frame, text="No findings for this file.", font=("Segoe UI", 11, "italic"))
                label.pack(pady=12)
                return
            self._show_module_tables(findings)
        else:
            print(f"[DEBUG] Tabular display not available for results: {json.dumps(results, indent=2, ensure_ascii=False)}")
            label = ttk.Label(self.tabular_frame, text="Tabular display is only available for analysis results.")
            label.pack()

    def _show_module_tables(self, findings):
        module_titles = {
            "poor_error_handling": "Poor Error Handling Findings",
            "unsafe_functions": "Unsafe Functions Findings",
            "unsanitized_input": "Unsanitized Input Findings",
            "weak_crypto": "Weak Crypto Findings",
            "auth": "Authentication Findings"
        }
        severity_colors = {
            "critical": "#ff0000",
            "high": "#ff4444",
            "medium": "#ff9900",
            "low": "#ffff00",
            "info": "#00cccc"
        }
        display_fields = ["Description", "Severity", "Remediation", "OWASP", "Line", "Code Snippet"]
        style = ttk.Style()
        style.configure("Treeview", rowheight=24, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.layout("Treeview", [('Treeview.treearea', {'sticky': 'nswe'})])
        style.map("Treeview", background=[('selected', '#cccccc')])
        any_table = False
        for module, findings_list in findings.items():
            if not findings_list:
                continue
            any_table = True
            table_label = ttk.Label(self.tabular_frame, text=module_titles.get(module, module.replace('_', ' ').title()), font=("Segoe UI", 12, "bold"))
            table_label.pack(anchor="w", pady=(6, 2))
            frame = ttk.Frame(self.tabular_frame)
            frame.pack(fill=tk.X, expand=True, padx=4, pady=2)
            tree = ttk.Treeview(frame, columns=display_fields, show="headings", height=min(12, len(findings_list)))
            for col in display_fields:
                tree.heading(col, text=col)
                tree.column(col, width=300 if col != "Severity" else 100, anchor="w", stretch=True)
            for finding in findings_list:
                desc = finding.get("Description") or finding.get("message") or ""
                sev = finding.get("Severity") or finding.get("severity") or "info"
                remediation = finding.get("Remediation") or finding.get("remedy") or ""
                owasp = finding.get("OWASP") or finding.get("owasp") or ""
                line = str(finding.get("line", ""))
                code_snippet = finding.get("code_snippet", "").replace('\n', ' ')
                values = [desc, sev, remediation, owasp, line, code_snippet]
                iid = tree.insert("", "end", values=values)
                color = severity_colors.get(sev.lower(), "#ffffff")
                tree.tag_configure(sev.lower(), background=color)
                tree.item(iid, tags=(sev.lower(),))
            vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
            hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
            tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
            tree.grid(row=0, column=0, sticky="nsew")
            vsb.grid(row=0, column=1, sticky="ns")
            hsb.grid(row=1, column=0, sticky="ew")
            frame.grid_rowconfigure(0, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            self.tabular_tables.append(tree)
        if not any_table:
            label = ttk.Label(self.tabular_frame, text="No findings for this file.", font=("Segoe UI", 11, "italic"))
            label.pack(pady=12)


def main():
    app = SCAGUI()
    app.mainloop()


if __name__ == "__main__":
    main()


