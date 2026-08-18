#!/usr/bin/env python3
"""
SCA - Static Code Analysis Tool
A comprehensive security analysis tool for JavaScript, PHP, Java, and Python code.

Usage:
    sca analyze <file> [options]
    sca scan <directory> [options]
    sca --help

Features:
    - Poor Error Handling Detection
    - Unsafe Functions Analysis
    - Unsanitized Input Detection
    - Weak Cryptography Analysis
    - Rich CLI interface with progress bars
    - JSON export with download capability
    - Comprehensive reporting

Requirements:
    All SCA modules must be self-contained and accessible
"""

import sys
import os
import json
import time
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import tempfile
import zipfile
import shutil

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.syntax import Syntax

# Import all SCA modules

try:
    # Import poor error handling module
    sys.path.append(os.path.join(os.path.dirname(__file__), 'SCA_POOR_ERROR_HANDLING'))
    from SCA_POOR_ERROR_HANDLING.poor_error_handling import analyze_file as analyze_poor_error_handling, parse_js as parse_js_poor, parse_php as parse_php_poor

    # Import unsafe functions module
    sys.path.append(os.path.join(os.path.dirname(__file__), 'SCA_UNSAFE_FUNCTIONS'))
    from SCA_UNSAFE_FUNCTIONS.unsafe_func_main import analyze_file as analyze_unsafe_functions, parse_js as parse_js_unsafe, parse_php as parse_php_unsafe

    # Import unsanitized input module
    sys.path.append(os.path.join(os.path.dirname(__file__), 'SCA_UNSANITIZED_INPUT'))
    from SCA_UNSANITIZED_INPUT.unsanitized_input import analyze_source, load_rules

    # Import weak crypto module
    sys.path.append(os.path.join(os.path.dirname(__file__), 'SCA_WEAK_CRYPTO'))
    from SCA_WEAK_CRYPTO.weak_crypto import analyze_file as analyze_weak_crypto, parse_js as parse_js_crypto, parse_php as parse_php_crypto

    # Import auth module
    sys.path.append(os.path.join(os.path.dirname(__file__), 'SCA_POOR_AUTH'))
    from SCA_POOR_AUTH.auth import analyze_password_encryption, load_rules as load_auth_rules
except ImportError as e:
    print(f"[!] Error importing SCA modules: {e}")
    print("[!] Make sure all SCA modules are accessible and self-contained")
    sys.exit(1)

def run_auth_analysis(file_path: str, language: str, code_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Run authentication analysis (password/encryption taint analysis)
    """
    try:
        # Only support JS and PHP for now
        if language == 'js':
            auth_language = 'javascript'
        elif language == 'php':
            auth_language = 'php'
        else:
            return []
        PASSWORD_SOURCES, ENCRYPTION_FUNCTIONS, STORAGE_SINKS = load_auth_rules(auth_language)
        findings = analyze_password_encryption(code_bytes, auth_language, PASSWORD_SOURCES, ENCRYPTION_FUNCTIONS, STORAGE_SINKS)
        # Add module identifier
        for finding in findings:
            finding['module'] = 'auth'
        return findings
    except Exception as e:
        console.print(f"[red][!] Auth analysis failed: {e}")
        return []

# Initialize Rich console
console = Console()

def validate_file(file_path: str) -> Tuple[str, str]:
    """
    Validate input file and return language and extension
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    ext = os.path.splitext(file_path)[1].lower()
    
    if ext in ('.js', '.mjs', '.jsx', '.ts', '.tsx'):
        language = 'js'
    elif ext == '.php':
        language = 'php'
    elif ext == '.java':
        language = 'java'
    elif ext == '.py':
        language = 'python'
    else:
        raise ValueError("Unsupported file extension. Use .js, .jsx, .ts, .tsx, .php, .java, or .py")
    
    return language, ext

def run_poor_error_handling(file_path: str, language: str, code_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Run poor error handling analysis with error handling
    """
    try:
        if language == 'js':
            tree = parse_js_poor(code_bytes)
        else:
            tree = parse_php_poor(code_bytes)
        
        rules_root = os.path.join(os.path.dirname(__file__), 'SCA_POOR_ERROR_HANDLING', 'rules')
        findings = analyze_poor_error_handling(tree, rules_root, code_bytes, language, file_path)
        
        # Normalize return shape to a list of findings
        if isinstance(findings, dict) and 'findings' in findings:
            findings_list = findings.get('findings', [])
        elif isinstance(findings, list):
            findings_list = findings
        else:
            findings_list = []
        
        # Add module identifier to each finding
        for finding in findings_list:
            if isinstance(finding, dict):
                finding['module'] = 'poor_error_handling'
        
        return findings_list
    except Exception as e:
        console.print(f"[red][!] Poor Error Handling analysis failed: {e}")
        return []

def run_unsafe_functions(file_path: str, language: str, code_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Run unsafe functions analysis with error handling
    """
    try:
        if language == 'js':
            tree = parse_js_unsafe(code_bytes)
        else:
            tree = parse_php_unsafe(code_bytes)
        
        rules_root = os.path.join(os.path.dirname(__file__), 'SCA_UNSAFE_FUNCTIONS', 'rules')
        findings = analyze_unsafe_functions(tree, rules_root, code_bytes, None, language, file_path, debug=False)
        
        # Normalize return shape
        if isinstance(findings, dict) and 'findings' in findings:
            findings_list = findings.get('findings', [])
        elif isinstance(findings, list):
            findings_list = findings
        else:
            findings_list = []
        
        # Add module identifier to each finding
        for finding in findings_list:
            if isinstance(finding, dict):
                finding['module'] = 'unsafe_functions'
        
        return findings_list
    except Exception as e:
        console.print(f"[red][!] Unsafe Functions analysis failed: {e}")
        return []

def run_unsanitized_input(file_path: str, language: str, code_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Run unsanitized input analysis with error handling
    """
    try:
        # Load rules from YAML files
        # Note: unsanitized input module expects "javascript" not "js"
        module_language = "javascript" if language == "js" else language
        SOURCES, SINKS, SANITIZERS, source_info, sink_info, sanitizer_info = load_rules(module_language)
        
        findings = analyze_source(code_bytes, module_language, SOURCES, SINKS, SANITIZERS, source_info, sink_info, sanitizer_info)
        
        # Add module identifier to each finding
        for finding in findings:
            finding['module'] = 'unsanitized_input'
        
        return findings
    except Exception as e:
        console.print(f"[red][!] Unsanitized Input analysis failed: {e}")
        return []

def run_weak_crypto(file_path: str, language: str, code_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Run weak crypto analysis with enhanced error handling
    """
    try:
        if language == 'js':
            tree = parse_js_crypto(code_bytes)
        else:
            tree = parse_php_crypto(code_bytes)
        
        rules_root = os.path.join(os.path.dirname(__file__), 'SCA_WEAK_CRYPTO', 'rules')
        
        # Enhanced error handling for weak crypto analysis
        try:
            findings = analyze_weak_crypto(tree, rules_root, code_bytes, language, file_path)
            
            # Extract findings from the output if it's a dict
            if isinstance(findings, dict) and 'findings' in findings:
                findings = findings['findings']
            elif not isinstance(findings, list):
                findings = []
            
            # Add module identifier to each finding
            for finding in findings:
                if isinstance(finding, dict):
                    finding['module'] = 'weak_crypto'
            
            return findings
        except Exception as inner_e:
            console.print(f"[yellow][!] Weak Crypto analysis had internal error: {inner_e}")
            return []
            
    except Exception as e:
        console.print(f"[red][!] Weak Crypto analysis failed: {e}[/red]")
        return []

def run_all_sca_analyses(file_path: str, show_progress: bool = True, severity: Optional[str] = None, language_filter: Optional[str] = None) -> Dict[str, Any]:
    """
    Run all four SCA analyses on the given file with progress tracking
    """
    try:
        # Validate file and determine language
        language, ext = validate_file(file_path)
        
        # Read file content
        with open(file_path, 'rb') as f:
            code_bytes = f.read()
        
        console.print(f"[bold blue]Analyzing {os.path.basename(file_path)} ({language})")
        
        findings = {}
        
        if show_progress:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                console=console
            ) as progress:
                # Poor Error Handling
                task1 = progress.add_task("Running Poor Error Handling analysis...", total=1)
                poor_error_findings = run_poor_error_handling(file_path, language, code_bytes)
                progress.update(task1, completed=1)
                findings['poor_error_handling'] = poor_error_findings

                # Unsafe Functions
                task2 = progress.add_task("Running Unsafe Functions analysis...", total=1)
                unsafe_func_findings = run_unsafe_functions(file_path, language, code_bytes)
                progress.update(task2, completed=1)
                findings['unsafe_functions'] = unsafe_func_findings

                # Unsanitized Input
                task3 = progress.add_task("Running Unsanitized Input analysis...", total=1)
                unsanitized_findings = run_unsanitized_input(file_path, language, code_bytes)
                progress.update(task3, completed=1)
                findings['unsanitized_input'] = unsanitized_findings

                # Weak Crypto
                task4 = progress.add_task("Running Weak Crypto analysis...", total=1)
                weak_crypto_findings = run_weak_crypto(file_path, language, code_bytes)
                progress.update(task4, completed=1)
                findings['weak_crypto'] = weak_crypto_findings

                # Auth
                task5 = progress.add_task("Running Authentication analysis...", total=1)
                auth_findings = run_auth_analysis(file_path, language, code_bytes)
                progress.update(task5, completed=1)
                findings['auth'] = auth_findings
        else:
            # Run without progress bars
            poor_error_findings = run_poor_error_handling(file_path, language, code_bytes)
            unsafe_func_findings = run_unsafe_functions(file_path, language, code_bytes)
            unsanitized_findings = run_unsanitized_input(file_path, language, code_bytes)
            weak_crypto_findings = run_weak_crypto(file_path, language, code_bytes)
            auth_findings = run_auth_analysis(file_path, language, code_bytes)

            findings = {
                'poor_error_handling': poor_error_findings,
                'unsafe_functions': unsafe_func_findings,
                'unsanitized_input': unsanitized_findings,
                'weak_crypto': weak_crypto_findings,
                'auth': auth_findings
            }
        
        # Create categorized output
        output = {
            "file": os.path.basename(file_path),
            "language": (
                "javascript" if language == "js" else
                "php" if language == "php" else
                "java" if language == "java" else
                "python" if language == "python" else language
            ),
            "file_extension": ext,
            "analysis_timestamp": datetime.now().isoformat(),
            "analysis_summary": {
                "poor_error_handling": {
                    "findings_count": len(findings.get('poor_error_handling', [])),
                    "status": "completed"
                },
                "unsafe_functions": {
                    "findings_count": len(findings.get('unsafe_functions', [])),
                    "status": "completed"
                },
                "unsanitized_input": {
                    "findings_count": len(findings.get('unsanitized_input', [])),
                    "status": "completed"
                },
                "weak_crypto": {
                    "findings_count": len(findings.get('weak_crypto', [])),
                    "status": "completed"
                },
                "auth": {
                    "findings_count": len(findings.get('auth', [])),
                    "status": "completed"
                }
            },
            "total_findings": sum(len(v) for v in findings.values() if isinstance(v, list)),
            "findings": {
                "poor_error_handling": findings.get('poor_error_handling', []),
                "unsafe_functions": findings.get('unsafe_functions', []),
                "unsanitized_input": findings.get('unsanitized_input', []),
                "weak_crypto": findings.get('weak_crypto', []),
                "auth": findings.get('auth', [])
            }
        }
        
        # Filter findings by severity and language if requested
        def filter_findings(findings, file_language=None):
            filtered = []
            for f in findings:
                if severity and f.get('Severity', '').lower() != severity:
                    continue
                if language_filter and language_filter.lower() != "all":
                    finding_lang = f.get('Language', '').lower() or (file_language.lower() if file_language else '')
                    if finding_lang != language_filter.lower():
                        continue
                filtered.append(f)
            return filtered
        for module in output['findings']:
            output['findings'][module] = filter_findings(output['findings'][module], output.get('language'))
        
        return output
        
    except Exception as e:
        console.print(f"[red][!] Analysis failed: {e}[/red]")
        return {
            "error": str(e),
            "status": "failed",
            "timestamp": datetime.now().isoformat()
        }

def display_results(results: Dict[str, Any], output_format: str = "rich"):
    """
    Display results in the specified format
    """
    if "error" in results:
        console.print(f"[red]❌ Analysis failed: {results['error']}")
        return

    # Bulk mode: multiple files
    if "file_results" in results:
        scan_summary = results.get("scan_summary", {})
        console.print("\n" + "="*80)
        console.print(f"[bold green]Bulk Analysis completed successfully!")
        console.print("="*80)
        console.print(f"[blue]Files analyzed: {scan_summary.get('total_files', 'N/A')}")
        console.print(f"[blue]Total findings: {scan_summary.get('total_findings', 'N/A')}")
        console.print(f"[blue]Scan timestamp: {scan_summary.get('scan_timestamp', '')}")
        for file_result in results["file_results"]:
            file_name = file_result.get("file", "(unknown)")
            console.print("\n" + "-"*60)
            console.print(f"[bold yellow]File: {file_name}")
            display_results(file_result, output_format)
        return

    if output_format == "json":
        console.print(json.dumps(results, indent=2, ensure_ascii=False))
        return
    
    # Rich display for single file
    console.print("\n" + "="*80)
    console.print(f"[bold green]Analysis completed successfully!")
    console.print("="*80)

    # File info
    file_info = Table(title="File Information", box=box.ROUNDED)
    file_info.add_column("Property", style="cyan")
    file_info.add_column("Value", style="white")
    file_info.add_row("File", results.get("file", "(unknown)"))
    file_info.add_row("Language", results.get("language", ""))
    file_info.add_row("Extension", results.get("file_extension", ""))
    file_info.add_row("Timestamp", results.get("analysis_timestamp", "N/A"))
    console.print(file_info)

    # Summary
    summary = Table(title="Analysis Summary", box=box.ROUNDED)
    summary.add_column("Module", style="cyan")
    summary.add_column("Findings", style="white", justify="center")
    summary.add_column("Status", style="green", justify="center")

    for module, info in results.get("analysis_summary", {}).items():
        findings_count = info["findings_count"]
        status = "OK" if findings_count == 0 else f"WARN {findings_count}"
        summary.add_row(
            module.replace("_", " ").title(),
            str(findings_count),
            status
        )

    console.print(summary)

    # Total findings
    total = results.get("total_findings", 0)
    if total == 0:
        console.print(f"\n[bold green]No security issues found!")
    else:
        console.print(f"\n[bold yellow]Total findings: {total}")
        # Show findings in separate tables for each module, ordered by severity
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        display_fields = ["Description", "Severity", "Remediation", "OWASP", "line", "code_snippet"]
        module_titles = {
            "poor_error_handling": "Poor Error Handling Findings",
            "unsafe_functions": "Unsafe Functions Findings",
            "unsanitized_input": "Unsanitized Input Findings",
            "weak_crypto": "Weak Crypto Findings",
            "auth": "Authentication Findings"
        }
        for module, findings in results.get("findings", {}).items():
            if not findings:
                continue
            table = Table(title=module_titles.get(module, module.replace("_", " ").title()), box=box.ROUNDED, show_lines=True)
            table.add_column("Description", style="magenta")
            table.add_column("Severity", style="red")
            table.add_column("Remediation", style="yellow")
            table.add_column("OWASP", style="cyan")
            table.add_column("Line", style="white", justify="center")
            table.add_column("Code Snippet", style="green")
            def get_sev(f):
                sev = f.get("Severity") or f.get("severity") or "info"
                return severity_order.get(sev.lower(), 0)
            sorted_findings = sorted(findings, key=get_sev, reverse=True)
            for finding in sorted_findings:
                desc = finding.get("Description") or finding.get("message") or ""
                sev = finding.get("Severity") or finding.get("severity") or ""
                remediation = finding.get("Remediation") or finding.get("remedy") or ""
                owasp = finding.get("OWASP") or finding.get("owasp") or ""
                line = str(finding.get("line", ""))
                code_snippet = finding.get("code_snippet", "")
                table.add_row(desc, sev, remediation, owasp, line, code_snippet)
            console.print(table)

def save_json_results(results: Dict[str, Any], output_file: str = None) -> str:
    """
    Save results to JSON file and return the file path
    """
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sca_results_{timestamp}.json"
        output_file = os.path.join(os.getcwd(), filename)
    
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        console.print(f"[green]💾 Results saved to: {output_file}")
        return output_file
    except Exception as e:
        console.print(f"[red]❌ Failed to save results: {e}")
        return None

def extract_and_collect_files(path: str, extensions: List[str], max_size_mb: int = 100) -> List[str]:
    """
    Extract zip (including nested zips) or collect files from folder. Returns list of file paths.
    Skips if total size exceeds max_size_mb.
    """
    temp_dir = None
    files = []
    total_size = 0
    def collect_files(dir_path):
        nonlocal total_size
        for root, _, filenames in os.walk(dir_path):
            for fname in filenames:
                fpath = os.path.join(root, fname)
                if any(fname.lower().endswith(ext) for ext in extensions):
                    size = os.path.getsize(fpath)
                    total_size += size
                    if total_size > max_size_mb * 1024 * 1024:
                        return False
                    files.append(fpath)
        return True
    if zipfile.is_zipfile(path):
        temp_dir = tempfile.mkdtemp()
        print(f"[DEBUG] Extracting zip file: {path} to temp dir: {temp_dir}")
        with zipfile.ZipFile(path, 'r') as z:
            z.extractall(temp_dir)
        # Recursively extract nested zips
        def extract_nested_zips(base_dir):
            for root, _, filenames in os.walk(base_dir):
                for fname in filenames:
                    fpath = os.path.join(root, fname)
                    if zipfile.is_zipfile(fpath):
                        nested_dir = tempfile.mkdtemp(dir=base_dir)
                        print(f"[DEBUG] Extracting nested zip: {fpath} to {nested_dir}")
                        with zipfile.ZipFile(fpath, 'r') as nz:
                            nz.extractall(nested_dir)
                        extract_nested_zips(nested_dir)
        extract_nested_zips(temp_dir)
        if not collect_files(temp_dir):
            shutil.rmtree(temp_dir)
            raise Exception(f"Total extracted size exceeds {max_size_mb}MB limit.")
        print(f"[DEBUG] Extracted files from zip: {files}")
    elif os.path.isdir(path):
        if not collect_files(path):
            raise Exception(f"Total folder size exceeds {max_size_mb}MB limit.")
        print(f"[DEBUG] Collected files from directory: {files}")
    else:
        files = [path]
        print(f"[DEBUG] Single file selected: {files}")
    return files, temp_dir

@click.group()
@click.version_option(version="1.0.0", prog_name="SCA")
def cli():
    """
    SCA - Static Code Analysis Tool
    
    A comprehensive security analysis tool for JavaScript, PHP, Java, and Python code.
    """
    pass

@cli.command()
@click.argument('file', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output JSON file path')
@click.option('--format', '-f', type=click.Choice(['rich', 'json']), default='rich', help='Output format')
@click.option('--no-progress', is_flag=True, help='Disable progress bars')
@click.option('--severity', '-s', default=None, help='Filter findings by severity (critical, high, medium, low, info)')
@click.option('--language', '-l', default=None, help='Filter findings by language (javascript, php, java, python, all)')
def analyze(file, output, format, no_progress, severity, language):
    """
    Analyze a single file for security vulnerabilities.
    
    FILE: Path to the JavaScript, PHP, Java, or Python file to analyze
    """
    try:
        # Run analysis
        results = run_all_sca_analyses(file, show_progress=not no_progress, severity=severity.lower() if severity else None, language_filter=language)
        # Display results
        display_results(results, format)

        # Save to file if requested
        if output or format == "json":
            saved_file = save_json_results(results, output)
            if saved_file:
                console.print(f"\n[blue]📁 To download: {saved_file}")

    except Exception as e:
        console.print(f"[red]❌ Analysis failed: {e}[/red]")
        sys.exit(1)

@cli.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False))
@click.option('--output', '-o', type=click.Path(), help='Output directory for JSON files')
@click.option('--format', '-f', type=click.Choice(['rich', 'json']), default='rich', help='Output format')
@click.option('--extensions', '-e', default='.js,.php,.java,.py', help='File extensions to analyze (comma-separated)')
@click.option('--recursive', '-r', is_flag=True, help='Recursively scan subdirectories')
@click.option('--severity', '-s', default=None, help='Filter findings by severity (critical, high, medium, low, info)')
@click.option('--language', '-l', default=None, help='Filter findings by language (javascript, php, java, python, all)')
def scan(directory, output, format, extensions, recursive, severity, language):
    """
    Scan a directory for security vulnerabilities in multiple files.
    
    DIRECTORY: Path to the directory to scan
    """
    try:
        ext_list = [ext.strip() for ext in extensions.split(',')]
        files_to_scan = []
        
        # Find files to scan
        if recursive:
            for ext in ext_list:
                files_to_scan.extend(Path(directory).rglob(f"*{ext}"))
        else:
            for ext in ext_list:
                files_to_scan.extend(Path(directory).glob(f"*{ext}"))
        
        if not files_to_scan:
            console.print(f"[yellow]⚠️ No files found with extensions: {extensions}")
            return

        console.print(f"[blue]🔍 Found {len(files_to_scan)} files to analyze")

        all_results = []
        
        for file_path in files_to_scan:
            try:
                console.print(f"\n[bold blue]📄 Analyzing: {file_path.name}")
                results = run_all_sca_analyses(str(file_path), show_progress=False, severity=severity.lower() if severity else None, language_filter=language)
                
                if "error" not in results:
                    all_results.append(results)
                    
                    # Save individual file results if output directory specified
                    if output:
                        output_file = os.path.join(output, f"sca_{file_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                        save_json_results(results, output_file)
                
            except Exception as e:
                console.print(f"[red]❌ Failed to analyze {file_path.name}: {e}")
        
        # Summary
        if all_results:
            total_files = len(all_results)
            total_findings = sum(r.get("total_findings", 0) for r in all_results)
            
            console.print(f"\n[bold green]Scan completed!")
            console.print(f"[blue]Files analyzed: {total_files}")
            console.print(f"[blue]Total findings: {total_findings}")
            
            # Save combined results
            if output:
                combined_file = os.path.join(output, f"sca_combined_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                combined_results = {
                    "scan_summary": {
                        "total_files": total_files,
                        "total_findings": total_findings,
                        "scan_timestamp": datetime.now().isoformat(),
                        "directory": directory
                    },
                    "file_results": all_results
                }
                save_json_results(combined_results, combined_file)
        
    except Exception as e:
        console.print(f"[red]❌ Scan failed: {e}")
        sys.exit(1)

# Add a new CLI command for bulk analysis
@cli.command()
@click.argument('input_path', type=click.Path(exists=True))
@click.option('--output', '-o', type=click.Path(), help='Output directory for JSON files')
@click.option('--format', '-f', type=click.Choice(['rich', 'json']), default='rich', help='Output format')
@click.option('--extensions', '-e', default='.js,.php,.java,.py', help='File extensions to analyze (comma-separated)')
@click.option('--recursive', '-r', is_flag=True, help='Recursively scan subdirectories')
@click.option('--severity', '-s', default=None, help='Filter findings by severity (critical, high, medium, low, info)')
@click.option('--language', '-l', default=None, help='Filter findings by language (javascript, php, java, python, all)')
def bulk_analyze(input_path, output, format, extensions, recursive, severity, language):
    """
    Analyze a zip file, folder, or single file. Handles nested zips, deletes temp files after analysis, skips if >100MB.

    INPUT_PATH: Path to a zip file, folder, or single code file (.js, .php, .java, .py, etc.)
    You can upload a zip file containing code files, and all supported files will be analyzed.
    """
    ext_list = [ext.strip() for ext in extensions.split(',')]
    files, temp_dir = extract_and_collect_files(input_path, ext_list, max_size_mb=100)
    if not files:
        if format == 'json':
            print(json.dumps({"error": "No files found for analysis."}, indent=2, ensure_ascii=False))
            return
        console.print(f"[yellow]⚠️ No files found for analysis.")
        return
    all_results = []
    for file_path in files:
        try:
            results = run_all_sca_analyses(str(file_path), show_progress=False, severity=severity.lower() if severity else None, language_filter=language)
            if "error" not in results:
                all_results.append(results)
                if output:
                    output_file = os.path.join(output, f"sca_{os.path.basename(file_path)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
                    save_json_results(results, output_file)
        except Exception as e:
            if format == 'json':
                print(json.dumps({"error": f"Failed to analyze {file_path}: {str(e)}"}, indent=2, ensure_ascii=False))
                return
            console.print(f"[red]❌ Failed to analyze {file_path}: {e}")
    if temp_dir:
        shutil.rmtree(temp_dir)
    combined_results = {
        "scan_summary": {
            "total_files": len(all_results),
            "total_findings": sum(r.get("total_findings", 0) for r in all_results),
            "scan_timestamp": datetime.now().isoformat(),
            "input_path": input_path
        },
        "file_results": all_results
    }
    if format == 'json':
        print(json.dumps(combined_results, indent=2, ensure_ascii=False))
        return
    display_results(combined_results, format)
    if output:
        combined_file = os.path.join(output, f"sca_combined_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        save_json_results(combined_results, combined_file)

@cli.command()
def info():
    """
    Display information about the SCA tool and available modules.
    """
    info_table = Table(title="SCA Tool Information", box=box.ROUNDED)
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="white")
    
    info_table.add_row("Tool Name", "SCA - Static Code Analysis")
    info_table.add_row("Version", "1.0.0")
    info_table.add_row("Description", "Comprehensive security analysis for JS/PHP/Java/Python")
    
    modules_table = Table(title="Available Analysis Modules", box=box.ROUNDED)
    modules_table.add_column("Module", style="cyan")
    modules_table.add_column("Description", style="white")
    modules_table.add_column("Status", style="green")
    
    modules = [
        ("Poor Error Handling", "Detects inadequate error handling patterns", "✅"),
        ("Unsafe Functions", "Identifies potentially dangerous function calls", "✅"),
        ("Unsanitized Input", "Finds taint analysis vulnerabilities", "✅"),
        ("Weak Cryptography", "Detects insecure cryptographic practices", "✅")
    ]
    
    for module, desc, status in modules:
        modules_table.add_row(module, desc, status)
    
    console.print(info_table)
    console.print("\n")
    console.print(modules_table)
    
    console.print("\n[bold blue]Usage Examples:[/bold blue]")
    console.print("  sca analyze file.js --severity high             # Analyze single file, filter by severity")
    console.print("  sca scan ./src --recursive --severity medium    # Scan directory recursively, filter by severity")
    console.print("  sca analyze file.php --output results.json --severity critical  # Save filtered results to file")
    console.print("\n[bold blue]Options:[/bold blue]")
    console.print("  --severity [critical|high|medium|low|info]      Filter findings by severity level")

def main():
    """
    Main entry point
    """
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()