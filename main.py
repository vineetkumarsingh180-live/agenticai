import argparse
import sys
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Load .env so GOOGLE_API_KEY is available before graph import
load_dotenv()

from graph import build_secure_agent_graph

console = Console()

EXT_MAP = {
    ".py":   "python",
    ".js":   "javascript",
    ".ts":   "typescript",
    ".php":  "php",
    ".java": "java",
    ".c":    "c",
    ".cpp":  "cpp",
    ".rb":   "ruby",
    ".go":   "go",
}


def scan_file(file_path: str, output_dir: str) -> dict:
    """Scan a single file — safe to run in a subprocess."""
    load_dotenv()  # re-load inside subprocess
    path = Path(file_path)
    if not path.is_file():
        return {"file": file_path, "status": "error", "reason": "File not found"}

    code     = path.read_text(encoding="utf-8")
    language = EXT_MAP.get(path.suffix.lower(), "python")

    app = build_secure_agent_graph()

    initial_state = {
        "file_path":       str(path),
        "original_code":   code,
        "language":        language,
        "analysis":        None,
        "patch":           None,
        "validation":      None,
        "retry_count":     0,
        "final_report_md": None,
        "final_report_pdf": None,
    }

    final_state = app.invoke(initial_state)

    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    # Save patched source
    patched_file = out_path / f"patched_{path.name}"
    patched_file.write_text(final_state["patch"].patched_code, encoding="utf-8")

    # Save Markdown report
    report_md = out_path / f"report_{path.stem}.md"
    report_md.write_text(final_state["final_report_md"], encoding="utf-8")

    return {
        "file":        file_path,
        "status":      "done",
        "patched":     str(patched_file),
        "report_md":   str(report_md),
        "report_pdf":  final_state.get("final_report_pdf"),
    }


def run_agent(file_path: str, output_dir: str = "output"):
    """Scan a single file with live console output."""
    path = Path(file_path)
    if not path.is_file():
        console.print(f"[bold red]Error:[/bold red] File '{file_path}' does not exist.")
        sys.exit(1)

    console.print(Panel(
        f"Starting Secure Code Assistant on [cyan]{file_path}[/cyan]",
        style="blue"
    ))

    result = scan_file(file_path, output_dir)

    if result["status"] == "error":
        console.print(f"[bold red]Error:[/bold red] {result['reason']}")
        return

    console.print("\n[bold green]** Execution Complete! **[/bold green]")
    console.print(f"  Patched Code    -> [bold]{result['patched']}[/bold]")
    console.print(f"  Markdown Report -> [bold]{result['report_md']}[/bold]")
    if result.get("report_pdf"):
        console.print(f"  PDF Report      -> [bold]{result['report_pdf']}[/bold]")
    console.print()


def run_parallel(file_paths: list[str], output_dir: str = "output", max_workers: int = 4):
    """Scan multiple files in parallel using ProcessPoolExecutor."""
    console.print(Panel(
        f"Scanning [bold]{len(file_paths)}[/bold] file(s) with up to "
        f"[bold]{max_workers}[/bold] parallel workers",
        style="blue"
    ))

    results = []
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(scan_file, fp, output_dir): fp
            for fp in file_paths
        }
        for future in as_completed(futures):
            try:
                res = future.result()
            except Exception as exc:
                res = {"file": futures[future], "status": "error", "reason": str(exc)}
            results.append(res)
            status = "[OK]" if res["status"] == "done" else "[ERR]"
            console.print(f"  [{status}] {res['file']}")

    # Summary table
    table = Table(title="\nScan Summary", show_lines=True)
    table.add_column("File",        style="cyan",  no_wrap=True)
    table.add_column("Status",      style="bold")
    table.add_column("Patched",     style="green")
    table.add_column("Report (MD)", style="yellow")
    table.add_column("Report (PDF)",style="magenta")

    for r in results:
        if r["status"] == "done":
            table.add_row(
                r["file"],
                "[green]DONE[/green]",
                r.get("patched",    "-"),
                r.get("report_md",  "-"),
                r.get("report_pdf", "-") or "-",
            )
        else:
            table.add_row(r["file"], "[red]ERROR[/red]", r.get("reason", "?"), "-", "-")

    console.print(table)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Autonomous Secure Coding Assistant (LangGraph + Gemini)"
    )
    parser.add_argument(
        "--file", "-f",
        nargs="+", required=True,
        help="Path(s) to vulnerable source file(s)"
    )
    parser.add_argument(
        "--out", "-o",
        default="output",
        help="Directory to save output files"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int, default=4,
        help="Max parallel workers when scanning multiple files (default: 4)"
    )
    args = parser.parse_args()

    if len(args.file) == 1:
        run_agent(args.file[0], args.out)
    else:
        run_parallel(args.file, args.out, args.workers)