"""CLI interface for secret-triage."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from .scanner import scan_directory
from .git_scanner import scan_git_history
from .reporter import report_terminal, report_sarif, report_markdown

console = Console()


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """secret-triage: Find leaked secrets with confidence scoring."""
    pass


@cli.command()
@click.argument("path", default=".", type=click.Path(exists=True))
@click.option("--history", is_flag=True, help="Also scan git history")
@click.option("--min-confidence", default=0.5, type=float, help="Minimum confidence score (0.0-1.0)")
@click.option("--format", "output_format", default="terminal", type=click.Choice(["terminal", "sarif", "markdown", "json"]), help="Output format")
@click.option("-o", "--output", "output_file", default=None, help="Output file (default: stdout)")
@click.option("--exclude", multiple=True, help="Patterns to exclude")
@click.option("--no-git-ignore", is_flag=True, help="Don't respect .gitignore")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(path, history, min_confidence, output_format, output_file, exclude, no_git_ignore, verbose):
    """Scan a directory (and optionally git history) for leaked secrets."""
    root = Path(path).resolve()

    if verbose:
        console.print(f"[dim]Scanning: {root}[/dim]")

    # Scan working directory
    findings = scan_directory(
        root,
        respect_gitignore=not no_git_ignore,
        exclude_patterns=list(exclude),
        verbose=verbose,
    )

    # Optionally scan git history
    if history:
        if verbose:
            console.print("[dim]Scanning git history...[/dim]")
        git_findings = scan_git_history(root, verbose=verbose)
        findings.extend(git_findings)

    # Filter by confidence
    findings = [f for f in findings if f.confidence >= min_confidence]

    # Sort by confidence descending
    findings.sort(key=lambda f: (-f.confidence, f.severity_order))

    if not findings:
        console.print("[green]No secrets found.[/green]")
        return

    # Output
    if output_format == "terminal":
        report_terminal(findings, console)
    elif output_format == "sarif":
        sarif = report_sarif(findings, str(root))
        _write_output(json.dumps(sarif, indent=2), output_file)
    elif output_format == "markdown":
        md = report_markdown(findings)
        _write_output(md, output_file)
    elif output_format == "json":
        data = [f.to_dict() for f in findings]
        _write_output(json.dumps(data, indent=2), output_file)

    # Exit with error code if critical findings
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")

    if critical_count > 0:
        sys.exit(2)
    elif high_count > 0:
        sys.exit(1)


@cli.command()
@click.option("--last", is_flag=True, help="Show last scan report")
def report(last):
    """Show the last scan report."""
    report_path = Path.home() / ".secret-triage" / "last-report.json"

    if not report_path.exists():
        console.print("[yellow]No previous scan found. Run: secret-triage scan[/yellow]")
        return

    data = json.loads(report_path.read_text())
    console.print(f"[bold]Last scan:[/bold] {data.get('timestamp', 'unknown')}")
    console.print(f"[bold]Path:[/bold] {data.get('path', 'unknown')}")
    console.print(f"[bold]Findings:[/bold] {data.get('count', 0)}")


def _write_output(content: str, output_file: str | None):
    """Write output to file or stdout."""
    if output_file:
        Path(output_file).write_text(content, encoding="utf-8")
        console.print(f"[green]Report written to {output_file}[/green]")
    else:
        print(content)


if __name__ == "__main__":
    cli()
