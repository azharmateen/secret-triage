"""
Output formatters: terminal table, SARIF JSON, and markdown.
"""

from datetime import datetime, timezone

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .scanner import Finding


def report_terminal(findings: list[Finding], console: Console):
    """Print findings as a rich terminal table."""
    # Summary
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")
    git_history = sum(1 for f in findings if f.is_git_history)

    summary = Text()
    summary.append(f"\n  {len(findings)} secrets found", style="bold")
    summary.append(f"  |  ")
    summary.append(f"CRITICAL: {critical}", style="bold red")
    summary.append(f"  HIGH: {high}", style="bold yellow")
    summary.append(f"  MEDIUM: {medium}", style="bold cyan")
    summary.append(f"  LOW: {low}", style="dim")
    if git_history:
        summary.append(f"  |  {git_history} in git history", style="bold magenta")

    console.print(Panel(summary, title="secret-triage scan results", border_style="blue"))

    # Table
    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("#", style="dim", width=3)
    table.add_column("Severity", width=10)
    table.add_column("Confidence", width=10)
    table.add_column("Type", width=20)
    table.add_column("File", width=30)
    table.add_column("Line", width=5)
    table.add_column("Match (redacted)", width=30)

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "cyan",
        "LOW": "dim",
    }

    for i, finding in enumerate(findings, 1):
        color = severity_colors.get(finding.severity, "white")
        conf_bar = _confidence_bar(finding.confidence)
        source = "git:" + finding.commit_sha if finding.is_git_history else ""
        file_display = finding.file_path
        if source:
            file_display += f" ({source})"

        table.add_row(
            str(i),
            Text(finding.severity, style=color),
            conf_bar,
            finding.pattern_name,
            file_display,
            str(finding.line_number),
            finding._redact(finding.matched_text),
        )

    console.print(table)

    # Show remediation for top findings
    shown_remediations = set()
    console.print("\n[bold]Remediation Steps:[/bold]\n")

    for finding in findings[:5]:
        if finding.pattern_id in shown_remediations:
            continue
        shown_remediations.add(finding.pattern_id)

        console.print(f"  [bold]{finding.pattern_name}[/bold] ({finding.severity})")
        for line in finding.remediation.split("\n"):
            console.print(f"    {line}")
        console.print()


def report_sarif(findings: list[Finding], root_path: str) -> dict:
    """Generate a SARIF 2.1.0 report."""
    rules = {}
    results = []

    for finding in findings:
        # Register rule
        if finding.pattern_id not in rules:
            rules[finding.pattern_id] = {
                "id": finding.pattern_id,
                "name": finding.pattern_name,
                "shortDescription": {"text": finding.description},
                "helpUri": "",
                "properties": {
                    "category": finding.category,
                },
                "defaultConfiguration": {
                    "level": _sarif_level(finding.severity),
                },
            }

        # Add result
        results.append({
            "ruleId": finding.pattern_id,
            "level": _sarif_level(finding.severity),
            "message": {
                "text": f"{finding.description} (confidence: {finding.confidence:.0%})",
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file_path,
                            "uriBaseId": "SRCROOT",
                        },
                        "region": {
                            "startLine": finding.line_number,
                        },
                    },
                }
            ],
            "properties": {
                "confidence": finding.confidence,
                "is_git_history": finding.is_git_history,
                "commit_sha": finding.commit_sha,
            },
        })

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "secret-triage",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/yourname/secret-triage",
                        "rules": list(rules.values()),
                    },
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": datetime.now(timezone.utc).isoformat(),
                    }
                ],
            }
        ],
    }


def report_markdown(findings: list[Finding]) -> str:
    """Generate a markdown report."""
    lines = [
        "# Secret Triage Report",
        "",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Total findings:** {len(findings)}",
        "",
    ]

    # Summary table
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    high = sum(1 for f in findings if f.severity == "HIGH")
    medium = sum(1 for f in findings if f.severity == "MEDIUM")
    low = sum(1 for f in findings if f.severity == "LOW")

    lines.extend([
        "| Severity | Count |",
        "|----------|-------|",
        f"| CRITICAL | {critical} |",
        f"| HIGH | {high} |",
        f"| MEDIUM | {medium} |",
        f"| LOW | {low} |",
        "",
        "## Findings",
        "",
    ])

    for i, f in enumerate(findings, 1):
        emoji = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": "-"}.get(f.severity, "-")
        source = f" (git history: {f.commit_sha})" if f.is_git_history else ""

        lines.append(f"### {i}. [{f.severity}] {f.pattern_name}")
        lines.append("")
        lines.append(f"- **File:** `{f.file_path}`{source}")
        lines.append(f"- **Line:** {f.line_number}")
        lines.append(f"- **Confidence:** {f.confidence:.0%}")
        lines.append(f"- **Category:** {f.category}")
        lines.append(f"- **Match:** `{f._redact(f.matched_text)}`")
        lines.append("")
        lines.append("**Remediation:**")
        for line in f.remediation.split("\n"):
            lines.append(f"  {line}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def _sarif_level(severity: str) -> str:
    """Map severity to SARIF level."""
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(severity, "note")


def _confidence_bar(confidence: float) -> Text:
    """Create a visual confidence bar."""
    filled = int(confidence * 5)
    bar = "#" * filled + "-" * (5 - filled)

    if confidence >= 0.8:
        style = "bold red"
    elif confidence >= 0.6:
        style = "yellow"
    elif confidence >= 0.4:
        style = "cyan"
    else:
        style = "dim"

    text = Text()
    text.append(f"[{bar}]", style=style)
    text.append(f" {confidence:.0%}", style="dim")
    return text
