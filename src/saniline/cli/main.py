"""
SaniLine Command Line Interface (CLI).

Provides commands for file auditing, streaming sanitization, MCP server invocation,
and pre-commit security shielding.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from saniline import __tagline__, __version__
from saniline.core.context import StreamContext
from saniline.core.engine import SaniLine
from saniline.core.models import AuditReport, SanitizeAction, SecurityLevel, Severity
from saniline.mcp.server import main as run_mcp_server
from saniline.rules.base import RuleRegistry

console = Console()
err_console = Console(stderr=True)

IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", ".next", ".turbo",
    ".cache", "coverage", "__pycache__", ".venv", "venv", ".gemini"
}

ALLOWED_EXTENSIONS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".sh", ".bash", ".go", ".c", ".cpp", ".sql", ".html",
    ".json", ".yaml", ".yml"
}


def collect_files(target_path: Path) -> list[Path]:
    """Recursively collects source files while avoiding symlink cycles and ignored directories."""
    resolved = target_path.resolve()
    if resolved.is_file():
        return [resolved]

    files: list[Path] = []
    visited_dirs: set[Path] = set()

    def walk(current: Path) -> None:
        try:
            real = current.resolve()
        except OSError:
            return
        if real in visited_dirs:
            return
        visited_dirs.add(real)

        try:
            entries = list(current.iterdir())
        except OSError:
            return

        for entry in entries:
            if entry.is_dir() and not entry.is_symlink():
                if entry.name not in IGNORED_DIRS:
                    walk(entry)
            elif entry.is_file():
                if entry.suffix.lower() in ALLOWED_EXTENSIONS:
                    files.append(entry)

    walk(resolved)
    return files


def generate_sarif(report: AuditReport) -> dict:
    """Generates OASIS SARIF v2.1.0 JSON report."""
    rules = RuleRegistry.all_rules()
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SaniLine",
                        "version": __version__,
                        "informationUri": "https://github.com/alivirgo/SaniLine",
                        "rules": [
                            {
                                "id": r.rule_id,
                                "name": r.title,
                                "shortDescription": {"text": r.title},
                                "properties": {
                                    "category": r.category.value,
                                    "severity": r.severity.value,
                                },
                            }
                            for r in rules
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": v.rule_id,
                        "level": "error" if v.severity in (Severity.CRITICAL, Severity.HIGH) else "warning",
                        "message": {"text": f"{v.title} - {v.remediation_advice}"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": report.target_name},
                                    "region": {"startLine": v.line_number or 1},
                                }
                            }
                        ],
                    }
                    for v in report.violations
                ],
            }
        ],
    }


@click.group(invoke_without_command=True)
@click.pass_context
@click.option("--version", "-v", is_flag=True, help="Show SaniLine version.")
def main(ctx: click.Context, version: bool) -> None:
    """SaniLine - Military-Grade Line-by-Line Code Sanitizer & Security Shield for AI Agents."""
    if version:
        console.print(f"[bold cyan]SaniLine[/bold cyan] v{__version__} - [dim]{__tagline__}[/dim]")
        ctx.exit()
    if ctx.invoked_subcommand is None:
        console.print(Panel.fit(
            f"[bold cyan]SaniLine[/bold cyan] [green]v{__version__}[/green]\n"
            f"[dim]{__tagline__}[/dim]\n\n"
            "Run [bold yellow]saniline --help[/bold yellow] for commands and options.",
            title="SaniLine Security Shield",
            border_style="cyan"
        ))


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--level", "-l", type=click.Choice(["standard", "strict", "military"]), default="military", help="Defense level.")
@click.option("--compact", "-c", is_flag=True, help="Output token-minified JSON for AI agent context efficiency.")
@click.option("--json-out", is_flag=True, help="Output full JSON audit telemetry.")
@click.option("--format", "output_format", type=click.Choice(["terminal", "sarif"]), default="terminal", help="Output format.")
def check(target: str, level: str, compact: bool, json_out: bool, output_format: str) -> None:
    """Audit a file or directory for vulnerabilities and security posture."""
    sec_level = SecurityLevel(level)
    engine = SaniLine(level=sec_level, action=SanitizeAction.AUDIT)

    target_path = Path(target)
    files_to_scan = collect_files(target_path)

    if not files_to_scan:
        if compact:
            click.echo(json.dumps({"status": "NO_SOURCE_FILES"}))
        else:
            console.print(f"[yellow]No source files identified in {target}[/yellow]")
        return

    total_lines = 0
    all_violations = []

    for file_path in files_to_scan:
        try:
            report = engine.audit_file(file_path)
            total_lines += report.total_lines
            all_violations.extend(report.violations)
        except Exception as err:
            err_console.print(f"[red]Error scanning {file_path}: {err}[/red]")

    combined = AuditReport(
        target_name=str(target_path),
        total_lines=total_lines,
        violations=all_violations,
    )
    score = combined.calculate_score()

    if output_format == "sarif":
        click.echo(json.dumps(generate_sarif(combined), indent=2))
        if not combined.passed_military_spec:
            sys.exit(1)
        return

    if compact:
        click.echo(json.dumps(combined.to_token_compact(), separators=(",", ":")))
        if not combined.passed_military_spec:
            sys.exit(1)
        return

    if json_out:
        click.echo(json.dumps(combined.to_dict(), indent=2))
        if not combined.passed_military_spec:
            sys.exit(1)
        return

    # Render Visual Scorecard
    color = "green" if score >= 90 else "yellow" if score >= 70 else "red"
    spec_status = "[bold green]PASS[/bold green]" if combined.passed_military_spec else "[bold red]FAIL[/bold red]"

    table = Table(title=f"SaniLine Security Scorecard: {target_path.name}")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold")

    table.add_row("Scanned Files", str(len(files_to_scan)))
    table.add_row("Total Lines Scanned", str(total_lines))
    table.add_row("Security Score", f"[{color}]{score:.1f} / 100.0[/{color}]")
    table.add_row("Military Spec (DoD / NIST)", spec_status)
    table.add_row("Total Findings", str(len(all_violations)))

    counts = combined.get_counts_by_severity()
    table.add_row("Critical Findings", f"[red]{counts['CRITICAL']}[/red]")
    table.add_row("High Findings", f"[bright_red]{counts['HIGH']}[/bright_red]")
    table.add_row("Medium Findings", f"[yellow]{counts['MEDIUM']}[/yellow]")
    table.add_row("Low Findings", f"[blue]{counts['LOW']}[/blue]")

    console.print(table)

    if all_violations:
        v_table = Table(title="Detected Vulnerabilities & Neutralization Advice", border_style="dim")
        v_table.add_column("Line", justify="right", style="cyan", width=6)
        v_table.add_column("Sev", justify="center", width=8)
        v_table.add_column("Rule / CWE", style="bold", width=20)
        v_table.add_column("Description & Remediation", style="white")

        for v in all_violations[:25]:  # show top 25
            sev_color = "red" if v.severity == Severity.CRITICAL else "bright_red" if v.severity == Severity.HIGH else "yellow"
            v_table.add_row(
                str(v.line_number),
                f"[{sev_color}]{v.severity.value}[/{sev_color}]",
                f"{v.rule_id}\n[dim]{v.cwe_id}[/dim]",
                f"[bold]{v.title}[/bold]\n{v.remediation_advice}"
            )
        console.print(v_table)

    if not combined.passed_military_spec:
        sys.exit(1)


@main.command()
@click.argument("target", type=click.Path(exists=True))
@click.option("--in-place", "-i", is_flag=True, help="Modify file directly in-place.")
@click.option("--output", "-o", type=click.Path(), help="Output path for sanitized code.")
@click.option("--level", "-l", type=click.Choice(["standard", "strict", "military"]), default="military")
def sanitize(target: str, in_place: bool, output: str | None, level: str) -> None:
    """Sanitize and auto-patch vulnerabilities in a file."""
    path = Path(target).resolve()
    if not path.is_file():
        err_console.print(f"[red]Target must be a file: {target}[/red]")
        sys.exit(1)

    content = path.read_text(encoding="utf-8", errors="replace")
    lang = StreamContext.detect_language_from_path_or_content(path.name)
    engine = SaniLine(
        level=SecurityLevel(level),
        action=SanitizeAction.AUTOPATCH,
        default_language=lang,
    )
    res = engine.sanitize_code(content, language=lang)

    if in_place:
        path.write_text(res.sanitized_code, encoding="utf-8")
        console.print(f"[green]✓ Sanitized in-place: {path} ({len(res.violations)} threats neutralized)[/green]")
    elif output:
        out_path = Path(output).resolve()
        out_path.write_text(res.sanitized_code, encoding="utf-8")
        console.print(f"[green]✓ Sanitized output written to: {out_path}[/green]")
    else:
        click.echo(res.sanitized_code, nl=False)


@main.command()
@click.option("--lang", "-L", default="generic", help="Target programming language.")
@click.option("--level", "-l", type=click.Choice(["standard", "strict", "military"]), default="military")
def stream(lang: str, level: str) -> None:
    """
    Stream sanitizer filter: reads stdin line-by-line and emits sanitized lines to stdout in real-time.
    Ideal for piping with LLM token streaming and agent processes.
    """
    engine = SaniLine(
        level=SecurityLevel(level),
        action=SanitizeAction.AUTOPATCH,
        default_language=lang,
    )
    for clean_line in engine.sanitize_stream(sys.stdin, language=lang):
        sys.stdout.write(clean_line)
        sys.stdout.flush()


@main.command()
def mcp() -> None:
    """Start the SaniLine Model Context Protocol (MCP) server for AI agents."""
    run_mcp_server()


@main.command(name="rules")
def list_rules() -> None:
    """List all registered military-grade defense rules and security standards."""
    rules = RuleRegistry.all_rules()
    table = Table(title=f"SaniLine Active Defense Rules Matrix ({len(rules)} Rules)")
    table.add_column("Rule ID", style="cyan", no_wrap=True)
    table.add_column("Title", style="bold")
    table.add_column("Severity", justify="center")
    table.add_column("CWE")
    table.add_column("DoD STIG")
    table.add_column("Min Level")

    for r in sorted(rules, key=lambda x: (x.severity.score_weight, x.rule_id), reverse=True):
        sev_color = "red" if r.severity == Severity.CRITICAL else "bright_red" if r.severity == Severity.HIGH else "yellow"
        table.add_row(
            r.rule_id,
            r.title,
            f"[{sev_color}]{r.severity.value}[/{sev_color}]",
            r.cwe_id,
            r.stig_id,
            r.min_security_level.value,
        )
    console.print(table)


@main.group(name="hook")
def hook_group() -> None:
    """Manage Git pre-commit hooks."""
    pass


@hook_group.command(name="install")
def install_hook() -> None:
    """Installs SaniLine as a zero-trust git pre-commit hook."""
    git_dir = Path(".git")
    if not git_dir.exists():
        err_console.print("[red]No .git repository directory found in current path.[/red]")
        sys.exit(1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"
    hook_content = (
        "#!/usr/bin/env sh\n"
        "# SaniLine Military-Grade Pre-Commit Security Shield\n"
        "saniline check . --level military\n"
    )
    hook_path.write_text(hook_content, encoding="utf-8")
    try:
        os.chmod(hook_path, 0o755)
    except Exception:
        pass
    console.print(f"[green]✓ Successfully installed pre-commit hook at {hook_path}[/green]")


if __name__ == "__main__":
    main()
