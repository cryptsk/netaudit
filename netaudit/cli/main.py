#!/usr/bin/env python3
"""
CRYPTSK NetAudit - CLI Entry Point
Linux Network Infrastructure Audit Tool

Copyright (c) 2025 CRYPTSK Pvt Ltd
Website: https://cryptsk.com
Contact: info@cryptsk.com

Usage:
    netaudit scan
    netaudit scan --json
    netaudit score
    netaudit --help
"""

import sys
import os
import json
from typing import Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import typer
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich import print as rprint
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install typer rich")
    sys.exit(1)

from core import (
    SysctlChecker,
    FirewallChecker,
    NetworkChecker,
    SecurityChecker,
    ScoringEngine,
    format_cli_output
)

# Company Information
COMPANY_NAME = "CRYPTSK Pvt Ltd"
COMPANY_WEBSITE = "https://cryptsk.com"
COMPANY_EMAIL = "info@cryptsk.com"
COPYRIGHT = "© 2025 CRYPTSK Pvt Ltd. All rights reserved."

app = typer.Typer(
    name="netaudit",
    help="CRYPTSK NetAudit - Linux Network Infrastructure Audit Tool by CRYPTSK Pvt Ltd",
    add_completion=False
)

console = Console()


def run_full_audit() -> dict:
    """Run all audit checks and return results"""
    engine = ScoringEngine()
    
    # Initialize checkers
    sysctl_checker = SysctlChecker()
    firewall_checker = FirewallChecker()
    network_checker = NetworkChecker()
    security_checker = SecurityChecker()
    
    # Run checks
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True
    ) as progress:
        progress.add_task("Checking sysctl parameters...", total=None)
        engine.add_findings('sysctl', sysctl_checker.run_all_checks()['security'] + sysctl_checker.run_all_checks()['performance'])
        
        progress.add_task("Checking firewall configuration...", total=None)
        engine.add_findings('firewall', firewall_checker.run_all_checks())
        
        progress.add_task("Checking network configuration...", total=None)
        engine.add_findings('network', network_checker.run_all_checks())
        
        progress.add_task("Checking security settings...", total=None)
        engine.add_findings('security', security_checker.run_all_checks())
    
    # Generate report
    return engine.generate_report()


@app.command()
def scan(
    json_output: bool = typer.Option(
        False, 
        "--json", "-j", 
        help="Output results in JSON format"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output", "-o",
        help="Save output to file"
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed output"
    )
):
    """
    Run a full network infrastructure security audit.
    
    Scans sysctl parameters, firewall configuration, network settings,
    and security configurations. Outputs a comprehensive security report.
    
    Copyright (c) 2025 CRYPTSK Pvt Ltd
    Website: https://cryptsk.com
    """
    console.print(Panel.fit(
        "[bold red]CRYPTSK NetAudit[/bold red]\n"
        "Linux Network Infrastructure Audit Tool\n"
        "[dim]by CRYPTSK Pvt Ltd[/dim]",
        border_style="red"
    ))
    
    try:
        result = run_full_audit()
        
        if json_output:
            output = result.to_json()
            console.print(output)
        else:
            output = format_cli_output(result)
            console.print(output)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(result.to_json() if json_output else output)
            console.print(f"\n[green]Report saved to: {output_file}[/green]")
        
        # Footer
        console.print(f"\n[dim]{COPYRIGHT}[/dim]")
        console.print(f"[dim]Website: {COMPANY_WEBSITE} | Contact: {COMPANY_EMAIL}[/dim]")
        
        # Return exit code based on score
        if result.overall_score < 50:
            raise typer.Exit(2)  # Critical issues
        elif result.overall_score < 70:
            raise typer.Exit(1)  # Warnings
        else:
            raise typer.Exit(0)  # OK
            
    except PermissionError:
        console.print("[red]Error: Insufficient permissions. Run with sudo for complete audit.[/red]")
        raise typer.Exit(3)
    except Exception as e:
        console.print(f"[red]Error during audit: {str(e)}[/red]")
        raise typer.Exit(4)


@app.command()
def score():
    """
    Display only the overall security score.
    
    Quick check that outputs just the security score (0-100)
    and grade (A-F).
    """
    try:
        result = run_full_audit()
        
        # Create a nice score display
        score = result.overall_score
        grade = result.grade
        
        # Color based on score
        if score >= 80:
            color = "green"
        elif score >= 60:
            color = "yellow"
        else:
            color = "red"
        
        table = Table(title="Security Score", show_header=False, box=None)
        table.add_column("Metric", style="bold")
        table.add_column("Value", style=color)
        
        table.add_row("Score", f"{score}/100")
        table.add_row("Grade", grade)
        table.add_row("Critical Issues", str(result.summary['risk_breakdown']['critical']))
        table.add_row("Warnings", str(result.summary['risk_breakdown']['warning']))
        
        console.print(table)
        console.print(f"\n[dim]{COPYRIGHT}[/dim]")
        console.print(f"[dim]Website: {COMPANY_WEBSITE}[/dim]")
        
        # Exit code based on score
        if score < 50:
            raise typer.Exit(2)
        elif score < 70:
            raise typer.Exit(1)
        else:
            raise typer.Exit(0)
            
    except PermissionError:
        console.print("[red]Error: Insufficient permissions. Run with sudo for complete audit.[/red]")
        raise typer.Exit(3)
    except Exception as e:
        console.print(f"[red]Error during audit: {str(e)}[/red]")
        raise typer.Exit(4)


@app.command()
def check(
    category: str = typer.Argument(
        ...,
        help="Category to check: sysctl, firewall, network, or security"
    ),
    json_output: bool = typer.Option(
        False,
        "--json", "-j",
        help="Output results in JSON format"
    )
):
    """
    Run checks for a specific category.
    
    Categories:
    - sysctl: Kernel parameter checks
    - firewall: Firewall configuration checks
    - network: Network interface checks
    - security: Security configuration checks
    """
    category = category.lower()
    valid_categories = ['sysctl', 'firewall', 'network', 'security']
    
    if category not in valid_categories:
        console.print(f"[red]Invalid category: {category}[/red]")
        console.print(f"Valid categories: {', '.join(valid_categories)}")
        raise typer.Exit(1)
    
    engine = ScoringEngine()
    
    try:
        if category == 'sysctl':
            checker = SysctlChecker()
            results = checker.run_all_checks()
            # Flatten results
            all_results = results.get('security', []) + results.get('performance', [])
            engine.add_findings('sysctl', all_results)
        
        elif category == 'firewall':
            checker = FirewallChecker()
            engine.add_findings('firewall', checker.run_all_checks())
        
        elif category == 'network':
            checker = NetworkChecker()
            engine.add_findings('network', checker.run_all_checks())
        
        elif category == 'security':
            checker = SecurityChecker()
            engine.add_findings('security', checker.run_all_checks())
        
        # Generate partial report
        result = engine.generate_report()
        
        if json_output:
            console.print(result.to_json())
        else:
            # Display category-specific results
            console.print(f"\n[bold]{category.upper()} CHECKS[/bold]\n")
            
            for finding in result.findings:
                if finding.status == 'pass':
                    icon = "[green]✓[/green]"
                elif finding.status == 'warning':
                    icon = "[yellow]![/yellow]"
                elif finding.status == 'fail':
                    icon = "[red]✗[/red]"
                else:
                    icon = "[blue]i[/blue]"
                
                console.print(f"{icon} {finding.check_name}")
                console.print(f"   {finding.message}")
                if finding.recommendation:
                    console.print(f"   [dim]→ {finding.recommendation}[/dim]")
                console.print()
        
        console.print(f"[dim]{COPYRIGHT}[/dim]")
        
    except PermissionError:
        console.print("[red]Error: Insufficient permissions. Run with sudo for complete audit.[/red]")
        raise typer.Exit(3)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        raise typer.Exit(4)


@app.command()
def version():
    """Display version information."""
    from core import __version__, __author__, __email__, __website__
    console.print(f"[bold red]CRYPTSK NetAudit[/bold red] v{__version__}")
    console.print(f"Author: {__author__}")
    console.print(f"Website: {__website__}")
    console.print(f"Contact: {__email__}")
    console.print(f"\n{COPYRIGHT}")


@app.command()
def about():
    """Display information about CRYPTSK."""
    console.print(Panel.fit(
        "[bold red]CRYPTSK Pvt Ltd[/bold red]\n\n"
        "Linux Network Infrastructure Security Solutions\n\n"
        f"[bold]Website:[/bold] {COMPANY_WEBSITE}\n"
        f"[bold]Email:[/bold] {COMPANY_EMAIL}\n\n"
        "[dim]CRYPTSK NetAudit - Professional Linux Security Auditing[/dim]",
        title="About CRYPTSK",
        border_style="red"
    ))
    console.print(f"\n{COPYRIGHT}")


def main():
    """Main entry point"""
    app()


if __name__ == "__main__":
    main()
