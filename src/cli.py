"""
Modern command-line interface for SharkScan
"""

import click
import sys
import json
import os
from datetime import datetime

# Ajouter le répertoire parent au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box
from typing import Optional
from src.core.config_manager import ConfigManager
from src.core.parallel_scanner import ParallelScanner
from src.core.vulnerability_signatures import VulnerabilitySignatures
from src.core.ids import IDS
from src.core.report_generator import ReportGenerator
from src.core.secure_logger import SecureLogger
from src.core.scanner import Scanner

console = Console()

@click.group()
@click.version_option(version="1.0.0")
def cli():
    """SharkScan - Advanced Network Security Scanner"""
    pass

@cli.command()
@click.option('--target', '-t', help='Target to scan (IP or hostname)')
@click.option('--ports', '-p', help='Ports to scan (e.g., "80,443,8080" or "1-1024")')
@click.option('--profile', '-P', default='default', help='Scan profile to use')
@click.option('--output', '-o', help='Output file for results')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
def scan(target: str, ports: str, profile: str, output: Optional[str], verbose: bool):
    """Run a security scan"""
    try:
        # Initialize components
        config = ConfigManager()
        logger = SecureLogger("cli")
        
        # Load profile
        if not config.load_profile(profile):
            console.print(f"[red]Error: Profile '{profile}' not found[/red]")
            sys.exit(1)
            
        # Update configuration
        if target:
            config.update_config("scan", "target", target)
        if ports:
            # Parse ports
            port_list = []
            for part in ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
            config.update_config("scan", "ports", port_list)
        if verbose:
            config.update_config("output", "verbose", True)
            
        # Get configuration
        scan_config = config.get_config()
        
        # Display scan configuration
        console.print(Panel(
            f"[bold blue]SharkScan Configuration[/bold blue]\n"
            f"Profile: {profile}\n"
            f"Target: {scan_config['scan']['target']}\n"
            f"Ports: {scan_config['scan']['ports']}\n"
            f"Protocol: {scan_config['scan']['protocol']}\n"
            f"Threads: {scan_config['scan']['threads']}",
            box=box.ROUNDED
        ))
        
        # Initialize scanners
        scanner = ParallelScanner(
            max_workers=scan_config['scan']['threads'],
            use_processes=scan_config['scan']['use_processes']
        )
        vuln_scanner = VulnerabilitySignatures()
        ids = IDS()
        
        # Start scan
        start_time = datetime.now()
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console
        ) as progress:
            # Port scan
            scan_task = progress.add_task("[cyan]Scanning ports...", total=len(scan_config['scan']['ports']))
            results = scanner.scan_range(
                targets=[scan_config['scan']['target']],
                ports=scan_config['scan']['ports'],
                protocol=scan_config['scan']['protocol']
            )
            progress.update(scan_task, completed=len(scan_config['scan']['ports']))
            
            # Vulnerability scan
            if scan_config['security']['enable_vuln_scan']:
                vuln_task = progress.add_task("[yellow]Scanning for vulnerabilities...", total=len(results))
                vuln_results = []
                for target, ports in results.items():
                    for port in ports:
                        if port['status'] == 'open':
                            vulnerabilities = vuln_scanner.scan_response(
                                str(port),
                                category='web' if port['port'] in [80, 443, 8080] else 'service'
                            )
                            if vulnerabilities:
                                vuln_results.extend(vulnerabilities)
                    progress.update(vuln_task, advance=1)
                    
            # IDS analysis
            if scan_config['security']['enable_ids']:
                ids_task = progress.add_task("[red]Analyzing security incidents...", total=1)
                ids_report = ids.get_incident_report(logger.get_current_log_file())
                ids_results = ids_report.get('details', []) if isinstance(ids_report, dict) else []
                progress.update(ids_task, completed=1)
                
        # Nettoyage des résultats pour éviter les None
        vuln_results = [v for v in (vuln_results or []) if isinstance(v, dict)]
        ids_results = [i for i in (ids_results or []) if isinstance(i, dict)]
        report_gen = ReportGenerator()
        report_file = report_gen.generate_report({
            'targets': [scan_config['scan']['target']],
            'ports': [p['port'] for p in results[scan_config['scan']['target']] if p['status'] == 'open'],
            'duration': (datetime.now() - start_time).total_seconds()
        }, vuln_results, ids_results, [])
        
        # Save results
        if output:
            with open(output, 'w') as f:
                json.dump({
                    'scan_results': results,
                    'vulnerabilities': vuln_results,
                    'security_incidents': ids_results
                }, f, indent=2)
            console.print(f"[green]Results saved to: {output}[/green]")
            
        console.print(f"[green]Report generated: {report_file}[/green]")
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--profile', '-P', default='default', help='Profile to show')
def show_profile(profile: str):
    """Show configuration profile"""
    try:
        config = ConfigManager()
        if not config.load_profile(profile):
            console.print(f"[red]Error: Profile '{profile}' not found[/red]")
            sys.exit(1)
            
        config_data = config.get_config()
        
        # Display profile
        table = Table(title=f"Profile: {profile}", box=box.ROUNDED)
        table.add_column("Section", style="cyan")
        table.add_column("Setting", style="green")
        table.add_column("Value", style="yellow")
        
        for section, settings in config_data.items():
            for key, value in settings.items():
                table.add_row(section, key, str(value))
                
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--name', '-n', required=True, help='Profile name')
@click.option('--base', '-b', default='default', help='Base profile to copy from')
def create_profile(name: str, base: str):
    """Create a new configuration profile"""
    try:
        config = ConfigManager()
        if not config.load_profile(base):
            console.print(f"[red]Error: Base profile '{base}' not found[/red]")
            sys.exit(1)
            
        # Save as new profile
        config.save_profile(name, config.get_config())
        console.print(f"[green]Created profile: {name}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
@click.option('--profile', '-P', required=True, help='Profile to delete')
def delete_profile(profile: str):
    """Delete a configuration profile"""
    try:
        config = ConfigManager()
        profile_file = os.path.join(config.config_dir, f"{profile}.json")
        
        if not os.path.exists(profile_file):
            console.print(f"[red]Error: Profile '{profile}' not found[/red]")
            sys.exit(1)
            
        os.remove(profile_file)
        console.print(f"[green]Deleted profile: {profile}[/green]")
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

@cli.command()
def list_profiles():
    """List available configuration profiles"""
    try:
        config = ConfigManager()
        profiles = [f.replace('.json', '') for f in os.listdir(config.config_dir) if f.endswith('.json')]
        
        if not profiles:
            console.print("[yellow]No profiles found[/yellow]")
            return
            
        table = Table(title="Available Profiles", box=box.ROUNDED)
        table.add_column("Profile", style="cyan")
        table.add_column("Description", style="green")
        
        for profile in profiles:
            description = {
                'default': 'Standard scan configuration',
                'aggressive': 'Fast and thorough scanning',
                'stealth': 'Slow and stealthy scanning'
            }.get(profile, 'Custom profile')
            
            table.add_row(profile, description)
            
        console.print(table)
        
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)

if __name__ == '__main__':
    cli() 