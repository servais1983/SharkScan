#!/usr/bin/env python3
"""
SharkScan - Professional Network Security Scanner
Main entry point for the application
"""

import sys
import argparse
import json
from datetime import datetime
import os
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

from src.core.scanner import ScannerFactory
from src.core.utils import validate_target, check_privileges
from src.core.secure_logger import SecureLogger
from src.core.ids import IDS
from utils.colors import Colors

__version__ = "1.0.0"
__author__ = "SharkScan Team"

console = Console()
logger = SecureLogger("sharkscan")
ids = IDS()


def print_banner():
    """Display SharkScan ASCII banner with enhanced styling"""
    banner = f"""{Colors.BLUE}
    ███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████╗███████║███████║██████╔╝█████╔╝ █████╗  ██║     ███████║██╔██╗ ██║
    ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██╔══╝  ██║     ██╔══██║██║╚██╗██║
    ███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗╚██████╗██║  ██║██║ ╚████║
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                                                            
    🦈 Professional Network Security Scanner v{__version__}{Colors.RESET}
    """
    
    # Create a fancy panel with gradient border
    console.print(Panel(banner, 
                       title="[bold blue]SharkScan[/bold blue]",
                       subtitle="[italic]Network Security at its Finest[/italic]",
                       border_style="blue",
                       box=box.DOUBLE))
    
    # Display module information
    modules_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
    modules_table.add_column("Module", style="cyan")
    modules_table.add_column("Description", style="green")
    
    modules = {
        "lateral": "Lateral movement detection",
        "lorenzini": "Advanced port scanning",
        "dents": "Vulnerability assessment",
        "caudale": "Service enumeration",
        "dermoid": "OS fingerprinting",
        "foie": "Network mapping",
        "olfactif": "Traffic analysis",
        "vision": "Visual network mapping"
    }
    
    for module, desc in modules.items():
        modules_table.add_row(module, desc)
    
    console.print("\n[bold blue]Available Modules:[/bold blue]")
    console.print(modules_table)
    console.print("\n")
    
    # Log banner display
    logger.info("Application started", version=__version__)
    logger.security_event("app_start", {"version": __version__}, severity="INFO")


def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="SharkScan - Professional Network Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  sudo python sharkscan.py -t 192.168.1.0/24 -m lorenzini
  python sharkscan.py -t example.com -m vision
  python sharkscan.py -t 10.0.0.1 -m caudale --ports 80,443,8080
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target IP, domain, or CIDR range')
    parser.add_argument('-m', '--module', required=True, 
                        choices=['lateral', 'lorenzini', 'dents', 'caudale', 'dermoid', 'foie', 'olfactif', 'vision'],
                        help='Scanner module to use')
    parser.add_argument('-o', '--output', help='Output file (JSON format)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--version', action='version', version=f'SharkScan {__version__}')
    
    # Module-specific options
    parser.add_argument('--ports', help='Specific ports to scan (comma-separated)')
    parser.add_argument('--threads', type=int, default=50, help='Number of threads (default: 50)')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds (default: 5)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests in seconds')
    parser.add_argument('--all-ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode')
    parser.add_argument('--interface', help='Network interface to use')
    
    return parser.parse_args()


def main():
    """Main function"""
    try:
        # Display banner
        print_banner()
        
        # Parse arguments
        args = parse_arguments()
        
        # Log scan configuration
        logger.info("Scan configuration", 
                   target=args.target,
                   module=args.module,
                   options={
                       "ports": args.ports,
                       "threads": args.threads,
                       "timeout": args.timeout,
                       "stealth": args.stealth
                   })
        
        # Validate target
        if not validate_target(args.target):
            error_msg = f"Invalid target: {args.target}"
            logger.error(error_msg)
            console.print(f"[red]❌ {error_msg}[/red]")
            sys.exit(1)
        
        # Check privileges for certain modules
        privileged_modules = ['lateral', 'lorenzini', 'dermoid']
        if args.module in privileged_modules and not check_privileges():
            warning_msg = f"Module '{args.module}' requires root privileges. Use sudo."
            logger.warning(warning_msg)
            console.print(f"[yellow]⚠️  {warning_msg}[/yellow]")
            sys.exit(1)
        
        # Create scanner instance
        scanner = ScannerFactory.create_scanner(args.module, args)
        
        # Display scan info in a fancy table
        info_table = Table(show_header=False, box=box.ROUNDED)
        info_table.add_column("Property", style="cyan")
        info_table.add_column("Value", style="green")
        
        info_table.add_row("🎯 Target", args.target)
        info_table.add_row("🦈 Module", args.module)
        info_table.add_row("⏱️  Started", datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
        console.print("\n[bold blue]Scan Information:[/bold blue]")
        console.print(info_table)
        console.print("\n")
        
        # Log scan start
        logger.security_event("scan_started", {
            "target": args.target,
            "module": args.module,
            "timestamp": datetime.now().isoformat()
        })
        
        # Execute scan with fancy progress
        with console.status(f"[bold blue]Scanning with {args.module} module...[/bold blue]") as status:
            results = scanner.scan(args.target)
            
            # Monitor for suspicious activity
            ids.monitor_activity(logger.get_current_log_file())
        
        # Display results
        if results:
            scanner.display_results(results)
            
            # Log successful scan
            logger.info("Scan completed successfully", 
                       target=args.target,
                       module=args.module,
                       results_count=len(results))
            
            # Generate incident report
            report = ids.get_incident_report(logger.get_current_log_file())
            if report['total_incidents'] > 0:
                console.print("\n[bold red]Security Incidents Detected:[/bold red]")
                incidents_table = Table(box=box.ROUNDED)
                incidents_table.add_column("Category", style="red")
                incidents_table.add_column("Count", style="yellow")
                
                for category, count in report['incidents_by_category'].items():
                    incidents_table.add_row(category, str(count))
                    
                console.print(incidents_table)
            
            # Save to file if requested
            if args.output:
                output_data = {
                    "scan_info": {
                        "target": args.target,
                        "module": args.module,
                        "timestamp": datetime.now().isoformat(),
                        "version": __version__
                    },
                    "results": results,
                    "security_report": report
                }
                
                with open(args.output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                logger.info("Results saved to file", output_file=args.output)
                console.print(f"\n[green]✅ Results saved to {args.output}[/green]")
        else:
            warning_msg = "No results found"
            logger.warning(warning_msg, target=args.target, module=args.module)
            console.print(f"[yellow]⚠️  {warning_msg}[/yellow]")
            
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error("Error during scan", error=str(e), traceback=str(sys.exc_info()))
        console.print(f"\n[red]❌ Error: {str(e)}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    logger.info("Application shutdown")
    console.print(f"\n[green]✅ Scan completed[/green]")


if __name__ == "__main__":
    main()