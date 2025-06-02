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

from src.core.scanner import ScannerFactory
from src.core.utils import validate_target, check_privileges
from utils.colors import Colors
from utils.logger import setup_logger

__version__ = "1.0.0"
__author__ = "SharkScan Team"

console = Console()


def print_banner():
    """Display SharkScan ASCII banner"""
    banner = f"""
{Colors.BLUE}     _____ _                _     _____                     
    / ____| |              | |   / ____|                    
   | (___ | |__   __ _ _ __| | _| (___   ___ __ _ _ __     
    \___ \| '_ \ / _` | '__| |/ /\___ \ / __/ _` | '_ \    
    ____) | | | | (_| | |  |   < ____) | (_| (_| | | | |   
   |_____/|_| |_|\__,_|_|  |_|\_\_____/ \___\__,_|_| |_|   
                                                            
   🦈 Professional Network Security Scanner v{__version__}{Colors.RESET}
   """
    console.print(Panel(banner, style="blue"))


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
    # Display banner
    print_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Setup logging
    logger = setup_logger('sharkscan', verbose=args.verbose)
    
    # Validate target
    if not validate_target(args.target):
        console.print(f"[red]❌ Invalid target: {args.target}[/red]")
        sys.exit(1)
    
    # Check privileges for certain modules
    privileged_modules = ['lateral', 'lorenzini', 'dermoid']
    if args.module in privileged_modules and not check_privileges():
        console.print(f"[yellow]⚠️  Module '{args.module}' requires root privileges. Use sudo.[/yellow]")
        sys.exit(1)
    
    try:
        # Create scanner instance
        scanner = ScannerFactory.create_scanner(args.module, args)
        
        # Display scan info
        console.print(f"\n[green]🎯 Target:[/green] {args.target}")
        console.print(f"[green]🦈 Module:[/green] {args.module}")
        console.print(f"[green]⏱️  Started:[/green] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        # Execute scan
        with console.status(f"[bold blue]Scanning with {args.module} module...[/bold blue]") as status:
            results = scanner.scan(args.target)
        
        # Display results
        if results:
            scanner.display_results(results)
            
            # Save to file if requested
            if args.output:
                output_data = {
                    "scan_info": {
                        "target": args.target,
                        "module": args.module,
                        "timestamp": datetime.now().isoformat(),
                        "version": __version__
                    },
                    "results": results
                }
                
                with open(args.output, 'w') as f:
                    json.dump(output_data, f, indent=2)
                console.print(f"\n[green]✅ Results saved to {args.output}[/green]")
        else:
            console.print("[yellow]⚠️  No results found[/yellow]")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Error during scan: {str(e)}")
        console.print(f"\n[red]❌ Error: {str(e)}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    
    console.print(f"\n[green]✅ Scan completed[/green]")


if __name__ == "__main__":
    main()