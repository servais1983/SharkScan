#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module d'empreinte du système d'exploitation pour SharkScan.
"""

import logging
from typing import Dict, Any
import nmap
import json
from datetime import datetime
from rich.table import Table
from rich.progress import Progress

from src.core.scanner import BaseScanner
from src.core.utils import resolve_target

logger = logging.getLogger(__name__)

class DermoidScanner(BaseScanner):
    """Advanced OS detection scanner using nmap"""
    
    def __init__(self, args):
        super().__init__(args)
        self.nm = nmap.PortScanner()
        self.timeout = args.timeout or 120  # 2 minutes default for OS detection
    
    def scan(self, target: str):
        """Perform OS detection scan"""
        self.logger.info(f"Starting OS detection scan on {target}")
        
        # Resolve target if needed
        target_ip = resolve_target(target)
        
        results = {
            'target': target,
            'target_ip': target_ip,
            'scan_time': datetime.now().isoformat(),
            'hosts': {},
            'os_matches': []
        }
        
        # Construct nmap command for OS detection
        nmap_args = '-O --osscan-limit --max-os-tries 1 -Pn --max-retries 2 --host-timeout 60s'
        
        from rich.console import Console
        console = Console()
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Running OS detection...", total=100)
            
            try:
                self.logger.info(f"Running nmap with arguments: {nmap_args}")
                console.print(f"[yellow]Running OS detection scan with timeout of 60 seconds...[/yellow]")
                
                # Run OS detection scan
                self.nm.scan(
                    hosts=target_ip,
                    arguments=nmap_args
                )
                
                progress.update(task, advance=50)
                self.logger.info("Nmap scan completed, processing results...")
                
                # Process results
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        host_info = {
                            'state': 'up',
                            'hostnames': self.nm[host].hostnames(),
                            'os_matches': []
                        }
                        
                        # Extract OS matches
                        if 'osmatch' in self.nm[host]:
                            for osmatch in self.nm[host]['osmatch']:
                                os_info = {
                                    'name': osmatch['name'],
                                    'accuracy': osmatch['accuracy'],
                                    'line': osmatch['line'],
                                    'type': osmatch.get('type', 'Unknown'),
                                    'vendor': osmatch.get('vendor', 'Unknown'),
                                    'family': osmatch.get('family', 'Unknown'),
                                    'version': osmatch.get('version', 'Unknown')
                                }
                                host_info['os_matches'].append(os_info)
                                results['os_matches'].append(os_info)
                        
                        results['hosts'][host] = host_info
                
                progress.update(task, advance=50)
                
            except Exception as e:
                self.logger.error(f"Error during OS detection scan: {str(e)}")
                console.print(f"[red]Error during scan: {str(e)}[/red]")
                results['error'] = str(e)
        
        return results
    
    def display_results(self, results):
        """Display OS detection results"""
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        
        # Summary panel
        summary = f"""🎯 Target: {results['target']} ({results['target_ip']})
⏱️  Scan Time: {results['scan_time']}
🔍 Hosts Scanned: {len(results['hosts'])}
💻 OS Matches Found: {len(results['os_matches'])}"""
        
        console.print(Panel(summary, title="🦈 Dermoid OS Detection Summary", border_style="blue"))
        
        # Host details
        for host, info in results['hosts'].items():
            console.print(f"\n[bold cyan]Host: {host}[/bold cyan]")
            
            # OS matches table
            if info['os_matches']:
                os_table = Table(title="OS Detection Results")
                os_table.add_column("OS Name", style="cyan")
                os_table.add_column("Accuracy", style="green")
                os_table.add_column("Type", style="yellow")
                os_table.add_column("Vendor", style="blue")
                os_table.add_column("Version", style="magenta")
                
                for os_match in info['os_matches']:
                    os_table.add_row(
                        os_match['name'],
                        f"{os_match['accuracy']}%",
                        os_match['type'],
                        os_match['vendor'],
                        os_match['version']
                    )
                
                console.print(os_table)
            else:
                console.print("[yellow]No OS matches found[/yellow]")

def run(target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Exécute le module d'empreinte du système d'exploitation.
    
    Args:
        target (str): La cible à analyser.
        options (Dict[str, Any], optional): Options supplémentaires. Defaults to None.
    
    Returns:
        Dict[str, Any]: Résultats de l'analyse.
    """
    logger.info(f"Module dermoid démarré pour la cible: {target}")
    # TODO: Implémenter la logique d'empreinte du système d'exploitation
    return {"status": "success", "message": "Module dermoid exécuté avec succès"} 