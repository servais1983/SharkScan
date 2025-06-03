#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de cartographie du réseau pour SharkScan.
"""

import logging
from typing import Dict, Any
import nmap
import json
from datetime import datetime
from rich.table import Table
from rich.progress import Progress
from rich.tree import Tree

from src.core.scanner import BaseScanner
from src.core.utils import resolve_target

logger = logging.getLogger(__name__)

class FoieScanner(BaseScanner):
    """Advanced network mapping scanner using nmap"""
    
    def __init__(self, args):
        super().__init__(args)
        self.nm = nmap.PortScanner()
        self.timeout = args.timeout or 300  # 5 minutes default for network mapping
    
    def scan(self, target: str):
        """Perform network mapping scan"""
        self.logger.info(f"Starting network mapping scan on {target}")
        
        # Resolve target if needed
        target_ip = resolve_target(target)
        
        results = {
            'target': target,
            'target_ip': target_ip,
            'scan_time': datetime.now().isoformat(),
            'network': {
                'hosts': {},
                'topology': {},
                'services': {},
                'total_hosts': 0,
                'total_services': 0
            }
        }
        
        # Construct nmap command for network mapping
        nmap_args = '-sn -PR -PS22,25,80,443,3389 -PA21,23,80,3389 -PE -PP -PM -PO -n --traceroute'
        
        from rich.console import Console
        console = Console()
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Mapping network...", total=100)
            
            try:
                self.logger.info(f"Running nmap with arguments: {nmap_args}")
                console.print(f"[yellow]Running network mapping scan...[/yellow]")
                
                # Run network discovery scan
                self.nm.scan(
                    hosts=target_ip,
                    arguments=nmap_args
                )
                
                progress.update(task, advance=30)
                self.logger.info("Network discovery completed, starting service scan...")
                
                # Run service scan on discovered hosts
                service_args = '-sV -sC --version-intensity 5 -O --osscan-limit'
                self.nm.scan(
                    hosts=','.join(self.nm.all_hosts()),
                    arguments=service_args
                )
                
                progress.update(task, advance=40)
                self.logger.info("Service scan completed, processing results...")
                
                # Process results
                for host in self.nm.all_hosts():
                    if self.nm[host].state() == 'up':
                        host_info = {
                            'state': 'up',
                            'hostnames': self.nm[host].hostnames(),
                            'services': {},
                            'os_match': self.nm[host].get('osmatch', []),
                            'traceroute': self.nm[host].get('traceroute', {}),
                            'hops': []
                        }
                        
                        # Process services
                        for proto in self.nm[host].all_protocols():
                            ports = self.nm[host][proto].keys()
                            for port in ports:
                                port_info = self.nm[host][proto][port]
                                service_info = {
                                    'state': port_info['state'],
                                    'name': port_info['name'],
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', ''),
                                    'extrainfo': port_info.get('extrainfo', '')
                                }
                                host_info['services'][port] = service_info
                                results['network']['services'][f"{host}:{port}"] = service_info
                        
                        # Process traceroute
                        if 'traceroute' in self.nm[host]:
                            for hop in self.nm[host]['traceroute'].get('hops', []):
                                host_info['hops'].append({
                                    'ttl': hop.get('ttl', ''),
                                    'ip': hop.get('ip', ''),
                                    'rtt': hop.get('rtt', '')
                                })
                        
                        results['network']['hosts'][host] = host_info
                        results['network']['total_hosts'] += 1
                        results['network']['total_services'] += len(host_info['services'])
                
                progress.update(task, advance=30)
                
            except Exception as e:
                self.logger.error(f"Error during network mapping: {str(e)}")
                console.print(f"[red]Error during scan: {str(e)}[/red]")
                results['error'] = str(e)
        
        return results
    
    def display_results(self, results):
        """Display network mapping results"""
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        
        # Summary panel
        summary = f"""🎯 Target: {results['target']} ({results['target_ip']})
⏱️  Scan Time: {results['scan_time']}
🔍 Hosts Discovered: {results['network']['total_hosts']}
🔌 Services Found: {results['network']['total_services']}"""
        
        console.print(Panel(summary, title="🦈 Foie Network Mapping Summary", border_style="blue"))
        
        # Create network tree
        tree = Tree("🌐 Network Topology")
        
        # Add hosts to tree
        for host, info in results['network']['hosts'].items():
            host_node = tree.add(f"🖥️  {host}")
            
            # Add hostname if available
            if info['hostnames']:
                hostnames = [h['name'] for h in info['hostnames'] if h['name']]
                if hostnames:
                    host_node.add(f"📝 Hostname: {', '.join(hostnames)}")
            
            # Add OS information
            if info['os_match']:
                os_info = info['os_match'][0]  # Get most accurate match
                host_node.add(f"💻 OS: {os_info['name']} ({os_info['accuracy']}%)")
            
            # Add services
            if info['services']:
                services_node = host_node.add("🔌 Services")
                for port, service in info['services'].items():
                    service_str = f"Port {port}: {service['name']}"
                    if service['product']:
                        service_str += f" ({service['product']}"
                        if service['version']:
                            service_str += f" {service['version']}"
                        service_str += ")"
                    services_node.add(service_str)
            
            # Add traceroute information
            if info['hops']:
                route_node = host_node.add("🛣️  Network Path")
                for hop in info['hops']:
                    route_node.add(f"TTL {hop['ttl']}: {hop['ip']} ({hop['rtt']}ms)")
        
        console.print("\n[bold cyan]Network Topology:[/bold cyan]")
        console.print(tree)

def run(target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Exécute le module de cartographie du réseau.
    
    Args:
        target (str): La cible à analyser.
        options (Dict[str, Any], optional): Options supplémentaires. Defaults to None.
    
    Returns:
        Dict[str, Any]: Résultats de l'analyse.
    """
    logger.info(f"Module foie démarré pour la cible: {target}")
    # TODO: Implémenter la logique de cartographie du réseau
    return {"status": "success", "message": "Module foie exécuté avec succès"} 