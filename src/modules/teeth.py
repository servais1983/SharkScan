"""
Teeth Module - Advanced vulnerability scanning
Uses nmap NSE scripts for comprehensive vulnerability detection
"""

import nmap
import json
from datetime import datetime
from rich.table import Table
from rich.progress import Progress

from src.core.scanner import BaseScanner
from src.core.utils import resolve_target


class TeethScanner(BaseScanner):
    """Advanced vulnerability scanner using nmap NSE scripts"""
    
    def __init__(self, args):
        super().__init__(args)
        self.nm = nmap.PortScanner()
        self.timeout = args.timeout or 300  # 5 minutes default for vuln scans
    
    def scan(self, target: str):
        """Perform vulnerability scan"""
        self.logger.info(f"Starting vulnerability scan on {target}")
        
        # Resolve target if needed
        target_ip = resolve_target(target)
        
        results = {
            'target': target,
            'target_ip': target_ip,
            'scan_time': datetime.now().isoformat(),
            'hosts': {},
            'vulnerabilities': [],
            'total_vulns': 0
        }
        
        # Define NSE scripts for vulnerability scanning
        vuln_scripts = [
            'vuln',
            'exploit',
            'auth',
            'default'
        ]
        
        # Construct nmap command with shorter timeout
        script_args = '--script-args="mssql.instance-port=1433,oracle-enum-users.sid=ORCL,http-enum.basepath=/"'
        nmap_args = f'-sV -sC --script={",".join(vuln_scripts)} {script_args} -Pn --max-retries 2 --host-timeout 60s'
        
        from rich.console import Console
        console = Console()
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Running vulnerability scan...", total=100)
            
            try:
                self.logger.info(f"Running nmap with arguments: {nmap_args}")
                console.print(f"[yellow]Running nmap scan with timeout of 60 seconds...[/yellow]")
                
                # Run comprehensive vulnerability scan
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
                            'ports': {},
                            'os_match': self.nm[host].get('osmatch', []),
                            'vulnerabilities': []
                        }
                        
                        # Process each port
                        for proto in self.nm[host].all_protocols():
                            ports = self.nm[host][proto].keys()
                            for port in ports:
                                port_info = self.nm[host][proto][port]
                                
                                # Extract service information
                                service_info = {
                                    'state': port_info['state'],
                                    'name': port_info['name'],
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', ''),
                                    'extrainfo': port_info.get('extrainfo', ''),
                                    'scripts': {}
                                }
                                
                                # Extract script results
                                if 'script' in port_info:
                                    for script_name, script_output in port_info['script'].items():
                                        service_info['scripts'][script_name] = script_output
                                        
                                        # Check for vulnerabilities
                                        if self._is_vulnerability(script_name, script_output):
                                            vuln = {
                                                'host': host,
                                                'port': port,
                                                'service': port_info['name'],
                                                'script': script_name,
                                                'details': script_output,
                                                'severity': self._get_severity(script_name, script_output)
                                            }
                                            host_info['vulnerabilities'].append(vuln)
                                            results['vulnerabilities'].append(vuln)
                                
                                host_info['ports'][port] = service_info
                        
                        results['hosts'][host] = host_info
                
                progress.update(task, advance=50)
                
            except Exception as e:
                self.logger.error(f"Error during vulnerability scan: {str(e)}")
                console.print(f"[red]Error during scan: {str(e)}[/red]")
                results['error'] = str(e)
        
        results['total_vulns'] = len(results['vulnerabilities'])
        return results
    
    def _is_vulnerability(self, script_name: str, output: str) -> bool:
        """Check if script output indicates a vulnerability"""
        vuln_indicators = [
            'VULNERABLE',
            'vulnerable',
            'Vulnerable',
            'EXPLOIT',
            'exploit',
            'CVE-',
            'MS0',
            'MS1',
            'default credentials',
            'Default credentials',
            'weak',
            'Weak',
            'outdated',
            'Outdated',
            'deprecated',
            'Deprecated'
        ]
        
        return any(indicator in output for indicator in vuln_indicators)
    
    def _get_severity(self, script_name: str, output: str) -> str:
        """Determine vulnerability severity"""
        # Critical indicators
        if any(x in output.lower() for x in ['remote code execution', 'rce', 'shell', 'command injection']):
            return 'CRITICAL'
        
        # High severity
        if any(x in output.lower() for x in ['sql injection', 'authentication bypass', 'default credentials']):
            return 'HIGH'
        
        # Medium severity
        if any(x in output.lower() for x in ['xss', 'csrf', 'information disclosure']):
            return 'MEDIUM'
        
        # Low severity
        return 'LOW'
    
    def display_results(self, results):
        """Display vulnerability scan results"""
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        
        # Summary panel
        summary = f"""🎯 Target: {results['target']} ({results['target_ip']})
⏱️  Scan Time: {results['scan_time']}
🔍 Hosts Scanned: {len(results['hosts'])}
⚠️  Vulnerabilities Found: {results['total_vulns']}"""
        
        console.print(Panel(summary, title="🦈 Teeth Vulnerability Scan Summary", border_style="blue"))
        
        # Host details
        for host, info in results['hosts'].items():
            console.print(f"\n[bold cyan]Host: {host}[/bold cyan]")
            
            # OS detection
            if info['os_match']:
                console.print("[yellow]OS Detection:[/yellow]")
                for os in info['os_match'][:3]:  # Top 3 matches
                    console.print(f"  • {os['name']} (Accuracy: {os['accuracy']}%)")
            
            # Services table
            if info['ports']:
                services_table = Table(title="Services Detected")
                services_table.add_column("Port", style="cyan")
                services_table.add_column("State", style="green")
                services_table.add_column("Service", style="yellow")
                services_table.add_column("Version", style="blue")
                
                for port, port_info in sorted(info['ports'].items()):
                    version = f"{port_info['product']} {port_info['version']}" if port_info['product'] else "-"
                    services_table.add_row(
                        str(port),
                        port_info['state'],
                        port_info['name'],
                        version
                    )
                
                console.print(services_table)
        
        # Vulnerabilities
        if results['vulnerabilities']:
            console.print("\n[bold red]⚠️  VULNERABILITIES DETECTED[/bold red]")
            
            # Group by severity
            vulns_by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
            for vuln in results['vulnerabilities']:
                vulns_by_severity[vuln['severity']].append(vuln)
            
            # Display by severity
            for severity, vulns in vulns_by_severity.items():
                if vulns:
                    severity_color = {
                        'CRITICAL': 'red',
                        'HIGH': 'bright_red',
                        'MEDIUM': 'yellow',
                        'LOW': 'bright_yellow'
                    }[severity]
                    
                    console.print(f"\n[{severity_color}]{severity} Severity ({len(vulns)} found):[/{severity_color}]")
                    
                    for vuln in vulns:
                        console.print(f"\n  📍 {vuln['host']}:{vuln['port']} ({vuln['service']})")
                        console.print(f"  📋 Script: {vuln['script']}")
                        console.print(f"  📝 Details: {vuln['details'][:200]}...")
        else:
            console.print("\n[green]✅ No vulnerabilities detected[/green]")