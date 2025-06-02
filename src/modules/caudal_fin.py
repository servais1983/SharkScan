"""
Caudal Fin Module - Fast TCP port scanning
High-speed port scanning with threading
"""

import socket
import threading
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.table import Table
from rich.progress import Progress, TaskID

from src.core.scanner import BaseScanner
from src.core.utils import parse_ports, resolve_target, get_service_name


class CaudalFinScanner(BaseScanner):
    """Fast TCP port scanner using multithreading"""
    
    def __init__(self, args):
        super().__init__(args)
        self.timeout = args.timeout or 1
        self.threads = args.threads or 50
        self.delay = args.delay or 0
        
        # Default ports if not specified
        if args.ports:
            self.ports = parse_ports(args.ports)
        elif args.all_ports:
            self.ports = list(range(1, 65536))
        else:
            # Top 1000 ports
            self.ports = [
                21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1723, 3306, 3389, 5900, 8080, 8443, 8888, 10000, 32768, 49152, 49153,
                49154, 49155, 49156, 49157, 1433, 1521, 1723, 2049, 2121, 3128, 3306,
                3389, 5432, 5900, 5984, 6379, 7001, 8020, 8080, 8081, 8443, 8888,
                9200, 9300, 11211, 27017, 27018, 27019, 50070, 5601, 9042, 7000, 7199,
                9160, 61616, 6066, 6666, 8000, 8008, 8083, 8086, 8088, 9000, 9090,
                9091, 4444, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6008,
                6009, 7000, 7070, 8000, 8001, 8002, 8003, 8004, 8005, 8006, 8007,
                8009, 8010, 8011, 8012, 8013, 8014, 8015, 8016, 8017, 8018, 8019,
                8020, 8021, 8022, 8023, 8024, 8025, 8026, 8027, 8028, 8029, 8030
            ][:1000]  # Limit to 1000 ports
    
    def scan_port(self, host: str, port: int, progress: Progress, task: TaskID) -> dict:
        """Scan a single port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        result = {
            'port': port,
            'state': 'closed',
            'service': get_service_name(port),
            'banner': None
        }
        
        try:
            # Attempt connection
            start_time = time.time()
            sock.connect((host, port))
            end_time = time.time()
            
            result['state'] = 'open'
            result['response_time'] = end_time - start_time
            
            # Try to grab banner
            try:
                sock.settimeout(2)
                banner = sock.recv(1024)
                if banner:
                    result['banner'] = banner.decode('utf-8', errors='ignore').strip()
            except:
                pass
                
        except socket.timeout:
            result['state'] = 'filtered'
        except socket.error:
            result['state'] = 'closed'
        finally:
            sock.close()
            progress.update(task, advance=1)
            
            # Apply delay if specified
            if self.delay > 0:
                time.sleep(self.delay)
        
        return result
    
    def scan(self, target: str):
        """Perform fast port scan"""
        # Resolve target
        host = resolve_target(target)
        
        results = {
            'target': target,
            'host': host,
            'scan_time': datetime.now().isoformat(),
            'total_ports_scanned': len(self.ports),
            'open_ports': [],
            'filtered_ports': [],
            'closed_ports': 0
        }
        
        self.logger.info(f"Scanning {len(self.ports)} ports on {host}")
        
        from rich.console import Console
        console = Console()
        
        # Perform scan with progress bar
        with Progress() as progress:
            task = progress.add_task(
                f"[cyan]Scanning {len(self.ports)} ports...", 
                total=len(self.ports)
            )
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                # Submit all tasks
                future_to_port = {
                    executor.submit(self.scan_port, host, port, progress, task): port 
                    for port in self.ports
                }
                
                # Process results as they complete
                for future in as_completed(future_to_port):
                    try:
                        result = future.result()
                        
                        if result['state'] == 'open':
                            results['open_ports'].append(result)
                        elif result['state'] == 'filtered':
                            results['filtered_ports'].append(result['port'])
                        else:
                            results['closed_ports'] += 1
                            
                    except Exception as e:
                        self.logger.error(f"Error scanning port: {str(e)}")
        
        # Sort open ports
        results['open_ports'].sort(key=lambda x: x['port'])
        
        return results
    
    def display_results(self, results):
        """Display scan results"""
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        
        # Summary
        summary = f"""🎯 Target: {results['target']} ({results['host']})
🔍 Ports Scanned: {results['total_ports_scanned']}
✅ Open Ports: {len(results['open_ports'])}
🚫 Filtered Ports: {len(results['filtered_ports'])}
❌ Closed Ports: {results['closed_ports']}"""
        
        console.print(Panel(summary, title="🦈 Caudal Fin Fast Scan Results", border_style="blue"))
        
        # Open ports table
        if results['open_ports']:
            table = Table(title="Open Ports")
            table.add_column("Port", style="cyan", width=10)
            table.add_column("Service", style="yellow", width=15)
            table.add_column("State", style="green", width=10)
            table.add_column("Response Time", style="blue", width=15)
            table.add_column("Banner", style="white", max_width=40)
            
            for port_info in results['open_ports']:
                response_time = f"{port_info.get('response_time', 0)*1000:.2f} ms"
                banner = port_info.get('banner', '-')[:40] if port_info.get('banner') else '-'
                
                table.add_row(
                    str(port_info['port']),
                    port_info['service'],
                    port_info['state'].upper(),
                    response_time,
                    banner
                )
            
            console.print("\n")
            console.print(table)
        else:
            console.print("\n[yellow]No open ports found[/yellow]")
        
        # Filtered ports
        if results['filtered_ports']:
            console.print(f"\n[yellow]🚫 Filtered ports:[/yellow] {', '.join(map(str, results['filtered_ports'][:20]))}")
            if len(results['filtered_ports']) > 20:
                console.print(f"   ... and {len(results['filtered_ports']) - 20} more")