"""
Olfactif Module - Traffic Analysis
Analyse le trafic réseau pour détecter des anomalies et des protocoles
"""

import json
from datetime import datetime
from rich.table import Table
from rich.progress import Progress
from scapy.all import sniff, IP, TCP, UDP

from src.core.scanner import BaseScanner

class OlfactoryScanner(BaseScanner):
    """Analyseur de trafic réseau utilisant scapy"""
    
    def __init__(self, args):
        super().__init__(args)
        self.timeout = args.timeout or 30  # 30 secondes par défaut
        self.packet_count = getattr(args, 'packet_count', 100)
        self.interface = getattr(args, 'interface', None)
    
    def scan(self, target: str):
        """Capture et analyse le trafic réseau"""
        from rich.console import Console
        console = Console()
        self.logger.info(f"Démarrage de l'analyse de trafic sur l'interface {self.interface or 'par défaut'}")
        
        results = {
            'target': target,
            'scan_time': datetime.now().isoformat(),
            'packets': [],
            'protocols': {},
            'total_packets': 0
        }
        
        def process_packet(pkt):
            proto = 'OTHER'
            if IP in pkt:
                if TCP in pkt:
                    proto = 'TCP'
                elif UDP in pkt:
                    proto = 'UDP'
                else:
                    proto = 'IP'
            results['protocols'][proto] = results['protocols'].get(proto, 0) + 1
            results['packets'].append({
                'src': pkt[IP].src if IP in pkt else '',
                'dst': pkt[IP].dst if IP in pkt else '',
                'proto': proto
            })
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Capture du trafic réseau...", total=self.packet_count)
            try:
                packets = sniff(count=self.packet_count, timeout=self.timeout, iface=self.interface, prn=process_packet)
                progress.update(task, completed=len(packets))
                self.logger.info(f"Capture terminée : {len(packets)} paquets")
                results['total_packets'] = len(packets)
            except Exception as e:
                self.logger.error(f"Erreur lors de la capture : {str(e)}")
                console.print(f"[red]Erreur lors de la capture : {str(e)}[/red]")
                results['error'] = str(e)
        return results
    
    def display_results(self, results):
        from rich.console import Console
        from rich.panel import Panel
        console = Console()
        summary = f"""🎯 Cible : {results['target']}
⏱️  Date : {results['scan_time']}
📦 Paquets capturés : {results['total_packets']}"""
        console.print(Panel(summary, title="🦈 Olfactif Analyse de Trafic", border_style="blue"))
        if results['protocols']:
            table = Table(title="Protocoles détectés")
            table.add_column("Protocole", style="cyan")
            table.add_column("Nombre de paquets", style="green")
            for proto, count in results['protocols'].items():
                table.add_row(proto, str(count))
            console.print(table)
        else:
            console.print("[yellow]Aucun paquet capturé ou protocole détecté.[/yellow]") 