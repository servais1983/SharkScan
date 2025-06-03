#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Vision Module - Visual Network Mapping
Crée une représentation visuelle du réseau et des services
"""

import logging
from typing import Dict, Any
import json
from datetime import datetime
from rich.table import Table
from rich.progress import Progress
from rich.tree import Tree
import networkx as nx
from rich.console import Console
from rich.panel import Panel

from src.core.scanner import BaseScanner
from src.core.utils import resolve_target

logger = logging.getLogger(__name__)

class VisionScanner(BaseScanner):
    """Scanner de cartographie visuelle du réseau"""
    
    def __init__(self, args):
        super().__init__(args)
        self.timeout = args.timeout or 120  # 2 minutes par défaut
        self.graph = nx.Graph()
    
    def scan(self, target: str):
        """Effectue la cartographie visuelle du réseau"""
        console = Console()
        self.logger.info(f"Démarrage de la cartographie visuelle sur {target}")
        
        # Résoudre la cible si nécessaire
        target_ip = resolve_target(target)
        
        results = {
            'target': target,
            'target_ip': target_ip,
            'scan_time': datetime.now().isoformat(),
            'network': {
                'nodes': [],
                'edges': [],
                'services': {},
                'total_nodes': 0,
                'total_connections': 0
            }
        }
        
        # Ajouter le nœud cible
        self.graph.add_node(target_ip, type='host', name=target)
        
        # Simuler la découverte de nœuds et de connexions
        with Progress() as progress:
            task = progress.add_task("[cyan]Cartographie du réseau...", total=100)
            
            try:
                # Simuler la découverte de nœuds
                discovered_nodes = [
                    {'ip': '192.168.1.1', 'type': 'router', 'name': 'Gateway'},
                    {'ip': '192.168.1.2', 'type': 'host', 'name': 'Server1'},
                    {'ip': '192.168.1.3', 'type': 'host', 'name': 'Server2'}
                ]
                
                # Ajouter les nœuds découverts
                for node in discovered_nodes:
                    self.graph.add_node(node['ip'], type=node['type'], name=node['name'])
                    results['network']['nodes'].append(node)
                
                # Simuler les connexions
                connections = [
                    (target_ip, '192.168.1.1', {'type': 'gateway'}),
                    ('192.168.1.1', '192.168.1.2', {'type': 'lan'}),
                    ('192.168.1.1', '192.168.1.3', {'type': 'lan'})
                ]
                
                # Ajouter les connexions
                for src, dst, data in connections:
                    self.graph.add_edge(src, dst, **data)
                    results['network']['edges'].append({
                        'source': src,
                        'target': dst,
                        'type': data['type']
                    })
                
                # Simuler les services
                services = {
                    '192.168.1.2': [
                        {'port': 80, 'service': 'http', 'version': 'Apache 2.4'},
                        {'port': 443, 'service': 'https', 'version': 'Nginx 1.18'}
                    ],
                    '192.168.1.3': [
                        {'port': 22, 'service': 'ssh', 'version': 'OpenSSH 8.2'},
                        {'port': 3306, 'service': 'mysql', 'version': 'MySQL 8.0'}
                    ]
                }
                
                for host, host_services in services.items():
                    results['network']['services'][host] = host_services
                
                progress.update(task, advance=100)
                self.logger.info("Cartographie terminée")
                
            except Exception as e:
                self.logger.error(f"Erreur lors de la cartographie : {str(e)}")
                console.print(f"[red]Erreur lors de la cartographie : {str(e)}[/red]")
                results['error'] = str(e)
        
        results['network']['total_nodes'] = len(results['network']['nodes'])
        results['network']['total_connections'] = len(results['network']['edges'])
        return results
    
    def display_results(self, results):
        """Affiche les résultats de la cartographie"""
        console = Console()
        
        # Panneau de résumé
        summary = f"""🎯 Cible : {results['target']} ({results['target_ip']})
⏱️  Date : {results['scan_time']}
🔍 Nœuds découverts : {results['network']['total_nodes']}
🔌 Connexions : {results['network']['total_connections']}"""
        
        console.print(Panel(summary, title="🦈 Vision Cartographie Visuelle", border_style="blue"))
        
        # Créer l'arbre de la topologie
        tree = Tree("🌐 Topologie du Réseau")
        
        # Ajouter les nœuds et leurs connexions
        for node in results['network']['nodes']:
            node_type = "🖥️" if node['type'] == 'host' else "🌐"
            node_tree = tree.add(f"{node_type} {node['name']} ({node['ip']})")
            
            # Ajouter les services si disponibles
            if node['ip'] in results['network']['services']:
                services_tree = node_tree.add("🔌 Services")
                for service in results['network']['services'][node['ip']]:
                    services_tree.add(f"Port {service['port']}: {service['service']} ({service['version']})")
        
        console.print("\n[bold cyan]Topologie du Réseau:[/bold cyan]")
        console.print(tree)
        
        # Afficher les connexions
        if results['network']['edges']:
            console.print("\n[bold cyan]Connexions Découvertes:[/bold cyan]")
            connections_table = Table()
            connections_table.add_column("Source", style="cyan")
            connections_table.add_column("Destination", style="green")
            connections_table.add_column("Type", style="yellow")
            
            for edge in results['network']['edges']:
                connections_table.add_row(
                    edge['source'],
                    edge['target'],
                    edge['type']
                )
            
            console.print(connections_table)

def run(target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Exécute le module de visualisation du réseau.
    
    Args:
        target (str): La cible à analyser.
        options (Dict[str, Any], optional): Options supplémentaires. Defaults to None.
    
    Returns:
        Dict[str, Any]: Résultats de l'analyse.
    """
    scanner = VisionScanner(options)
    return scanner.scan(target) 