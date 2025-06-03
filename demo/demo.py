#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de démonstration pour SharkScan.
Ce script simule les résultats de SharkScan de manière sécurisée.
"""

import sys
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress
from rich.tree import Tree

console = Console()

def print_banner():
    """Affiche la bannière de SharkScan"""
    banner = """╔════════════════════════════════════════════ SharkScan ════════════════════════════════════════════╗
║                                                                                               ║
║     ███████╗██╗  ██╗ █████╗ ██████╗ ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗                    ║
║     ██╔════╝██║  ██║██╔══██╗██╔══██╗██║ ██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║                    ║
║     ███████╗███████║███████║██████╔╝█████╔╝ █████╗  ██║     ███████║██╔██╗ ██║                    ║
║     ╚════██║██╔══██║██╔══██║██╔══██╗██╔═██╗ ██╔══╝  ██║     ██╔══██║██║╚██╗██║                    ║
║     ███████║██║  ██║██║  ██║██║  ██║██║  ██╗███████╗╚██████╗██║  ██║██║ ╚████║                    ║
║     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝                    ║
║                                                                                                   ║
║     🦈 Professional Network Security Scanner v1.0.0                                            ║
║                                                                                                   ║
╚═════════════════════════════════ Network Security at its Finest ══════════════════════════════════╝"""
    console.print(banner)

def print_modules():
    """Affiche la liste des modules disponibles"""
    modules = Table(title="Modules Disponibles")
    modules.add_column("Module", style="cyan")
    modules.add_column("Description", style="green")
    
    modules.add_row("lateral", "Détection des mouvements latéraux")
    modules.add_row("lorenzini", "Scan de ports avancé")
    modules.add_row("dents", "Évaluation des vulnérabilités")
    modules.add_row("caudale", "Énumération des services")
    modules.add_row("dermoid", "Détection du système d'exploitation")
    modules.add_row("foie", "Cartographie réseau")
    modules.add_row("olfactif", "Analyse du trafic")
    modules.add_row("vision", "Cartographie visuelle")
    
    console.print(modules)

def simulate_scan(module: str, target: str):
    """Simule un scan avec le module spécifié"""
    console.print(f"\n[bold cyan]Démarrage du scan avec le module {module} sur {target}[/bold cyan]")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scan en cours...", total=100)
        
        # Simuler le temps de scan
        for i in range(100):
            time.sleep(0.05)
            progress.update(task, advance=1)
    
    # Résultats simulés selon le module
    if module == "lorenzini":
        results = {
            "ports": [
                {"port": 80, "state": "open", "service": "http"},
                {"port": 443, "state": "open", "service": "https"},
                {"port": 22, "state": "open", "service": "ssh"}
            ]
        }
        display_port_scan(results)
    
    elif module == "dents":
        results = {
            "vulnerabilities": [
                {"severity": "high", "name": "CVE-2023-1234", "description": "Vulnérabilité critique dans Apache"},
                {"severity": "medium", "name": "CVE-2023-5678", "description": "Vulnérabilité dans OpenSSL"}
            ]
        }
        display_vulnerabilities(results)
    
    elif module == "caudale":
        results = {
            "services": [
                {"port": 80, "service": "http", "version": "Apache 2.4.41"},
                {"port": 443, "service": "https", "version": "Nginx 1.18.0"},
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.2p1"}
            ]
        }
        display_services(results)
    
    elif module == "dermoid":
        results = {
            "os": "Linux 5.15.0-56-generic",
            "accuracy": "98%",
            "type": "Linux",
            "vendor": "Ubuntu"
        }
        display_os_detection(results)
    
    elif module == "foie":
        results = {
            "network": {
                "nodes": [
                    {"ip": "192.168.1.1", "type": "router"},
                    {"ip": "192.168.1.2", "type": "server"},
                    {"ip": "192.168.1.3", "type": "workstation"}
                ],
                "services": {
                    "192.168.1.2": [
                        {"port": 80, "service": "http"},
                        {"port": 443, "service": "https"}
                    ]
                }
            }
        }
        display_network_map(results)
    
    elif module == "olfactif":
        results = {
            "traffic": [
                {"protocol": "TCP", "source": "192.168.1.2", "destination": "192.168.1.3", "port": 80},
                {"protocol": "UDP", "source": "192.168.1.3", "destination": "8.8.8.8", "port": 53}
            ]
        }
        display_traffic_analysis(results)
    
    elif module == "vision":
        results = {
            "topology": {
                "nodes": [
                    {"ip": "192.168.1.1", "type": "router", "name": "Gateway"},
                    {"ip": "192.168.1.2", "type": "server", "name": "Web Server"},
                    {"ip": "192.168.1.3", "type": "workstation", "name": "Client"}
                ],
                "connections": [
                    {"source": "192.168.1.1", "target": "192.168.1.2", "type": "lan"},
                    {"source": "192.168.1.1", "target": "192.168.1.3", "type": "lan"}
                ]
            }
        }
        display_visual_map(results)

def display_port_scan(results):
    """Affiche les résultats du scan de ports"""
    table = Table(title="Résultats du Scan de Ports")
    table.add_column("Port", style="cyan")
    table.add_column("État", style="green")
    table.add_column("Service", style="yellow")
    
    for port in results["ports"]:
        table.add_row(
            str(port["port"]),
            port["state"],
            port["service"]
        )
    
    console.print(table)

def display_vulnerabilities(results):
    """Affiche les vulnérabilités détectées"""
    table = Table(title="Vulnérabilités Détectées")
    table.add_column("Sévérité", style="red")
    table.add_column("CVE", style="cyan")
    table.add_column("Description", style="yellow")
    
    for vuln in results["vulnerabilities"]:
        table.add_row(
            vuln["severity"],
            vuln["name"],
            vuln["description"]
        )
    
    console.print(table)

def display_services(results):
    """Affiche les services détectés"""
    table = Table(title="Services Détectés")
    table.add_column("Port", style="cyan")
    table.add_column("Service", style="green")
    table.add_column("Version", style="yellow")
    
    for service in results["services"]:
        table.add_row(
            str(service["port"]),
            service["service"],
            service["version"]
        )
    
    console.print(table)

def display_os_detection(results):
    """Affiche les résultats de la détection d'OS"""
    panel = Panel(
        f"""Système d'exploitation : {results['os']}
Précision : {results['accuracy']}
Type : {results['type']}
Vendeur : {results['vendor']}""",
        title="Détection du Système d'Exploitation",
        border_style="blue"
    )
    console.print(panel)

def display_network_map(results):
    """Affiche la cartographie réseau"""
    tree = Tree("🌐 Topologie du Réseau")
    
    for node in results["network"]["nodes"]:
        node_type = "🖥️" if node["type"] == "server" else "🌐"
        node_tree = tree.add(f"{node_type} {node['ip']}")
        
        if node["ip"] in results["network"]["services"]:
            services_tree = node_tree.add("🔌 Services")
            for service in results["network"]["services"][node["ip"]]:
                services_tree.add(f"Port {service['port']}: {service['service']}")
    
    console.print(tree)

def display_traffic_analysis(results):
    """Affiche l'analyse du trafic"""
    table = Table(title="Analyse du Trafic")
    table.add_column("Protocole", style="cyan")
    table.add_column("Source", style="green")
    table.add_column("Destination", style="yellow")
    table.add_column("Port", style="magenta")
    
    for traffic in results["traffic"]:
        table.add_row(
            traffic["protocol"],
            traffic["source"],
            traffic["destination"],
            str(traffic["port"])
        )
    
    console.print(table)

def display_visual_map(results):
    """Affiche la cartographie visuelle"""
    tree = Tree("🌐 Topologie du Réseau")
    
    for node in results["topology"]["nodes"]:
        node_type = "🖥️" if node["type"] == "server" else "🌐"
        node_tree = tree.add(f"{node_type} {node['name']} ({node['ip']})")
    
    console.print(tree)
    
    table = Table(title="Connexions")
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="green")
    table.add_column("Type", style="yellow")
    
    for conn in results["topology"]["connections"]:
        table.add_row(
            conn["source"],
            conn["target"],
            conn["type"]
        )
    
    console.print(table)

def main():
    """Fonction principale"""
    print_banner()
    print_modules()
    
    if len(sys.argv) < 3:
        console.print("[red]Usage: python demo.py <module> <target>[/red]")
        console.print("Exemple: python demo.py lorenzini example.com")
        sys.exit(1)
    
    module = sys.argv[1]
    target = sys.argv[2]
    
    simulate_scan(module, target)

if __name__ == "__main__":
    main() 