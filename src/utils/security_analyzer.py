"""
Security log analyzer for SharkScan
"""

from datetime import datetime, timedelta
from collections import defaultdict
from rich.console import Console
from rich.table import Table
from rich import box
from .log_reader import LogReader

class SecurityAnalyzer:
    """Analyze security logs for patterns and anomalies"""
    
    def __init__(self, log_dir="logs"):
        """
        Initialize security analyzer
        
        Args:
            log_dir (str): Log directory
        """
        self.log_reader = LogReader(log_dir)
        self.console = Console()
        
    def analyze_timeframe(self, log_file, hours=24):
        """
        Analyze security events in a timeframe
        
        Args:
            log_file (str): Log file name
            hours (int): Hours to analyze
        """
        events = self.log_reader.get_security_events(log_file)
        cutoff = datetime.now() - timedelta(hours=hours)
        
        # Filter events by time
        recent_events = [
            e for e in events 
            if datetime.fromisoformat(e['timestamp']) > cutoff
        ]
        
        # Group by event type
        event_counts = defaultdict(int)
        for event in recent_events:
            event_counts[event['event_type']] += 1
            
        # Display results
        table = Table(title=f"Security Events (Last {hours} hours)", box=box.ROUNDED)
        table.add_column("Event Type", style="cyan")
        table.add_column("Count", style="green")
        table.add_column("Severity", style="yellow")
        
        for event_type, count in event_counts.items():
            severity = next(
                (e['level'] for e in recent_events if e['event_type'] == event_type),
                "INFO"
            )
            table.add_row(event_type, str(count), severity)
            
        self.console.print(table)
        
    def analyze_targets(self, log_file):
        """
        Analyze scan targets
        
        Args:
            log_file (str): Log file name
        """
        events = self.log_reader.get_security_events(log_file)
        target_stats = defaultdict(lambda: {'count': 0, 'modules': set()})
        
        for event in events:
            if event['event_type'] == 'scan_started':
                target = event['details']['target']
                module = event['details']['module']
                target_stats[target]['count'] += 1
                target_stats[target]['modules'].add(module)
                
        # Display results
        table = Table(title="Target Analysis", box=box.ROUNDED)
        table.add_column("Target", style="cyan")
        table.add_column("Scan Count", style="green")
        table.add_column("Modules Used", style="yellow")
        
        for target, stats in target_stats.items():
            table.add_row(
                target,
                str(stats['count']),
                ', '.join(stats['modules'])
            )
            
        self.console.print(table)
        
    def find_anomalies(self, log_file):
        """
        Find security anomalies
        
        Args:
            log_file (str): Log file name
        """
        events = self.log_reader.get_security_events(log_file)
        anomalies = []
        
        # Check for rapid successive scans
        scan_times = [
            datetime.fromisoformat(e['timestamp'])
            for e in events
            if e['event_type'] == 'scan_started'
        ]
        
        for i in range(1, len(scan_times)):
            if (scan_times[i] - scan_times[i-1]) < timedelta(seconds=5):
                anomalies.append({
                    'type': 'rapid_scan',
                    'timestamp': scan_times[i].isoformat(),
                    'details': 'Rapid successive scans detected'
                })
                
        # Check for multiple failed scans
        failed_scans = [
            e for e in events
            if e['event_type'] == 'scan_error'
        ]
        
        if len(failed_scans) > 3:
            anomalies.append({
                'type': 'multiple_failures',
                'count': len(failed_scans),
                'details': 'Multiple scan failures detected'
            })
            
        # Display results
        if anomalies:
            table = Table(title="Security Anomalies", box=box.ROUNDED)
            table.add_column("Type", style="red")
            table.add_column("Details", style="yellow")
            table.add_column("Timestamp", style="cyan")
            
            for anomaly in anomalies:
                table.add_row(
                    anomaly['type'],
                    anomaly['details'],
                    anomaly.get('timestamp', 'N/A')
                )
                
            self.console.print(table)
        else:
            self.console.print("[green]No security anomalies detected[/green]") 