"""
Intrusion Detection System (IDS) for SharkScan
"""

import re
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional
from .secure_logger import SecureLogger

class IDS:
    """Intrusion Detection System for SharkScan"""
    
    def __init__(self, log_dir: str = "logs"):
        """
        Initialize IDS
        
        Args:
            log_dir (str): Log directory
        """
        self.logger = SecureLogger("ids", log_dir)
        self.patterns = self._load_patterns()
        self.alert_threshold = 3
        self.time_window = 300  # 5 minutes
        
    def _load_patterns(self) -> Dict[str, List[re.Pattern]]:
        """Load detection patterns"""
        return {
            'port_scan': [
                re.compile(r'port\s+(\d+)\s+is\s+open', re.I),
                re.compile(r'scanning\s+(\d+)\s+ports', re.I)
            ],
            'brute_force': [
                re.compile(r'failed\s+login\s+attempt', re.I),
                re.compile(r'authentication\s+failed', re.I)
            ],
            'suspicious_activity': [
                re.compile(r'root\s+access\s+attempt', re.I),
                re.compile(r'privilege\s+escalation', re.I),
                re.compile(r'exploit\s+attempt', re.I)
            ]
        }
        
    def analyze_log(self, log_content: str) -> List[Dict]:
        """
        Analyze log content for suspicious activity
        
        Args:
            log_content (str): Log content to analyze
            
        Returns:
            List[Dict]: List of detected incidents
        """
        incidents = []
        event_counts = defaultdict(int)
        
        for line in log_content.split('\n'):
            timestamp = self._extract_timestamp(line)
            if not timestamp:
                continue
                
            for category, patterns in self.patterns.items():
                for pattern in patterns:
                    if pattern.search(line):
                        event_counts[category] += 1
                        if event_counts[category] >= self.alert_threshold:
                            incidents.append({
                                'timestamp': timestamp,
                                'category': category,
                                'pattern': pattern.pattern,
                                'line': line.strip(),
                                'count': event_counts[category]
                            })
                            
        return incidents
        
    def _extract_timestamp(self, line: str) -> Optional[str]:
        """Extract timestamp from log line"""
        try:
            # Common timestamp formats
            patterns = [
                r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
                r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})',
                r'(\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    return match.group(1)
                    
            return None
        except Exception:
            return None
            
    def monitor_activity(self, log_file: str) -> None:
        """
        Monitor log file for suspicious activity
        
        Args:
            log_file (str): Log file to monitor
        """
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                
            incidents = self.analyze_log(content)
            
            if incidents:
                self.logger.security_event(
                    "ids_alert",
                    {
                        "incidents": incidents,
                        "log_file": log_file
                    },
                    severity="WARNING"
                )
                
                # Log detailed incident information
                for incident in incidents:
                    self.logger.warning(
                        f"IDS Alert: {incident['category']}",
                        details={
                            "pattern": incident['pattern'],
                            "count": incident['count'],
                            "timestamp": incident['timestamp']
                        }
                    )
                    
        except Exception as e:
            self.logger.error(f"Error monitoring log file: {str(e)}")
            
    def get_incident_report(self, log_file: str) -> Dict:
        """
        Generate incident report
        
        Args:
            log_file (str): Log file to analyze
            
        Returns:
            Dict: Incident report
        """
        try:
            with open(log_file, 'r') as f:
                content = f.read()
                
            incidents = self.analyze_log(content)
            
            report = {
                'timestamp': datetime.now().isoformat(),
                'log_file': log_file,
                'total_incidents': len(incidents),
                'incidents_by_category': defaultdict(int),
                'details': []
            }
            
            for incident in incidents:
                report['incidents_by_category'][incident['category']] += 1
                report['details'].append({
                    'type': incident['category'],
                    'timestamp': incident['timestamp'],
                    'count': incident['count'],
                    'description': incident['pattern'],
                    'severity': 'HIGH' if incident['count'] > 5 else 'MEDIUM'
                })
                
            return report
            
        except Exception as e:
            self.logger.error(f"Error generating incident report: {str(e)}")
            return {
                'timestamp': datetime.now().isoformat(),
                'log_file': log_file,
                'total_incidents': 0,
                'incidents_by_category': defaultdict(int),
                'details': []
            } 