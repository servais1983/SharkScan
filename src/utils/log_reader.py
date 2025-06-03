"""
Utility to read encrypted logs
"""

import json
from pathlib import Path
from cryptography.fernet import Fernet

class LogReader:
    """Utility to read encrypted logs"""
    
    def __init__(self, log_dir="logs"):
        """
        Initialize log reader
        
        Args:
            log_dir (str): Log directory
        """
        self.log_dir = Path(log_dir)
        self.key_file = self.log_dir / ".key"
        
        if not self.key_file.exists():
            raise FileNotFoundError("Encryption key not found")
            
        with open(self.key_file, 'rb') as f:
            self.key = f.read()
            
        self.fernet = Fernet(self.key)
        
    def read_log(self, log_file):
        """
        Read and decrypt log file
        
        Args:
            log_file (str): Log file name
            
        Returns:
            list: List of decrypted log entries
        """
        log_path = self.log_dir / log_file
        if not log_path.exists():
            raise FileNotFoundError(f"Log file not found: {log_file}")
            
        decrypted_logs = []
        with open(log_path, 'rb') as f:
            for line in f:
                try:
                    decrypted = self.fernet.decrypt(line.strip())
                    log_entry = json.loads(decrypted)
                    decrypted_logs.append(log_entry)
                except Exception as e:
                    print(f"Error decrypting log entry: {e}")
                    
        return decrypted_logs
        
    def search_logs(self, log_file, **criteria):
        """
        Search logs by criteria
        
        Args:
            log_file (str): Log file name
            **criteria: Search criteria (key=value)
            
        Returns:
            list: Matching log entries
        """
        logs = self.read_log(log_file)
        matches = []
        
        for log in logs:
            if all(log.get(k) == v for k, v in criteria.items()):
                matches.append(log)
                
        return matches
        
    def get_security_events(self, log_file, severity=None):
        """
        Get security events from logs
        
        Args:
            log_file (str): Log file name
            severity (str, optional): Filter by severity
            
        Returns:
            list: Security events
        """
        logs = self.read_log(log_file)
        events = [log for log in logs if log.get('security_event')]
        
        if severity:
            events = [e for e in events if e.get('level') == severity]
            
        return events 