"""
Secure logging system for SharkScan
"""

import logging
import os
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler
from cryptography.fernet import Fernet
from pathlib import Path

class SecureLogger:
    """Secure logging system with encryption and rotation"""
    
    def __init__(self, name, log_dir="logs", max_bytes=10*1024*1024, backup_count=5):
        """
        Initialize secure logger
        
        Args:
            name (str): Logger name
            log_dir (str): Log directory
            max_bytes (int): Maximum bytes per log file
            backup_count (int): Number of backup files to keep
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Generate encryption key if not exists
        self.key_file = self.log_dir / ".key"
        if not self.key_file.exists():
            self.key = Fernet.generate_key()
            with open(self.key_file, 'wb') as f:
                f.write(self.key)
        else:
            with open(self.key_file, 'rb') as f:
                self.key = f.read()
        
        self.fernet = Fernet(self.key)
        
        # Setup logger
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.INFO)
        
        # Create handlers
        self._setup_handlers(max_bytes, backup_count)
        
    def _setup_handlers(self, max_bytes, backup_count):
        """Setup logging handlers"""
        # Encrypted file handler
        encrypted_handler = RotatingFileHandler(
            self.log_dir / f"{self.name}_encrypted.log",
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        encrypted_handler.setFormatter(logging.Formatter('%(message)s'))
        
        # Console handler (non-encrypted)
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        )
        
        self.logger.addHandler(encrypted_handler)
        self.logger.addHandler(console_handler)
        
    def _encrypt_log(self, log_data):
        """Encrypt log data"""
        return self.fernet.encrypt(json.dumps(log_data).encode())
    
    def info(self, message, **kwargs):
        """Log info message"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": "INFO",
            "message": message,
            **kwargs
        }
        self.logger.info(self._encrypt_log(log_data))
        
    def warning(self, message, **kwargs):
        """Log warning message"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": "WARNING",
            "message": message,
            **kwargs
        }
        self.logger.warning(self._encrypt_log(log_data))
        
    def error(self, message, **kwargs):
        """Log error message"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": "ERROR",
            "message": message,
            **kwargs
        }
        self.logger.error(self._encrypt_log(log_data))
        
    def critical(self, message, **kwargs):
        """Log critical message"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": "CRITICAL",
            "message": message,
            **kwargs
        }
        self.logger.critical(self._encrypt_log(log_data))
        
    def debug(self, message, **kwargs):
        """Log debug message"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": "DEBUG",
            "message": message,
            **kwargs
        }
        self.logger.debug(self._encrypt_log(log_data))
        
    def security_event(self, event_type, details, severity="INFO"):
        """Log security event"""
        log_data = {
            "timestamp": datetime.now().isoformat(),
            "level": severity,
            "event_type": event_type,
            "details": details,
            "security_event": True
        }
        self.logger.info(self._encrypt_log(log_data))
        
    def get_current_log_file(self) -> str:
        """Get the current log file path"""
        return str(self.log_dir / f"{self.name}_encrypted.log") 