"""
Logger configuration for SharkScan
"""

import logging
import sys
import json
from datetime import datetime

class JsonFormatter(logging.Formatter):
    """Custom JSON formatter for logs"""
    def format(self, record):
        log_obj = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.getMessage()
        }
        if record.exc_info:
            log_obj["exception"] = self.formatException(record.exc_info)
        return json.dumps(log_obj)

def setup_logger(name, verbose=False):
    """
    Configure and return a logger instance
    
    Args:
        name (str): Name of the logger
        verbose (bool): Enable verbose logging if True
        
    Returns:
        logging.Logger: Configured logger instance
    """
    logger = logging.getLogger(name)
    
    # Set log level based on verbose flag
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)
    
    # Create handlers
    console_handler = logging.StreamHandler(sys.stdout)
    file_handler = logging.FileHandler(f"logs/{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    json_formatter = JsonFormatter()
    
    # Set formatters
    console_handler.setFormatter(console_formatter)
    file_handler.setFormatter(json_formatter)
    
    # Add handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    
    return logger 