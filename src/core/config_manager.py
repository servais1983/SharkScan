"""
Advanced configuration manager for SharkScan
"""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass
from src.core.secure_logger import SecureLogger

try:
    import yaml
except ImportError:
    yaml = None

@dataclass
class ScanConfig:
    """Scan configuration"""
    target: str
    ports: list
    protocol: str = 'tcp'
    timeout: float = 5.0
    retries: int = 2
    delay: float = 0.0
    threads: int = 50
    use_processes: bool = False

@dataclass
class SecurityConfig:
    """Security configuration"""
    enable_ids: bool = True
    enable_vuln_scan: bool = True
    alert_threshold: int = 5
    risk_threshold: int = 10
    log_level: str = 'INFO'
    encrypt_logs: bool = True

@dataclass
class OutputConfig:
    """Output configuration"""
    save_results: bool = True
    output_format: str = 'json'
    output_dir: str = 'results'
    generate_report: bool = True
    report_format: str = 'html'
    verbose: bool = False

class ConfigManager:
    """Advanced configuration manager"""
    
    def __init__(self, config_dir: str = "config"):
        """
        Initialize configuration manager
        
        Args:
            config_dir (str): Configuration directory
        """
        self.logger = SecureLogger("config_manager")
        self.config_dir = config_dir
        self.current_profile = "default"
        self.config = self._load_default_config()
        self._setup_config_dir()
        
    def _setup_config_dir(self):
        """Setup configuration directory"""
        try:
            os.makedirs(self.config_dir, exist_ok=True)
            self._create_default_profiles()
        except Exception as e:
            self.logger.error(f"Error setting up config directory: {str(e)}")
            
    def _create_default_profiles(self):
        """Create default configuration profiles"""
        profiles = {
            "default": {
                "scan": {
                    "target": "",
                    "ports": [20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389],
                    "protocol": "tcp",
                    "timeout": 5.0,
                    "retries": 2,
                    "delay": 0.0,
                    "threads": 50,
                    "use_processes": False
                },
                "security": {
                    "enable_ids": True,
                    "enable_vuln_scan": True,
                    "alert_threshold": 5,
                    "risk_threshold": 10,
                    "log_level": "INFO",
                    "encrypt_logs": True
                },
                "output": {
                    "save_results": True,
                    "output_format": "json",
                    "output_dir": "results",
                    "generate_report": True,
                    "report_format": "html",
                    "verbose": False
                }
            },
            "aggressive": {
                "scan": {
                    "target": "",
                    "ports": list(range(1, 1025)),
                    "protocol": "tcp",
                    "timeout": 3.0,
                    "retries": 1,
                    "delay": 0.0,
                    "threads": 100,
                    "use_processes": True
                },
                "security": {
                    "enable_ids": True,
                    "enable_vuln_scan": True,
                    "alert_threshold": 10,
                    "risk_threshold": 15,
                    "log_level": "DEBUG",
                    "encrypt_logs": True
                },
                "output": {
                    "save_results": True,
                    "output_format": "json",
                    "output_dir": "results",
                    "generate_report": True,
                    "report_format": "html",
                    "verbose": True
                }
            },
            "stealth": {
                "scan": {
                    "target": "",
                    "ports": [80, 443, 8080, 8443],
                    "protocol": "tcp",
                    "timeout": 10.0,
                    "retries": 3,
                    "delay": 1.0,
                    "threads": 20,
                    "use_processes": False
                },
                "security": {
                    "enable_ids": True,
                    "enable_vuln_scan": False,
                    "alert_threshold": 3,
                    "risk_threshold": 5,
                    "log_level": "WARNING",
                    "encrypt_logs": True
                },
                "output": {
                    "save_results": True,
                    "output_format": "json",
                    "output_dir": "results",
                    "generate_report": True,
                    "report_format": "html",
                    "verbose": False
                }
            }
        }
        
        for profile, config in profiles.items():
            self.save_profile(profile, config)
            
    def _load_default_config(self) -> Dict:
        """Load default configuration"""
        return {
            "scan": ScanConfig(
                target="",
                ports=[20, 21, 22, 23, 25, 53, 80, 443, 3306, 3389],
                protocol="tcp",
                timeout=5.0,
                retries=2,
                delay=0.0,
                threads=50,
                use_processes=False
            ),
            "security": SecurityConfig(),
            "output": OutputConfig()
        }
        
    def load_profile(self, profile_name: str) -> bool:
        """
        Load configuration profile
        
        Args:
            profile_name (str): Profile name
            
        Returns:
            bool: True if successful
        """
        try:
            profile_file = os.path.join(self.config_dir, f"{profile_name}.json")
            if not os.path.exists(profile_file):
                self.logger.warning(f"Profile {profile_name} not found")
                return False
                
            with open(profile_file, 'r') as f:
                profile_config = json.load(f)
                
            # Update configuration
            self.config["scan"] = ScanConfig(**profile_config["scan"])
            self.config["security"] = SecurityConfig(**profile_config["security"])
            self.config["output"] = OutputConfig(**profile_config["output"])
            self.current_profile = profile_name
            
            self.logger.info(f"Loaded profile: {profile_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading profile: {str(e)}")
            return False
            
    def save_profile(self, profile_name: str, config: Dict) -> bool:
        """
        Save configuration profile
        
        Args:
            profile_name (str): Profile name
            config (Dict): Configuration to save
            
        Returns:
            bool: True if successful
        """
        try:
            profile_file = os.path.join(self.config_dir, f"{profile_name}.json")
            with open(profile_file, 'w') as f:
                json.dump(config, f, indent=2)
                
            self.logger.info(f"Saved profile: {profile_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error saving profile: {str(e)}")
            return False
            
    def get_config(self) -> Dict:
        """
        Get current configuration
        
        Returns:
            Dict: Current configuration
        """
        return {
            "scan": self.config["scan"].__dict__,
            "security": self.config["security"].__dict__,
            "output": self.config["output"].__dict__
        }
        
    def update_config(self, section: str, key: str, value: Any) -> bool:
        """
        Update configuration value
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            value (Any): New value
            
        Returns:
            bool: True if successful
        """
        try:
            if section not in self.config:
                self.logger.warning(f"Invalid section: {section}")
                return False
                
            if not hasattr(self.config[section], key):
                self.logger.warning(f"Invalid key: {key}")
                return False
                
            setattr(self.config[section], key, value)
            self.logger.info(f"Updated {section}.{key} = {value}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating config: {str(e)}")
            return False
            
    def export_config(self, format: str = "json") -> Optional[str]:
        """
        Export configuration to string
        
        Args:
            format (str): Output format (json or yaml)
            
        Returns:
            Optional[str]: Configuration string
        """
        try:
            config_dict = {
                "scan": self.config["scan"].__dict__,
                "security": self.config["security"].__dict__,
                "output": self.config["output"].__dict__
            }
            
            if format.lower() == "yaml":
                if yaml is None:
                    self.logger.warning("YAML module not available, falling back to JSON")
                    return json.dumps(config_dict, indent=4)
                return yaml.dump(config_dict, default_flow_style=False)
            else:
                return json.dumps(config_dict, indent=4)
                
        except Exception as e:
            self.logger.error(f"Error exporting config: {str(e)}")
            return None
            
    def import_config(self, config_str: str, format: str = "json") -> bool:
        """
        Import configuration from string
        
        Args:
            config_str (str): Configuration string
            format (str): Input format (json or yaml)
            
        Returns:
            bool: True if successful
        """
        try:
            if format.lower() == "yaml":
                if yaml is None:
                    self.logger.warning("YAML module not available, falling back to JSON")
                    config_dict = json.loads(config_str)
                else:
                    config_dict = yaml.safe_load(config_str)
            else:
                config_dict = json.loads(config_str)
                
            # Update configuration
            self.config["scan"] = ScanConfig(**config_dict["scan"])
            self.config["security"] = SecurityConfig(**config_dict["security"])
            self.config["output"] = OutputConfig(**config_dict["output"])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error importing config: {str(e)}")
            return False 