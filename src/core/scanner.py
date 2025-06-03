"""
Base scanner classes and factory
"""

from abc import ABC, abstractmethod
import logging
from typing import Dict, Any, Optional
from rich.console import Console

logger = logging.getLogger(__name__)
console = Console()


class BaseScanner(ABC):
    """Abstract base class for all scanner modules"""
    
    def __init__(self, args):
        self.args = args
        self.logger = logging.getLogger(self.__class__.__name__)
        
    @abstractmethod
    def scan(self, target: str) -> Dict[str, Any]:
        """Execute the scan on the target"""
        pass
    
    @abstractmethod
    def display_results(self, results: Dict[str, Any]) -> None:
        """Display scan results in a formatted way"""
        pass
    
    def validate_options(self) -> bool:
        """Validate module-specific options"""
        return True


class Scanner(BaseScanner):
    """Main scanner class for SharkScan"""
    
    def __init__(self, args):
        super().__init__(args)
        self.results = {}
        
    def scan(self, target: str) -> Dict[str, Any]:
        """Execute the scan on the target"""
        self.logger.info(f"Starting scan on target: {target}")
        # Implement basic scanning logic here
        self.results = {
            'target': target,
            'status': 'completed',
            'findings': []
        }
        return self.results
    
    def display_results(self, results: Dict[str, Any]) -> None:
        """Display scan results in a formatted way"""
        console.print(f"\n[bold blue]Scan Results for {results['target']}[/bold blue]")
        console.print(f"Status: {results['status']}")
        if results['findings']:
            console.print("\n[bold]Findings:[/bold]")
            for finding in results['findings']:
                console.print(f"- {finding}")


class ScannerFactory:
    """Factory class to create scanner instances"""
    
    @staticmethod
    def create_scanner(module: str, args) -> BaseScanner:
        """Create and return appropriate scanner instance"""
        
        # Import modules dynamically to avoid circular imports
        if module == 'lateral':
            from src.modules.lateral_line import LateralLineScanner
            return LateralLineScanner(args)
        
        elif module == 'lorenzini':
            from src.modules.lorenzini import LorenziniScanner
            return LorenziniScanner(args)
        
        elif module == 'dents':
            from src.modules.teeth import TeethScanner
            return TeethScanner(args)
        
        elif module == 'caudale':
            from src.modules.caudal_fin import CaudalFinScanner
            return CaudalFinScanner(args)
        
        elif module == 'dermoid':
            from src.modules.dermoid import DermoidScanner
            return DermoidScanner(args)
        
        elif module == 'foie':
            from src.modules.foie import FoieScanner
            return FoieScanner(args)
        
        elif module == 'olfactif':
            from src.modules.olfactory import OlfactoryScanner
            return OlfactoryScanner(args)
        
        elif module == 'vision':
            from src.modules.vision import VisionScanner
            return VisionScanner(args)
        
        else:
            raise ValueError(f"Unknown module: {module}")