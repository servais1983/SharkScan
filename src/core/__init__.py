"""
Core functionality for SharkScan
"""

from .scanner import BaseScanner, ScannerFactory
from .utils import validate_target, check_privileges

__all__ = ['BaseScanner', 'ScannerFactory', 'validate_target', 'check_privileges']