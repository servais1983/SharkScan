import pytest
from src.core.scanner import ScannerFactory
from src.core.utils import validate_target

def test_validate_target():
    """Test target validation"""
    assert validate_target("192.168.1.1") == True
    assert validate_target("example.com") == True
    assert validate_target("192.168.1.0/24") == True
    assert validate_target("invalid!@#") == False

def test_scanner_factory():
    """Test scanner factory"""
    scanner = ScannerFactory.create_scanner("lorenzini", None)
    assert scanner is not None
    assert scanner.__class__.__name__ == "LorenziniScanner"

def test_privilege_check():
    """Test privilege checking"""
    with pytest.raises(PermissionError):
        ScannerFactory.create_scanner("lateral", None) 