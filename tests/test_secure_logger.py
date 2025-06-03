import pytest
import os
from pathlib import Path
from src.core.secure_logger import SecureLogger
from src.utils.log_reader import LogReader

@pytest.fixture
def temp_log_dir(tmp_path):
    """Create temporary log directory"""
    return tmp_path / "logs"

@pytest.fixture
def logger(temp_log_dir):
    """Create logger instance"""
    return SecureLogger("test_logger", log_dir=str(temp_log_dir))

@pytest.fixture
def log_reader(temp_log_dir):
    """Create log reader instance"""
    return LogReader(log_dir=str(temp_log_dir))

def test_logger_initialization(logger, temp_log_dir):
    """Test logger initialization"""
    assert logger.log_dir.exists()
    assert (temp_log_dir / ".key").exists()
    assert (temp_log_dir / "test_logger_encrypted.log").exists()

def test_log_encryption(logger, log_reader):
    """Test log encryption and decryption"""
    test_message = "Test log message"
    logger.info(test_message, test_field="test_value")
    
    logs = log_reader.read_log("test_logger_encrypted.log")
    assert len(logs) == 1
    assert logs[0]["message"] == test_message
    assert logs[0]["test_field"] == "test_value"

def test_security_event(logger, log_reader):
    """Test security event logging"""
    event_type = "scan_started"
    details = {"target": "192.168.1.1", "module": "lorenzini"}
    
    logger.security_event(event_type, details, severity="INFO")
    
    events = log_reader.get_security_events("test_logger_encrypted.log")
    assert len(events) == 1
    assert events[0]["event_type"] == event_type
    assert events[0]["details"] == details

def test_log_rotation(logger, temp_log_dir):
    """Test log rotation"""
    # Write enough data to trigger rotation
    for i in range(1000):
        logger.info("x" * 1000)
    
    log_files = list(temp_log_dir.glob("test_logger_encrypted.log*"))
    assert len(log_files) > 1  # Should have rotated at least once 