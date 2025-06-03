"""
Tests for the Intrusion Detection System
"""

import pytest
import os
import tempfile
from datetime import datetime
from src.core.ids import IDS

@pytest.fixture
def temp_log_dir():
    """Create temporary log directory"""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir

@pytest.fixture
def ids_instance(temp_log_dir):
    """Create IDS instance"""
    return IDS(log_dir=temp_log_dir)

def test_initialize_ids(ids_instance):
    """Test IDS initialization"""
    assert ids_instance.alert_threshold == 3
    assert ids_instance.time_window == 300
    assert 'port_scan' in ids_instance.patterns
    assert 'brute_force' in ids_instance.patterns
    assert 'suspicious_activity' in ids_instance.patterns

def test_extract_timestamp():
    """Test timestamp extraction"""
    ids = IDS()
    
    # Test different timestamp formats
    test_cases = [
        ("2024-03-20 14:30:00 Some log message", "2024-03-20 14:30:00"),
        ("03/20/2024 14:30:00 Another log", "03/20/2024 14:30:00"),
        ("20-03-2024 14:30:00 Third log", "20-03-2024 14:30:00"),
        ("Invalid timestamp log", None)
    ]
    
    for log_line, expected in test_cases:
        assert ids._extract_timestamp(log_line) == expected

def test_analyze_log(ids_instance, temp_log_dir):
    """Test log analysis"""
    # Create test log file
    log_file = os.path.join(temp_log_dir, "test.log")
    with open(log_file, 'w') as f:
        f.write("""2024-03-20 14:30:00 Scanning 1000 ports
2024-03-20 14:30:01 Port 80 is open
2024-03-20 14:30:02 Port 443 is open
2024-03-20 14:30:03 Failed login attempt
2024-03-20 14:30:04 Authentication failed
2024-03-20 14:30:05 Root access attempt
2024-03-20 14:30:06 Privilege escalation detected""")
    
    # Analyze log
    with open(log_file, 'r') as f:
        content = f.read()
    incidents = ids_instance.analyze_log(content)
    
    # Verify results
    assert len(incidents) > 0
    assert any(inc['category'] == 'port_scan' for inc in incidents)
    assert any(inc['category'] == 'brute_force' for inc in incidents)
    assert any(inc['category'] == 'suspicious_activity' for inc in incidents)

def test_monitor_activity(ids_instance, temp_log_dir):
    """Test activity monitoring"""
    # Create test log file
    log_file = os.path.join(temp_log_dir, "monitor.log")
    with open(log_file, 'w') as f:
        f.write("""2024-03-20 14:30:00 Scanning 1000 ports
2024-03-20 14:30:01 Port 80 is open
2024-03-20 14:30:02 Port 443 is open
2024-03-20 14:30:03 Failed login attempt
2024-03-20 14:30:04 Authentication failed
2024-03-20 14:30:05 Root access attempt""")
    
    # Monitor activity
    ids_instance.monitor_activity(log_file)
    
    # Verify log file was created
    log_files = os.listdir(temp_log_dir)
    assert any(f.startswith("ids_") for f in log_files)

def test_incident_report(ids_instance, temp_log_dir):
    """Test incident report generation"""
    # Create test log file
    log_file = os.path.join(temp_log_dir, "report.log")
    with open(log_file, 'w') as f:
        f.write("""2024-03-20 14:30:00 Scanning 1000 ports
2024-03-20 14:30:01 Port 80 is open
2024-03-20 14:30:02 Port 443 is open
2024-03-20 14:30:03 Failed login attempt
2024-03-20 14:30:04 Authentication failed
2024-03-20 14:30:05 Root access attempt""")
    
    # Generate report
    report = ids_instance.get_incident_report(log_file)
    
    # Verify report structure
    assert 'timestamp' in report
    assert 'log_file' in report
    assert 'total_incidents' in report
    assert 'incidents_by_category' in report
    assert 'details' in report
    assert report['log_file'] == log_file
    assert report['total_incidents'] > 0 