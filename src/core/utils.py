"""
Core utility functions
"""

import re
import os
import socket
import ipaddress
import validators
from typing import Union, List, Tuple


def validate_target(target: str) -> bool:
    """Validate target format (IP, domain, CIDR)"""
    # Check if it's a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid CIDR network
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    
    # Check if it's a valid domain
    if validators.domain(target):
        return True
    
    # Check if it's a valid email (for olfactory module)
    if validators.email(target):
        return True
    
    # Check if it's a valid hostname
    if re.match(r'^[a-zA-Z0-9.-]+$', target):
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            pass
    
    return False


def check_privileges() -> bool:
    """Check if running with root privileges"""
    return os.geteuid() == 0


def parse_ports(port_string: str) -> List[int]:
    """Parse port string into list of integers"""
    ports = []
    
    if not port_string:
        return ports
    
    for part in port_string.split(','):
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(set(ports))


def resolve_target(target: str) -> str:
    """Resolve hostname to IP address"""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


def get_network_hosts(cidr: str) -> List[str]:
    """Get all host IPs from CIDR notation"""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        # Skip network and broadcast addresses
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        return []


def format_mac(mac: str) -> str:
    """Format MAC address"""
    # Remove any existing separators
    mac = re.sub('[.:-]', '', mac).upper()
    # Add colons every 2 characters
    return ':'.join(mac[i:i+2] for i in range(0, len(mac), 2))


def get_service_name(port: int, protocol: str = 'tcp') -> str:
    """Get service name for a port"""
    try:
        return socket.getservbyport(port, protocol)
    except OSError:
        # Common services not in /etc/services
        common_services = {
            8080: 'http-alt',
            8443: 'https-alt',
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis',
            27017: 'mongodb',
            9200: 'elasticsearch'
        }
        return common_services.get(port, 'unknown')


def is_private_ip(ip: str) -> bool:
    """Check if IP is private"""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False