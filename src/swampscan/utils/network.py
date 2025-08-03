"""
Network Utilities

This module provides utilities for handling IP addresses, network ranges,
port specifications, and other network-related operations.
"""

import ipaddress
import socket
import re
import logging
from typing import List, Set, Tuple, Union, Iterator, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class NetworkTarget:
    """Represents a network target for scanning."""
    
    def __init__(self, target: str, resolved_ips: List[str] = None):
        """
        Initialize a network target.
        
        Args:
            target: Original target specification (IP, hostname, CIDR)
            resolved_ips: List of resolved IP addresses
        """
        self.original = target
        self.resolved_ips = resolved_ips or []
        self.target_type = self._determine_type(target)
    
    def _determine_type(self, target: str) -> str:
        """Determine the type of target specification."""
        try:
            ipaddress.ip_address(target)
            return "ip"
        except ValueError:
            pass
        
        try:
            ipaddress.ip_network(target, strict=False)
            return "cidr"
        except ValueError:
            pass
        
        # Check if it looks like a hostname
        if re.match(r'^[a-zA-Z0-9.-]+$', target):
            return "hostname"
        
        return "unknown"
    
    def __str__(self):
        return f"NetworkTarget({self.original}, type={self.target_type}, ips={len(self.resolved_ips)})"
    
    def __repr__(self):
        return self.__str__()


class PortSpecification:
    """Represents a port specification for scanning."""
    
    def __init__(self, spec: str):
        """
        Initialize port specification.
        
        Args:
            spec: Port specification string (e.g., "80,443", "1-1000", "all")
        """
        self.original = spec
        self.ports = self._parse_ports(spec)
    
    def _parse_ports(self, spec: str) -> Set[int]:
        """Parse port specification into a set of port numbers."""
        ports = set()
        
        if spec.lower() in ['all', '*']:
            # All ports (1-65535)
            return set(range(1, 65536))
        
        # Split by commas for multiple specifications
        parts = [part.strip() for part in spec.split(',')]
        
        for part in parts:
            if '-' in part:
                # Port range
                try:
                    start, end = part.split('-', 1)
                    start_port = int(start.strip())
                    end_port = int(end.strip())
                    
                    if start_port < 1 or end_port > 65535 or start_port > end_port:
                        raise ValueError(f"Invalid port range: {part}")
                    
                    ports.update(range(start_port, end_port + 1))
                except ValueError as e:
                    logger.warning(f"Invalid port range '{part}': {e}")
            else:
                # Single port
                try:
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port out of range: {port}")
                    ports.add(port)
                except ValueError as e:
                    logger.warning(f"Invalid port '{part}': {e}")
        
        return ports
    
    def get_port_list(self) -> List[int]:
        """Get sorted list of ports."""
        return sorted(self.ports)
    
    def get_port_ranges(self) -> List[Tuple[int, int]]:
        """Get list of port ranges for efficient representation."""
        if not self.ports:
            return []
        
        sorted_ports = sorted(self.ports)
        ranges = []
        start = sorted_ports[0]
        end = start
        
        for port in sorted_ports[1:]:
            if port == end + 1:
                end = port
            else:
                ranges.append((start, end))
                start = end = port
        
        ranges.append((start, end))
        return ranges
    
    def __str__(self):
        if len(self.ports) == 65535:
            return "all ports"
        elif len(self.ports) <= 10:
            return f"ports {','.join(map(str, sorted(self.ports)))}"
        else:
            ranges = self.get_port_ranges()
            if len(ranges) <= 5:
                range_strs = []
                for start, end in ranges:
                    if start == end:
                        range_strs.append(str(start))
                    else:
                        range_strs.append(f"{start}-{end}")
                return f"ports {','.join(range_strs)}"
            else:
                return f"{len(self.ports)} ports"


class NetworkUtils:
    """Utility functions for network operations."""
    
    @staticmethod
    def parse_targets(targets: Union[str, List[str]]) -> List[NetworkTarget]:
        """
        Parse target specifications into NetworkTarget objects.
        
        Args:
            targets: Single target string or list of target strings
            
        Returns:
            List of NetworkTarget objects
        """
        if isinstance(targets, str):
            targets = [targets]
        
        network_targets = []
        for target in targets:
            target = target.strip()
            if target:
                network_targets.append(NetworkTarget(target))
        
        return network_targets
    
    @staticmethod
    def parse_targets_from_file(file_path: Union[str, Path]) -> List[NetworkTarget]:
        """
        Parse targets from a file.
        
        Args:
            file_path: Path to file containing targets (one per line)
            
        Returns:
            List of NetworkTarget objects
        """
        targets = []
        file_path = Path(file_path)
        
        try:
            with open(file_path, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    # Handle multiple targets per line (space or comma separated)
                    line_targets = re.split(r'[,\\s]+', line)
                    for target in line_targets:
                        target = target.strip()
                        if target:
                            targets.append(NetworkTarget(target))
            
            logger.info(f"Loaded {len(targets)} targets from {file_path}")
            return targets
            
        except FileNotFoundError:
            raise ValueError(f"Target file not found: {file_path}")
        except Exception as e:
            raise ValueError(f"Error reading target file {file_path}: {e}")
    
    @staticmethod
    def resolve_targets(targets: List[NetworkTarget]) -> List[NetworkTarget]:
        """
        Resolve hostnames and expand CIDR ranges in targets.
        
        Args:
            targets: List of NetworkTarget objects
            
        Returns:
            List of NetworkTarget objects with resolved IPs
        """
        resolved_targets = []
        
        for target in targets:
            try:
                if target.target_type == "ip":
                    # Already an IP address
                    target.resolved_ips = [target.original]
                    resolved_targets.append(target)
                    
                elif target.target_type == "cidr":
                    # Expand CIDR range
                    network = ipaddress.ip_network(target.original, strict=False)
                    ips = [str(ip) for ip in network.hosts()]
                    
                    # Limit large networks to prevent memory issues
                    if len(ips) > 10000:
                        logger.warning(f"CIDR range {target.original} contains {len(ips)} hosts, limiting to first 10000")
                        ips = ips[:10000]
                    
                    target.resolved_ips = ips
                    resolved_targets.append(target)
                    
                elif target.target_type == "hostname":
                    # Resolve hostname
                    try:
                        ip = socket.gethostbyname(target.original)
                        target.resolved_ips = [ip]
                        resolved_targets.append(target)
                        logger.debug(f"Resolved {target.original} to {ip}")
                    except socket.gaierror as e:
                        logger.warning(f"Could not resolve hostname {target.original}: {e}")
                        # Still add the target but with no resolved IPs
                        resolved_targets.append(target)
                        
                else:
                    logger.warning(f"Unknown target type for {target.original}")
                    resolved_targets.append(target)
                    
            except Exception as e:
                logger.error(f"Error processing target {target.original}: {e}")
                resolved_targets.append(target)
        
        return resolved_targets
    
    @staticmethod
    def get_all_ips(targets: List[NetworkTarget]) -> List[str]:
        """
        Get all resolved IP addresses from targets.
        
        Args:
            targets: List of NetworkTarget objects
            
        Returns:
            List of unique IP addresses
        """
        all_ips = set()
        for target in targets:
            all_ips.update(target.resolved_ips)
        
        return sorted(all_ips)
    
    @staticmethod
    def validate_ip(ip: str) -> bool:
        """
        Validate if a string is a valid IP address.
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid IP address, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """
        Validate if a string is a valid CIDR notation.
        
        Args:
            cidr: CIDR string to validate
            
        Returns:
            True if valid CIDR, False otherwise
        """
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_hostname(hostname: str) -> bool:
        """
        Validate if a string is a valid hostname format.
        
        Args:
            hostname: Hostname string to validate
            
        Returns:
            True if valid hostname format, False otherwise
        """
        if not hostname or len(hostname) > 253:
            return False
        
        # Check for valid hostname characters and format
        hostname_pattern = re.compile(
            r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
            r'(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        )
        
        return bool(hostname_pattern.match(hostname))
    
    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if an IP address is in a private range.
        
        Args:
            ip: IP address string
            
        Returns:
            True if private IP, False otherwise
        """
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    @staticmethod
    def get_network_summary(targets: List[NetworkTarget]) -> str:
        """
        Generate a summary of network targets.
        
        Args:
            targets: List of NetworkTarget objects
            
        Returns:
            Human-readable summary string
        """
        total_targets = len(targets)
        total_ips = len(NetworkUtils.get_all_ips(targets))
        
        type_counts = {}
        for target in targets:
            type_counts[target.target_type] = type_counts.get(target.target_type, 0) + 1
        
        lines = []
        lines.append(f"Network Targets Summary:")
        lines.append(f"  Total targets: {total_targets}")
        lines.append(f"  Total IP addresses: {total_ips}")
        
        if type_counts:
            lines.append(f"  Target types:")
            for target_type, count in type_counts.items():
                lines.append(f"    {target_type}: {count}")
        
        return "\\n".join(lines)


# Predefined port sets for common services
COMMON_PORTS = {
    'web': [80, 443, 8080, 8443, 8000, 8888],
    'ssh': [22],
    'ftp': [21, 990],
    'telnet': [23],
    'smtp': [25, 465, 587],
    'dns': [53],
    'http': [80, 8080, 8000, 8888],
    'https': [443, 8443],
    'pop3': [110, 995],
    'imap': [143, 993],
    'snmp': [161, 162],
    'ldap': [389, 636],
    'smb': [139, 445],
    'rdp': [3389],
    'vnc': [5900, 5901, 5902],
    'mysql': [3306],
    'postgresql': [5432],
    'mongodb': [27017],
    'redis': [6379],
    'elasticsearch': [9200, 9300],
    'top100': [
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111,
        113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465,
        513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995,
        1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900,
        2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899,
        5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800,
        5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443,
        8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156,
        49157
    ]
}


def get_service_ports(service: str) -> List[int]:
    """
    Get port list for a named service.
    
    Args:
        service: Service name (e.g., 'web', 'ssh', 'top100')
        
    Returns:
        List of port numbers for the service
    """
    return COMMON_PORTS.get(service.lower(), [])


def parse_port_specification(spec: str) -> PortSpecification:
    """
    Parse a port specification string.
    
    Args:
        spec: Port specification (e.g., "80,443", "1-1000", "web", "all")
        
    Returns:
        PortSpecification object
    """
    # Check if it's a named service
    if spec.lower() in COMMON_PORTS:
        service_ports = COMMON_PORTS[spec.lower()]
        port_spec = PortSpecification(','.join(map(str, service_ports)))
        port_spec.original = spec  # Keep original service name
        return port_spec
    
    return PortSpecification(spec)


if __name__ == "__main__":
    # Test the network utilities
    logging.basicConfig(level=logging.INFO)
    
    # Test target parsing
    print("Testing target parsing:")
    targets = NetworkUtils.parse_targets([
        "192.168.1.1",
        "192.168.1.0/24", 
        "google.com",
        "invalid..hostname"
    ])
    
    for target in targets:
        print(f"  {target}")
    
    # Test port specification
    print("\\nTesting port specifications:")
    port_specs = [
        "80,443",
        "1-1000", 
        "web",
        "all",
        "22,80,443,8080-8090"
    ]
    
    for spec in port_specs:
        ports = parse_port_specification(spec)
        print(f"  {spec} -> {ports}")
    
    # Test network resolution
    print("\\nTesting network resolution:")
    resolved = NetworkUtils.resolve_targets(targets[:2])  # Skip hostname resolution for test
    for target in resolved:
        print(f"  {target.original} -> {len(target.resolved_ips)} IPs")
    
    print("\\nNetwork summary:")
    print(NetworkUtils.get_network_summary(resolved))

