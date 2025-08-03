"""
OpenVAS CLI Scanner

A Python command-line interface for OpenVAS vulnerability scanner with automatic
installation capabilities and flexible output formatting.
"""

__version__ = "1.0.0"
__author__ = "OpenVAS CLI Scanner Team"
__description__ = "Python CLI interface to OpenVAS vulnerability scanner"

# Core scanner functionality
from .scanner import (
    ScannerManager,
    QuickScanner,
    ScanRequest,
    ScanResult,
    ScanConfiguration,
    VulnerabilityFinding,
    create_scan_request
)

# Installation and setup
from .installation import (
    setup_openvas,
    check_openvas_status,
    print_dependency_info,
    OpenVASDetector,
    InstallationStatus
)

# Output formatting
from .output import (
    format_scan_results,
    create_summary_report,
    CSVFormatter,
    TXTFormatter,
    JSONFormatter
)

# Utilities
from .utils import (
    NetworkUtils,
    PortSpecification,
    parse_port_specification,
    setup_logging,
    get_logger
)

# CLI interface
from .cli import (
    main,
    console_entry_point,
    CLIApplication
)

__all__ = [
    # Version info
    '__version__',
    '__author__',
    '__description__',
    
    # Core scanning
    'ScannerManager',
    'QuickScanner', 
    'ScanRequest',
    'ScanResult',
    'ScanConfiguration',
    'VulnerabilityFinding',
    'create_scan_request',
    
    # Installation
    'setup_openvas',
    'check_openvas_status',
    'print_dependency_info',
    'OpenVASDetector',
    'InstallationStatus',
    
    # Output
    'format_scan_results',
    'create_summary_report',
    'CSVFormatter',
    'TXTFormatter',
    'JSONFormatter',
    
    # Utilities
    'NetworkUtils',
    'PortSpecification',
    'parse_port_specification',
    'setup_logging',
    'get_logger',
    
    # CLI
    'main',
    'console_entry_point',
    'CLIApplication'
]


def quick_scan(target: str, ports: str = "top100") -> ScanResult:
    """
    Perform a quick vulnerability scan on a single target.
    
    Args:
        target: Target IP address or hostname
        ports: Port specification (default: top100)
        
    Returns:
        ScanResult object with findings
        
    Example:
        >>> result = quick_scan("192.168.1.1", "web")
        >>> print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    """
    scanner = QuickScanner()
    return scanner.scan_host(target, ports)


def scan_network(network: str, ports: str = "top100") -> ScanResult:
    """
    Perform a vulnerability scan on a network range.
    
    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        ports: Port specification (default: top100)
        
    Returns:
        ScanResult object with findings
        
    Example:
        >>> result = scan_network("192.168.1.0/24", "ssh,web")
        >>> print(f"Scanned {result.targets_scanned} targets")
    """
    scanner = QuickScanner()
    return scanner.scan_network(network, ports)


def scan_from_file(targets_file: str, ports: str = "top100") -> ScanResult:
    """
    Perform a vulnerability scan on targets from a file.
    
    Args:
        targets_file: Path to file containing targets (one per line)
        ports: Port specification (default: top100)
        
    Returns:
        ScanResult object with findings
        
    Example:
        >>> result = scan_from_file("targets.txt", "all")
        >>> print(f"Found {len(result.vulnerabilities)} vulnerabilities")
    """
    scanner = QuickScanner()
    return scanner.scan_file(targets_file, ports)


def is_openvas_ready() -> bool:
    """
    Check if OpenVAS is ready for scanning.
    
    Returns:
        True if OpenVAS is ready, False otherwise
        
    Example:
        >>> if is_openvas_ready():
        ...     result = quick_scan("192.168.1.1")
        ... else:
        ...     setup_openvas()
    """
    try:
        status = check_openvas_status()
        return status.ready_for_scanning
    except Exception:
        return False

