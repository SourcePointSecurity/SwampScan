"""
Utilities Module

This module provides utility functions for network operations, logging, and other common tasks.
"""

from .network import (
    NetworkTarget,
    PortSpecification,
    NetworkUtils,
    parse_port_specification,
    get_service_ports,
    COMMON_PORTS
)

from .logging import (
    ScannerLogger,
    get_logger,
    setup_logging,
    log_scan_start,
    log_scan_complete,
    log_progress,
    log_error_with_context,
    ScanProgressLogger
)

__all__ = [
    # Network utilities
    'NetworkTarget',
    'PortSpecification',
    'NetworkUtils',
    'parse_port_specification',
    'get_service_ports',
    'COMMON_PORTS',
    
    # Logging utilities
    'ScannerLogger',
    'get_logger',
    'setup_logging',
    'log_scan_start',
    'log_scan_complete',
    'log_progress',
    'log_error_with_context',
    'ScanProgressLogger'
]

