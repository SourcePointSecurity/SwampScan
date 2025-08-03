"""
Scanner Module

This module provides the core scanning functionality and OpenVAS integration.
"""

from .openvas_integration import (
    OpenVASIntegration,
    OpenVASHTTPClient,
    ScannerCtlClient,
    ScanConfiguration,
    ScanResult,
    ScanStatus,
    VulnerabilityFinding,
    create_scan_configuration
)

from .manager import (
    ScannerManager,
    ScanRequest,
    ScanSummary,
    QuickScanner,
    create_scan_request
)

__all__ = [
    # OpenVAS integration
    'OpenVASIntegration',
    'OpenVASHTTPClient',
    'ScannerCtlClient',
    'ScanConfiguration',
    'ScanResult',
    'ScanStatus',
    'VulnerabilityFinding',
    'create_scan_configuration',
    
    # Scanner management
    'ScannerManager',
    'ScanRequest',
    'ScanSummary',
    'QuickScanner',
    'create_scan_request'
]

