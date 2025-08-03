"""
Scanner Manager

This module provides the main scanning orchestration functionality,
coordinating between target parsing, OpenVAS integration, and result processing.
"""

import time
import logging
from typing import List, Optional, Dict, Any
from dataclasses import dataclass
from pathlib import Path

from ..utils.network import NetworkTarget, PortSpecification, NetworkUtils
from ..utils.logging import get_logger, ScanProgressLogger
from .openvas_integration import (
    OpenVASIntegration, 
    ScanConfiguration, 
    ScanResult, 
    ScanStatus,
    create_scan_configuration
)

logger = get_logger(__name__)


@dataclass
class ScanRequest:
    """Represents a complete scan request."""
    targets: List[str]
    target_file: Optional[str] = None
    ports: str = "top100"
    output_file: Optional[str] = None
    output_format: str = "csv"
    scan_name: Optional[str] = None
    exclude_hosts: List[str] = None
    max_concurrent: int = 1
    timeout: int = 3600
    verbose: bool = False
    
    def __post_init__(self):
        if self.exclude_hosts is None:
            self.exclude_hosts = []


@dataclass
class ScanSummary:
    """Summary of scan execution."""
    total_targets: int
    total_ips: int
    ports_scanned: int
    scan_duration: float
    vulnerabilities_found: int
    high_severity: int
    medium_severity: int
    low_severity: int
    errors: List[str]
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class ScannerManager:
    """Main scanner manager that orchestrates vulnerability scans."""
    
    def __init__(self, openvas_integration: Optional[OpenVASIntegration] = None):
        """
        Initialize the scanner manager.
        
        Args:
            openvas_integration: OpenVAS integration instance (auto-created if None)
        """
        self.logger = get_logger(self.__class__.__name__)
        self.openvas = openvas_integration or OpenVASIntegration()
        
        if not self.openvas.is_available():
            raise Exception("No OpenVAS integration methods available. Please install OpenVAS components.")
        
        self.logger.info(f"Scanner initialized with methods: {self.openvas.get_available_methods()}")
    
    def execute_scan(self, request: ScanRequest) -> ScanResult:
        """
        Execute a complete vulnerability scan.
        
        Args:
            request: Scan request configuration
            
        Returns:
            ScanResult object with findings
            
        Raises:
            Exception: If scan execution fails
        """
        self.logger.info("Starting vulnerability scan execution")
        start_time = time.time()
        
        try:
            # Step 1: Parse and resolve targets
            with ScanProgressLogger("Target Resolution") as progress:
                targets = self._resolve_targets(request)
                progress.update(message=f"Resolved {len(targets)} targets")
            
            # Step 2: Parse port specification
            with ScanProgressLogger("Port Configuration") as progress:
                port_spec = self._parse_ports(request.ports)
                progress.update(message=f"Configured {len(port_spec.ports)} ports")
            
            # Step 3: Prepare scan configuration
            all_ips = NetworkUtils.get_all_ips(targets)
            if not all_ips:
                raise Exception("No valid IP addresses found in targets")
            
            scan_config = create_scan_configuration(
                targets=all_ips,
                ports=port_spec.get_port_list(),
                scan_name=request.scan_name or f"CLI Scan {int(time.time())}"
            )
            
            # Add exclude hosts
            scan_config.exclude_hosts = request.exclude_hosts
            
            self.logger.info(f"Scan configuration: {len(all_ips)} IPs, {len(port_spec.ports)} ports")
            
            # Step 4: Execute the scan
            with ScanProgressLogger("Vulnerability Scanning") as progress:
                result = self.openvas.run_scan(scan_config)
                progress.update(message=f"Scan {result.status.value}")
            
            # Step 5: Log results
            end_time = time.time()
            duration = end_time - start_time
            
            self.logger.info(f"Scan completed in {duration:.2f} seconds")
            self.logger.info(f"Status: {result.status.value}")
            self.logger.info(f"Vulnerabilities found: {len(result.vulnerabilities)}")
            
            if result.errors:
                for error in result.errors:
                    self.logger.warning(f"Scan error: {error}")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Scan execution failed: {e}")
            raise
    
    def _resolve_targets(self, request: ScanRequest) -> List[NetworkTarget]:
        """Resolve targets from request specification."""
        targets = []
        
        # Add targets from command line
        if request.targets:
            targets.extend(NetworkUtils.parse_targets(request.targets))
        
        # Add targets from file
        if request.target_file:
            file_targets = NetworkUtils.parse_targets_from_file(request.target_file)
            targets.extend(file_targets)
        
        if not targets:
            raise Exception("No targets specified")
        
        # Resolve hostnames and expand CIDR ranges
        resolved_targets = NetworkUtils.resolve_targets(targets)
        
        # Log summary
        summary = NetworkUtils.get_network_summary(resolved_targets)
        self.logger.info(f"Target resolution complete:\\n{summary}")
        
        return resolved_targets
    
    def _parse_ports(self, port_spec: str) -> PortSpecification:
        """Parse port specification."""
        from ..utils.network import parse_port_specification
        
        ports = parse_port_specification(port_spec)
        self.logger.info(f"Port specification: {ports}")
        
        return ports
    
    def validate_request(self, request: ScanRequest) -> List[str]:
        """
        Validate a scan request and return list of validation errors.
        
        Args:
            request: Scan request to validate
            
        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []
        
        # Check targets
        if not request.targets and not request.target_file:
            errors.append("No targets specified (use --target or --targets-file)")
        
        if request.target_file and not Path(request.target_file).exists():
            errors.append(f"Target file not found: {request.target_file}")
        
        # Check output format
        if request.output_format not in ['csv', 'txt']:
            errors.append(f"Invalid output format: {request.output_format} (must be csv or txt)")
        
        # Check timeout
        if request.timeout <= 0:
            errors.append("Timeout must be positive")
        
        # Check max concurrent
        if request.max_concurrent <= 0:
            errors.append("Max concurrent must be positive")
        
        # Validate port specification
        try:
            self._parse_ports(request.ports)
        except Exception as e:
            errors.append(f"Invalid port specification: {e}")
        
        # Try to parse targets if provided
        if request.targets:
            try:
                targets = NetworkUtils.parse_targets(request.targets)
                if not targets:
                    errors.append("No valid targets found")
            except Exception as e:
                errors.append(f"Invalid target specification: {e}")
        
        return errors
    
    def get_scan_summary(self, result: ScanResult, 
                        targets_count: int, ports_count: int,
                        duration: float) -> ScanSummary:
        """
        Generate a scan summary from results.
        
        Args:
            result: Scan result
            targets_count: Number of targets scanned
            ports_count: Number of ports scanned
            duration: Scan duration in seconds
            
        Returns:
            ScanSummary object
        """
        # Count vulnerabilities by severity
        high_count = 0
        medium_count = 0
        low_count = 0
        
        for vuln in result.vulnerabilities:
            severity = vuln.severity.lower()
            if severity in ['high', 'critical']:
                high_count += 1
            elif severity == 'medium':
                medium_count += 1
            else:
                low_count += 1
        
        return ScanSummary(
            total_targets=targets_count,
            total_ips=result.targets_scanned,
            ports_scanned=ports_count,
            scan_duration=duration,
            vulnerabilities_found=len(result.vulnerabilities),
            high_severity=high_count,
            medium_severity=medium_count,
            low_severity=low_count,
            errors=result.errors.copy()
        )
    
    def print_scan_summary(self, summary: ScanSummary):
        """Print a formatted scan summary."""
        print("\\n" + "=" * 60)
        print("VULNERABILITY SCAN SUMMARY")
        print("=" * 60)
        print(f"Targets Scanned:     {summary.total_ips}")
        print(f"Ports Scanned:       {summary.ports_scanned}")
        print(f"Scan Duration:       {summary.scan_duration:.2f} seconds")
        print(f"Total Findings:      {summary.vulnerabilities_found}")
        print(f"  High/Critical:     {summary.high_severity}")
        print(f"  Medium:            {summary.medium_severity}")
        print(f"  Low/Info:          {summary.low_severity}")
        
        if summary.errors:
            print(f"Errors:              {len(summary.errors)}")
            for error in summary.errors[:3]:  # Show first 3 errors
                print(f"  - {error}")
            if len(summary.errors) > 3:
                print(f"  ... and {len(summary.errors) - 3} more")
        
        print("=" * 60)


class QuickScanner:
    """Simplified interface for quick scans."""
    
    def __init__(self):
        """Initialize quick scanner."""
        self.manager = ScannerManager()
    
    def scan_host(self, host: str, ports: str = "top100") -> ScanResult:
        """
        Scan a single host.
        
        Args:
            host: Target host (IP or hostname)
            ports: Port specification
            
        Returns:
            ScanResult object
        """
        request = ScanRequest(
            targets=[host],
            ports=ports,
            scan_name=f"Quick scan of {host}"
        )
        
        return self.manager.execute_scan(request)
    
    def scan_network(self, network: str, ports: str = "top100") -> ScanResult:
        """
        Scan a network range.
        
        Args:
            network: Network in CIDR notation
            ports: Port specification
            
        Returns:
            ScanResult object
        """
        request = ScanRequest(
            targets=[network],
            ports=ports,
            scan_name=f"Network scan of {network}"
        )
        
        return self.manager.execute_scan(request)
    
    def scan_file(self, targets_file: str, ports: str = "top100") -> ScanResult:
        """
        Scan targets from a file.
        
        Args:
            targets_file: Path to file containing targets
            ports: Port specification
            
        Returns:
            ScanResult object
        """
        request = ScanRequest(
            targets=[],
            target_file=targets_file,
            ports=ports,
            scan_name=f"File scan from {Path(targets_file).name}"
        )
        
        return self.manager.execute_scan(request)


def create_scan_request(**kwargs) -> ScanRequest:
    """
    Create a scan request with validation.
    
    Args:
        **kwargs: Scan request parameters
        
    Returns:
        ScanRequest object
        
    Raises:
        ValueError: If request is invalid
    """
    request = ScanRequest(**kwargs)
    
    # Validate the request
    manager = ScannerManager()
    errors = manager.validate_request(request)
    
    if errors:
        raise ValueError(f"Invalid scan request: {'; '.join(errors)}")
    
    return request


if __name__ == "__main__":
    # Test the scanner manager
    import logging
    logging.basicConfig(level=logging.INFO)
    
    try:
        # Test quick scanner
        quick = QuickScanner()
        print("Quick scanner initialized successfully")
        print(f"Available methods: {quick.manager.openvas.get_available_methods()}")
        
        # Test request validation
        request = ScanRequest(
            targets=["127.0.0.1"],
            ports="22,80,443"
        )
        
        manager = ScannerManager()
        errors = manager.validate_request(request)
        
        if errors:
            print(f"Validation errors: {errors}")
        else:
            print("Request validation passed")
            
    except Exception as e:
        print(f"Scanner manager test failed: {e}")

