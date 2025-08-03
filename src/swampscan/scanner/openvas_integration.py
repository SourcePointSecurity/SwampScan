"""
OpenVAS Integration

This module provides integration with OpenVAS components including
openvasd HTTP API and direct binary execution of scannerctl.
"""

import json
import subprocess
import tempfile
import time
import uuid
import requests
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from pathlib import Path
from enum import Enum

from ..utils.logging import get_logger

logger = get_logger(__name__)


class ScanStatus(Enum):
    """Scan status enumeration."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanConfiguration:
    """Configuration for a vulnerability scan."""
    targets: List[str]
    ports: List[int]
    scan_id: str
    scan_name: Optional[str] = None
    exclude_hosts: List[str] = None
    credentials: Optional[Dict[str, Any]] = None
    scan_preferences: Optional[Dict[str, Any]] = None
    
    def __post_init__(self):
        if self.exclude_hosts is None:
            self.exclude_hosts = []
        if self.scan_name is None:
            self.scan_name = f"CLI Scan {self.scan_id}"


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding."""
    target: str
    port: int
    protocol: str
    vulnerability_id: str
    name: str
    severity: str
    description: str
    solution: Optional[str] = None
    references: List[str] = None
    cvss_score: Optional[float] = None
    cve_ids: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []
        if self.cve_ids is None:
            self.cve_ids = []


@dataclass
class ScanResult:
    """Complete scan result."""
    scan_id: str
    status: ScanStatus
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    targets_scanned: int = 0
    vulnerabilities: List[VulnerabilityFinding] = None
    errors: List[str] = None
    
    def __post_init__(self):
        if self.vulnerabilities is None:
            self.vulnerabilities = []
        if self.errors is None:
            self.errors = []


class OpenVASHTTPClient:
    """HTTP client for communicating with openvasd."""
    
    def __init__(self, base_url: str = "http://localhost:3000", 
                 api_key: Optional[str] = None):
        """
        Initialize HTTP client.
        
        Args:
            base_url: Base URL for openvasd API
            api_key: API key for authentication (if required)
        """
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        
        if api_key:
            self.session.headers.update({'Authorization': f'Bearer {api_key}'})
        
        self.logger = get_logger(self.__class__.__name__)
    
    def check_connection(self) -> bool:
        """
        Check if openvasd is accessible.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            response = self.session.get(f"{self.base_url}/health", timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.debug(f"Connection check failed: {e}")
            return False
    
    def start_scan(self, config: ScanConfiguration) -> str:
        """
        Start a vulnerability scan.
        
        Args:
            config: Scan configuration
            
        Returns:
            Scan ID
            
        Raises:
            Exception: If scan start fails
        """
        scan_data = {
            "scan_id": config.scan_id,
            "name": config.scan_name,
            "targets": config.targets,
            "ports": config.ports,
            "exclude_hosts": config.exclude_hosts
        }
        
        if config.credentials:
            scan_data["credentials"] = config.credentials
        
        if config.scan_preferences:
            scan_data["preferences"] = config.scan_preferences
        
        try:
            response = self.session.post(
                f"{self.base_url}/scans",
                json=scan_data,
                timeout=30
            )
            response.raise_for_status()
            
            result = response.json()
            scan_id = result.get('scan_id', config.scan_id)
            
            self.logger.info(f"Started scan {scan_id}")
            return scan_id
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to start scan: {e}")
    
    def get_scan_status(self, scan_id: str) -> ScanResult:
        """
        Get scan status and results.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            ScanResult object
            
        Raises:
            Exception: If status retrieval fails
        """
        try:
            response = self.session.get(
                f"{self.base_url}/scans/{scan_id}",
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            
            # Parse status
            status_str = data.get('status', 'unknown').lower()
            try:
                status = ScanStatus(status_str)
            except ValueError:
                status = ScanStatus.PENDING
            
            # Parse vulnerabilities
            vulnerabilities = []
            for vuln_data in data.get('vulnerabilities', []):
                vuln = VulnerabilityFinding(
                    target=vuln_data.get('target', ''),
                    port=vuln_data.get('port', 0),
                    protocol=vuln_data.get('protocol', 'tcp'),
                    vulnerability_id=vuln_data.get('id', ''),
                    name=vuln_data.get('name', ''),
                    severity=vuln_data.get('severity', 'unknown'),
                    description=vuln_data.get('description', ''),
                    solution=vuln_data.get('solution'),
                    references=vuln_data.get('references', []),
                    cvss_score=vuln_data.get('cvss_score'),
                    cve_ids=vuln_data.get('cve_ids', [])
                )
                vulnerabilities.append(vuln)
            
            result = ScanResult(
                scan_id=scan_id,
                status=status,
                start_time=data.get('start_time'),
                end_time=data.get('end_time'),
                targets_scanned=data.get('targets_scanned', 0),
                vulnerabilities=vulnerabilities,
                errors=data.get('errors', [])
            )
            
            return result
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Failed to get scan status: {e}")
    
    def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: Scan identifier
            
        Returns:
            True if cancellation successful, False otherwise
        """
        try:
            response = self.session.delete(
                f"{self.base_url}/scans/{scan_id}",
                timeout=10
            )
            response.raise_for_status()
            
            self.logger.info(f"Cancelled scan {scan_id}")
            return True
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to cancel scan {scan_id}: {e}")
            return False


class ScannerCtlClient:
    """Client for direct scannerctl binary execution."""
    
    def __init__(self, scannerctl_path: Optional[str] = None):
        """
        Initialize scannerctl client.
        
        Args:
            scannerctl_path: Path to scannerctl binary (auto-detected if None)
        """
        self.scannerctl_path = scannerctl_path or self._find_scannerctl()
        self.logger = get_logger(self.__class__.__name__)
        
        if not self.scannerctl_path:
            raise Exception("scannerctl binary not found")
    
    def _find_scannerctl(self) -> Optional[str]:
        """Find scannerctl binary in common locations."""
        import shutil
        
        # Try common paths
        paths = [
            '/usr/local/bin/scannerctl',
            '/usr/bin/scannerctl',
            '~/.cargo/bin/scannerctl'
        ]
        
        for path in paths:
            expanded_path = Path(path).expanduser()
            if expanded_path.exists() and expanded_path.is_file():
                return str(expanded_path)
        
        # Try using which
        return shutil.which('scannerctl')
    
    def check_availability(self) -> bool:
        """
        Check if scannerctl is available and working.
        
        Returns:
            True if available, False otherwise
        """
        try:
            result = subprocess.run(
                [self.scannerctl_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def run_scan(self, config: ScanConfiguration) -> ScanResult:
        """
        Run a scan using scannerctl.
        
        Args:
            config: Scan configuration
            
        Returns:
            ScanResult object
            
        Raises:
            Exception: If scan fails
        """
        self.logger.info(f"Starting scannerctl scan {config.scan_id}")
        
        # Create temporary files for input and output
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as targets_file:
            targets_file.write('\\n'.join(config.targets))
            targets_file_path = targets_file.name
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as output_file:
            output_file_path = output_file.name
        
        try:
            # Build scannerctl command
            cmd = [
                self.scannerctl_path,
                'scan',
                '--targets-file', targets_file_path,
                '--output', output_file_path,
                '--format', 'json'
            ]
            
            # Add port specification
            if config.ports:
                if len(config.ports) == 65535:  # All ports
                    cmd.extend(['--ports', 'all'])
                else:
                    port_ranges = self._compress_port_list(config.ports)
                    cmd.extend(['--ports', ','.join(port_ranges)])
            
            # Add exclude hosts
            if config.exclude_hosts:
                cmd.extend(['--exclude', ','.join(config.exclude_hosts)])
            
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            
            # Run the scan
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            end_time = time.time()
            
            if result.returncode != 0:
                error_msg = f"scannerctl failed with code {result.returncode}: {result.stderr}"
                self.logger.error(error_msg)
                return ScanResult(
                    scan_id=config.scan_id,
                    status=ScanStatus.FAILED,
                    errors=[error_msg]
                )
            
            # Parse results
            vulnerabilities = []
            try:
                with open(output_file_path, 'r') as f:
                    scan_data = json.load(f)
                
                for vuln_data in scan_data.get('vulnerabilities', []):
                    vuln = VulnerabilityFinding(
                        target=vuln_data.get('target', ''),
                        port=vuln_data.get('port', 0),
                        protocol=vuln_data.get('protocol', 'tcp'),
                        vulnerability_id=vuln_data.get('id', ''),
                        name=vuln_data.get('name', ''),
                        severity=vuln_data.get('severity', 'unknown'),
                        description=vuln_data.get('description', ''),
                        solution=vuln_data.get('solution'),
                        references=vuln_data.get('references', []),
                        cvss_score=vuln_data.get('cvss_score'),
                        cve_ids=vuln_data.get('cve_ids', [])
                    )
                    vulnerabilities.append(vuln)
                    
            except Exception as e:
                self.logger.warning(f"Failed to parse scan results: {e}")
            
            scan_result = ScanResult(
                scan_id=config.scan_id,
                status=ScanStatus.COMPLETED,
                start_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(start_time)),
                end_time=time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time)),
                targets_scanned=len(config.targets),
                vulnerabilities=vulnerabilities
            )
            
            self.logger.info(f"Scan {config.scan_id} completed with {len(vulnerabilities)} findings")
            return scan_result
            
        except subprocess.TimeoutExpired:
            error_msg = "Scan timed out after 1 hour"
            self.logger.error(error_msg)
            return ScanResult(
                scan_id=config.scan_id,
                status=ScanStatus.FAILED,
                errors=[error_msg]
            )
        except Exception as e:
            error_msg = f"Scan failed: {e}"
            self.logger.error(error_msg)
            return ScanResult(
                scan_id=config.scan_id,
                status=ScanStatus.FAILED,
                errors=[error_msg]
            )
        finally:
            # Clean up temporary files
            try:
                Path(targets_file_path).unlink()
                Path(output_file_path).unlink()
            except Exception:
                pass
    
    def _compress_port_list(self, ports: List[int]) -> List[str]:
        """Compress a list of ports into ranges for efficient representation."""
        if not ports:
            return []
        
        sorted_ports = sorted(set(ports))
        ranges = []
        start = sorted_ports[0]
        end = start
        
        for port in sorted_ports[1:]:
            if port == end + 1:
                end = port
            else:
                if start == end:
                    ranges.append(str(start))
                else:
                    ranges.append(f"{start}-{end}")
                start = end = port
        
        # Add the last range
        if start == end:
            ranges.append(str(start))
        else:
            ranges.append(f"{start}-{end}")
        
        return ranges


class OpenVASIntegration:
    """Main integration class that handles both HTTP and binary methods."""
    
    def __init__(self, prefer_http: bool = True, 
                 openvasd_url: str = "http://localhost:3000",
                 api_key: Optional[str] = None):
        """
        Initialize OpenVAS integration.
        
        Args:
            prefer_http: Prefer HTTP API over binary execution
            openvasd_url: URL for openvasd HTTP API
            api_key: API key for HTTP authentication
        """
        self.prefer_http = prefer_http
        self.logger = get_logger(self.__class__.__name__)
        
        # Initialize clients
        self.http_client = None
        self.scannerctl_client = None
        
        try:
            self.http_client = OpenVASHTTPClient(openvasd_url, api_key)
            if not self.http_client.check_connection():
                self.logger.warning("openvasd HTTP API not available")
                self.http_client = None
        except Exception as e:
            self.logger.debug(f"Failed to initialize HTTP client: {e}")
        
        try:
            self.scannerctl_client = ScannerCtlClient()
            if not self.scannerctl_client.check_availability():
                self.logger.warning("scannerctl binary not available")
                self.scannerctl_client = None
        except Exception as e:
            self.logger.debug(f"Failed to initialize scannerctl client: {e}")
    
    def is_available(self) -> bool:
        """Check if any OpenVAS integration method is available."""
        return self.http_client is not None or self.scannerctl_client is not None
    
    def get_available_methods(self) -> List[str]:
        """Get list of available integration methods."""
        methods = []
        if self.http_client:
            methods.append("HTTP API")
        if self.scannerctl_client:
            methods.append("scannerctl binary")
        return methods
    
    def run_scan(self, config: ScanConfiguration, 
                 method: Optional[str] = None) -> ScanResult:
        """
        Run a vulnerability scan using the best available method.
        
        Args:
            config: Scan configuration
            method: Force specific method ("http" or "binary")
            
        Returns:
            ScanResult object
            
        Raises:
            Exception: If no methods available or scan fails
        """
        if not self.is_available():
            raise Exception("No OpenVAS integration methods available")
        
        # Determine which method to use
        use_http = False
        use_binary = False
        
        if method == "http":
            if self.http_client:
                use_http = True
            else:
                raise Exception("HTTP API method not available")
        elif method == "binary":
            if self.scannerctl_client:
                use_binary = True
            else:
                raise Exception("Binary method not available")
        else:
            # Auto-select based on preference and availability
            if self.prefer_http and self.http_client:
                use_http = True
            elif self.scannerctl_client:
                use_binary = True
            elif self.http_client:
                use_http = True
            else:
                raise Exception("No suitable integration method available")
        
        # Run the scan
        if use_http:
            self.logger.info("Using HTTP API method")
            return self._run_http_scan(config)
        else:
            self.logger.info("Using binary execution method")
            return self.scannerctl_client.run_scan(config)
    
    def _run_http_scan(self, config: ScanConfiguration) -> ScanResult:
        """Run scan using HTTP API with polling."""
        # Start the scan
        scan_id = self.http_client.start_scan(config)
        
        # Poll for completion
        max_wait_time = 3600  # 1 hour
        poll_interval = 10    # 10 seconds
        elapsed_time = 0
        
        while elapsed_time < max_wait_time:
            result = self.http_client.get_scan_status(scan_id)
            
            if result.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
                return result
            
            self.logger.debug(f"Scan {scan_id} status: {result.status.value}")
            time.sleep(poll_interval)
            elapsed_time += poll_interval
        
        # Timeout - try to cancel the scan
        self.http_client.cancel_scan(scan_id)
        
        return ScanResult(
            scan_id=scan_id,
            status=ScanStatus.FAILED,
            errors=["Scan timed out after 1 hour"]
        )


def create_scan_configuration(targets: List[str], ports: List[int], 
                            scan_name: Optional[str] = None) -> ScanConfiguration:
    """
    Create a scan configuration.
    
    Args:
        targets: List of target IP addresses
        ports: List of port numbers to scan
        scan_name: Optional scan name
        
    Returns:
        ScanConfiguration object
    """
    scan_id = str(uuid.uuid4())
    
    return ScanConfiguration(
        targets=targets,
        ports=ports,
        scan_id=scan_id,
        scan_name=scan_name
    )


if __name__ == "__main__":
    # Test the OpenVAS integration
    logging.basicConfig(level=logging.INFO)
    
    # Test configuration
    config = create_scan_configuration(
        targets=["127.0.0.1"],
        ports=[22, 80, 443],
        scan_name="Test Scan"
    )
    
    print(f"Created scan configuration: {config.scan_id}")
    
    # Test integration
    integration = OpenVASIntegration()
    print(f"Available methods: {integration.get_available_methods()}")
    
    if integration.is_available():
        print("OpenVAS integration is available")
    else:
        print("No OpenVAS integration methods available")

