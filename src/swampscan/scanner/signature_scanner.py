#!/usr/bin/env python3
"""
Simplified Signature-Based Scanner

This module provides a lightweight vulnerability scanner that works with
downloaded NASL signature files without requiring the full OpenVAS infrastructure.
"""

import os
import re
import json
import socket
import subprocess
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilitySignature:
    """Represents a parsed vulnerability signature."""
    oid: str
    name: str
    family: str
    category: str
    cvss_base: float
    cve_ids: List[str]
    description: str
    solution: str
    ports: List[int]
    dependencies: List[str]
    script_content: str
    
    def __post_init__(self):
        if self.cve_ids is None:
            self.cve_ids = []
        if self.ports is None:
            self.ports = []
        if self.dependencies is None:
            self.dependencies = []


@dataclass
class ScanResult:
    """Represents a vulnerability scan result."""
    target: str
    port: int
    protocol: str
    vulnerability_oid: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    description: str
    solution: str
    cve_ids: List[str]
    
    def __post_init__(self):
        if self.cve_ids is None:
            self.cve_ids = []


class NASLParser:
    """Parser for NASL (Nessus Attack Scripting Language) files."""
    
    def __init__(self):
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def parse_nasl_file(self, file_path: str) -> Optional[VulnerabilitySignature]:
        """Parse a NASL file and extract vulnerability information."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Extract basic information using regex patterns
            oid = self._extract_field(content, r'script_oid\("([^"]+)"\)')
            name = self._extract_field(content, r'script_name\("([^"]+)"\)')
            family = self._extract_field(content, r'script_family\("([^"]+)"\)')
            category = self._extract_field(content, r'script_category\(([^)]+)\)')
            
            # Extract CVSS score
            cvss_base = 0.0
            cvss_match = re.search(r'script_tag\(name:"cvss_base",\s*value:"([^"]+)"\)', content)
            if cvss_match:
                try:
                    cvss_base = float(cvss_match.group(1))
                except ValueError:
                    cvss_base = 0.0
            
            # Extract CVE IDs
            cve_ids = []
            cve_matches = re.findall(r'script_cve_id\("([^"]+)"\)', content)
            for match in cve_matches:
                cve_ids.extend([cve.strip() for cve in match.split(',')])
            
            # Extract description and solution
            description = self._extract_tag_content(content, 'insight') or \
                         self._extract_tag_content(content, 'summary') or \
                         "No description available"
            
            solution = self._extract_tag_content(content, 'solution') or \
                      "No solution available"
            
            # Extract port dependencies (simplified)
            ports = self._extract_ports_from_content(content)
            
            # Extract script dependencies
            dependencies = []
            dep_matches = re.findall(r'script_dependencies\("([^"]+)"\)', content)
            for match in dep_matches:
                dependencies.extend([dep.strip() for dep in match.split(',')])
            
            if not oid or not name:
                return None
            
            return VulnerabilitySignature(
                oid=oid,
                name=name,
                family=family or "Unknown",
                category=category or "ACT_GATHER_INFO",
                cvss_base=cvss_base,
                cve_ids=cve_ids,
                description=description,
                solution=solution,
                ports=ports,
                dependencies=dependencies,
                script_content=content
            )
            
        except Exception as e:
            self.logger.warning(f"Failed to parse NASL file {file_path}: {e}")
            return None
    
    def _extract_field(self, content: str, pattern: str) -> Optional[str]:
        """Extract a field using regex pattern."""
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def _extract_tag_content(self, content: str, tag_name: str) -> Optional[str]:
        """Extract content from a script_tag."""
        pattern = rf'script_tag\(name:"{tag_name}",\s*value:"([^"]+)"\)'
        match = re.search(pattern, content)
        return match.group(1) if match else None
    
    def _extract_ports_from_content(self, content: str) -> List[int]:
        """Extract port numbers from NASL content."""
        ports = []
        
        # Look for common port patterns
        port_patterns = [
            r'get_http_port\(default:(\d+)\)',
            r'get_kb_item\("Services/www/(\d+)"\)',
            r'port\s*=\s*(\d+)',
            r'dport:\s*(\d+)'
        ]
        
        for pattern in port_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                try:
                    port = int(match)
                    if 1 <= port <= 65535 and port not in ports:
                        ports.append(port)
                except ValueError:
                    continue
        
        return ports


class SignatureScanner:
    """Simplified vulnerability scanner using signature files."""
    
    def __init__(self, signature_dir: str = "/var/lib/openvas/plugins"):
        self.signature_dir = Path(signature_dir)
        self.parser = NASLParser()
        self.signatures: Dict[str, VulnerabilitySignature] = {}
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def load_signatures(self, max_signatures: int = 1000) -> int:
        """Load vulnerability signatures from NASL files."""
        self.logger.info(f"Loading signatures from {self.signature_dir}")
        
        loaded_count = 0
        
        # Find NASL files
        nasl_files = []
        if self.signature_dir.exists():
            nasl_files = list(self.signature_dir.rglob("*.nasl"))
        
        # Load a subset for testing
        for nasl_file in nasl_files[:max_signatures]:
            try:
                signature = self.parser.parse_nasl_file(str(nasl_file))
                if signature:
                    self.signatures[signature.oid] = signature
                    loaded_count += 1
            except Exception as e:
                self.logger.debug(f"Failed to load {nasl_file}: {e}")
        
        self.logger.info(f"Loaded {loaded_count} vulnerability signatures")
        return loaded_count
    
    def scan_target(self, target: str, ports: List[int] = None) -> List[ScanResult]:
        """Perform vulnerability scan on target."""
        if not self.signatures:
            self.logger.warning("No signatures loaded. Call load_signatures() first.")
            return []
        
        if ports is None:
            ports = [22, 80, 443, 8080, 8443]  # Common ports
        
        results = []
        
        self.logger.info(f"Scanning {target} on ports {ports}")
        
        # Basic port scanning
        open_ports = self._scan_ports(target, ports)
        
        if not open_ports:
            self.logger.info(f"No open ports found on {target}")
            return results
        
        self.logger.info(f"Found open ports: {open_ports}")
        
        # Check signatures against open ports
        for port in open_ports:
            port_results = self._check_port_vulnerabilities(target, port)
            results.extend(port_results)
        
        return results
    
    def _scan_ports(self, target: str, ports: List[int], timeout: int = 3) -> List[int]:
        """Perform basic port scanning."""
        open_ports = []
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((target, port))
                sock.close()
                
                if result == 0:
                    open_ports.append(port)
                    
            except Exception as e:
                self.logger.debug(f"Port scan error for {target}:{port} - {e}")
        
        return open_ports
    
    def _check_port_vulnerabilities(self, target: str, port: int) -> List[ScanResult]:
        """Check for vulnerabilities on a specific port."""
        results = []
        
        # Get service banner if possible
        banner = self._get_service_banner(target, port)
        
        # Check signatures that might apply to this port
        for oid, signature in self.signatures.items():
            if self._signature_applies_to_port(signature, port, banner):
                # Perform simplified vulnerability check
                if self._check_vulnerability(target, port, signature, banner):
                    severity = self._calculate_severity(signature.cvss_base)
                    
                    result = ScanResult(
                        target=target,
                        port=port,
                        protocol="tcp",
                        vulnerability_oid=oid,
                        vulnerability_name=signature.name,
                        severity=severity,
                        cvss_score=signature.cvss_base,
                        description=signature.description,
                        solution=signature.solution,
                        cve_ids=signature.cve_ids
                    )
                    results.append(result)
        
        return results
    
    def _get_service_banner(self, target: str, port: int, timeout: int = 5) -> str:
        """Get service banner from target port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Send HTTP request for web services
            if port in [80, 8080, 8000]:
                sock.send(b"GET / HTTP/1.0\r\n\r\n")
            elif port in [443, 8443]:
                # For HTTPS, we'd need SSL/TLS handling
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            return banner
            
        except Exception as e:
            self.logger.debug(f"Banner grab failed for {target}:{port} - {e}")
            return ""
    
    def _signature_applies_to_port(self, signature: VulnerabilitySignature, 
                                  port: int, banner: str) -> bool:
        """Check if signature applies to the given port/service."""
        # Simple heuristics for signature applicability
        
        # Check if signature specifies ports
        if signature.ports and port not in signature.ports:
            return False
        
        # Check service-specific signatures
        if port == 22 and "ssh" not in signature.name.lower():
            return False
        
        if port in [80, 8080] and "http" not in signature.name.lower() and "web" not in signature.name.lower():
            return False
        
        if port in [443, 8443] and "https" not in signature.name.lower() and "ssl" not in signature.name.lower():
            return False
        
        return True
    
    def _check_vulnerability(self, target: str, port: int, 
                           signature: VulnerabilitySignature, banner: str) -> bool:
        """Perform simplified vulnerability check."""
        # This is a simplified implementation
        # In a real scanner, this would execute the NASL script logic
        
        # For demonstration, we'll do basic pattern matching
        if banner and signature.name:
            # Look for version patterns that might indicate vulnerabilities
            version_patterns = [
                r'Apache/(\d+\.\d+\.\d+)',
                r'nginx/(\d+\.\d+\.\d+)',
                r'OpenSSH_(\d+\.\d+)',
                r'Microsoft-IIS/(\d+\.\d+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, banner)
                if match:
                    version = match.group(1)
                    # Simple version-based vulnerability detection
                    if self._is_vulnerable_version(signature, version):
                        return True
        
        # For now, return False to avoid false positives
        # In a real implementation, this would execute NASL script logic
        return False
    
    def _is_vulnerable_version(self, signature: VulnerabilitySignature, version: str) -> bool:
        """Check if version is vulnerable (simplified)."""
        # This is a placeholder for version comparison logic
        # Real implementation would parse version strings and compare ranges
        return False
    
    def _calculate_severity(self, cvss_score: float) -> str:
        """Calculate severity level from CVSS score."""
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        elif cvss_score > 0.0:
            return "Low"
        else:
            return "Info"


def main():
    """Test the signature scanner."""
    logging.basicConfig(level=logging.INFO)
    
    scanner = SignatureScanner()
    
    print("Loading vulnerability signatures...")
    loaded = scanner.load_signatures(max_signatures=100)  # Load subset for testing
    print(f"Loaded {loaded} signatures")
    
    if loaded == 0:
        print("No signatures loaded. Make sure NASL files are available.")
        return
    
    target = "scanme.nmap.org"
    print(f"\nScanning {target}...")
    
    results = scanner.scan_target(target)
    
    print(f"\nScan Results for {target}:")
    print("=" * 50)
    
    if results:
        for result in results:
            print(f"Port {result.port}: {result.vulnerability_name}")
            print(f"  Severity: {result.severity} (CVSS: {result.cvss_score})")
            print(f"  Description: {result.description[:100]}...")
            print(f"  CVEs: {', '.join(result.cve_ids) if result.cve_ids else 'None'}")
            print()
    else:
        print("No vulnerabilities detected (or signatures need refinement)")


if __name__ == "__main__":
    main()

