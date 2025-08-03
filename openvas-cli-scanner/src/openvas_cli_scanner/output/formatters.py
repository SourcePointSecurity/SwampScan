"""
Output Formatters

This module provides formatting functionality for scan results in various output formats.
"""

import csv
import io
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
from dataclasses import asdict

from ..scanner.openvas_integration import ScanResult, VulnerabilityFinding, ScanStatus


class CSVFormatter:
    """Formatter for CSV output."""
    
    def __init__(self, include_header: bool = True):
        """
        Initialize CSV formatter.
        
        Args:
            include_header: Whether to include header row
        """
        self.include_header = include_header
        self.field_names = [
            'target',
            'port',
            'protocol',
            'vulnerability_id',
            'name',
            'severity',
            'cvss_score',
            'cve_ids',
            'description',
            'solution',
            'references'
        ]
    
    def format_scan_result(self, result: ScanResult) -> str:
        """
        Format scan result as CSV.
        
        Args:
            result: Scan result to format
            
        Returns:
            CSV formatted string
        """
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self.field_names, quoting=csv.QUOTE_MINIMAL)
        
        # Write header if requested
        if self.include_header:
            writer.writeheader()
        
        # Write vulnerability data
        for vuln in result.vulnerabilities:
            row = self._vulnerability_to_row(vuln)
            writer.writerow(row)
        
        return output.getvalue()
    
    def _vulnerability_to_row(self, vuln: VulnerabilityFinding) -> Dict[str, Any]:
        """Convert vulnerability finding to CSV row."""
        return {
            'target': vuln.target,
            'port': vuln.port,
            'protocol': vuln.protocol,
            'vulnerability_id': vuln.vulnerability_id,
            'name': vuln.name,
            'severity': vuln.severity,
            'cvss_score': vuln.cvss_score or '',
            'cve_ids': ','.join(vuln.cve_ids) if vuln.cve_ids else '',
            'description': self._clean_text(vuln.description),
            'solution': self._clean_text(vuln.solution) if vuln.solution else '',
            'references': ','.join(vuln.references) if vuln.references else ''
        }
    
    def _clean_text(self, text: str) -> str:
        """Clean text for CSV output."""
        if not text:
            return ''
        
        # Remove excessive whitespace and newlines
        cleaned = ' '.join(text.split())
        
        # Truncate very long descriptions
        if len(cleaned) > 500:
            cleaned = cleaned[:497] + '...'
        
        return cleaned


class TXTFormatter:
    """Formatter for human-readable text output."""
    
    def __init__(self, detailed: bool = True):
        """
        Initialize TXT formatter.
        
        Args:
            detailed: Whether to include detailed information
        """
        self.detailed = detailed
    
    def format_scan_result(self, result: ScanResult) -> str:
        """
        Format scan result as human-readable text.
        
        Args:
            result: Scan result to format
            
        Returns:
            Text formatted string
        """
        lines = []
        
        # Header
        lines.append("OpenVAS Vulnerability Scan Report")
        lines.append("=" * 50)
        lines.append(f"Scan ID: {result.scan_id}")
        lines.append(f"Status: {result.status.value}")
        
        if result.start_time:
            lines.append(f"Start Time: {result.start_time}")
        if result.end_time:
            lines.append(f"End Time: {result.end_time}")
        
        lines.append(f"Targets Scanned: {result.targets_scanned}")
        lines.append(f"Vulnerabilities Found: {len(result.vulnerabilities)}")
        lines.append("")
        
        # Summary by severity
        severity_counts = self._count_by_severity(result.vulnerabilities)
        if severity_counts:
            lines.append("Severity Summary:")
            lines.append("-" * 20)
            for severity, count in severity_counts.items():
                lines.append(f"  {severity.title()}: {count}")
            lines.append("")
        
        # Vulnerabilities
        if result.vulnerabilities:
            lines.append("Vulnerability Details:")
            lines.append("-" * 30)
            
            # Group by target for better organization
            by_target = self._group_by_target(result.vulnerabilities)
            
            for target, vulns in by_target.items():
                lines.append(f"\\nTarget: {target}")
                lines.append("~" * (len(target) + 8))
                
                for vuln in vulns:
                    lines.extend(self._format_vulnerability(vuln))
                    lines.append("")
        
        # Errors
        if result.errors:
            lines.append("\\nErrors:")
            lines.append("-" * 10)
            for error in result.errors:
                lines.append(f"  • {error}")
        
        return "\\n".join(lines)
    
    def _format_vulnerability(self, vuln: VulnerabilityFinding) -> List[str]:
        """Format a single vulnerability finding."""
        lines = []
        
        # Basic info
        lines.append(f"  [{vuln.severity.upper()}] {vuln.name}")
        lines.append(f"    Port: {vuln.port}/{vuln.protocol}")
        
        if vuln.vulnerability_id:
            lines.append(f"    ID: {vuln.vulnerability_id}")
        
        if vuln.cvss_score:
            lines.append(f"    CVSS Score: {vuln.cvss_score}")
        
        if vuln.cve_ids:
            lines.append(f"    CVE IDs: {', '.join(vuln.cve_ids)}")
        
        # Description (if detailed mode)
        if self.detailed and vuln.description:
            desc = self._wrap_text(vuln.description, 70, "    ")
            lines.append(f"    Description: {desc}")
        
        # Solution (if available and detailed mode)
        if self.detailed and vuln.solution:
            solution = self._wrap_text(vuln.solution, 70, "    ")
            lines.append(f"    Solution: {solution}")
        
        # References (if available)
        if vuln.references:
            lines.append(f"    References: {', '.join(vuln.references[:3])}")
            if len(vuln.references) > 3:
                lines.append(f"      ... and {len(vuln.references) - 3} more")
        
        return lines
    
    def _count_by_severity(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            counts[severity] = counts.get(severity, 0) + 1
        
        # Sort by severity priority
        severity_order = ['critical', 'high', 'medium', 'low', 'info', 'unknown']
        ordered_counts = {}
        for severity in severity_order:
            if severity in counts:
                ordered_counts[severity] = counts[severity]
        
        # Add any other severities not in the standard list
        for severity, count in counts.items():
            if severity not in ordered_counts:
                ordered_counts[severity] = count
        
        return ordered_counts
    
    def _group_by_target(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, List[VulnerabilityFinding]]:
        """Group vulnerabilities by target."""
        groups = {}
        for vuln in vulnerabilities:
            if vuln.target not in groups:
                groups[vuln.target] = []
            groups[vuln.target].append(vuln)
        
        # Sort vulnerabilities within each group by severity and port
        severity_priority = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4, 'unknown': 5}
        
        for target in groups:
            groups[target].sort(key=lambda v: (
                severity_priority.get(v.severity.lower(), 5),
                v.port
            ))
        
        return groups
    
    def _wrap_text(self, text: str, width: int, indent: str = "") -> str:
        """Wrap text to specified width with indentation."""
        if not text:
            return ""
        
        # Simple word wrapping
        words = text.split()
        lines = []
        current_line = []
        current_length = 0
        
        for word in words:
            if current_length + len(word) + 1 <= width:
                current_line.append(word)
                current_length += len(word) + 1
            else:
                if current_line:
                    lines.append(' '.join(current_line))
                current_line = [word]
                current_length = len(word)
        
        if current_line:
            lines.append(' '.join(current_line))
        
        # Add indentation to continuation lines
        if len(lines) > 1:
            result = lines[0]
            for line in lines[1:]:
                result += f"\\n{indent}             {line}"
            return result
        else:
            return lines[0] if lines else ""


class JSONFormatter:
    """Formatter for JSON output."""
    
    def __init__(self, pretty: bool = True):
        """
        Initialize JSON formatter.
        
        Args:
            pretty: Whether to use pretty printing
        """
        self.pretty = pretty
    
    def format_scan_result(self, result: ScanResult) -> str:
        """
        Format scan result as JSON.
        
        Args:
            result: Scan result to format
            
        Returns:
            JSON formatted string
        """
        # Convert to dictionary
        data = {
            'scan_id': result.scan_id,
            'status': result.status.value,
            'start_time': result.start_time,
            'end_time': result.end_time,
            'targets_scanned': result.targets_scanned,
            'vulnerabilities': [asdict(vuln) for vuln in result.vulnerabilities],
            'errors': result.errors,
            'summary': {
                'total_vulnerabilities': len(result.vulnerabilities),
                'severity_counts': self._count_by_severity(result.vulnerabilities)
            }
        }
        
        if self.pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        else:
            return json.dumps(data, ensure_ascii=False)
    
    def _count_by_severity(self, vulnerabilities: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Count vulnerabilities by severity."""
        counts = {}
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            counts[severity] = counts.get(severity, 0) + 1
        return counts


def format_scan_results(result: ScanResult, format_type: str = 'csv', 
                       include_header: bool = True, detailed: bool = True) -> str:
    """
    Format scan results in the specified format.
    
    Args:
        result: Scan result to format
        format_type: Output format ('csv', 'txt', 'json')
        include_header: Whether to include header (CSV only)
        detailed: Whether to include detailed information (TXT only)
        
    Returns:
        Formatted string
        
    Raises:
        ValueError: If format_type is not supported
    """
    if format_type.lower() == 'csv':
        formatter = CSVFormatter(include_header=include_header)
        return formatter.format_scan_result(result)
    
    elif format_type.lower() == 'txt':
        formatter = TXTFormatter(detailed=detailed)
        return formatter.format_scan_result(result)
    
    elif format_type.lower() == 'json':
        formatter = JSONFormatter(pretty=True)
        return formatter.format_scan_result(result)
    
    else:
        raise ValueError(f"Unsupported format type: {format_type}")


def create_summary_report(result: ScanResult) -> str:
    """
    Create a brief summary report of scan results.
    
    Args:
        result: Scan result to summarize
        
    Returns:
        Summary report string
    """
    lines = []
    lines.append("Scan Summary Report")
    lines.append("=" * 25)
    lines.append(f"Scan ID: {result.scan_id}")
    lines.append(f"Status: {result.status.value}")
    lines.append(f"Targets: {result.targets_scanned}")
    lines.append(f"Total Vulnerabilities: {len(result.vulnerabilities)}")
    
    # Severity breakdown
    severity_counts = {}
    for vuln in result.vulnerabilities:
        severity = vuln.severity.lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    if severity_counts:
        lines.append("\\nSeverity Breakdown:")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if severity in severity_counts:
                lines.append(f"  {severity.title()}: {severity_counts[severity]}")
    
    # Top vulnerabilities
    if result.vulnerabilities:
        lines.append("\\nTop Vulnerabilities:")
        high_severity = [v for v in result.vulnerabilities if v.severity.lower() in ['critical', 'high']]
        for vuln in high_severity[:5]:
            lines.append(f"  • {vuln.target}:{vuln.port} - {vuln.name}")
    
    return "\\n".join(lines)


if __name__ == "__main__":
    # Test the formatters
    from ..scanner.openvas_integration import VulnerabilityFinding, ScanResult, ScanStatus
    
    # Create test data
    test_vulns = [
        VulnerabilityFinding(
            target="192.168.1.1",
            port=22,
            protocol="tcp",
            vulnerability_id="CVE-2023-1234",
            name="SSH Weak Encryption",
            severity="medium",
            description="The SSH service supports weak encryption algorithms.",
            solution="Update SSH configuration to disable weak ciphers.",
            cvss_score=5.3,
            cve_ids=["CVE-2023-1234"],
            references=["https://example.com/advisory"]
        ),
        VulnerabilityFinding(
            target="192.168.1.1",
            port=80,
            protocol="tcp",
            vulnerability_id="CVE-2023-5678",
            name="HTTP Server Information Disclosure",
            severity="low",
            description="The HTTP server reveals version information.",
            solution="Configure server to hide version information.",
            cvss_score=2.1,
            cve_ids=["CVE-2023-5678"],
            references=["https://example.com/advisory2"]
        )
    ]
    
    test_result = ScanResult(
        scan_id="test-scan-123",
        status=ScanStatus.COMPLETED,
        start_time="2024-01-01 10:00:00",
        end_time="2024-01-01 10:30:00",
        targets_scanned=1,
        vulnerabilities=test_vulns,
        errors=[]
    )
    
    # Test CSV format
    print("CSV Format:")
    print("-" * 40)
    csv_output = format_scan_results(test_result, 'csv')
    print(csv_output)
    
    # Test TXT format
    print("\\nTXT Format:")
    print("-" * 40)
    txt_output = format_scan_results(test_result, 'txt')
    print(txt_output)
    
    # Test summary
    print("\\nSummary:")
    print("-" * 40)
    summary = create_summary_report(test_result)
    print(summary)

