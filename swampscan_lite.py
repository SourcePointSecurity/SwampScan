#!/usr/bin/env python3
"""
SwampScan Lite - Simplified Vulnerability Scanner

A lightweight version of SwampScan that works with downloaded signature files
without requiring the full OpenVAS backend infrastructure.
"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import List, Dict, Any
import logging

# Import our signature scanner
sys.path.insert(0, str(Path(__file__).parent / "src"))
from swampscan.scanner.signature_scanner import SignatureScanner, ScanResult


class SwampScanLite:
    """Simplified SwampScan using signature files."""
    
    def __init__(self, signature_dir: str = "/var/lib/openvas/plugins"):
        self.scanner = SignatureScanner(signature_dir)
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def scan(self, targets: List[str], ports: List[int] = None, 
             output_format: str = "txt", output_file: str = None,
             max_signatures: int = 1000) -> Dict[str, Any]:
        """Perform vulnerability scan on targets."""
        
        # Load signatures
        print("🔄 Loading vulnerability signatures...")
        loaded = self.scanner.load_signatures(max_signatures=max_signatures)
        
        if loaded == 0:
            print("❌ No vulnerability signatures found!")
            print("   Make sure NASL files are available in the signature directory.")
            return {"error": "No signatures loaded"}
        
        print(f"✅ Loaded {loaded} vulnerability signatures")
        
        # Default ports if not specified
        if ports is None:
            ports = [22, 80, 443, 8080, 8443, 21, 25, 53, 110, 143, 993, 995]
        
        all_results = {}
        
        # Scan each target
        for target in targets:
            print(f"\n🎯 Scanning {target}...")
            start_time = time.time()
            
            results = self.scanner.scan_target(target, ports)
            scan_time = time.time() - start_time
            
            all_results[target] = {
                "scan_time": scan_time,
                "vulnerabilities": [self._result_to_dict(r) for r in results],
                "vulnerability_count": len(results)
            }
            
            print(f"   Completed in {scan_time:.2f} seconds")
            print(f"   Found {len(results)} potential vulnerabilities")
        
        # Generate output
        report = {
            "scan_info": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "targets": targets,
                "ports": ports,
                "signatures_loaded": loaded,
                "scanner": "SwampScan Lite"
            },
            "results": all_results
        }
        
        # Save results
        if output_file:
            self._save_results(report, output_format, output_file)
        else:
            self._print_results(report, output_format)
        
        return report
    
    def _result_to_dict(self, result: ScanResult) -> Dict[str, Any]:
        """Convert ScanResult to dictionary."""
        return {
            "target": result.target,
            "port": result.port,
            "protocol": result.protocol,
            "vulnerability_oid": result.vulnerability_oid,
            "vulnerability_name": result.vulnerability_name,
            "severity": result.severity,
            "cvss_score": result.cvss_score,
            "description": result.description,
            "solution": result.solution,
            "cve_ids": result.cve_ids
        }
    
    def _save_results(self, report: Dict[str, Any], format_type: str, output_file: str):
        """Save scan results to file."""
        output_path = Path(output_file)
        
        if format_type.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        elif format_type.lower() == "txt":
            with open(output_path, 'w') as f:
                self._write_text_report(report, f)
        
        elif format_type.lower() == "csv":
            self._write_csv_report(report, output_path)
        
        print(f"📄 Results saved to {output_path}")
    
    def _print_results(self, report: Dict[str, Any], format_type: str):
        """Print scan results to console."""
        if format_type.lower() == "json":
            print(json.dumps(report, indent=2))
        else:
            self._write_text_report(report, sys.stdout)
    
    def _write_text_report(self, report: Dict[str, Any], file_obj):
        """Write text format report."""
        file_obj.write("SwampScan Lite - Vulnerability Scan Report\n")
        file_obj.write("=" * 50 + "\n\n")
        
        # Scan info
        scan_info = report["scan_info"]
        file_obj.write(f"Scan Date: {scan_info['timestamp']}\n")
        file_obj.write(f"Targets: {', '.join(scan_info['targets'])}\n")
        file_obj.write(f"Ports: {', '.join(map(str, scan_info['ports']))}\n")
        file_obj.write(f"Signatures Loaded: {scan_info['signatures_loaded']}\n\n")
        
        # Results for each target
        for target, target_data in report["results"].items():
            file_obj.write(f"Target: {target}\n")
            file_obj.write("-" * 30 + "\n")
            file_obj.write(f"Scan Time: {target_data['scan_time']:.2f} seconds\n")
            file_obj.write(f"Vulnerabilities Found: {target_data['vulnerability_count']}\n\n")
            
            if target_data["vulnerabilities"]:
                for vuln in target_data["vulnerabilities"]:
                    file_obj.write(f"  Port {vuln['port']}: {vuln['vulnerability_name']}\n")
                    file_obj.write(f"    Severity: {vuln['severity']} (CVSS: {vuln['cvss_score']})\n")
                    file_obj.write(f"    Description: {vuln['description'][:100]}...\n")
                    if vuln['cve_ids']:
                        file_obj.write(f"    CVEs: {', '.join(vuln['cve_ids'])}\n")
                    file_obj.write(f"    Solution: {vuln['solution'][:100]}...\n\n")
            else:
                file_obj.write("  No vulnerabilities detected\n\n")
    
    def _write_csv_report(self, report: Dict[str, Any], output_path: Path):
        """Write CSV format report."""
        import csv
        
        with open(output_path, 'w', newline='') as csvfile:
            fieldnames = [
                'target', 'port', 'protocol', 'vulnerability_name', 
                'severity', 'cvss_score', 'description', 'solution', 'cve_ids'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for target, target_data in report["results"].items():
                for vuln in target_data["vulnerabilities"]:
                    row = {
                        'target': vuln['target'],
                        'port': vuln['port'],
                        'protocol': vuln['protocol'],
                        'vulnerability_name': vuln['vulnerability_name'],
                        'severity': vuln['severity'],
                        'cvss_score': vuln['cvss_score'],
                        'description': vuln['description'],
                        'solution': vuln['solution'],
                        'cve_ids': ', '.join(vuln['cve_ids'])
                    }
                    writer.writerow(row)


def create_parser():
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="SwampScan Lite - Simplified Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s scanme.nmap.org
  %(prog)s 192.168.1.1 -p 80,443,22
  %(prog)s target.com -o scan_results.json -f json
  %(prog)s multiple.targets.com another.target.com -p 1-1000
        """
    )
    
    parser.add_argument(
        "targets",
        nargs="+",
        help="Target hosts to scan (IP addresses or hostnames)"
    )
    
    parser.add_argument(
        "-p", "--ports",
        default="22,80,443,8080,8443",
        help="Ports to scan (default: common ports)"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path"
    )
    
    parser.add_argument(
        "-f", "--format",
        choices=["txt", "json", "csv"],
        default="txt",
        help="Output format (default: txt)"
    )
    
    parser.add_argument(
        "--signature-dir",
        default="/var/lib/openvas/plugins",
        help="Directory containing NASL signature files"
    )
    
    parser.add_argument(
        "--max-signatures",
        type=int,
        default=1000,
        help="Maximum number of signatures to load (default: 1000)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser


def parse_ports(port_string: str) -> List[int]:
    """Parse port specification string."""
    ports = []
    
    for part in port_string.split(','):
        part = part.strip()
        
        if '-' in part:
            # Port range
            start, end = part.split('-', 1)
            try:
                start_port = int(start.strip())
                end_port = int(end.strip())
                ports.extend(range(start_port, end_port + 1))
            except ValueError:
                print(f"Warning: Invalid port range '{part}'")
        else:
            # Single port
            try:
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    print(f"Warning: Port {port} out of range")
            except ValueError:
                print(f"Warning: Invalid port '{part}'")
    
    return sorted(list(set(ports)))  # Remove duplicates and sort


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Parse ports
    ports = parse_ports(args.ports)
    if not ports:
        print("Error: No valid ports specified")
        return 1
    
    # Check signature directory
    sig_dir = Path(args.signature_dir)
    if not sig_dir.exists():
        print(f"Error: Signature directory not found: {sig_dir}")
        print("Make sure NASL signature files are available.")
        return 1
    
    print("🛡️  SwampScan Lite - Simplified Vulnerability Scanner")
    print("=" * 50)
    
    # Initialize scanner
    scanner = SwampScanLite(args.signature_dir)
    
    # Perform scan
    try:
        results = scanner.scan(
            targets=args.targets,
            ports=ports,
            output_format=args.format,
            output_file=args.output,
            max_signatures=args.max_signatures
        )
        
        if "error" in results:
            return 1
        
        print("\n✅ Scan completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())

