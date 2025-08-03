"""
Main CLI Entry Point

This module provides the main command-line interface for SwampScan.
Now supports both OpenVAS integration and standalone signature-based scanning.
"""

import sys
import time
import logging
from typing import Optional, List
from pathlib import Path

# Handle both package and direct execution
try:
    from .parser import create_parser
    from ..utils.logging import setup_logging, get_logger, log_scan_start, log_scan_complete
    from ..scanner.manager import ScannerManager, ScanRequest
    from ..scanner.signature_scanner import SignatureScanner
    from ..installation import (
        setup_openvas, 
        check_openvas_status, 
        print_dependency_info,
        OpenVASDetector
    )
except ImportError:
    # Direct execution - add parent directories to path
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    parent_dir = os.path.dirname(current_dir)
    grandparent_dir = os.path.dirname(parent_dir)
    sys.path.insert(0, grandparent_dir)
    
    from swampscan.cli.parser import create_parser
    from swampscan.utils.logging import setup_logging, get_logger, log_scan_start, log_scan_complete
    from swampscan.scanner.manager import ScannerManager, ScanRequest
    from swampscan.scanner.signature_scanner import SignatureScanner
    from swampscan.installation import (
        setup_openvas, 
        check_openvas_status, 
        print_dependency_info,
        OpenVASDetector
    )


class CLIApplication:
    """Main CLI application class."""
    
    def __init__(self):
        """Initialize the CLI application."""
        self.parser = create_parser()
        self.logger = None
        self.scanner_manager = None
    
    def run(self, args: Optional[List[str]] = None) -> int:
        """
        Run the CLI application.
        
        Args:
            args: Command-line arguments (uses sys.argv if None)
            
        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            # Parse arguments
            parsed_args = self.parser.parse_args(args)
            
            # Set up logging
            setup_logging(
                verbose=parsed_args.verbose,
                log_file=parsed_args.log_file,
                quiet=parsed_args.quiet
            )
            self.logger = get_logger()
            
            # Handle special commands that don't require scanning
            if parsed_args.list_services:
                self.parser.print_service_groups()
                return 0
            
            if parsed_args.list_dependencies:
                print_dependency_info()
                return 0
            
            if parsed_args.check_installation:
                return self._handle_check_installation()
            
            if parsed_args.install:
                return self._handle_installation(parsed_args)
            
            # Check for signature download request
            if hasattr(parsed_args, 'download_signatures') and parsed_args.download_signatures:
                return self._handle_signature_download(parsed_args)
            
            # Execute scan (signature-based by default, OpenVAS if available)
            return self._handle_scan(parsed_args)
            
        except KeyboardInterrupt:
            print("\\n\\nScan interrupted by user")
            return 130
        except Exception as e:
            if self.logger:
                self.logger.error(f"Application error: {e}")
            else:
                print(f"Error: {e}", file=sys.stderr)
            return 1
    
    def _handle_check_installation(self) -> int:
        """Handle installation status check."""
        print("Checking OpenVAS installation status...")
        print()
        
        try:
            status = check_openvas_status()
            detector = OpenVASDetector()
            summary = detector.get_installation_summary(status)
            print(summary)
            
            if status.ready_for_scanning:
                print("\\n✅ System is ready for vulnerability scanning!")
                return 0
            else:
                print("\\n❌ System requires additional setup.")
                print("Run with --install to automatically install missing components.")
                return 1
                
        except Exception as e:
            print(f"❌ Installation check failed: {e}")
            return 1
    
    def _handle_installation(self, args) -> int:
        """Handle OpenVAS installation."""
        print("Starting OpenVAS installation...")
        print()
        
        try:
            interactive = not args.non_interactive
            success = setup_openvas(
                interactive=interactive,
                install_prefix=args.install_prefix
            )
            
            if success:
                print("\\n🎉 OpenVAS installation completed successfully!")
                return 0
            else:
                print("\\n❌ OpenVAS installation failed.")
                print("Please check the error messages above and resolve any issues.")
                return 1
                
        except Exception as e:
            print(f"❌ Installation failed: {e}")
            return 1
    
    def _check_openvas_availability(self) -> bool:
        """Check if OpenVAS is available for scanning."""
        try:
            status = check_openvas_status()
            
            if status.ready_for_scanning:
                return True
            
            self.logger.error("OpenVAS is not ready for scanning")
            print("❌ OpenVAS is not properly installed or configured.")
            print("Run with --check-installation to see detailed status.")
            print("Run with --install to automatically install missing components.")
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to check OpenVAS availability: {e}")
            print(f"❌ Failed to check OpenVAS status: {e}")
            return False
    
    def _handle_scan(self, args) -> int:
        """Handle vulnerability scanning with signature-based approach."""
        try:
            # Determine scanning method
            use_openvas = hasattr(args, 'use_openvas') and args.use_openvas
            signature_dir = getattr(args, 'signature_dir', '/var/lib/openvas/plugins')
            
            if use_openvas and self._check_openvas_availability():
                return self._handle_openvas_scan(args)
            else:
                return self._handle_signature_scan(args, signature_dir)
                
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            print(f"❌ Scan failed: {e}")
            return 1
    
    def _handle_signature_scan(self, args, signature_dir: str) -> int:
        """Handle signature-based vulnerability scanning."""
        print("🛡️  SwampScan - Signature-Based Vulnerability Scanner")
        print("=" * 55)
        
        # Initialize signature scanner
        scanner = SignatureScanner(signature_dir)
        
        # Load signatures
        max_signatures = getattr(args, 'max_signatures', 1000)
        print("🔄 Loading vulnerability signatures...")
        loaded = scanner.load_signatures(max_signatures=max_signatures)
        
        if loaded == 0:
            print("❌ No vulnerability signatures found!")
            print(f"   Signature directory: {signature_dir}")
            print("   Try downloading signatures with: swampscan --download-signatures")
            return 1
        
        print(f"✅ Loaded {loaded} vulnerability signatures")
        
        # Parse targets and ports
        targets = args.targets if hasattr(args, 'targets') else []
        if hasattr(args, 'targets_file') and args.targets_file:
            with open(args.targets_file, 'r') as f:
                targets.extend([line.strip() for line in f if line.strip()])
        
        if not targets:
            print("❌ No targets specified")
            return 1
        
        # Parse ports
        ports = self._parse_ports(getattr(args, 'ports', '22,80,443,8080,8443'))
        
        # Scan each target
        all_results = {}
        total_vulnerabilities = 0
        
        for target in targets:
            print(f"\n🎯 Scanning {target}...")
            start_time = time.time()
            
            results = scanner.scan_target(target, ports)
            scan_time = time.time() - start_time
            
            all_results[target] = {
                "scan_time": scan_time,
                "vulnerabilities": results,
                "vulnerability_count": len(results)
            }
            
            total_vulnerabilities += len(results)
            print(f"   Completed in {scan_time:.2f} seconds")
            print(f"   Found {len(results)} potential vulnerabilities")
        
        # Generate report
        report = {
            "scan_info": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "targets": targets,
                "ports": ports,
                "signatures_loaded": loaded,
                "scanner": "SwampScan Signature-Based"
            },
            "results": all_results,
            "summary": {
                "total_targets": len(targets),
                "total_vulnerabilities": total_vulnerabilities,
                "scan_duration": sum(data["scan_time"] for data in all_results.values())
            }
        }
        
        # Output results
        output_file = getattr(args, 'output', None)
        output_format = getattr(args, 'format', 'txt')
        
        if output_file:
            self._save_signature_results(report, output_format, output_file)
            print(f"\n📄 Results saved to: {output_file}")
        else:
            self._print_signature_results(report, output_format)
        
        print(f"\n✅ Scan completed successfully!")
        print(f"📊 Summary: {len(targets)} targets, {total_vulnerabilities} vulnerabilities found")
        
        return 0
    
    def _handle_openvas_scan(self, args) -> int:
        """Handle vulnerability scanning."""
        try:
            # Create scan request
            request = self._create_scan_request(args)
            
            # Validate request
            self.scanner_manager = ScannerManager()
            errors = self.scanner_manager.validate_request(request)
            
            if errors:
                self.logger.error("Scan request validation failed")
                for error in errors:
                    print(f"❌ {error}")
                return 1
            
            # Log scan start
            log_scan_start(
                targets=request.targets + ([request.target_file] if request.target_file else []),
                ports=request.ports,
                output_file=request.output_file or "stdout"
            )
            
            # Execute scan
            start_time = time.time()
            result = self.scanner_manager.execute_scan(request)
            end_time = time.time()
            duration = end_time - start_time
            
            # Log completion
            log_scan_complete(duration, len(result.vulnerabilities))
            
            # Generate and save output
            if request.output_file:
                self._save_results(result, request, duration)
                print(f"\\n📄 Results saved to: {request.output_file}")
            else:
                self._print_results(result, request)
            
            # Print summary
            targets_count = len(request.targets) + (1 if request.target_file else 0)
            ports_count = len(self.scanner_manager._parse_ports(request.ports).ports)
            summary = self.scanner_manager.get_scan_summary(
                result, targets_count, ports_count, duration
            )
            self.scanner_manager.print_scan_summary(summary)
            
            # Return appropriate exit code
            if result.vulnerabilities:
                return 0  # Vulnerabilities found (success)
            else:
                return 0  # No vulnerabilities (also success)
                
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            print(f"❌ Scan failed: {e}")
            return 1
    
    def _create_scan_request(self, args) -> ScanRequest:
        """Create scan request from parsed arguments."""
        return ScanRequest(
            targets=args.targets,
            target_file=args.targets_file,
            ports=args.ports,
            output_file=args.output,
            output_format=args.format,
            scan_name=args.scan_name,
            exclude_hosts=args.exclude,
            max_concurrent=args.max_concurrent,
            timeout=args.timeout,
            verbose=args.verbose
        )
    
    def _save_results(self, result, request, duration):
        """Save scan results to file."""
        from ..output.formatters import format_scan_results
        
        try:
            formatted_output = format_scan_results(
                result, 
                format_type=request.output_format,
                include_header=not getattr(request, 'no_header', False)
            )
            
            output_path = Path(request.output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(formatted_output)
            
            self.logger.info(f"Results saved to {output_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save results: {e}")
            raise
    
    def _print_results(self, result, request):
        """Print scan results to stdout."""
        from ..output.formatters import format_scan_results
        
        try:
            formatted_output = format_scan_results(
                result,
                format_type=request.output_format,
                include_header=True
            )
            
            print("\\n" + "=" * 60)
            print("SCAN RESULTS")
            print("=" * 60)
            print(formatted_output)
            
        except Exception as e:
            self.logger.error(f"Failed to format results: {e}")
            # Fallback to simple output
            print(f"\\nFound {len(result.vulnerabilities)} vulnerabilities:")
            for vuln in result.vulnerabilities[:10]:  # Show first 10
                print(f"  {vuln.target}:{vuln.port} - {vuln.name} ({vuln.severity})")
            if len(result.vulnerabilities) > 10:
                print(f"  ... and {len(result.vulnerabilities) - 10} more")
    
    def _parse_ports(self, port_string: str) -> List[int]:
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
                    self.logger.warning(f"Invalid port range '{part}'")
            else:
                # Single port
                try:
                    port = int(part)
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        self.logger.warning(f"Port {port} out of range")
                except ValueError:
                    self.logger.warning(f"Invalid port '{part}'")
        
        return sorted(list(set(ports)))  # Remove duplicates and sort
    
    def _save_signature_results(self, report: dict, format_type: str, output_file: str):
        """Save signature scan results to file."""
        import json
        import csv
        from pathlib import Path
        
        output_path = Path(output_file)
        
        if format_type.lower() == "json":
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
        
        elif format_type.lower() == "txt":
            with open(output_path, 'w') as f:
                self._write_text_report(report, f)
        
        elif format_type.lower() == "csv":
            self._write_csv_report(report, output_path)
    
    def _print_signature_results(self, report: dict, format_type: str):
        """Print signature scan results to console."""
        import json
        import sys
        
        if format_type.lower() == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            self._write_text_report(report, sys.stdout)
    
    def _write_text_report(self, report: dict, file_obj):
        """Write text format report."""
        file_obj.write("SwampScan - Vulnerability Scan Report\\n")
        file_obj.write("=" * 50 + "\\n\\n")
        
        # Scan info
        scan_info = report["scan_info"]
        file_obj.write(f"Scan Date: {scan_info['timestamp']}\\n")
        file_obj.write(f"Targets: {', '.join(scan_info['targets'])}\\n")
        file_obj.write(f"Ports: {', '.join(map(str, scan_info['ports']))}\\n")
        file_obj.write(f"Signatures Loaded: {scan_info['signatures_loaded']}\\n\\n")
        
        # Results for each target
        for target, target_data in report["results"].items():
            file_obj.write(f"Target: {target}\\n")
            file_obj.write("-" * 30 + "\\n")
            file_obj.write(f"Scan Time: {target_data['scan_time']:.2f} seconds\\n")
            file_obj.write(f"Vulnerabilities Found: {target_data['vulnerability_count']}\\n\\n")
            
            if target_data["vulnerabilities"]:
                for vuln in target_data["vulnerabilities"]:
                    file_obj.write(f"  Port {vuln.port}: {vuln.vulnerability_name}\\n")
                    file_obj.write(f"    Severity: {vuln.severity} (CVSS: {vuln.cvss_score})\\n")
                    file_obj.write(f"    Description: {vuln.description[:100]}...\\n")
                    if vuln.cve_ids:
                        file_obj.write(f"    CVEs: {', '.join(vuln.cve_ids)}\\n")
                    file_obj.write(f"    Solution: {vuln.solution[:100]}...\\n\\n")
            else:
                file_obj.write("  No vulnerabilities detected\\n\\n")
    
    def _write_csv_report(self, report: dict, output_path: Path):
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
                        'target': vuln.target,
                        'port': vuln.port,
                        'protocol': vuln.protocol,
                        'vulnerability_name': vuln.vulnerability_name,
                        'severity': vuln.severity,
                        'cvss_score': vuln.cvss_score,
                        'description': vuln.description,
                        'solution': vuln.solution,
                        'cve_ids': ', '.join(vuln.cve_ids)
                    }
                    writer.writerow(row)
    
    def _handle_signature_download(self, args) -> int:
        """Handle signature download request."""
        print("📥 SwampScan Signature Downloader")
        print("=" * 40)
        
        # Import the downloader
        import sys
        from pathlib import Path
        
        # Add the download script to path
        script_dir = Path(__file__).parent.parent.parent.parent
        sys.path.insert(0, str(script_dir))
        
        try:
            from download_signatures import SignatureDownloader
            
            target_dir = getattr(args, 'signature_dir', './signatures')
            source_dir = getattr(args, 'source_dir', '/var/lib/openvas/plugins')
            method = getattr(args, 'download_method', 'all')
            
            downloader = SignatureDownloader(target_dir)
            success = False
            
            if method in ["copy", "all"]:
                print("\\n1. Trying to copy existing signatures...")
                if downloader.copy_existing_signatures(source_dir):
                    success = True
                else:
                    print("   No existing signatures found to copy")
            
            if method in ["download", "all"]:
                print("\\n2. Trying to download from official feeds...")
                if downloader.download_greenbone_community_feed():
                    success = True
                else:
                    print("   Official feed download not available")
            
            if method in ["samples", "all"] or not success:
                print("\\n3. Creating sample signatures...")
                if downloader.download_sample_signatures():
                    success = True
            
            if success:
                print(f"\\n✅ Signatures are ready in: {target_dir}")
                print(f"   Use with: swampscan --signature-dir {target_dir}")
                return 0
            else:
                print("\\n❌ Failed to obtain any signatures")
                return 1
                
        except ImportError as e:
            print(f"❌ Failed to import signature downloader: {e}")
            print("   Make sure download_signatures.py is available")
            return 1


def main(args: Optional[List[str]] = None) -> int:
    """
    Main entry point for the CLI application.
    
    Args:
        args: Command-line arguments (uses sys.argv if None)
        
    Returns:
        Exit code
    """
    app = CLIApplication()
    return app.run(args)


def console_entry_point():
    """Console script entry point."""
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())

