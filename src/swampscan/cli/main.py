"""
Main CLI Entry Point

This module provides the main command-line interface for the OpenVAS CLI scanner.
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
            
            # Ensure OpenVAS is available before scanning
            if not self._check_openvas_availability():
                return 1
            
            # Execute scan
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

