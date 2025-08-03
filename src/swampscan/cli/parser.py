"""
CLI Argument Parser

This module provides command-line argument parsing for the OpenVAS CLI scanner.
"""

import argparse
import sys
from typing import List, Optional
from pathlib import Path

from ..utils.network import COMMON_PORTS


class ScannerArgumentParser:
    """Argument parser for the OpenVAS CLI scanner."""
    
    def __init__(self):
        """Initialize the argument parser."""
        self.parser = self._create_parser()
    
    def _create_parser(self) -> argparse.ArgumentParser:
        """Create and configure the argument parser."""
        parser = argparse.ArgumentParser(
            prog='swampscan',
            description='SwampScan - Vulnerability Scanner with Signature-Based Detection (OpenVAS Optional)',
            epilog=self._get_examples(),
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        
        # Target specification
        target_group = parser.add_argument_group('Target Specification')
        target_group.add_argument(
            'targets',
            nargs='*',
            help='Target IP addresses, hostnames, or CIDR ranges'
        )
        target_group.add_argument(
            '-f', '--targets-file',
            type=str,
            help='File containing targets (one per line)'
        )
        target_group.add_argument(
            '--exclude',
            type=str,
            help='Comma-separated list of hosts to exclude'
        )
        
        # Port specification
        port_group = parser.add_argument_group('Port Specification')
        port_group.add_argument(
            '-p', '--ports',
            type=str,
            default='top100',
            help='Port specification (default: top100). Examples: 80,443 | 1-1000 | all | web | ssh'
        )
        port_group.add_argument(
            '-A', '--all-ports',
            action='store_true',
            help='Scan all 65535 ports (equivalent to --ports all)'
        )
        port_group.add_argument(
            '--list-services',
            action='store_true',
            help='List available service port groups and exit'
        )
        
        # Output options
        output_group = parser.add_argument_group('Output Options')
        output_group.add_argument(
            '-o', '--output',
            type=str,
            help='Output file path (default: stdout)'
        )
        output_group.add_argument(
            '-F', '--format',
            choices=['csv', 'txt', 'json'],
            default='csv',
            help='Output format (default: csv)'
        )
        output_group.add_argument(
            '--no-header',
            action='store_true',
            help='Omit header row in CSV output'
        )
        
        # Scan options
        scan_group = parser.add_argument_group('Scan Options')
        scan_group.add_argument(
            '--scan-name',
            type=str,
            help='Custom name for the scan'
        )
        scan_group.add_argument(
            '--timeout',
            type=int,
            default=3600,
            help='Scan timeout in seconds (default: 3600)'
        )
        scan_group.add_argument(
            '--max-concurrent',
            type=int,
            default=1,
            help='Maximum concurrent scans (default: 1)'
        )
        
        # OpenVAS options
        openvas_group = parser.add_argument_group('OpenVAS Options')
        openvas_group.add_argument(
            '--use-openvas',
            action='store_true',
            help='Force use of OpenVAS backend (requires OpenVAS installation)'
        )
        openvas_group.add_argument(
            '--method',
            choices=['auto', 'http', 'binary'],
            default='auto',
            help='OpenVAS integration method (default: auto)'
        )
        openvas_group.add_argument(
            '--openvasd-url',
            type=str,
            default='http://localhost:3000',
            help='OpenVAS daemon URL (default: http://localhost:3000)'
        )
        openvas_group.add_argument(
            '--api-key',
            type=str,
            help='API key for OpenVAS authentication'
        )
        
        # Signature-based scanning options
        signature_group = parser.add_argument_group('Signature-Based Scanning (Default)')
        signature_group.add_argument(
            '--signature-dir',
            type=str,
            default='/var/lib/openvas/plugins',
            help='Directory containing NASL signature files (default: /var/lib/openvas/plugins)'
        )
        signature_group.add_argument(
            '--max-signatures',
            type=int,
            default=1000,
            help='Maximum number of signatures to load (default: 1000)'
        )
        signature_group.add_argument(
            '--download-signatures',
            action='store_true',
            help='Download vulnerability signatures before scanning'
        )
        signature_group.add_argument(
            '--download-method',
            choices=['copy', 'download', 'samples', 'all'],
            default='all',
            help='Signature download method (default: all)'
        )
        signature_group.add_argument(
            '--source-dir',
            type=str,
            default='/var/lib/openvas/plugins',
            help='Source directory for copying existing signatures'
        )
        
        # Installation options
        install_group = parser.add_argument_group('Installation Options')
        install_group.add_argument(
            '--install',
            action='store_true',
            help='Install missing OpenVAS components'
        )
        install_group.add_argument(
            '--check-installation',
            action='store_true',
            help='Check OpenVAS installation status and exit'
        )
        install_group.add_argument(
            '--install-prefix',
            type=str,
            default='/usr/local',
            help='Installation prefix for compiled components (default: /usr/local)'
        )
        install_group.add_argument(
            '--non-interactive',
            action='store_true',
            help='Run installation without user prompts'
        )
        
        # Logging and verbosity
        log_group = parser.add_argument_group('Logging Options')
        log_group.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Enable verbose output'
        )
        log_group.add_argument(
            '-q', '--quiet',
            action='store_true',
            help='Suppress console output (log to file only)'
        )
        log_group.add_argument(
            '--log-file',
            type=str,
            help='Log file path'
        )
        log_group.add_argument(
            '--progress',
            action='store_true',
            help='Show progress information'
        )
        
        # Information options
        info_group = parser.add_argument_group('Information Options')
        info_group.add_argument(
            '--version',
            action='version',
            version='%(prog)s 1.0.0'
        )
        info_group.add_argument(
            '--list-dependencies',
            action='store_true',
            help='List OpenVAS dependencies and exit'
        )
        
        return parser
    
    def _get_examples(self) -> str:
        """Get usage examples for the help text."""
        return '''
Examples:
  # Basic signature-based scanning (default)
  swampscan 192.168.1.1
  swampscan scanme.nmap.org -p 22,80,443
  
  # Download signatures first, then scan
  swampscan --download-signatures --download-method samples
  swampscan 192.168.1.1 --signature-dir ./signatures
  
  # Scan multiple hosts with custom signatures
  swampscan 192.168.1.1 192.168.1.2 --signature-dir ./custom_sigs --max-signatures 500
  
  # Scan a network range with output
  swampscan 192.168.1.0/24 -p web -o results.json -f json
  
  # Scan targets from file
  swampscan -f targets.txt -p all -o report.csv -f csv
  
  # Force OpenVAS backend (requires OpenVAS installation)
  swampscan example.com --use-openvas -p ssh,web -F txt -o report.txt
  
  # Check installation status
  swampscan --check-installation
  
  # Install missing components (OpenVAS)
  swampscan --install
  
  # List available service groups
  swampscan --list-services

Signature Management:
  # Download sample signatures
  swampscan --download-signatures --download-method samples
  
  # Copy existing OpenVAS signatures
  swampscan --download-signatures --download-method copy
  
  # Try all signature sources
  swampscan --download-signatures --download-method all

Available service groups:
  web, ssh, ftp, telnet, smtp, dns, http, https, pop3, imap,
  snmp, ldap, smb, rdp, vnc, mysql, postgresql, mongodb,
  redis, elasticsearch, top100
        '''
    
    def parse_args(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """
        Parse command-line arguments.
        
        Args:
            args: List of arguments (uses sys.argv if None)
            
        Returns:
            Parsed arguments namespace
        """
        parsed_args = self.parser.parse_args(args)
        
        # Post-processing and validation
        self._validate_args(parsed_args)
        self._process_args(parsed_args)
        
        return parsed_args
    
    def _validate_args(self, args: argparse.Namespace):
        """Validate parsed arguments."""
        # Check for conflicting options
        if args.quiet and args.verbose:
            self.parser.error("Cannot use --quiet and --verbose together")
        
        if args.all_ports and args.ports != 'top100':
            self.parser.error("Cannot use --all-ports with --ports")
        
        # Check target specification
        if not args.check_installation and not args.install and not args.list_services and not args.list_dependencies and not args.download_signatures:
            if not args.targets and not args.targets_file:
                self.parser.error("No targets specified. Use targets or --targets-file")
        
        # Check file existence
        if args.targets_file and not Path(args.targets_file).exists():
            self.parser.error(f"Target file not found: {args.targets_file}")
        
        # Check timeout
        if args.timeout <= 0:
            self.parser.error("Timeout must be positive")
        
        # Check max concurrent
        if args.max_concurrent <= 0:
            self.parser.error("Max concurrent must be positive")
    
    def _process_args(self, args: argparse.Namespace):
        """Process and normalize arguments."""
        # Handle --all-ports
        if args.all_ports:
            args.ports = 'all'
        
        # Process exclude hosts
        if args.exclude:
            args.exclude = [host.strip() for host in args.exclude.split(',')]
        else:
            args.exclude = []
        
        # Ensure targets is a list
        if not args.targets:
            args.targets = []
    
    def print_service_groups(self):
        """Print available service groups."""
        print("Available Service Port Groups:")
        print("=" * 40)
        
        for service, ports in COMMON_PORTS.items():
            if service == 'top100':
                print(f"{service:15} : Top 100 most common ports ({len(ports)} ports)")
            else:
                port_list = ','.join(map(str, ports[:5]))
                if len(ports) > 5:
                    port_list += f"... ({len(ports)} total)"
                print(f"{service:15} : {port_list}")
    
    def get_parser(self) -> argparse.ArgumentParser:
        """Get the underlying argument parser."""
        return self.parser


def create_parser() -> ScannerArgumentParser:
    """Create a new scanner argument parser."""
    return ScannerArgumentParser()


def parse_command_line(args: Optional[List[str]] = None) -> argparse.Namespace:
    """
    Parse command-line arguments.
    
    Args:
        args: List of arguments (uses sys.argv if None)
        
    Returns:
        Parsed arguments namespace
    """
    parser = create_parser()
    return parser.parse_args(args)


if __name__ == "__main__":
    # Test the argument parser
    parser = create_parser()
    
    # Test with sample arguments
    test_args = [
        "192.168.1.1",
        "-p", "web",
        "-o", "results.csv",
        "--verbose"
    ]
    
    try:
        args = parser.parse_args(test_args)
        print("Parsed arguments:")
        for key, value in vars(args).items():
            print(f"  {key}: {value}")
    except SystemExit:
        pass
    
    print("\\nService groups:")
    parser.print_service_groups()

