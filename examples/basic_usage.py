#!/usr/bin/env python3
"""
Basic Usage Examples for OpenVAS CLI Scanner

This script demonstrates basic usage patterns for the OpenVAS CLI Scanner
including single host scanning, network range scanning, and result processing.
"""

import sys
import os
import logging

# Add the source directory to Python path for development
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import openvas_cli_scanner
from openvas_cli_scanner import (
    quick_scan, scan_network, scan_from_file,
    is_openvas_ready, setup_openvas,
    format_scan_results, create_summary_report
)


def example_1_single_host_scan():
    """Example 1: Scan a single host with default ports."""
    print("Example 1: Single Host Scan")
    print("-" * 40)
    
    target = "127.0.0.1"  # Localhost for safe testing
    
    try:
        print(f"Scanning {target} with default ports...")
        result = quick_scan(target, "22,80,443")
        
        print(f"Scan completed!")
        print(f"Status: {result.status.value}")
        print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
        
        if result.vulnerabilities:
            print("\\nTop vulnerabilities:")
            for vuln in result.vulnerabilities[:3]:
                print(f"  - {vuln.name} ({vuln.severity}) on port {vuln.port}")
        
        return result
        
    except Exception as e:
        print(f"Scan failed: {e}")
        return None


def example_2_network_range_scan():
    """Example 2: Scan a small network range."""
    print("\\nExample 2: Network Range Scan")
    print("-" * 40)
    
    network = "127.0.0.0/30"  # Very small range for testing
    
    try:
        print(f"Scanning network {network}...")
        result = scan_network(network, "ssh,web")
        
        print(f"Scan completed!")
        print(f"Targets scanned: {result.targets_scanned}")
        print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
        
        return result
        
    except Exception as e:
        print(f"Network scan failed: {e}")
        return None


def example_3_target_file_scan():
    """Example 3: Scan targets from a file."""
    print("\\nExample 3: Target File Scan")
    print("-" * 40)
    
    # Create a sample target file
    targets_file = "/tmp/sample_targets.txt"
    with open(targets_file, 'w') as f:
        f.write("127.0.0.1\\n")
        f.write("localhost\\n")
    
    try:
        print(f"Scanning targets from {targets_file}...")
        result = scan_from_file(targets_file, "top100")
        
        print(f"Scan completed!")
        print(f"Vulnerabilities found: {len(result.vulnerabilities)}")
        
        # Clean up
        os.unlink(targets_file)
        
        return result
        
    except Exception as e:
        print(f"File scan failed: {e}")
        if os.path.exists(targets_file):
            os.unlink(targets_file)
        return None


def example_4_advanced_scanning():
    """Example 4: Advanced scanning with custom configuration."""
    print("\\nExample 4: Advanced Scanning")
    print("-" * 40)
    
    try:
        from openvas_cli_scanner import ScannerManager, ScanRequest
        
        # Create custom scan request
        request = ScanRequest(
            targets=["127.0.0.1"],
            ports="22,80,443,8080",
            scan_name="Advanced Example Scan",
            output_file="/tmp/advanced_scan_results.csv",
            output_format="csv",
            verbose=True
        )
        
        print("Creating scanner manager...")
        manager = ScannerManager()
        
        print("Validating scan request...")
        errors = manager.validate_request(request)
        if errors:
            print(f"Validation errors: {errors}")
            return None
        
        print("Executing advanced scan...")
        result = manager.execute_scan(request)
        
        print(f"Advanced scan completed!")
        print(f"Results saved to: {request.output_file}")
        
        # Clean up
        if os.path.exists(request.output_file):
            os.unlink(request.output_file)
        
        return result
        
    except Exception as e:
        print(f"Advanced scan failed: {e}")
        return None


def example_5_result_formatting():
    """Example 5: Different result formatting options."""
    print("\\nExample 5: Result Formatting")
    print("-" * 40)
    
    try:
        # Perform a simple scan
        result = quick_scan("127.0.0.1", "22,80")
        
        if result:
            print("Formatting results in different formats...")
            
            # CSV format
            csv_output = format_scan_results(result, 'csv')
            print(f"CSV format: {len(csv_output.split('\\n'))} lines")
            
            # Text format
            txt_output = format_scan_results(result, 'txt')
            print(f"TXT format: {len(txt_output.split('\\n'))} lines")
            
            # JSON format
            json_output = format_scan_results(result, 'json')
            print(f"JSON format: {len(json_output)} characters")
            
            # Summary report
            summary = create_summary_report(result)
            print("\\nSummary Report:")
            print(summary)
        
    except Exception as e:
        print(f"Result formatting failed: {e}")


def example_6_installation_check():
    """Example 6: Check OpenVAS installation status."""
    print("\\nExample 6: Installation Status Check")
    print("-" * 40)
    
    try:
        print("Checking OpenVAS installation status...")
        
        if is_openvas_ready():
            print("✅ OpenVAS is ready for scanning!")
        else:
            print("❌ OpenVAS is not ready. Installation may be required.")
            
            # Show detailed status
            from openvas_cli_scanner import check_openvas_status, OpenVASDetector
            
            status = check_openvas_status()
            detector = OpenVASDetector()
            summary = detector.get_installation_summary(status)
            
            print("\\nDetailed Status:")
            print(summary)
            
            print("\\nTo install missing components, run:")
            print("  openvas-cli-scanner --install")
    
    except Exception as e:
        print(f"Installation check failed: {e}")


def main():
    """Run all examples."""
    print("OpenVAS CLI Scanner - Basic Usage Examples")
    print("=" * 50)
    
    # Set up logging
    logging.basicConfig(level=logging.WARNING)
    
    # Check installation first
    example_6_installation_check()
    
    # Only run scanning examples if OpenVAS is available
    if is_openvas_ready():
        print("\\n🚀 Running scanning examples...")
        
        # Run examples
        example_1_single_host_scan()
        example_2_network_range_scan()
        example_3_target_file_scan()
        example_4_advanced_scanning()
        example_5_result_formatting()
        
        print("\\n✅ All examples completed successfully!")
    else:
        print("\\n⚠️  Skipping scanning examples - OpenVAS not ready")
        print("Run 'openvas-cli-scanner --install' to set up OpenVAS")
    
    print("\\n" + "=" * 50)
    print("Examples finished. Check the output above for results.")


if __name__ == "__main__":
    main()

