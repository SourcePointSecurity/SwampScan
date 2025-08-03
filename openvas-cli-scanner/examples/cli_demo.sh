#!/bin/bash
"""
CLI Demonstration Script for OpenVAS CLI Scanner

This script demonstrates various command-line usage patterns for the
OpenVAS CLI Scanner, including different target specifications, port
configurations, and output formats.
"""

set -e  # Exit on any error

# Colors for output
RED='\\033[0;31m'
GREEN='\\033[0;32m'
YELLOW='\\033[1;33m'
BLUE='\\033[0;34m'
NC='\\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}$(printf '=%.0s' {1..50})${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if the scanner is available
check_scanner() {
    print_header "Checking OpenVAS CLI Scanner Installation"
    
    if command -v openvas-cli-scanner &> /dev/null; then
        print_success "OpenVAS CLI Scanner is installed"
        openvas-cli-scanner --version
    else
        print_error "OpenVAS CLI Scanner not found in PATH"
        print_info "Please install the scanner first:"
        echo "  cd /path/to/openvas-cli-scanner"
        echo "  pip install -e ."
        exit 1
    fi
}

# Check OpenVAS installation status
check_openvas_status() {
    print_header "Checking OpenVAS Installation Status"
    
    echo "Running installation check..."
    if openvas-cli-scanner --check-installation; then
        print_success "OpenVAS is properly installed and ready"
    else
        print_warning "OpenVAS installation issues detected"
        print_info "To install missing components:"
        echo "  openvas-cli-scanner --install"
        echo ""
        print_info "Continuing with demo (some examples may fail)..."
    fi
}

# Demonstrate basic help and information commands
demo_help_commands() {
    print_header "Help and Information Commands"
    
    echo "1. Show help:"
    echo "   openvas-cli-scanner --help"
    echo ""
    
    echo "2. Show version:"
    openvas-cli-scanner --version
    echo ""
    
    echo "3. List available service groups:"
    openvas-cli-scanner --list-services
    echo ""
    
    echo "4. List dependencies:"
    openvas-cli-scanner --list-dependencies
    echo ""
}

# Demonstrate target specification
demo_target_specification() {
    print_header "Target Specification Examples"
    
    echo "1. Single IP address:"
    echo "   openvas-cli-scanner 127.0.0.1"
    echo ""
    
    echo "2. Multiple targets:"
    echo "   openvas-cli-scanner 127.0.0.1 localhost"
    echo ""
    
    echo "3. Network range (CIDR):"
    echo "   openvas-cli-scanner 127.0.0.0/30"
    echo ""
    
    echo "4. Target file:"
    echo "   Create targets.txt with:"
    cat > /tmp/demo_targets.txt << EOF
127.0.0.1
localhost
EOF
    echo "   127.0.0.1"
    echo "   localhost"
    echo ""
    echo "   Then scan:"
    echo "   openvas-cli-scanner -f /tmp/demo_targets.txt"
    echo ""
    
    echo "5. Exclude hosts:"
    echo "   openvas-cli-scanner 127.0.0.0/30 --exclude 127.0.0.1"
    echo ""
}

# Demonstrate port specification
demo_port_specification() {
    print_header "Port Specification Examples"
    
    echo "1. Specific ports:"
    echo "   openvas-cli-scanner 127.0.0.1 -p 22,80,443"
    echo ""
    
    echo "2. Port ranges:"
    echo "   openvas-cli-scanner 127.0.0.1 -p 1-1000"
    echo ""
    
    echo "3. Service groups:"
    echo "   openvas-cli-scanner 127.0.0.1 -p web"
    echo "   openvas-cli-scanner 127.0.0.1 -p ssh,web,ftp"
    echo ""
    
    echo "4. All ports:"
    echo "   openvas-cli-scanner 127.0.0.1 --all-ports"
    echo ""
    
    echo "5. Top 100 ports (default):"
    echo "   openvas-cli-scanner 127.0.0.1 -p top100"
    echo ""
}

# Demonstrate output options
demo_output_options() {
    print_header "Output Format Examples"
    
    echo "1. CSV output (default):"
    echo "   openvas-cli-scanner 127.0.0.1 -o results.csv"
    echo ""
    
    echo "2. Text output:"
    echo "   openvas-cli-scanner 127.0.0.1 -o report.txt -F txt"
    echo ""
    
    echo "3. JSON output:"
    echo "   openvas-cli-scanner 127.0.0.1 -o data.json -F json"
    echo ""
    
    echo "4. Console output (no file):"
    echo "   openvas-cli-scanner 127.0.0.1"
    echo ""
    
    echo "5. CSV without header:"
    echo "   openvas-cli-scanner 127.0.0.1 -o results.csv --no-header"
    echo ""
}

# Demonstrate advanced options
demo_advanced_options() {
    print_header "Advanced Options Examples"
    
    echo "1. Custom scan name:"
    echo "   openvas-cli-scanner 127.0.0.1 --scan-name \"My Security Scan\""
    echo ""
    
    echo "2. Verbose logging:"
    echo "   openvas-cli-scanner 127.0.0.1 --verbose"
    echo ""
    
    echo "3. Log to file:"
    echo "   openvas-cli-scanner 127.0.0.1 --log-file scan.log"
    echo ""
    
    echo "4. Custom timeout:"
    echo "   openvas-cli-scanner 127.0.0.1 --timeout 7200  # 2 hours"
    echo ""
    
    echo "5. Quiet mode:"
    echo "   openvas-cli-scanner 127.0.0.1 --quiet --log-file scan.log"
    echo ""
    
    echo "6. OpenVAS method selection:"
    echo "   openvas-cli-scanner 127.0.0.1 --method binary"
    echo "   openvas-cli-scanner 127.0.0.1 --method http"
    echo ""
}

# Run actual scan examples (if OpenVAS is available)
run_scan_examples() {
    print_header "Running Actual Scan Examples"
    
    # Check if we can run scans
    if ! openvas-cli-scanner --check-installation &>/dev/null; then
        print_warning "OpenVAS not ready - skipping actual scan examples"
        return
    fi
    
    print_info "Running safe localhost scans for demonstration..."
    
    echo ""
    echo "Example 1: Basic localhost scan"
    echo "Command: openvas-cli-scanner 127.0.0.1 -p 22,80 --verbose"
    if openvas-cli-scanner 127.0.0.1 -p 22,80 --verbose; then
        print_success "Basic scan completed"
    else
        print_error "Basic scan failed"
    fi
    
    echo ""
    echo "Example 2: Scan with CSV output"
    echo "Command: openvas-cli-scanner 127.0.0.1 -p ssh -o /tmp/demo_results.csv"
    if openvas-cli-scanner 127.0.0.1 -p ssh -o /tmp/demo_results.csv; then
        print_success "CSV output scan completed"
        if [ -f /tmp/demo_results.csv ]; then
            echo "Results saved to /tmp/demo_results.csv:"
            head -5 /tmp/demo_results.csv
            rm -f /tmp/demo_results.csv
        fi
    else
        print_error "CSV output scan failed"
    fi
    
    echo ""
    echo "Example 3: Scan with text output"
    echo "Command: openvas-cli-scanner 127.0.0.1 -p 22 -F txt"
    if openvas-cli-scanner 127.0.0.1 -p 22 -F txt; then
        print_success "Text output scan completed"
    else
        print_error "Text output scan failed"
    fi
}

# Installation examples
demo_installation() {
    print_header "Installation and Setup Examples"
    
    echo "1. Check installation status:"
    echo "   openvas-cli-scanner --check-installation"
    echo ""
    
    echo "2. Install missing components (interactive):"
    echo "   openvas-cli-scanner --install"
    echo ""
    
    echo "3. Non-interactive installation:"
    echo "   openvas-cli-scanner --install --non-interactive"
    echo ""
    
    echo "4. Custom installation prefix:"
    echo "   openvas-cli-scanner --install --install-prefix /opt/openvas"
    echo ""
    
    echo "5. List dependencies:"
    echo "   openvas-cli-scanner --list-dependencies"
    echo ""
}

# Common use cases
demo_use_cases() {
    print_header "Common Use Case Examples"
    
    echo "1. Quick security check of a server:"
    echo "   openvas-cli-scanner 192.168.1.100 -p web,ssh,ftp"
    echo ""
    
    echo "2. Comprehensive network assessment:"
    echo "   openvas-cli-scanner 192.168.1.0/24 -p top100 -o network_scan.csv"
    echo ""
    
    echo "3. Scan specific services across multiple hosts:"
    echo "   openvas-cli-scanner 192.168.1.10 192.168.1.20 192.168.1.30 -p web"
    echo ""
    
    echo "4. Automated scanning with logging:"
    echo "   openvas-cli-scanner -f production_hosts.txt -p all \\"
    echo "     --log-file security_scan.log --quiet -o results.csv"
    echo ""
    
    echo "5. Development environment scan:"
    echo "   openvas-cli-scanner localhost -p 3000,8000,8080,9000 -F txt"
    echo ""
}

# Troubleshooting examples
demo_troubleshooting() {
    print_header "Troubleshooting Examples"
    
    echo "1. Debug mode with verbose logging:"
    echo "   openvas-cli-scanner 127.0.0.1 --verbose --log-file debug.log"
    echo ""
    
    echo "2. Check what's wrong with installation:"
    echo "   openvas-cli-scanner --check-installation"
    echo ""
    
    echo "3. Test connectivity to OpenVAS daemon:"
    echo "   curl http://localhost:3000/health"
    echo ""
    
    echo "4. Force specific integration method:"
    echo "   openvas-cli-scanner 127.0.0.1 --method binary --verbose"
    echo ""
    
    echo "5. Increase timeout for slow networks:"
    echo "   openvas-cli-scanner 192.168.1.0/24 --timeout 14400  # 4 hours"
    echo ""
}

# Main demo function
main() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                OpenVAS CLI Scanner Demo                     ║"
    echo "║              Command Line Usage Examples                    ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    # Check prerequisites
    check_scanner
    echo ""
    check_openvas_status
    echo ""
    
    # Run demonstrations
    demo_help_commands
    echo ""
    demo_target_specification
    echo ""
    demo_port_specification
    echo ""
    demo_output_options
    echo ""
    demo_advanced_options
    echo ""
    demo_installation
    echo ""
    demo_use_cases
    echo ""
    demo_troubleshooting
    echo ""
    
    # Run actual examples if possible
    run_scan_examples
    echo ""
    
    # Cleanup
    rm -f /tmp/demo_targets.txt
    
    print_header "Demo Complete"
    print_success "All examples demonstrated successfully!"
    print_info "Try running the commands shown above to test the scanner."
    echo ""
    print_info "For more information:"
    echo "  - Run: openvas-cli-scanner --help"
    echo "  - Read: README.md"
    echo "  - Check: examples/ directory"
}

# Run the demo
main "$@"

