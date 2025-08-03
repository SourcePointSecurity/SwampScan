#!/bin/bash

# SwampScan Simple Installation Script
# Installs SwampScan with signature-based scanning (OpenVAS optional)

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_OPENVAS=${INSTALL_OPENVAS:-false}
SIGNATURE_DIR=${SIGNATURE_DIR:-"./signatures"}
PYTHON_MIN_VERSION="3.7"

echo -e "${BLUE}🛡️  SwampScan Simple Installation${NC}"
echo -e "${BLUE}=================================${NC}"
echo ""

# Function to print colored output
print_status() {
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

# Check if running as root
if [[ $EUID -eq 0 ]]; then
    print_warning "Running as root. This is not recommended for normal usage."
fi

# Check Python version
check_python() {
    print_info "Checking Python installation..."
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        print_status "Found Python $PYTHON_VERSION"
        
        # Check if version is sufficient
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 7) else 1)"; then
            print_status "Python version is sufficient"
        else
            print_error "Python 3.7 or higher is required. Found: $PYTHON_VERSION"
            exit 1
        fi
    else
        print_error "Python 3 is not installed"
        print_info "Please install Python 3.7 or higher"
        exit 1
    fi
}

# Install Python dependencies
install_python_deps() {
    print_info "Installing Python dependencies..."
    
    # Check if pip is available
    if ! command -v pip3 &> /dev/null; then
        print_warning "pip3 not found, attempting to install..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3-pip
        else
            print_error "Could not install pip3. Please install it manually."
            exit 1
        fi
    fi
    
    # Install required packages
    pip3 install --user requests pathlib
    print_status "Python dependencies installed"
}

# Install SwampScan
install_swampscan() {
    print_info "Installing SwampScan..."
    
    # Install in development mode
    pip3 install --user -e .
    
    print_status "SwampScan installed successfully"
}

# Download signatures
download_signatures() {
    print_info "Setting up vulnerability signatures..."
    
    if [[ -f "download_signatures.py" ]]; then
        python3 download_signatures.py --target-dir "$SIGNATURE_DIR" --method all
        print_status "Signatures downloaded to $SIGNATURE_DIR"
    else
        print_warning "Signature downloader not found, creating sample signatures..."
        mkdir -p "$SIGNATURE_DIR/samples"
        
        # Create a basic signature file
        cat > "$SIGNATURE_DIR/samples/basic_check.nasl" << 'EOF'
# Basic SwampScan Signature
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999999");
  script_version("2025-01-01");
  script_name("Basic Service Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Service detection");
  script_tag(name:"summary", value:"Basic service detection");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}
# Basic detection logic would go here
EOF
        print_status "Sample signatures created"
    fi
}

# Optional OpenVAS installation
install_openvas_optional() {
    if [[ "$INSTALL_OPENVAS" == "true" ]]; then
        print_info "Installing OpenVAS components (optional)..."
        
        # Detect OS and install OpenVAS
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y openvas gvmd ospd-openvas gsa
        elif command -v yum &> /dev/null; then
            sudo yum install -y openvas-scanner gvmd ospd-openvas gsa
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y openvas-scanner gvmd ospd-openvas gsa
        else
            print_warning "Could not detect package manager for OpenVAS installation"
            print_info "OpenVAS installation skipped - signature-based scanning will be used"
            return
        fi
        
        print_status "OpenVAS components installed"
    else
        print_info "OpenVAS installation skipped (signature-based scanning enabled)"
    fi
}

# Test installation
test_installation() {
    print_info "Testing SwampScan installation..."
    
    if command -v swampscan &> /dev/null; then
        print_status "SwampScan command is available"
        
        # Test help command
        if swampscan --help &> /dev/null; then
            print_status "SwampScan help command works"
        else
            print_warning "SwampScan help command failed"
        fi
        
        # Test signature loading
        if [[ -d "$SIGNATURE_DIR" ]]; then
            print_status "Signature directory exists: $SIGNATURE_DIR"
        else
            print_warning "Signature directory not found: $SIGNATURE_DIR"
        fi
        
    else
        print_error "SwampScan command not found in PATH"
        print_info "Try adding ~/.local/bin to your PATH:"
        print_info "export PATH=\$PATH:~/.local/bin"
    fi
}

# Main installation process
main() {
    echo -e "${BLUE}Starting SwampScan installation...${NC}"
    echo ""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --with-openvas)
                INSTALL_OPENVAS=true
                shift
                ;;
            --signature-dir)
                SIGNATURE_DIR="$2"
                shift 2
                ;;
            --help)
                echo "SwampScan Simple Installation Script"
                echo ""
                echo "Options:"
                echo "  --with-openvas     Install OpenVAS components (optional)"
                echo "  --signature-dir    Directory for signatures (default: ./signatures)"
                echo "  --help            Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Installation steps
    check_python
    install_python_deps
    install_swampscan
    download_signatures
    install_openvas_optional
    test_installation
    
    echo ""
    echo -e "${GREEN}🎉 SwampScan installation completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Quick Start:${NC}"
    echo "  1. Download signatures: swampscan --download-signatures"
    echo "  2. Run a scan: swampscan scanme.nmap.org"
    echo "  3. Check help: swampscan --help"
    echo ""
    
    if [[ "$INSTALL_OPENVAS" == "true" ]]; then
        echo -e "${BLUE}OpenVAS Integration:${NC}"
        echo "  - Use --use-openvas flag to force OpenVAS backend"
        echo "  - Check status: swampscan --check-installation"
        echo ""
    fi
    
    echo -e "${BLUE}Signature Directory:${NC} $SIGNATURE_DIR"
    echo -e "${BLUE}Documentation:${NC} https://github.com/SourcePointSecurity/SwampScan"
}

# Run main function
main "$@"

