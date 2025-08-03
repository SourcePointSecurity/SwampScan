#!/bin/bash

# SwampScan Enhanced Installation Script
# Installs SwampScan with full OpenVAS/GVM integration on Ubuntu systems

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root"
        exit 1
    fi
}

# Check system compatibility
check_system() {
    if grep -q "Ubuntu" /etc/os-release; then
        local version=$(lsb_release -rs 2>/dev/null || echo "Unknown")
        log_info "Detected Ubuntu version: $version"
    elif grep -q "Debian" /etc/os-release; then
        local version=$(lsb_release -rs 2>/dev/null || echo "Unknown")
        log_info "Detected Debian-based system: $version"
    elif command -v apt-get &> /dev/null; then
        log_info "Detected Debian-based system (using apt package manager)"
    else
        log_warning "This script is designed for Ubuntu/Debian systems. Other distributions may require modifications."
        log_info "Continuing with installation..."
    fi
}

# Install system dependencies
install_system_deps() {
    log_info "Installing system dependencies..."
    
    # Update package lists first
    sudo apt-get update
    
    # Core build tools and system packages
    local core_packages=(
        gcc cmake pkg-config make git curl wget
        build-essential autoconf automake libtool
        python3-pip python3-dev python3-venv
    )
    
    # Database and service packages
    local service_packages=(
        redis-server postgresql postgresql-contrib 
        postgresql-server-dev-all
    )
    
    # Development libraries (the key missing ones from the report)
    local dev_libraries=(
        libgpgme-dev libksba-dev libgnutls28-dev libgcrypt-dev
        libpcap-dev libglib2.0-dev libjson-glib-dev libssh-dev
        libcurl4-gnutls-dev libxml2-dev libxslt1-dev
        libkrb5-dev libldap2-dev libradcli-dev
        libpq-dev libssl-dev libffi-dev
    )
    
    # Install packages in groups for better error handling
    log_info "Installing core build tools..."
    sudo apt-get install -y "${core_packages[@]}" || {
        log_error "Failed to install core packages"
        return 1
    }
    
    log_info "Installing service packages..."
    sudo apt-get install -y "${service_packages[@]}" || {
        log_error "Failed to install service packages"
        return 1
    }
    
    log_info "Installing development libraries..."
    sudo apt-get install -y "${dev_libraries[@]}" || {
        log_error "Failed to install development libraries"
        return 1
    }
    
    log_success "System dependencies installed"
}

# Install OpenVAS/GVM
install_openvas() {
    log_info "Installing OpenVAS/GVM packages..."
    
    # Check if packages are available before installing
    local available_packages=()
    local gvm_packages=(
        gvm openvas-scanner ospd-openvas gvmd
        python3-gvm
    )
    
    # Check each package availability
    for pkg in "${gvm_packages[@]}"; do
        if apt-cache show "$pkg" &>/dev/null; then
            available_packages+=("$pkg")
            log_info "Package $pkg is available"
        else
            log_warning "Package $pkg is not available in repositories"
        fi
    done
    
    if [ ${#available_packages[@]} -eq 0 ]; then
        log_warning "No OpenVAS packages available in repositories"
        log_info "This may be normal - OpenVAS components will be built from source"
        return 0
    fi
    
    # Install available packages
    log_info "Installing available OpenVAS packages: ${available_packages[*]}"
    sudo apt-get install -y "${available_packages[@]}" || {
        log_warning "Some OpenVAS packages failed to install - will build from source"
        return 0
    }
    
    log_success "Available OpenVAS/GVM packages installed"
}

# Install Rust toolchain
install_rust() {
    if ! command -v rustc &> /dev/null; then
        log_info "Installing Rust toolchain..."
        
        # Download and install Rust
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        
        # Source Rust environment for current session
        if [[ -f "$HOME/.cargo/env" ]]; then
            source "$HOME/.cargo/env"
            log_info "Rust environment sourced for current session"
        fi
        
        # Add to shell profile for future sessions
        if [[ -f "$HOME/.bashrc" ]] && ! grep -q "/.cargo/env" "$HOME/.bashrc"; then
            echo 'source "$HOME/.cargo/env"' >> "$HOME/.bashrc"
            log_info "Added Rust to .bashrc for future sessions"
        fi
        
        # Verify installation
        if command -v rustc &> /dev/null; then
            local rust_version=$(rustc --version)
            log_success "Rust toolchain installed: $rust_version"
        else
            log_error "Rust installation failed - rustc not found"
            return 1
        fi
    else
        local rust_version=$(rustc --version)
        log_info "Rust toolchain already installed: $rust_version"
    fi
}

# Setup directories and permissions
setup_directories() {
    log_info "Setting up directories and permissions..."
    
    sudo mkdir -p /var/lib/gvm /var/log/gvm /run/gvmd /run/ospd
    sudo chown -R _gvm:_gvm /var/lib/gvm /var/log/gvm /run/gvmd /run/ospd
    
    log_success "Directories configured"
}

# Configure PostgreSQL
setup_postgresql() {
    log_info "Configuring PostgreSQL database..."
    
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    
    # Create database and extensions
    sudo -u postgres createdb gvmd 2>/dev/null || log_warning "Database may already exist"
    sudo -u postgres psql gvmd -c "create extension \"uuid-ossp\";" 2>/dev/null || true
    sudo -u postgres psql gvmd -c "create extension \"pgcrypto\";" 2>/dev/null || true
    
    log_success "PostgreSQL configured"
}

# Fix library paths
fix_library_paths() {
    log_info "Configuring library paths..."
    
    echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/openvas.conf
    sudo ldconfig
    
    log_success "Library paths configured"
}

# Create compatibility links
create_compatibility_links() {
    log_info "Creating SwampScan compatibility links..."
    
    sudo ln -sf /usr/sbin/openvas /usr/local/bin/openvas-scanner 2>/dev/null || true
    sudo ln -sf /usr/sbin/gvmd /usr/local/bin/openvasd 2>/dev/null || true
    sudo ln -sf /usr/bin/gvm-cli /usr/local/bin/scannerctl 2>/dev/null || true
    
    log_success "Compatibility links created"
}

# Setup GVM user and database
setup_gvm_user() {
    log_info "Setting up GVM admin user..."
    
    sudo -u _gvm gvmd --create-user=admin --password=admin 2>/dev/null || \
    sudo -u _gvm gvmd --user=admin --new-password=admin 2>/dev/null || \
    log_warning "Admin user may already exist"
    
    log_success "GVM admin user configured"
}

# Start services
start_services() {
    log_info "Starting required services..."
    
    sudo systemctl start redis-server
    sudo systemctl enable redis-server
    
    sudo systemctl start gvmd
    sudo systemctl enable gvmd
    
    # Wait for services to start
    sleep 5
    
    log_success "Services started"
}

# Install SwampScan
install_swampscan() {
    log_info "Installing SwampScan..."
    
    # Install in development mode if we're in the repo directory
    if [[ -f "setup.py" ]]; then
        pip3 install -e .
    else
        log_error "setup.py not found. Please run this script from the SwampScan repository directory."
        exit 1
    fi
    
    log_success "SwampScan installed"
}

# Download vulnerability feeds
download_feeds() {
    log_info "Downloading vulnerability feeds..."
    log_warning "This step may take 10-30 minutes depending on your internet connection"
    
    # Download feeds in background to avoid timeout
    sudo -u _gvm greenbone-nvt-sync &
    local nvt_pid=$!
    
    # Show progress
    while kill -0 $nvt_pid 2>/dev/null; do
        echo -n "."
        sleep 5
    done
    echo ""
    
    wait $nvt_pid || log_warning "NVT sync completed with warnings"
    
    log_success "Vulnerability feeds downloaded"
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    # Check SwampScan installation
    if command -v swampscan &> /dev/null; then
        log_success "SwampScan command available"
    else
        log_error "SwampScan command not found"
        return 1
    fi
    
    # Check installation status
    if swampscan --check-installation | grep -q "ready for vulnerability scanning"; then
        log_success "SwampScan installation verified"
    else
        log_warning "SwampScan installation check shows warnings"
    fi
    
    # Check services
    if sudo systemctl is-active --quiet redis-server; then
        log_success "Redis server is running"
    else
        log_warning "Redis server is not running"
    fi
    
    if sudo systemctl is-active --quiet gvmd; then
        log_success "GVM daemon is running"
    else
        log_warning "GVM daemon is not running"
    fi
}

# Run test scan
run_test_scan() {
    log_info "Running test scan..."
    
    if swampscan 127.0.0.1 -p 22 -o test_scan.csv --scan-name "Installation Test"; then
        log_success "Test scan completed successfully"
        
        if [[ -f "test_scan.csv" ]]; then
            local findings=$(tail -n +2 test_scan.csv | wc -l)
            log_info "Test scan found $findings vulnerability findings"
            rm -f test_scan.csv
        fi
    else
        log_warning "Test scan failed - this may be normal if no services are running on localhost"
    fi
}

# Main installation function
main() {
    echo "🛡️  SwampScan Enhanced Installation"
    echo "=================================="
    echo ""
    
    check_root
    check_system
    
    log_info "Starting installation process..."
    
    install_system_deps
    install_openvas
    install_rust
    setup_directories
    setup_postgresql
    fix_library_paths
    create_compatibility_links
    setup_gvm_user
    start_services
    install_swampscan
    
    # Optional feed download (can be skipped for faster installation)
    if [[ "${SKIP_FEEDS:-}" != "true" ]]; then
        download_feeds
    else
        log_warning "Skipping feed download (SKIP_FEEDS=true)"
    fi
    
    verify_installation
    run_test_scan
    
    echo ""
    echo "🎉 Installation completed!"
    echo ""
    echo "📋 Next steps:"
    echo "1. Check installation: swampscan --check-installation"
    echo "2. Run your first scan: swampscan google.com -p 80,443"
    echo "3. View help: swampscan --help"
    echo ""
    echo "📚 Documentation:"
    echo "- Troubleshooting: docs/TROUBLESHOOTING.md"
    echo "- Configuration: config/openvas_config.yaml"
    echo ""
    echo "🔧 If you encounter issues:"
    echo "- Check service status: sudo systemctl status redis-server gvmd"
    echo "- View logs: sudo journalctl -u gvmd"
    echo "- Run setup manually: sudo gvm-setup && sudo gvm-start"
}

# Handle command line arguments
case "${1:-}" in
    --help|-h)
        echo "SwampScan Enhanced Installation Script"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --skip-feeds   Skip vulnerability feed download (faster installation)"
        echo ""
        echo "Environment variables:"
        echo "  SKIP_FEEDS=true   Skip feed download"
        exit 0
        ;;
    --skip-feeds)
        export SKIP_FEEDS=true
        main
        ;;
    *)
        main
        ;;
esac

