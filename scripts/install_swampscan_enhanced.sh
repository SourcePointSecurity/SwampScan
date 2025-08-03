#!/bin/bash

# Enhanced SwampScan Installation Script
# This script includes fixes for common installation issues and improved error handling

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Check for sudo privileges
if ! sudo -n true 2>/dev/null; then
    error "This script requires sudo privileges. Please ensure you can run sudo commands."
    exit 1
fi

log "Starting Enhanced SwampScan Installation..."

# Function to fix package manager issues
fix_package_manager() {
    log "Checking and fixing package manager issues..."
    
    # Fix any interrupted dpkg operations
    if sudo dpkg --audit | grep -q "broken"; then
        warning "Fixing interrupted dpkg operations..."
        sudo dpkg --configure -a
        sudo apt-get update
        sudo apt-get -f install -y
    fi
    
    # Update package lists
    sudo apt-get update
    
    success "Package manager is ready"
}

# Function to detect distribution
detect_distribution() {
    log "Detecting operating system distribution..."
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    else
        error "Cannot detect operating system"
        exit 1
    fi
    
    log "Detected: $OS $VER"
    
    # Ensure we support this distribution
    case "$OS" in
        *Ubuntu*|*Debian*|*Kali*)
            log "Supported distribution detected"
            ;;
        *)
            warning "Distribution may not be fully supported, proceeding anyway..."
            ;;
    esac
}

# Function to install system dependencies
install_system_dependencies() {
    log "Installing system dependencies..."
    
    # Core build tools
    local packages=(
        "build-essential"
        "cmake"
        "pkg-config"
        "gcc"
        "make"
        "git"
        "curl"
        "wget"
        "unzip"
    )
    
    # Development libraries
    local dev_packages=(
        "libglib2.0-dev"
        "libjson-glib-dev"
        "libpcap-dev"
        "libgcrypt-dev"
        "libgpgme-dev"
        "libssh-dev"
        "libksba-dev"
        "libgnutls28-dev"
        "libcurl4-gnutls-dev"
        "libxml2-dev"
    )
    
    # Database and services
    local service_packages=(
        "postgresql"
        "postgresql-contrib"
        "redis-server"
    )
    
    # Install packages in groups
    log "Installing core build tools..."
    sudo apt-get install -y "${packages[@]}"
    
    log "Installing development libraries..."
    sudo apt-get install -y "${dev_packages[@]}"
    
    log "Installing database and service packages..."
    sudo apt-get install -y "${service_packages[@]}"
    
    success "System dependencies installed"
}

# Function to install Rust toolchain
install_rust() {
    log "Installing Rust toolchain..."
    
    if command -v rustc &> /dev/null; then
        local rust_version=$(rustc --version)
        log "Rust already installed: $rust_version"
        return 0
    fi
    
    # Install Rust
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source ~/.cargo/env
    
    # Verify installation
    if command -v rustc &> /dev/null; then
        local rust_version=$(rustc --version)
        success "Rust installed: $rust_version"
    else
        error "Rust installation failed"
        exit 1
    fi
}

# Function to setup GVM user and permissions
setup_gvm_user() {
    log "Setting up GVM user and permissions..."
    
    # Create GVM user if it doesn't exist
    if ! id "gvm" &>/dev/null; then
        sudo useradd -r -M -U -G sudo -s /usr/sbin/nologin gvm
        log "Created GVM user"
    else
        log "GVM user already exists"
    fi
    
    # Add current user to GVM group
    sudo usermod -aG gvm $USER
    
    # Create necessary directories
    sudo mkdir -p /var/lib/gvm
    sudo mkdir -p /var/lib/openvas
    sudo mkdir -p /var/log/gvm
    sudo mkdir -p /run/gvmd
    
    # Set proper ownership
    sudo chown -R gvm:gvm /var/lib/gvm
    sudo chown -R gvm:gvm /var/lib/openvas
    sudo chown -R gvm:gvm /var/log/gvm
    sudo chown -R gvm:gvm /run/gvmd
    
    success "GVM user and permissions configured"
}

# Function to configure database
configure_database() {
    log "Configuring PostgreSQL database..."
    
    # Start and enable PostgreSQL
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    
    # Create GVM database user and database
    sudo -u postgres createuser -DRS gvm 2>/dev/null || log "GVM user already exists in PostgreSQL"
    sudo -u postgres createdb -O gvm gvmd 2>/dev/null || log "GVM database already exists"
    
    # Test database connection
    if sudo -u gvm psql gvmd -c "SELECT version();" &>/dev/null; then
        success "Database configured and accessible"
    else
        error "Database configuration failed"
        exit 1
    fi
}

# Function to configure Redis
configure_redis() {
    log "Configuring Redis..."
    
    # Start and enable Redis
    sudo systemctl start redis-server
    sudo systemctl enable redis-server
    
    # Optimize Redis for OpenVAS
    sudo sysctl -w net.core.somaxconn=1024
    sudo sysctl -w vm.overcommit_memory=1
    
    # Test Redis connection
    if redis-cli ping | grep -q "PONG"; then
        success "Redis configured and running"
    else
        error "Redis configuration failed"
        exit 1
    fi
}

# Function to build OpenVAS components
build_openvas() {
    log "Building OpenVAS components..."
    
    # This would typically involve building from source
    # For now, we'll use the existing installation script
    if [ -f "./scripts/install_swampscan.sh" ]; then
        log "Running existing installation script..."
        ./scripts/install_swampscan.sh --skip-deps
    else
        warning "Original installation script not found, skipping OpenVAS build"
    fi
}

# Function to start services
start_services() {
    log "Starting OpenVAS services..."
    
    # Start core services
    sudo systemctl start postgresql
    sudo systemctl start redis-server
    
    # Start OpenVAS daemon if available
    if command -v openvasd &> /dev/null; then
        log "Starting OpenVAS daemon..."
        nohup openvasd --listening 127.0.0.1:3000 > /var/log/gvm/openvasd.log 2>&1 &
        sleep 3
        
        # Test daemon connectivity
        if curl -s http://127.0.0.1:3000/ &>/dev/null; then
            success "OpenVAS daemon started and responding"
        else
            warning "OpenVAS daemon may not be responding yet"
        fi
    fi
}

# Function to sync feeds
sync_feeds() {
    log "Initiating vulnerability feed synchronization..."
    
    warning "Feed synchronization will download ~2GB of data and may take 30-60 minutes"
    read -p "Do you want to start feed synchronization now? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log "Starting feed synchronization in background..."
        
        # Start feed sync in background
        nohup sudo -u gvm greenbone-nvt-sync > /var/log/gvm/feed-sync.log 2>&1 &
        nohup sudo -u gvm greenbone-feed-sync --type GVMD_DATA >> /var/log/gvm/feed-sync.log 2>&1 &
        
        log "Feed synchronization started in background"
        log "Monitor progress with: tail -f /var/log/gvm/feed-sync.log"
    else
        log "Skipping feed synchronization - you can run it later with:"
        log "  sudo -u gvm greenbone-nvt-sync"
        log "  sudo -u gvm greenbone-feed-sync --type GVMD_DATA"
    fi
}

# Function to install SwampScan Python package
install_swampscan() {
    log "Installing SwampScan Python package..."
    
    # Install in development mode
    pip3 install -e .
    
    # Verify installation
    if command -v swampscan &> /dev/null; then
        success "SwampScan installed successfully"
    else
        error "SwampScan installation failed"
        exit 1
    fi
}

# Function to run post-installation tests
run_tests() {
    log "Running post-installation tests..."
    
    # Test SwampScan installation
    log "Testing SwampScan installation..."
    swampscan --version
    
    # Test OpenVAS detection
    log "Testing OpenVAS component detection..."
    swampscan --check-installation
    
    success "Post-installation tests completed"
}

# Function to display final instructions
show_final_instructions() {
    echo
    success "SwampScan installation completed!"
    echo
    echo "Next steps:"
    echo "1. Complete feed synchronization (if not started):"
    echo "   sudo -u gvm greenbone-nvt-sync"
    echo
    echo "2. Test vulnerability scanning:"
    echo "   swampscan scanme.nmap.org -p web -F txt -o test_scan.txt"
    echo
    echo "3. Check installation status:"
    echo "   swampscan --check-installation"
    echo
    echo "4. View logs:"
    echo "   tail -f /var/log/gvm/openvasd.log"
    echo "   tail -f /var/log/gvm/feed-sync.log"
    echo
    echo "For troubleshooting, see: docs/TROUBLESHOOTING.md"
    echo
}

# Main installation function
main() {
    log "Enhanced SwampScan Installation Starting..."
    
    # Pre-installation checks and fixes
    detect_distribution
    fix_package_manager
    
    # Core installation steps
    install_system_dependencies
    install_rust
    setup_gvm_user
    configure_database
    configure_redis
    
    # Build and install SwampScan
    build_openvas
    install_swampscan
    
    # Post-installation setup
    start_services
    sync_feeds
    run_tests
    
    # Final instructions
    show_final_instructions
    
    success "Installation completed successfully!"
}

# Handle script interruption
trap 'error "Installation interrupted"; exit 1' INT TERM

# Run main installation
main "$@"

