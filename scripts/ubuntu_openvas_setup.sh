#!/bin/bash

# SwampScan - Ubuntu OpenVAS Setup Script
# This script sets up OpenVAS/GVM on Ubuntu systems for SwampScan compatibility

set -e

echo "🔧 SwampScan Ubuntu OpenVAS Setup"
echo "=================================="

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   echo "❌ This script should not be run as root"
   exit 1
fi

# Update system packages
echo "📦 Updating system packages..."
sudo apt-get update

# Install system dependencies
echo "🔨 Installing system dependencies..."
sudo apt-get install -y \
    gcc \
    cmake \
    pkg-config \
    redis-server \
    git \
    curl \
    make \
    postgresql \
    postgresql-contrib \
    postgresql-server-dev-all \
    libgpgme-dev \
    libksba-dev \
    libgnutls28-dev \
    libgcrypt-dev \
    libpcap-dev \
    libglib2.0-dev \
    libjson-glib-dev \
    libssh-dev \
    libcurl4-gnutls-dev \
    python3-pip \
    python3-dev

# Install OpenVAS/GVM packages
echo "🛡️ Installing OpenVAS/GVM packages..."
sudo apt-get install -y \
    gvm \
    openvas-scanner \
    ospd-openvas \
    gvmd \
    greenbone-security-assistant \
    python3-gvm

# Install Rust toolchain if not present
if ! command -v rustc &> /dev/null; then
    echo "🦀 Installing Rust toolchain..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Create necessary directories
echo "📁 Creating OpenVAS directories..."
sudo mkdir -p /var/lib/gvm /var/log/gvm /run/gvmd /run/ospd
sudo chown -R _gvm:_gvm /var/lib/gvm /var/log/gvm /run/gvmd /run/ospd

# Setup PostgreSQL database
echo "🗄️ Setting up PostgreSQL database..."
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create GVM database
sudo -u postgres createdb gvmd || echo "Database may already exist"
sudo -u postgres psql gvmd -c "create extension \"uuid-ossp\";" || echo "Extension may already exist"
sudo -u postgres psql gvmd -c "create extension \"pgcrypto\";" || echo "Extension may already exist"

# Initialize GVM database
echo "🔧 Initializing GVM database..."
sudo -u _gvm gvmd --create-user=admin --password=admin || echo "User may already exist"

# Fix library paths for OpenVAS scanner
echo "🔗 Fixing library paths..."
echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/openvas.conf
sudo ldconfig

# Create symbolic links for SwampScan compatibility
echo "🔗 Creating compatibility links..."
sudo ln -sf /usr/sbin/openvas /usr/local/bin/openvas-scanner || true
sudo ln -sf /usr/sbin/gvmd /usr/local/bin/openvasd || true
sudo ln -sf /usr/bin/gvm-cli /usr/local/bin/scannerctl || true

# Start Redis server
echo "🚀 Starting Redis server..."
sudo systemctl start redis-server
sudo systemctl enable redis-server

# Download vulnerability feeds (this may take a while)
echo "📡 Downloading vulnerability feeds..."
echo "⚠️  This step may take 10-30 minutes depending on your internet connection"
sudo -u _gvm greenbone-nvt-sync || echo "NVT sync completed with warnings"

# Start GVM services
echo "🚀 Starting GVM services..."
sudo systemctl start gvmd
sudo systemctl enable gvmd

# Wait for services to start
sleep 5

# Check service status
echo "✅ Checking service status..."
sudo systemctl status redis-server --no-pager || true
sudo systemctl status gvmd --no-pager || true

echo ""
echo "🎉 OpenVAS setup completed!"
echo ""
echo "📋 Next steps:"
echo "1. Install SwampScan: pip3 install -e ."
echo "2. Check installation: swampscan --check-installation"
echo "3. Run a test scan: swampscan 127.0.0.1 -p ssh"
echo ""
echo "⚠️  Note: If services fail to start, try:"
echo "   sudo gvm-setup"
echo "   sudo gvm-start"
echo ""
echo "🔧 Troubleshooting:"
echo "   - Check logs: sudo journalctl -u gvmd"
echo "   - Restart services: sudo systemctl restart gvmd"
echo "   - Verify feeds: sudo -u _gvm gvm-check-setup"

