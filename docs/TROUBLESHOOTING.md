# SwampScan Troubleshooting Guide

This guide provides solutions to common issues encountered when installing and configuring SwampScan with OpenVAS.

## Table of Contents

1. [Installation Issues](#installation-issues)
2. [OpenVAS Configuration Problems](#openvas-configuration-problems)
3. [Service Detection Issues](#service-detection-issues)
4. [Scanning Problems](#scanning-problems)
5. [Feed Synchronization Issues](#feed-synchronization-issues)
6. [Permission Problems](#permission-problems)
7. [Network and Connectivity Issues](#network-and-connectivity-issues)

## Installation Issues

### Issue: "Unsupported distribution" on Kali Linux

**Symptoms:**
- Installer reports "Unsupported distribution"
- Package manager commands fail

**Solution:**
```bash
# Ensure the installer correctly identifies Kali as Debian-based
sudo apt-get update
sudo apt-get install -y lsb-release

# If dpkg was interrupted, fix it first
sudo dpkg --configure -a
sudo apt-get update
sudo apt-get -f install

# Then retry installation
./scripts/install_swampscan.sh
```

### Issue: Missing Development Libraries

**Symptoms:**
- Compilation errors during OpenVAS build
- "dev-libraries" marked as missing

**Solution:**
```bash
# Install all required development libraries
sudo apt-get update && sudo apt-get install -y \
  cmake \
  libglib2.0-dev \
  libjson-glib-dev \
  libpcap-dev \
  libgcrypt-dev \
  libgpgme-dev \
  libssh-dev \
  libksba-dev \
  libgnutls28-dev \
  libcurl4-gnutls-dev \
  libxml2-dev \
  pkg-config \
  gcc \
  make
```

### Issue: Rust Toolchain Installation Fails

**Symptoms:**
- Rust components fail to build
- `cargo` command not found

**Solution:**
```bash
# Install Rust toolchain manually
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Verify installation
rustc --version
cargo --version

# Retry SwampScan installation
./scripts/install_swampscan.sh
```

## OpenVAS Configuration Problems

### Issue: OpenVAS Services Not Starting

**Symptoms:**
- `systemctl start gvmd` fails
- `systemctl start ospd-openvas` fails
- Services show "failed" status

**Solution:**
```bash
# Check service status and logs
sudo systemctl status gvmd
sudo journalctl -xeu gvmd

# Fix common issues
sudo chown -R gvm:gvm /var/lib/gvm
sudo chown -R gvm:gvm /var/log/gvm
sudo mkdir -p /run/gvmd
sudo chown -R gvm:gvm /run/gvmd

# Restart services
sudo systemctl restart postgresql
sudo systemctl restart redis-server
sudo systemctl restart gvmd
```

### Issue: Database Connection Problems

**Symptoms:**
- "Database connection failed" errors
- GVM database not accessible

**Solution:**
```bash
# Ensure PostgreSQL is running
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create/recreate GVM database
sudo -u postgres dropdb gvmd 2>/dev/null || true
sudo -u postgres dropuser gvm 2>/dev/null || true
sudo -u postgres createuser -DRS gvm
sudo -u postgres createdb -O gvm gvmd

# Test database connection
sudo -u gvm psql gvmd -c "SELECT version();"
```

## Service Detection Issues

### Issue: SwampScan Reports "OpenVAS not ready"

**Symptoms:**
- `swampscan --check-installation` shows missing components
- Components exist but not detected

**Root Cause:**
The installation detector uses incorrect command flags for newer OpenVAS components.

**Solution:**
This has been fixed in the updated detector. The new version:
- Uses `openvas-scanner --version` (correct binary name)
- Uses `openvasd --help` instead of `--version` (not supported)
- Uses `scannerctl --help` instead of `--version` (not supported)
- Marks components as available if binary exists, even if command test fails

### Issue: "Command failed" for openvasd/scannerctl

**Symptoms:**
- `openvasd --version` returns error
- `scannerctl --version` returns error

**Explanation:**
These newer Rust-based tools don't support the `--version` flag in the same way as older tools.

**Verification:**
```bash
# Test the correct commands
openvasd --help
scannerctl --help

# These should work and show help output
```

## Scanning Problems

### Issue: "No vulnerability tests loaded"

**Symptoms:**
- Scans return empty results
- VTS endpoint returns empty array
- "feeds still syncing" message

**Solution:**
```bash
# Complete feed synchronization
sudo -u gvm greenbone-feed-sync --type GVMD_DATA
sudo -u gvm greenbone-feed-sync --type SCAP
sudo -u gvm greenbone-feed-sync --type CERT
sudo -u gvm greenbone-nvt-sync

# This may take 30-60 minutes for initial sync
# Monitor progress:
tail -f /var/log/gvm/gvmd.log
```

### Issue: OpenVAS Daemon Not Responding

**Symptoms:**
- Connection refused to port 3000
- API endpoints not accessible

**Solution:**
```bash
# Check if openvasd is running
ps aux | grep openvasd

# Start openvasd manually if needed
/home/ubuntu/.cargo/bin/openvasd --listening 127.0.0.1:3000 &

# Test connectivity
curl -s http://127.0.0.1:3000/health
```

## Feed Synchronization Issues

### Issue: Feed Sync Permission Denied

**Symptoms:**
- "Permission denied" when syncing feeds
- Cannot create lock files

**Solution:**
```bash
# Fix ownership of OpenVAS directories
sudo chown -R gvm:gvm /var/lib/openvas
sudo chown -R gvm:gvm /var/lib/gvm
sudo chown -R gvm:gvm /var/log/gvm

# Retry feed sync
sudo -u gvm greenbone-nvt-sync
```

### Issue: Feed Sync Takes Too Long

**Symptoms:**
- Sync appears to hang
- Very slow download speeds

**Solution:**
```bash
# Use rsync with verbose output to monitor progress
sudo -u gvm greenbone-nvt-sync --verbose

# For faster sync, ensure good internet connection
# Initial sync downloads ~2GB of vulnerability data
```

## Permission Problems

### Issue: GVM User Permission Errors

**Symptoms:**
- "Permission denied" for GVM operations
- Cannot access GVM directories

**Solution:**
```bash
# Ensure GVM user exists and has correct permissions
sudo useradd -r -M -U -G sudo -s /usr/sbin/nologin gvm 2>/dev/null || true
sudo usermod -aG gvm $USER

# Fix directory permissions
sudo chown -R gvm:gvm /var/lib/gvm
sudo chown -R gvm:gvm /var/lib/openvas
sudo chown -R gvm:gvm /var/log/gvm
sudo chown -R gvm:gvm /run/gvmd

# Create missing directories
sudo mkdir -p /var/lib/gvm
sudo mkdir -p /var/lib/openvas
sudo mkdir -p /var/log/gvm
sudo mkdir -p /run/gvmd
```

## Network and Connectivity Issues

### Issue: Cannot Connect to Feed Servers

**Symptoms:**
- Feed sync fails with connection errors
- "Unable to connect to feed server"

**Solution:**
```bash
# Test connectivity to Greenbone feed server
curl -I http://feed.community.greenbone.net/

# If behind firewall, ensure these are allowed:
# - HTTP/HTTPS outbound connections
# - rsync protocol (port 873)

# Alternative: Use HTTP-based feed sync
export GREENBONE_FEED_SYNC_METHOD=http
sudo -u gvm greenbone-feed-sync --type GVMD_DATA
```

### Issue: Scanner Cannot Reach Targets

**Symptoms:**
- Scans fail with "Host unreachable"
- Network timeouts during scanning

**Solution:**
```bash
# Test basic connectivity
ping scanme.nmap.org
nmap -p 80,443 scanme.nmap.org

# Check firewall rules
sudo iptables -L
sudo ufw status

# Ensure scanner has network access
sudo setcap cap_net_raw+ep /usr/local/bin/openvas-scanner
```

## Advanced Troubleshooting

### Debug Mode

Enable debug logging for detailed troubleshooting:

```bash
# Enable debug logging for SwampScan
export SWAMPSCAN_DEBUG=1
swampscan --check-installation

# Enable debug logging for OpenVAS
sudo -u gvm gvmd --foreground --listen=127.0.0.1 --port=9390 --verbose
```

### Manual Component Testing

Test individual components:

```bash
# Test OpenVAS scanner directly
echo "127.0.0.1" > /tmp/targets.txt
/usr/local/bin/openvas-scanner --target-file /tmp/targets.txt

# Test openvasd API
curl -X GET http://127.0.0.1:3000/vts

# Test database connectivity
sudo -u gvm psql gvmd -c "SELECT COUNT(*) FROM users;"
```

### Log File Locations

Check these log files for detailed error information:

- SwampScan logs: `~/.swampscan/logs/`
- GVM logs: `/var/log/gvm/gvmd.log`
- OpenVAS logs: `/var/log/gvm/openvas.log`
- System logs: `journalctl -xeu gvmd`

## Getting Help

If you continue to experience issues:

1. Check the [GitHub Issues](https://github.com/SourcePointSecurity/SwampScan/issues)
2. Run `swampscan --check-installation` and include output
3. Include relevant log files
4. Specify your operating system and version

## Quick Fix Summary

For most common issues, try this sequence:

```bash
# 1. Fix package manager if needed
sudo dpkg --configure -a
sudo apt-get update
sudo apt-get -f install

# 2. Install missing dependencies
sudo apt-get install -y cmake libglib2.0-dev libjson-glib-dev libpcap-dev \
  libgcrypt-dev libgpgme-dev libssh-dev libksba-dev libgnutls28-dev \
  libcurl4-gnutls-dev pkg-config gcc make

# 3. Fix permissions
sudo chown -R gvm:gvm /var/lib/gvm /var/lib/openvas /var/log/gvm

# 4. Restart services
sudo systemctl restart postgresql redis-server

# 5. Start OpenVAS daemon
/home/ubuntu/.cargo/bin/openvasd --listening 127.0.0.1:3000 &

# 6. Sync feeds
sudo -u gvm greenbone-nvt-sync

# 7. Test installation
swampscan --check-installation
```

This should resolve most installation and configuration issues.

