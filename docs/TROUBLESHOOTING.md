# SwampScan Troubleshooting Guide

This guide covers common issues and solutions for SwampScan installation and operation, particularly with Ubuntu OpenVAS/GVM integration.

## 🚨 Common Installation Issues

### 1. "System requires additional setup" Error

**Symptoms:**
```
❌ System requires additional setup.
Run with --install to automatically install missing components.
```

**Cause:** SwampScan's validation logic is too strict for Ubuntu package-based OpenVAS installations.

**Solution:** This has been fixed in the latest version. The validation logic now properly recognizes Ubuntu OpenVAS installations.

**Manual Fix (if needed):**
```bash
# Ensure symbolic links exist
sudo ln -sf /usr/sbin/openvas /usr/local/bin/openvas-scanner
sudo ln -sf /usr/sbin/gvmd /usr/local/bin/openvasd  
sudo ln -sf /usr/bin/gvm-cli /usr/local/bin/scannerctl
```

### 2. "Missing libraries: libgpgme, libksba" Warning

**Symptoms:**
```
❌ dev-libraries
    ⚠️  Missing libraries: libgpgme, libksba
```

**Cause:** Development libraries not installed or not detected by pkg-config.

**Solution:**
```bash
sudo apt-get install -y libgpgme-dev libksba-dev libgnutls28-dev
```

### 3. OpenVAS Scanner Library Issues

**Symptoms:**
```
/usr/sbin/openvas: error while loading shared libraries
```

**Cause:** Library path not configured for OpenVAS scanner.

**Solution:**
```bash
# Add library path
echo "/usr/lib64" | sudo tee /etc/ld.so.conf.d/openvas.conf
sudo ldconfig

# Verify fix
/usr/sbin/openvas --help
```

## 🔧 Service Configuration Issues

### 1. GVM Services Not Starting

**Symptoms:**
```
● gvmd.service - failed to start
● ospd-openvas.service - failed to start
```

**Diagnosis:**
```bash
# Check service status
sudo systemctl status gvmd ospd-openvas redis-server

# Check logs
sudo journalctl -u gvmd --no-pager -n 20
sudo journalctl -u ospd-openvas --no-pager -n 20
```

**Solutions:**

**PostgreSQL Database Issues:**
```bash
# Ensure PostgreSQL is running
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Recreate database if needed
sudo -u postgres dropdb gvmd
sudo -u postgres createdb gvmd
sudo -u postgres psql gvmd -c "create extension \"uuid-ossp\";"
sudo -u postgres psql gvmd -c "create extension \"pgcrypto\";"
```

**Permission Issues:**
```bash
# Fix ownership
sudo chown -R _gvm:_gvm /var/lib/gvm /var/log/gvm /run/gvmd /run/ospd

# Create missing directories
sudo mkdir -p /var/lib/gvm /var/log/gvm /run/gvmd /run/ospd
```

**Feed Synchronization:**
```bash
# Download vulnerability feeds
sudo -u _gvm greenbone-nvt-sync
sudo -u _gvm greenbone-feed-sync --type SCAP
sudo -u _gvm greenbone-feed-sync --type CERT
```

### 2. Socket Connection Issues

**Symptoms:**
```
Socket /var/run/gvm/gvmd.sock does not exist
```

**Solution:**
```bash
# Restart GVM services
sudo systemctl restart gvmd
sudo systemctl restart ospd-openvas

# Wait for socket creation
sleep 5

# Verify socket exists
ls -la /var/run/gvm/gvmd.sock
```

### 3. Authentication Failures

**Symptoms:**
```
GVM authentication failed
```

**Solution:**
```bash
# Create/reset admin user
sudo -u _gvm gvmd --create-user=admin --password=admin

# Or modify existing user
sudo -u _gvm gvmd --user=admin --new-password=admin
```

## 🐛 Scanning Issues

### 1. "No valid IP addresses found in targets"

**Symptoms:**
```
Scan execution failed: No valid IP addresses found in targets
```

**Cause:** Target parsing issue with comma-separated targets.

**Solution:**
```bash
# Use individual scans instead of comma-separated
swampscan target1.com -p 80
swampscan target2.com -p 80

# Or use file-based targets
echo -e "target1.com\ntarget2.com" > targets.txt
swampscan -f targets.txt -p 80
```

### 2. "Invalid port" Errors

**Symptoms:**
```
Invalid port 'ssh': invalid literal for int() with base 10: 'ssh'
```

**Cause:** Port name not recognized by port parser.

**Solution:**
```bash
# Use numeric ports
swampscan target.com -p 22,80,443

# Or use predefined port sets
swampscan target.com -p top100
swampscan target.com -p web
```

### 3. Scan Timeouts

**Symptoms:**
```
Scan timed out after 1 hour
```

**Solutions:**
```bash
# Reduce port range
swampscan target.com -p top100

# Use faster scan methods
swampscan target.com -p 80,443 --timeout 300
```

## 🔍 Diagnostic Commands

### System Status Check
```bash
# Check SwampScan installation
swampscan --check-installation

# Check OpenVAS components
sudo gvm-check-setup

# Verify services
sudo systemctl status redis-server gvmd ospd-openvas
```

### Service Management
```bash
# Start all services
sudo gvm-start

# Stop all services  
sudo gvm-stop

# Restart individual services
sudo systemctl restart gvmd
sudo systemctl restart ospd-openvas
sudo systemctl restart redis-server
```

### Log Analysis
```bash
# GVM daemon logs
sudo journalctl -u gvmd --follow

# OpenVAS scanner logs
sudo journalctl -u ospd-openvas --follow

# SwampScan logs (if verbose mode)
swampscan target.com -p 80 --verbose
```

## 🛠️ Manual Recovery Procedures

### Complete OpenVAS Reset
```bash
# Stop all services
sudo gvm-stop

# Remove data (CAUTION: This deletes all scan data)
sudo rm -rf /var/lib/gvm/*

# Reinitialize
sudo gvm-setup

# Start services
sudo gvm-start
```

### Database Recovery
```bash
# Backup existing database
sudo -u postgres pg_dump gvmd > gvmd_backup.sql

# Drop and recreate
sudo -u postgres dropdb gvmd
sudo -u postgres createdb gvmd
sudo -u postgres psql gvmd -c "create extension \"uuid-ossp\";"
sudo -u postgres psql gvmd -c "create extension \"pgcrypto\";"

# Initialize GVM
sudo -u _gvm gvmd --create-user=admin --password=admin
```

### Feed Refresh
```bash
# Force feed update
sudo -u _gvm greenbone-nvt-sync --rsync
sudo -u _gvm greenbone-feed-sync --type SCAP --rsync  
sudo -u _gvm greenbone-feed-sync --type CERT --rsync

# Check feed status
sudo -u _gvm gvm-check-setup
```

## 📞 Getting Help

### Log Collection
When reporting issues, please include:

```bash
# System information
uname -a
lsb_release -a

# SwampScan version
swampscan --version

# Installation status
swampscan --check-installation

# Service status
sudo systemctl status redis-server gvmd ospd-openvas --no-pager

# Recent logs
sudo journalctl -u gvmd --no-pager -n 50
sudo journalctl -u ospd-openvas --no-pager -n 50
```

### Common Environment Info
```bash
# Python environment
python3 --version
pip3 list | grep -E "(gvm|openvas)"

# OpenVAS components
which openvas gvmd gvm-cli
/usr/sbin/openvas --version
gvmd --version
```

### Support Resources
- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: Check the latest docs for updates
- **Community**: Join discussions for community support

## ✅ Verification Steps

After applying fixes, verify everything works:

```bash
# 1. Check installation
swampscan --check-installation
# Should show: "✅ System is ready for vulnerability scanning!"

# 2. Test basic scan
swampscan 127.0.0.1 -p 22 -o test_scan.csv

# 3. Verify output
cat test_scan.csv
# Should contain vulnerability findings

# 4. Test external scan
swampscan google.com -p 80,443 -o external_test.csv
```

If all steps complete successfully, SwampScan is properly configured and ready for use.

