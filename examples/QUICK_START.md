# SwampScan Quick Start Guide

This guide will help you get started with SwampScan vulnerability scanning quickly and effectively.

## Prerequisites

- SwampScan installed and configured
- OpenVAS backend running
- Vulnerability feeds synchronized (at least partially)

## Basic Usage

### 1. Check Installation Status

Before running scans, verify that everything is properly configured:

```bash
swampscan --check-installation
```

Expected output should show all components as available:
```
✅ openvas-scanner (v21.4.3)
✅ openvasd (Available - responds to --help)
✅ scannerctl (Available - responds to --help)
✅ System dependencies
✅ Rust toolchain (v1.88.0)
```

### 2. Your First Scan

Run a basic vulnerability scan on the test target:

```bash
swampscan scanme.nmap.org -p web -F txt -o my_first_scan.txt
```

Parameters:
- `scanme.nmap.org` - Target host (safe test target)
- `-p web` - Scan web services (ports 80, 443, 8080, etc.)
- `-F txt` - Output format (txt, json, xml, html)
- `-o my_first_scan.txt` - Output file

### 3. Comprehensive Network Scan

For a more thorough assessment:

```bash
swampscan 192.168.1.0/24 -p all -F html -o network_scan.html --timeout 3600
```

Parameters:
- `192.168.1.0/24` - Scan entire subnet
- `-p all` - Scan all common ports
- `-F html` - Generate HTML report
- `--timeout 3600` - Set 1-hour timeout

## Scan Types

### Web Application Scanning

Focus on web vulnerabilities:

```bash
# Basic web scan
swampscan example.com -p web -F json -o web_scan.json

# Comprehensive web scan with authentication
swampscan example.com -p web --auth-type basic --username admin --password-file creds.txt
```

### Network Infrastructure Scanning

Scan network devices and services:

```bash
# Router/firewall scan
swampscan 192.168.1.1 -p infrastructure -F xml -o router_scan.xml

# Database server scan
swampscan db.example.com -p database -F txt -o db_scan.txt
```

### Custom Port Scanning

Specify exact ports to scan:

```bash
# Scan specific ports
swampscan target.com -p 22,80,443,3389,5432 -F json -o custom_scan.json

# Scan port range
swampscan target.com -p 1000-2000 -F txt -o port_range_scan.txt
```

## Output Formats

### Text Format (Default)
```bash
swampscan target.com -F txt -o scan.txt
```
- Human-readable format
- Good for quick review
- Easy to parse with scripts

### JSON Format
```bash
swampscan target.com -F json -o scan.json
```
- Machine-readable format
- Good for automation
- Easy integration with other tools

### HTML Format
```bash
swampscan target.com -F html -o scan.html
```
- Professional report format
- Good for presentations
- Includes charts and graphs

### XML Format
```bash
swampscan target.com -F xml -o scan.xml
```
- Structured data format
- Good for data exchange
- Compatible with other security tools

## Advanced Features

### Authenticated Scanning

For deeper vulnerability assessment:

```bash
# SSH key authentication
swampscan target.com --auth-type ssh --ssh-key ~/.ssh/id_rsa --username admin

# Username/password authentication
swampscan target.com --auth-type basic --username admin --password mypassword

# Certificate-based authentication
swampscan target.com --auth-type cert --cert-file client.crt --key-file client.key
```

### Scan Profiles

Use predefined scan configurations:

```bash
# Quick scan (fast, basic checks)
swampscan target.com --profile quick

# Full scan (comprehensive, all tests)
swampscan target.com --profile full

# Compliance scan (regulatory compliance)
swampscan target.com --profile compliance

# Custom profile
swampscan target.com --profile-file my_profile.json
```

### Scheduling Scans

Set up automated scanning:

```bash
# Schedule daily scan
swampscan target.com --schedule daily --time "02:00"

# Schedule weekly scan
swampscan target.com --schedule weekly --day monday --time "01:00"

# One-time scheduled scan
swampscan target.com --schedule once --datetime "2024-01-15 03:00"
```

## Troubleshooting Common Issues

### Issue: "OpenVAS not ready for scanning"

**Solution:**
```bash
# Check service status
sudo systemctl status gvmd ospd-openvas

# Restart services
sudo systemctl restart postgresql redis-server

# Start OpenVAS daemon
openvasd --listening 127.0.0.1:3000 &

# Verify connectivity
curl -s http://127.0.0.1:3000/health
```

### Issue: "No vulnerability tests loaded"

**Solution:**
```bash
# Sync vulnerability feeds
sudo -u gvm greenbone-nvt-sync
sudo -u gvm greenbone-feed-sync --type GVMD_DATA

# Monitor sync progress
tail -f /var/log/gvm/gvmd.log
```

### Issue: Scan takes too long

**Solutions:**
```bash
# Use quick profile
swampscan target.com --profile quick

# Limit port range
swampscan target.com -p 1-1000

# Set shorter timeout
swampscan target.com --timeout 1800

# Scan fewer hosts
swampscan 192.168.1.1-10 instead of 192.168.1.0/24
```

## Best Practices

### 1. Start Small
- Begin with single hosts
- Use quick scans initially
- Gradually increase scope

### 2. Understand Your Network
- Know what you're scanning
- Get proper authorization
- Understand potential impact

### 3. Regular Scanning
- Schedule regular scans
- Monitor for new vulnerabilities
- Track remediation progress

### 4. Report Management
- Use consistent naming conventions
- Archive old reports
- Share results with stakeholders

### 5. Performance Optimization
- Scan during off-hours
- Use appropriate scan profiles
- Monitor system resources

## Example Workflows

### Weekly Security Assessment

```bash
#!/bin/bash
# Weekly security scan script

DATE=$(date +%Y%m%d)
TARGETS="web.company.com db.company.com mail.company.com"

for target in $TARGETS; do
    echo "Scanning $target..."
    swampscan $target -p all -F html -o "weekly_scan_${target}_${DATE}.html"
done

echo "Weekly scans completed. Reports generated."
```

### Compliance Scanning

```bash
#!/bin/bash
# PCI DSS compliance scan

swampscan payment.company.com \
    --profile compliance \
    --standard pci-dss \
    -F xml \
    -o "pci_compliance_$(date +%Y%m%d).xml" \
    --auth-type ssh \
    --ssh-key ~/.ssh/compliance_key \
    --username scanner
```

### Incident Response Scanning

```bash
#!/bin/bash
# Quick incident response scan

INCIDENT_HOST=$1
if [ -z "$INCIDENT_HOST" ]; then
    echo "Usage: $0 <host>"
    exit 1
fi

echo "Running incident response scan on $INCIDENT_HOST"
swampscan $INCIDENT_HOST \
    --profile quick \
    -p all \
    -F json \
    -o "incident_scan_${INCIDENT_HOST}_$(date +%Y%m%d_%H%M).json" \
    --timeout 900

echo "Incident scan completed."
```

## Getting Help

### Command Line Help
```bash
swampscan --help
swampscan scan --help
swampscan --check-installation --help
```

### Log Files
- SwampScan logs: `~/.swampscan/logs/`
- OpenVAS logs: `/var/log/gvm/`
- System logs: `journalctl -u gvmd`

### Documentation
- Full documentation: `docs/`
- Troubleshooting guide: `docs/TROUBLESHOOTING.md`
- API reference: `docs/API.md`

### Support
- GitHub Issues: https://github.com/SourcePointSecurity/SwampScan/issues
- Community Forum: https://community.swampscan.dev
- Email Support: support@swampscan.dev

## Next Steps

1. **Learn Advanced Features**: Explore authentication, custom profiles, and scheduling
2. **Integrate with CI/CD**: Add security scanning to your development pipeline
3. **Automate Reporting**: Set up automated report generation and distribution
4. **Customize Scans**: Create custom scan profiles for your environment
5. **Monitor Trends**: Track vulnerability trends over time

Happy scanning! 🔍🛡️

