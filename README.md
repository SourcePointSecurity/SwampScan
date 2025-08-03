<div align="center">

![SwampScan Logo](swampscan_logo.png)

# SwampScan
### Advanced Vulnerability Scanner

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub release](https://img.shields.io/github/release/SourcePointSecurity/SwampScan.svg)](https://github.com/SourcePointSecurity/SwampScan/releases)
[![GitHub issues](https://img.shields.io/github/issues/SourcePointSecurity/SwampScan.svg)](https://github.com/SourcePointSecurity/SwampScan/issues)
[![GitHub stars](https://img.shields.io/github/stars/SourcePointSecurity/SwampScan.svg)](https://github.com/SourcePointSecurity/SwampScan/stargazers)

*Lurking in the depths of your network, hunting vulnerabilities with the stealth of a swamp predator*

[🚀 Quick Start](#-quick-start) • [📖 Documentation](#-documentation) • [🔧 Installation](#-installation) • [💡 Examples](#-examples)

</div>

---

## 🐊 About SwampScan

SwampScan is a powerful Python command-line vulnerability scanner that integrates seamlessly with OpenVAS to provide comprehensive network security assessments. Like a predator lurking in the digital swamp, SwampScan silently hunts for security vulnerabilities across your infrastructure with precision and stealth.

Built by security professionals for security professionals, SwampScan combines the robust scanning capabilities of OpenVAS with an intuitive command-line interface, automatic installation management, and flexible output formatting. Whether you're conducting penetration tests, compliance audits, or routine security assessments, SwampScan adapts to your workflow.

### 🎯 Key Features

**🔍 Comprehensive Scanning**
- Automatic OpenVAS installation and configuration
- Support for single hosts, network ranges, and target files
- Flexible port specification with predefined service groups
- Real-time progress tracking and detailed logging

**📊 Flexible Output**
- CSV format for spreadsheet analysis
- Human-readable text reports for documentation
- JSON format for API integration and automation
- Customizable formatting options

**🛠️ Developer-Friendly**
- Python API for programmatic access
- Modular architecture for easy extension
- Comprehensive error handling and validation
- Extensive documentation and examples

**🚀 Enterprise-Ready**
- CI/CD pipeline integration
- Automated reporting capabilities
- Scalable architecture for large networks
- Security-focused design principles

---

## 🚀 Quick Start

Get SwampScan running in under 5 minutes:

```bash
# Clone the repository
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan

# Install SwampScan
pip install -e .

# Install OpenVAS components (automatic)
swampscan --install

# Run your first scan
swampscan 192.168.1.1 -p web -o results.csv
```

### 🎬 Demo Video

Watch SwampScan in action with our comprehensive installation and usage demonstration:

[![SwampScan Demo Video](https://img.youtube.com/vi/DEMO_VIDEO_ID/maxresdefault.jpg)](https://www.youtube.com/watch?v=DEMO_VIDEO_ID)

*Click the image above to watch the full demo video showing installation on Kali Linux and real vulnerability scanning*

### 📺 What You'll See in the Demo

The demo video covers:
- **Complete Installation**: Step-by-step setup on Kali Linux including dependency resolution
- **OpenVAS Integration**: Automatic installation and configuration of OpenVAS components
- **Real Scanning**: Live vulnerability assessment with actual results
- **Output Formats**: CSV, TXT, and JSON output examples
- **Advanced Features**: Target files, port specifications, and logging options

### 🚀 Quick Demo Commands

Try these commands to get started immediately:

```bash
# Basic vulnerability scan
swampscan 192.168.1.100 -p web -o results.csv

# Network range assessment
swampscan 192.168.1.0/24 -p top100 --verbose

# Comprehensive security audit
swampscan -f targets.txt -p ssh,web,ftp,database \
  --scan-name "Security Assessment" \
  --log-file audit.log \
  -o security_report.txt -F txt

# API integration format
swampscan 127.0.0.1 -p web -F json -o api_results.json
```

### 📊 Sample Output Preview

**CSV Format** (Perfect for spreadsheets and analysis):
```csv
target,port,protocol,vulnerability_id,name,severity,cvss_score,description,solution
192.168.1.100,22,tcp,CVE-2023-38408,OpenSSH Weak Key Exchange,Medium,5.3,"SSH server supports weak algorithms","Update SSH configuration"
192.168.1.101,443,tcp,CVE-2023-5678,SSL/TLS Weak Ciphers,High,7.5,"Weak cipher suites detected","Update SSL configuration"
```

**Text Format** (Human-readable reports):
```
SwampScan Vulnerability Assessment Report
==========================================
Scan Information:
- Targets Scanned: 3 hosts
- Total Vulnerabilities: 8 findings
- Critical: 2 | High: 2 | Medium: 2 | Low: 2

[CRITICAL] MySQL Default Configuration (CVE-2023-22084)
Target: 192.168.1.102:3306
CVSS Score: 9.8
Description: MySQL server allows anonymous connections
Recommendation: Run mysql_secure_installation script
```

**JSON Format** (API integration and automation):
```json
{
  "scan_metadata": {
    "scan_id": "swampscan_20240115_143022",
    "targets_scanned": 3,
    "total_vulnerabilities": 8,
    "severity_summary": {"critical": 2, "high": 2, "medium": 2, "low": 2}
  },
  "scan_results": [
    {
      "target": "192.168.1.100",
      "vulnerabilities": [
        {
          "vulnerability_id": "CVE-2023-38408",
          "name": "OpenSSH Weak Key Exchange Algorithms",
          "severity": "Medium",
          "cvss_score": 5.3,
          "solution": "Update SSH configuration to disable weak algorithms"
        }
      ]
    }
  ]
}
```

### 🎯 Real-World Results

SwampScan identifies genuine security vulnerabilities including:

| Vulnerability Type | Example Finding | Severity | Impact |
|-------------------|----------------|----------|---------|
| **Authentication Issues** | MySQL default configuration | Critical | Complete system access |
| **Encryption Weaknesses** | SSL/TLS weak ciphers | High | Data interception |
| **Service Misconfigurations** | SMTP open relay | High | Spam distribution |
| **Information Disclosure** | Version information leakage | Low | Attack reconnaissance |

### 🔧 Installation Walkthrough

Follow these steps exactly as shown in the demo video:

#### Step 1: System Preparation
```bash
# Update package lists (Kali Linux/Debian/Ubuntu)
sudo apt-get update

# Fix any broken packages (if needed)
sudo dpkg --configure -a
sudo apt-get -f install
```

#### Step 2: SwampScan Installation
```bash
# Clone repository
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan

# Install SwampScan
pip3 install -e .

# Verify installation
swampscan --version
```

#### Step 3: OpenVAS Component Setup
```bash
# Check what needs to be installed
swampscan --check-installation

# Install all components automatically
swampscan --install --non-interactive

# Verify complete installation
swampscan --check-installation
```

#### Step 4: First Scan
```bash
# Run your first vulnerability scan
swampscan 127.0.0.1 -p web -o first_scan.csv

# View results
cat first_scan.csv
```

### 🛠️ Troubleshooting Common Issues

**Issue**: `Package 'libssh-gcrypt-dev' has no installation candidate`
**Solution**: This is fixed in v1.0.2+ - run `git pull origin main` to get the latest version

**Issue**: `Unsupported distribution for automatic installation`
**Solution**: Ensure you're using the latest version with Kali Linux support

**Issue**: `dpkg was interrupted`
**Solution**: Run `sudo dpkg --configure -a` then retry installation

**Issue**: Virtual environment pip missing
**Solution**: Use system Python with `pip3 install -e .` instead of virtual environment

---

## 🔧 Installation

### System Requirements

SwampScan requires a Linux environment with the following specifications:

- **Operating System**: Ubuntu 20.04+, CentOS 8+, or compatible Linux distribution
- **Python**: Version 3.8 or higher
- **Memory**: Minimum 2GB RAM (4GB+ recommended for large scans)
- **Storage**: 5GB free space for OpenVAS components
- **Network**: Internet connectivity for component downloads
- **Privileges**: sudo access for OpenVAS installation

### Automated Installation

SwampScan handles all dependencies automatically:

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install python3 python3-pip git

# Clone and install SwampScan
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan
pip install -e .

# Install OpenVAS components automatically
swampscan --install
```

### Manual Installation

For custom installations or troubleshooting:

```bash
# Check installation status
swampscan --check-installation

# Install with custom prefix
swampscan --install --install-prefix /opt/swampscan

# Non-interactive installation for automation
swampscan --install --non-interactive
```

### Docker Installation

Run SwampScan in a containerized environment:

```bash
# Build Docker image
docker build -t swampscan .

# Run SwampScan container
docker run -it --rm swampscan swampscan --help

# Scan with volume mounting for results
docker run -it --rm -v $(pwd)/results:/results swampscan \
  swampscan 192.168.1.1 -o /results/scan.csv
```

---

## 📖 Documentation

### Command Line Interface

SwampScan provides a comprehensive command-line interface with extensive options:

#### Target Specification

```bash
# Single IP address
swampscan 192.168.1.100

# Multiple targets
swampscan 192.168.1.100 192.168.1.101 example.com

# Network range (CIDR notation)
swampscan 192.168.1.0/24

# Target file (one target per line)
swampscan -f targets.txt

# Exclude specific hosts
swampscan 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

#### Port Specification

SwampScan supports flexible port specification options:

```bash
# Specific ports
swampscan 192.168.1.100 -p 22,80,443

# Port ranges
swampscan 192.168.1.100 -p 1-1000

# Service groups
swampscan 192.168.1.100 -p web,ssh,ftp

# All ports (comprehensive scan)
swampscan 192.168.1.100 --all-ports

# List available service groups
swampscan --list-services
```

#### Output Options

```bash
# CSV output (default)
swampscan 192.168.1.100 -o results.csv

# Human-readable text report
swampscan 192.168.1.100 -o report.txt -F txt

# JSON format for automation
swampscan 192.168.1.100 -o data.json -F json

# Console output only
swampscan 192.168.1.100

# CSV without header row
swampscan 192.168.1.100 -o results.csv --no-header
```

### Service Port Groups

SwampScan includes predefined port groups for common services:

| Service Group | Ports | Description |
|---------------|-------|-------------|
| `web` | 80, 443, 8080, 8443, 8000, 8888 | Web services (HTTP/HTTPS) |
| `ssh` | 22 | Secure Shell |
| `ftp` | 21, 990 | File Transfer Protocol |
| `smtp` | 25, 465, 587 | Email services |
| `dns` | 53 | Domain Name System |
| `smb` | 139, 445 | SMB/CIFS file sharing |
| `rdp` | 3389 | Remote Desktop Protocol |
| `mysql` | 3306 | MySQL database |
| `postgresql` | 5432 | PostgreSQL database |
| `top100` | Various | Top 100 most common ports |

### Python API

SwampScan provides a comprehensive Python API for programmatic access:

```python
import swampscan

# Quick scan with default settings
result = swampscan.quick_scan("192.168.1.100", "web")
print(f"Found {len(result.vulnerabilities)} vulnerabilities")

# Network range scanning
result = swampscan.scan_network("192.168.1.0/24", "top100")
for vuln in result.vulnerabilities:
    if vuln.severity in ['high', 'critical']:
        print(f"Critical: {vuln.target}:{vuln.port} - {vuln.name}")

# File-based scanning
result = swampscan.scan_from_file("targets.txt", "all")

# Check OpenVAS readiness
if swampscan.is_openvas_ready():
    result = swampscan.quick_scan("192.168.1.100")
else:
    swampscan.setup_openvas()
```

#### Advanced API Usage

```python
from swampscan import ScannerManager, ScanRequest

# Create custom scan request
request = ScanRequest(
    targets=["192.168.1.0/24"],
    ports="web,ssh",
    output_file="enterprise_scan.csv",
    output_format="csv",
    scan_name="Monthly Security Assessment",
    verbose=True,
    timeout=7200
)

# Execute scan with custom configuration
manager = ScannerManager()
result = manager.execute_scan(request)

# Process results
summary = swampscan.create_summary_report(result)
print(summary)
```

---

## 💡 Examples

### Basic Usage Examples

**Single Host Assessment**
```bash
# Quick security check of a web server
swampscan 192.168.1.100 -p web,ssh -o webserver_scan.csv

# Comprehensive scan of a critical server
swampscan 192.168.1.100 --all-ports --verbose \
  --scan-name "Critical Server Assessment" \
  --log-file critical_scan.log \
  -o comprehensive_results.txt -F txt
```

**Network Range Scanning**
```bash
# Scan entire subnet for common vulnerabilities
swampscan 192.168.1.0/24 -p top100 -o network_assessment.csv

# DMZ security assessment
swampscan 10.0.1.0/24 -p web,ssh,ftp,smtp \
  --exclude 10.0.1.1,10.0.1.254 \
  -o dmz_security_scan.json -F json
```

**Enterprise Scanning**
```bash
# Multi-target scan from file
echo "192.168.1.100" > production_servers.txt
echo "192.168.1.101" >> production_servers.txt
echo "192.168.1.102" >> production_servers.txt

swampscan -f production_servers.txt -p all \
  --scan-name "Production Environment Audit" \
  --timeout 14400 \
  -o production_audit.csv
```

### Integration Examples

**CI/CD Pipeline Integration**
```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly scan

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install SwampScan
        run: |
          git clone https://github.com/SourcePointSecurity/SwampScan.git
          cd SwampScan
          pip install -e .
          swampscan --install --non-interactive
      
      - name: Run Security Scan
        run: |
          swampscan -f production-hosts.txt -p top100 \
            -o security-scan-results.csv
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-scan-results
          path: security-scan-results.csv
```

**Automated Reporting Script**
```python
#!/usr/bin/env python3
"""
Automated SwampScan reporting with email notifications
"""

import swampscan
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

def automated_security_scan():
    """Perform automated security scan with email reporting."""
    
    # Define scan targets
    targets = ["192.168.1.0/24", "10.0.1.0/24"]
    
    # Execute scans
    all_results = []
    for target in targets:
        print(f"Scanning {target}...")
        result = swampscan.scan_network(target, "top100")
        all_results.append(result)
    
    # Generate comprehensive report
    total_vulns = sum(len(r.vulnerabilities) for r in all_results)
    critical_vulns = sum(
        len([v for v in r.vulnerabilities if v.severity == 'critical'])
        for r in all_results
    )
    
    # Create email report
    report = f"""
    SwampScan Security Assessment Report
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
    
    Summary:
    - Targets Scanned: {len(targets)}
    - Total Vulnerabilities: {total_vulns}
    - Critical Vulnerabilities: {critical_vulns}
    
    Detailed results attached.
    """
    
    # Send email notification
    send_email_report(report, all_results)

def send_email_report(summary, results):
    """Send email report with scan results."""
    msg = MIMEMultipart()
    msg['Subject'] = f'SwampScan Security Report - {len(results)} networks scanned'
    msg['From'] = 'security@company.com'
    msg['To'] = 'security-team@company.com'
    
    msg.attach(MIMEText(summary, 'plain'))
    
    # Add CSV attachment
    for i, result in enumerate(results):
        csv_data = swampscan.format_scan_results(result, 'csv')
        attachment = MIMEText(csv_data)
        attachment.add_header('Content-Disposition', 
                            f'attachment; filename=scan_results_{i}.csv')
        msg.attach(attachment)
    
    # Send email
    smtp = smtplib.SMTP('localhost')
    smtp.send_message(msg)
    smtp.quit()

if __name__ == "__main__":
    automated_security_scan()
```

---

## 🔍 Output Formats

### CSV Format

The CSV format provides structured data ideal for spreadsheet analysis and database import:

```csv
target,port,protocol,vulnerability_id,name,severity,cvss_score,cve_ids,description,solution,references
192.168.1.100,22,tcp,CVE-2023-28531,SSH Weak Key Exchange,medium,5.3,CVE-2023-28531,"SSH server supports weak key exchange algorithms","Update SSH configuration",https://nvd.nist.gov/vuln/detail/CVE-2023-28531
192.168.1.100,80,tcp,CVE-2023-44487,Apache Info Disclosure,low,2.7,CVE-2023-44487,"Server reveals version information","Configure ServerTokens Prod",https://httpd.apache.org/docs/
```

### Text Format

Human-readable reports perfect for documentation and executive summaries:

```
SwampScan Vulnerability Assessment Report
==========================================
Scan ID: swamp-scan-2024-01-15-143022
Status: completed
Start Time: 2024-01-15 14:30:22
End Time: 2024-01-15 14:45:18
Targets Scanned: 3
Vulnerabilities Found: 4

Severity Summary:
----------------
  Critical: 1
  High: 1  
  Medium: 1
  Low: 1

Vulnerability Details:
---------------------

Target: 192.168.1.100
~~~~~~~~~~~~~~~~~~~~~~
  [MEDIUM] SSH Weak Key Exchange Algorithms
    Port: 22/tcp
    CVSS Score: 5.3
    Description: SSH server supports weak key exchange algorithms
    Solution: Update SSH configuration to disable weak ciphers
    References: https://nvd.nist.gov/vuln/detail/CVE-2023-28531
```

### JSON Format

Structured data format for API integration and automation:

```json
{
  "scan_id": "swamp-scan-2024-01-15-143022",
  "status": "completed",
  "start_time": "2024-01-15 14:30:22",
  "end_time": "2024-01-15 14:45:18",
  "targets_scanned": 3,
  "vulnerabilities": [
    {
      "target": "192.168.1.100",
      "port": 22,
      "protocol": "tcp",
      "vulnerability_id": "CVE-2023-28531",
      "name": "SSH Weak Key Exchange Algorithms",
      "severity": "medium",
      "cvss_score": 5.3,
      "cve_ids": ["CVE-2023-28531"],
      "description": "SSH server supports weak key exchange algorithms",
      "solution": "Update SSH configuration",
      "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-28531"]
    }
  ],
  "summary": {
    "total_vulnerabilities": 1,
    "severity_counts": {"medium": 1}
  }
}
```

---

## 🛡️ Security Considerations

### Responsible Scanning

SwampScan is a powerful tool that should be used responsibly and ethically:

**Legal Compliance**
- Only scan networks you own or have explicit written permission to test
- Comply with local laws and regulations regarding security testing
- Respect terms of service for cloud providers and hosting services
- Document authorization before conducting any security assessments

**Network Impact**
- Be aware that vulnerability scans may trigger security alerts
- Consider rate limiting for large network scans to minimize impact
- Schedule comprehensive scans during maintenance windows
- Monitor network performance during scanning operations

**Data Protection**
- Scan results may contain sensitive information about network infrastructure
- Store output files securely with appropriate access controls
- Encrypt scan results for long-term storage or transmission
- Follow organizational data retention and disposal policies
- Implement proper access controls for scan data

### Access Control

**Authentication and Authorization**
- Limit access to SwampScan to authorized security personnel only
- Use strong authentication mechanisms for OpenVAS daemon access
- Implement role-based access controls for scan operations
- Regularly audit user access and permissions

**System Security**
- Keep SwampScan and OpenVAS components updated with latest security patches
- Run scans from dedicated security assessment systems
- Isolate scanning infrastructure from production networks
- Monitor scanning systems for unauthorized access or modifications

### Operational Security

**Logging and Monitoring**
- Enable comprehensive logging for all scan activities
- Monitor scan execution for anomalies or failures
- Implement alerting for critical vulnerability discoveries
- Maintain audit trails for compliance and forensic purposes

**Incident Response**
- Develop procedures for handling critical vulnerability discoveries
- Establish escalation paths for high-severity findings
- Create templates for vulnerability disclosure and remediation
- Test incident response procedures regularly

---

<div align="center">

### 🐊 Ready to Hunt for Vulnerabilities?

[Get Started](#-quick-start) • [Download Latest Release](https://github.com/SourcePointSecurity/SwampScan/releases) • [Report Issues](https://github.com/SourcePointSecurity/SwampScan/issues)

**SwampScan** - *Lurking in the depths, hunting vulnerabilities*

Made with ❤️ by [SourcePoint Security](https://sourcepointsecurity.com)

</div>


### 📁 Complete Sample Output Files

View complete examples of SwampScan output in different formats:

- **[CSV Format](examples/sample_scan_results.csv)** - Structured data perfect for spreadsheet analysis and data processing
- **[Text Format](examples/sample_scan_results.txt)** - Professional vulnerability assessment report with executive summary
- **[JSON Format](examples/sample_scan_results.json)** - Complete API-ready format with metadata and structured vulnerability data

These sample files demonstrate real vulnerability findings including critical MySQL misconfigurations, SSL/TLS weaknesses, authentication bypasses, and information disclosure issues. Each format provides the same vulnerability data optimized for different use cases:

**CSV Format Features:**
- Spreadsheet-compatible structure
- Easy filtering and sorting
- Perfect for data analysis and reporting
- Compatible with Excel, Google Sheets, and databases

**Text Format Features:**
- Executive summary with severity breakdown
- Detailed vulnerability descriptions
- Remediation recommendations
- Professional report formatting
- Ready for documentation and presentations

**JSON Format Features:**
- Complete scan metadata
- Structured vulnerability objects
- API integration ready
- Automation and CI/CD pipeline compatible
- Compliance framework mapping

### 🎥 Creating Your Own Demo Video

Want to create a demo video for your organization? Here's our recommended approach:

#### Video Structure (8-10 minutes)
1. **Introduction** (30 seconds) - SwampScan overview and capabilities
2. **System Preparation** (1 minute) - Package updates and prerequisites  
3. **Installation** (1.5 minutes) - Git clone, pip install, component setup
4. **OpenVAS Setup** (2 minutes) - Automatic installation process
5. **Basic Scanning** (1.5 minutes) - First scan with CSV output
6. **Advanced Features** (2 minutes) - Multiple formats, target files, logging
7. **Results Analysis** (1 minute) - Output format comparison
8. **Conclusion** (30 seconds) - Summary and next steps

#### Technical Requirements
- **Resolution**: 1920x1080 (Full HD)
- **Terminal**: Dark theme with high contrast text
- **Font Size**: 14-16pt monospace for readability
- **Recording**: Use OBS Studio or similar screen capture
- **Audio**: Clear narration with optional background music

#### Sample Commands for Demo
```bash
# System preparation
sudo apt-get update
cat /etc/os-release

# Installation sequence
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan
pip3 install -e .
swampscan --version

# Component installation
swampscan --check-installation
swampscan --install --non-interactive
swampscan --check-installation

# Demonstration scans
swampscan 127.0.0.1 -p web -o demo_scan.csv
swampscan 192.168.1.0/24 -p top100 --verbose -F txt -o network_assessment.txt
swampscan 127.0.0.1 -p ssh,web -F json -o api_results.json

# Results viewing
cat demo_scan.csv
head -20 network_assessment.txt
python3 -m json.tool api_results.json | head -20
```


