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

### 🚀 Live Demonstration

Experience SwampScan's capabilities through our interactive demonstration and sample outputs.

### 📋 Quick Start Guide

**Step 1: Installation**
```bash
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan && pip3 install -e .
```

**Step 2: System Setup**
```bash
swampscan --check-installation
swampscan --install --non-interactive
```

**Step 3: First Scan**
```bash
swampscan 127.0.0.1 -p web -o results.csv
cat results.csv
```

### 🖥️ Sample Output Preview

```
$ swampscan 192.168.1.100 -p web -o results.csv

Starting SwampScan v1.0.2...
🐊 Lurking in the digital swamp, hunting vulnerabilities...

Target: 192.168.1.100
Ports: web (80,443,8080,8443)
Output: results.csv

[████████████████████████████████████████] 100%

Scan Complete! 🎯
┌─────────────────────────────────────────┐
│ 📊 VULNERABILITY SUMMARY                │
├─────────────────────────────────────────┤
│ 🔴 Critical: 1 finding                 │
│ 🟠 High:     2 findings                │
│ 🟡 Medium:   1 finding                 │
│ 🟢 Low:      1 finding                 │
└─────────────────────────────────────────┘

Results saved to: results.csv
```

### 🎯 Real Vulnerability Examples

```
🔍 TYPICAL FINDINGS:

🔴 CRITICAL: MySQL Default Configuration (CVSS 9.8)
   └─ Anonymous database access enabled
   └─ Fix: Run mysql_secure_installation

🟠 HIGH: SSL/TLS Weak Ciphers (CVSS 7.5)  
   └─ Vulnerable encryption protocols
   └─ Fix: Update SSL configuration

🟡 MEDIUM: SSH Weak Algorithms (CVSS 5.3)
   └─ Deprecated key exchange methods
   └─ Fix: Update SSH config

🟢 LOW: Version Information Disclosure (CVSS 2.7)
   └─ Server version exposed in headers
   └─ Fix: Hide version information
```

### 📊 Complete Sample Outputs

View comprehensive examples of SwampScan results:

- **[CSV Format](examples/sample_scan_results.csv)** - Structured data for analysis and reporting
- **[Text Report](examples/sample_scan_results.txt)** - Professional vulnerability assessment report  
- **[JSON Format](examples/sample_scan_results.json)** - API-ready format for automation

### 🔧 Advanced Usage Examples

```bash
# Network range assessment
swampscan 192.168.1.0/24 -p top100 --verbose

# Professional security report
swampscan -f targets.txt -p ssh,web,database \
  --scan-name "Security Assessment" \
  -F txt -o security_report.txt

# API integration format  
swampscan 192.168.1.100 -p web -F json -o api_data.json

# Custom port specification
swampscan 192.168.1.100 -p 22,80,443,3389 -o custom_scan.csv
```

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
  swampscan 192.168.1.100 -p web -o /results/scan.csv
```

### Verification

Confirm your installation is working correctly:

```bash
# Check SwampScan version
swampscan --version

# Verify all components
swampscan --check-installation

# Test with localhost scan
swampscan 127.0.0.1 -p 80 -o test_scan.csv
```

---

## 💡 Examples

### Basic Usage

```bash
# Scan single host
swampscan 192.168.1.100

# Scan with specific ports
swampscan 192.168.1.100 -p 22,80,443

# Scan with port groups
swampscan 192.168.1.100 -p web,ssh

# Save results to file
swampscan 192.168.1.100 -p web -o results.csv
```

### Network Scanning

```bash
# Scan network range
swampscan 192.168.1.0/24 -p top100

# Scan multiple hosts from file
echo "192.168.1.100" > targets.txt
echo "192.168.1.101" >> targets.txt
swampscan -f targets.txt -p web

# Exclude specific hosts
swampscan 192.168.1.0/24 -p web --exclude 192.168.1.1,192.168.1.254
```

### Output Formats

```bash
# CSV format (default)
swampscan 192.168.1.100 -p web -o results.csv

# Human-readable text report
swampscan 192.168.1.100 -p web -F txt -o report.txt

# JSON format for APIs
swampscan 192.168.1.100 -p web -F json -o data.json

# Multiple formats
swampscan 192.168.1.100 -p web -o results.csv -F txt -o report.txt
```

### Advanced Features

```bash
# Verbose logging
swampscan 192.168.1.100 -p web --verbose

# Custom scan name
swampscan 192.168.1.100 -p web --scan-name "Production Web Servers"

# Log to file
swampscan 192.168.1.100 -p web --log-file scan.log

# Timeout configuration
swampscan 192.168.1.100 -p web --timeout 300

# All ports scan
swampscan 192.168.1.100 --all-ports
```

### Port Specifications

```bash
# Individual ports
swampscan 192.168.1.100 -p 22,80,443,3389

# Port ranges
swampscan 192.168.1.100 -p 1-1000

# Service groups
swampscan 192.168.1.100 -p web,ssh,ftp,database

# Top ports
swampscan 192.168.1.100 -p top100

# Custom combinations
swampscan 192.168.1.100 -p web,22,3389,8000-8100
```

### Professional Reporting

```bash
# Executive summary report
swampscan 192.168.1.0/24 -p web \
  --scan-name "Q4 Security Assessment" \
  -F txt -o executive_report.txt

# Compliance scan
swampscan -f critical_servers.txt -p top1000 \
  --scan-name "PCI DSS Compliance Scan" \
  -F json -o compliance_data.json

# Detailed technical report
swampscan 192.168.1.0/24 --all-ports \
  --verbose --log-file detailed_scan.log \
  -F txt -o technical_report.txt
```

---

## 📖 Documentation

### Command Line Interface

```
Usage: swampscan [OPTIONS] [TARGETS...]

Arguments:
  TARGETS  Target hosts, networks, or files to scan

Options:
  -p, --ports TEXT        Port specification (default: top100)
  -f, --target-file PATH  File containing targets to scan
  -o, --output PATH       Output file path
  -F, --format TEXT       Output format: csv, txt, json (default: csv)
  --scan-name TEXT        Custom name for the scan
  --timeout INTEGER       Scan timeout in seconds (default: 300)
  --verbose              Enable verbose logging
  --log-file PATH        Log file path
  --all-ports            Scan all 65535 ports
  --exclude TEXT         Comma-separated hosts to exclude
  --install              Install OpenVAS components
  --check-installation   Check installation status
  --version              Show version information
  --help                 Show this help message
```

### Port Specifications

SwampScan supports flexible port specification:

| Format | Example | Description |
|--------|---------|-------------|
| Individual | `22,80,443` | Specific port numbers |
| Ranges | `1-1000` | Port ranges |
| Services | `web,ssh,ftp` | Predefined service groups |
| Top ports | `top100`, `top1000` | Most common ports |
| All ports | `--all-ports` | Complete port range (1-65535) |

### Service Groups

| Group | Ports | Description |
|-------|-------|-------------|
| `web` | 80,443,8080,8443 | Web services |
| `ssh` | 22 | SSH service |
| `ftp` | 21,990,989 | FTP services |
| `database` | 3306,5432,1433,1521 | Database services |
| `email` | 25,110,143,993,995 | Email services |
| `dns` | 53 | DNS service |
| `top100` | Most common 100 ports | Popular services |
| `top1000` | Most common 1000 ports | Comprehensive scan |

### Output Formats

#### CSV Format
Structured data perfect for spreadsheet analysis:
```csv
target,port,protocol,vulnerability_id,name,severity,cvss_score,description,solution
192.168.1.100,22,tcp,CVE-2023-38408,OpenSSH Weak Key Exchange,Medium,5.3,"SSH server supports weak algorithms","Update SSH configuration"
```

#### Text Format
Professional vulnerability assessment reports:
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

#### JSON Format
API-ready structured data:
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

### Python API

SwampScan provides a Python API for programmatic access:

```python
from swampscan import SwampScanner

# Initialize scanner
scanner = SwampScanner()

# Configure scan
scanner.add_target("192.168.1.100")
scanner.set_ports("web,ssh")
scanner.set_output_format("json")

# Run scan
results = scanner.scan()

# Process results
for result in results:
    print(f"Target: {result.target}")
    print(f"Vulnerabilities: {len(result.vulnerabilities)}")
    for vuln in result.vulnerabilities:
        print(f"  - {vuln.name} ({vuln.severity})")
```

### Integration Examples

#### CI/CD Pipeline Integration

```yaml
# GitHub Actions example
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Install SwampScan
      run: |
        git clone https://github.com/SourcePointSecurity/SwampScan.git
        cd SwampScan && pip install -e .
        swampscan --install --non-interactive
    - name: Run Security Scan
      run: |
        swampscan ${{ secrets.TARGET_HOSTS }} -p web \
          -F json -o security_results.json
    - name: Upload Results
      uses: actions/upload-artifact@v2
      with:
        name: security-scan-results
        path: security_results.json
```

#### Automated Reporting

```bash
#!/bin/bash
# Weekly security scan script

DATE=$(date +%Y%m%d)
TARGETS="production_servers.txt"
REPORT="weekly_security_report_${DATE}.txt"

# Run comprehensive scan
swampscan -f $TARGETS -p top1000 \
  --scan-name "Weekly Security Assessment" \
  --verbose --log-file "scan_${DATE}.log" \
  -F txt -o $REPORT

# Email results
mail -s "Weekly Security Report - $DATE" security@company.com < $REPORT
```

---

## 🛡️ Security Considerations

### Responsible Scanning

- **Authorization**: Only scan systems you own or have explicit permission to test
- **Network Impact**: Be mindful of scan intensity on production networks
- **Data Handling**: Secure storage and transmission of vulnerability data
- **Compliance**: Ensure scans comply with organizational policies and regulations

### Best Practices

- **Regular Scanning**: Implement scheduled vulnerability assessments
- **Baseline Establishment**: Create security baselines for comparison
- **Remediation Tracking**: Monitor vulnerability remediation progress
- **Documentation**: Maintain detailed records of security assessments

### Performance Optimization

- **Target Segmentation**: Break large networks into smaller scan segments
- **Port Selection**: Use targeted port specifications for faster scans
- **Timing**: Schedule intensive scans during maintenance windows
- **Resource Monitoring**: Monitor system resources during large scans

---

## 🤝 Contributing

We welcome contributions to SwampScan! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on how to get started.

### Development Setup

```bash
# Clone repository
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan

# Create development environment
python -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .[dev]

# Run tests
pytest tests/

# Run linting
flake8 src/
black src/
```

### Reporting Issues

Please report bugs and feature requests through our [GitHub Issues](https://github.com/SourcePointSecurity/SwampScan/issues) page.

---

## 📄 License

SwampScan is released under the MIT License. See [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **OpenVAS Team** - For the robust vulnerability scanning engine
- **Security Community** - For continuous feedback and contributions
- **Beta Testers** - For helping improve SwampScan's reliability

---

<div align="center">

**SwampScan** - *Lurking in the depths, hunting vulnerabilities*

Made with 🐊 by [SourcePoint Security](https://github.com/SourcePointSecurity)

[⭐ Star this repository](https://github.com/SourcePointSecurity/SwampScan) • [🐛 Report Issues](https://github.com/SourcePointSecurity/SwampScan/issues) • [💡 Request Features](https://github.com/SourcePointSecurity/SwampScan/issues/new)

</div>

