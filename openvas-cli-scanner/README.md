# OpenVAS CLI Scanner

A powerful Python command-line interface for OpenVAS vulnerability scanner with automatic installation capabilities and flexible output formatting.

## Overview

OpenVAS CLI Scanner provides a streamlined interface to the OpenVAS vulnerability assessment platform, enabling security professionals and system administrators to perform comprehensive vulnerability scans from the command line. The tool automatically handles OpenVAS installation and configuration, supports multiple target specifications, and outputs results in various formats suitable for reporting and integration with other security tools.

## Features

### Core Functionality
- **Automatic OpenVAS Installation**: Detects and installs missing OpenVAS components automatically
- **Flexible Target Specification**: Supports IP addresses, hostnames, CIDR ranges, and target files
- **Comprehensive Port Scanning**: Configurable port ranges with predefined service groups
- **Multiple Output Formats**: CSV, TXT, and JSON output with customizable formatting
- **Progress Tracking**: Real-time scan progress and detailed logging
- **Error Handling**: Robust error handling with detailed diagnostic information

### Target Support
- Single IP addresses (`192.168.1.1`)
- Hostname resolution (`example.com`)
- CIDR network ranges (`192.168.1.0/24`)
- Target files with multiple entries
- Host exclusion capabilities

### Port Specification
- Individual ports (`80,443`)
- Port ranges (`1-1000`)
- Service groups (`web`, `ssh`, `top100`)
- All ports scanning (`all`)
- Custom port combinations

## Installation

### Prerequisites

The scanner requires a Linux environment (Ubuntu 20.04+ or similar) with the following system packages:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install gcc cmake make pkg-config git curl

# CentOS/RHEL/Fedora
sudo yum install gcc cmake make pkgconfig git curl
# or
sudo dnf install gcc cmake make pkgconfig git curl
```

### Quick Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/example/openvas-cli-scanner.git
   cd openvas-cli-scanner
   ```

2. **Install the package:**
   ```bash
   pip install -e .
   ```

3. **Install OpenVAS components:**
   ```bash
   openvas-cli-scanner --install
   ```

### Manual Installation

If you prefer to install OpenVAS components manually or need custom configuration:

1. **Check installation status:**
   ```bash
   openvas-cli-scanner --check-installation
   ```

2. **Install missing components interactively:**
   ```bash
   openvas-cli-scanner --install
   ```

3. **Non-interactive installation:**
   ```bash
   openvas-cli-scanner --install --non-interactive
   ```

## Usage

### Basic Scanning

**Scan a single host:**
```bash
openvas-cli-scanner 192.168.1.1
```

**Scan multiple hosts:**
```bash
openvas-cli-scanner 192.168.1.1 192.168.1.2 example.com
```

**Scan a network range:**
```bash
openvas-cli-scanner 192.168.1.0/24
```

### Port Specification

**Scan specific ports:**
```bash
openvas-cli-scanner 192.168.1.1 -p 22,80,443
```

**Scan port ranges:**
```bash
openvas-cli-scanner 192.168.1.1 -p 1-1000
```

**Scan service groups:**
```bash
openvas-cli-scanner 192.168.1.1 -p web
openvas-cli-scanner 192.168.1.1 -p ssh,web,ftp
```

**Scan all ports:**
```bash
openvas-cli-scanner 192.168.1.1 --all-ports
```

### Target Files

**Create a target file:**
```bash
cat > targets.txt << EOF
192.168.1.1
192.168.1.10-20
example.com
test.local
EOF
```

**Scan from file:**
```bash
openvas-cli-scanner -f targets.txt -p top100
```

### Output Options

**Save results to CSV:**
```bash
openvas-cli-scanner 192.168.1.1 -o results.csv -F csv
```

**Save results to text format:**
```bash
openvas-cli-scanner 192.168.1.1 -o report.txt -F txt
```

**JSON output:**
```bash
openvas-cli-scanner 192.168.1.1 -o data.json -F json
```

### Advanced Options

**Custom scan name:**
```bash
openvas-cli-scanner 192.168.1.1 --scan-name "Production Network Scan"
```

**Exclude hosts:**
```bash
openvas-cli-scanner 192.168.1.0/24 --exclude 192.168.1.1,192.168.1.254
```

**Verbose logging:**
```bash
openvas-cli-scanner 192.168.1.1 --verbose --log-file scan.log
```

**Timeout configuration:**
```bash
openvas-cli-scanner 192.168.1.1 --timeout 7200  # 2 hours
```

## Command Reference

### Target Specification
```
positional arguments:
  targets               Target IP addresses, hostnames, or CIDR ranges

optional arguments:
  -f, --targets-file    File containing targets (one per line)
  --exclude            Comma-separated list of hosts to exclude
```

### Port Specification
```
  -p, --ports          Port specification (default: top100)
  -A, --all-ports      Scan all 65535 ports
  --list-services      List available service port groups
```

### Output Options
```
  -o, --output         Output file path (default: stdout)
  -F, --format         Output format: csv, txt, json (default: csv)
  --no-header          Omit header row in CSV output
```

### Scan Options
```
  --scan-name          Custom name for the scan
  --timeout            Scan timeout in seconds (default: 3600)
  --max-concurrent     Maximum concurrent scans (default: 1)
```

### OpenVAS Options
```
  --method             Integration method: auto, http, binary (default: auto)
  --openvasd-url       OpenVAS daemon URL (default: http://localhost:3000)
  --api-key            API key for OpenVAS authentication
```

### Installation Options
```
  --install            Install missing OpenVAS components
  --check-installation Check OpenVAS installation status
  --install-prefix     Installation prefix (default: /usr/local)
  --non-interactive    Run installation without prompts
```

### Logging Options
```
  -v, --verbose        Enable verbose output
  -q, --quiet          Suppress console output
  --log-file           Log file path
  --progress           Show progress information
```

## Service Port Groups

The scanner includes predefined port groups for common services:

| Service Group | Ports | Description |
|---------------|-------|-------------|
| `web` | 80, 443, 8080, 8443, 8000, 8888 | Web services |
| `ssh` | 22 | SSH service |
| `ftp` | 21, 990 | FTP services |
| `smtp` | 25, 465, 587 | Email services |
| `dns` | 53 | DNS service |
| `http` | 80, 8080, 8000, 8888 | HTTP services |
| `https` | 443, 8443 | HTTPS services |
| `smb` | 139, 445 | SMB/CIFS services |
| `rdp` | 3389 | Remote Desktop |
| `mysql` | 3306 | MySQL database |
| `postgresql` | 5432 | PostgreSQL database |
| `top100` | Various | Top 100 most common ports |

List all available service groups:
```bash
openvas-cli-scanner --list-services
```

## Output Formats

### CSV Format

The CSV format provides structured data suitable for spreadsheet applications and automated processing:

```csv
target,port,protocol,vulnerability_id,name,severity,cvss_score,cve_ids,description,solution,references
192.168.1.1,22,tcp,CVE-2023-1234,SSH Weak Encryption,medium,5.3,CVE-2023-1234,The SSH service supports weak encryption algorithms.,Update SSH configuration to disable weak ciphers.,https://example.com/advisory
```

### Text Format

The text format provides human-readable reports suitable for documentation and presentations:

```
OpenVAS Vulnerability Scan Report
==================================================
Scan ID: scan-12345
Status: completed
Start Time: 2024-01-01 10:00:00
End Time: 2024-01-01 10:30:00
Targets Scanned: 1
Vulnerabilities Found: 2

Severity Summary:
--------------------
  Medium: 1
  Low: 1

Vulnerability Details:
------------------------------

Target: 192.168.1.1
~~~~~~~~~~~~~~~~~~~~~~~~

  [MEDIUM] SSH Weak Encryption
    Port: 22/tcp
    ID: CVE-2023-1234
    CVSS Score: 5.3
    CVE IDs: CVE-2023-1234
    Description: The SSH service supports weak encryption algorithms.
    Solution: Update SSH configuration to disable weak ciphers.
    References: https://example.com/advisory
```

### JSON Format

The JSON format provides structured data for integration with other tools and APIs:

```json
{
  "scan_id": "scan-12345",
  "status": "completed",
  "start_time": "2024-01-01 10:00:00",
  "end_time": "2024-01-01 10:30:00",
  "targets_scanned": 1,
  "vulnerabilities": [
    {
      "target": "192.168.1.1",
      "port": 22,
      "protocol": "tcp",
      "vulnerability_id": "CVE-2023-1234",
      "name": "SSH Weak Encryption",
      "severity": "medium",
      "cvss_score": 5.3,
      "cve_ids": ["CVE-2023-1234"],
      "description": "The SSH service supports weak encryption algorithms.",
      "solution": "Update SSH configuration to disable weak ciphers.",
      "references": ["https://example.com/advisory"]
    }
  ],
  "errors": [],
  "summary": {
    "total_vulnerabilities": 1,
    "severity_counts": {
      "medium": 1
    }
  }
}
```

## Python API

The scanner can also be used as a Python library for integration with other tools:

### Quick Scanning

```python
import openvas_cli_scanner

# Check if OpenVAS is ready
if openvas_cli_scanner.is_openvas_ready():
    # Perform a quick scan
    result = openvas_cli_scanner.quick_scan("192.168.1.1", "web")
    print(f"Found {len(result.vulnerabilities)} vulnerabilities")
else:
    # Install OpenVAS components
    openvas_cli_scanner.setup_openvas()
```

### Advanced Usage

```python
from openvas_cli_scanner import ScannerManager, ScanRequest

# Create a scan request
request = ScanRequest(
    targets=["192.168.1.0/24"],
    ports="top100",
    output_file="results.csv",
    output_format="csv",
    scan_name="Network Security Assessment"
)

# Execute the scan
manager = ScannerManager()
result = manager.execute_scan(request)

# Process results
for vuln in result.vulnerabilities:
    if vuln.severity in ['high', 'critical']:
        print(f"Critical: {vuln.target}:{vuln.port} - {vuln.name}")
```

### Network Utilities

```python
from openvas_cli_scanner.utils import NetworkUtils, parse_port_specification

# Parse targets
targets = NetworkUtils.parse_targets(["192.168.1.1", "example.com", "10.0.0.0/24"])
resolved = NetworkUtils.resolve_targets(targets)

# Parse ports
ports = parse_port_specification("web,ssh,1000-2000")
print(f"Scanning {len(ports.ports)} ports")
```

## Configuration

### Environment Variables

The scanner supports several environment variables for configuration:

- `OPENVAS_URL`: Default OpenVAS daemon URL
- `OPENVAS_API_KEY`: Default API key for authentication
- `OPENVAS_TIMEOUT`: Default scan timeout in seconds
- `OPENVAS_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)

### Configuration File

Create a configuration file at `~/.openvas-cli-scanner.conf`:

```ini
[openvas]
url = http://localhost:3000
api_key = your-api-key-here
timeout = 3600
method = auto

[logging]
level = INFO
file = ~/.openvas-cli-scanner.log

[output]
format = csv
include_header = true
```

## Troubleshooting

### Common Issues

**OpenVAS components not found:**
```bash
# Check installation status
openvas-cli-scanner --check-installation

# Install missing components
openvas-cli-scanner --install
```

**Permission denied errors:**
```bash
# Ensure user has sudo privileges for installation
sudo usermod -aG sudo $USER

# Or install to user directory
openvas-cli-scanner --install --install-prefix ~/.local
```

**Network connectivity issues:**
```bash
# Test OpenVAS daemon connectivity
curl http://localhost:3000/health

# Check firewall settings
sudo ufw status
```

**Scan timeout errors:**
```bash
# Increase timeout for large networks
openvas-cli-scanner 192.168.1.0/24 --timeout 7200
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
openvas-cli-scanner 192.168.1.1 --verbose --log-file debug.log
```

### Log Analysis

Check log files for detailed error information:

```bash
# View recent log entries
tail -f ~/.openvas-cli-scanner.log

# Search for errors
grep ERROR ~/.openvas-cli-scanner.log
```

## Security Considerations

### Network Security

- Run scans only on networks you own or have explicit permission to test
- Be aware that vulnerability scans may trigger security alerts
- Consider rate limiting for large network scans
- Use VPN or secure networks for sensitive assessments

### Data Protection

- Scan results may contain sensitive information about network infrastructure
- Store output files securely with appropriate access controls
- Consider encrypting scan results for long-term storage
- Follow organizational data retention policies

### Access Control

- Limit access to the scanner to authorized personnel only
- Use strong authentication for OpenVAS daemon access
- Regularly update OpenVAS components for security patches
- Monitor scanner usage through logging

## Performance Optimization

### Large Network Scans

For scanning large networks efficiently:

```bash
# Use CIDR notation for network ranges
openvas-cli-scanner 10.0.0.0/16 -p top100

# Exclude known safe hosts
openvas-cli-scanner 10.0.0.0/24 --exclude 10.0.0.1,10.0.0.254

# Increase timeout for comprehensive scans
openvas-cli-scanner 10.0.0.0/24 --timeout 14400  # 4 hours
```

### Resource Management

- Monitor system resources during large scans
- Adjust `--max-concurrent` based on system capabilities
- Use `--quiet` mode to reduce logging overhead
- Consider running scans during off-peak hours

## Integration Examples

### CI/CD Pipeline

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
      - uses: actions/checkout@v2
      - name: Install OpenVAS CLI Scanner
        run: |
          pip install openvas-cli-scanner
          openvas-cli-scanner --install --non-interactive
      - name: Run Security Scan
        run: |
          openvas-cli-scanner -f production-hosts.txt -o scan-results.csv
      - name: Upload Results
        uses: actions/upload-artifact@v2
        with:
          name: vulnerability-scan-results
          path: scan-results.csv
```

### Automated Reporting

```python
#!/usr/bin/env python3
"""
Automated vulnerability scanning and reporting script.
"""

import openvas_cli_scanner
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_scan_report(results, recipients):
    """Send scan results via email."""
    msg = MIMEMultipart()
    msg['Subject'] = f'Vulnerability Scan Report - {len(results.vulnerabilities)} findings'
    
    # Create summary
    summary = openvas_cli_scanner.create_summary_report(results)
    msg.attach(MIMEText(summary, 'plain'))
    
    # Send email
    smtp = smtplib.SMTP('localhost')
    smtp.send_message(msg, to_addrs=recipients)
    smtp.quit()

# Perform scan
result = openvas_cli_scanner.scan_network("192.168.1.0/24", "top100")

# Send report if vulnerabilities found
if result.vulnerabilities:
    send_scan_report(result, ['security@company.com'])
```

## Contributing

We welcome contributions to the OpenVAS CLI Scanner project. Please see our contributing guidelines for more information.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/example/openvas-cli-scanner.git
cd openvas-cli-scanner

# Install development dependencies
pip install -e .[dev]

# Run tests
pytest tests/

# Run linting
flake8 src/
black src/
```

### Reporting Issues

Please report bugs and feature requests through our GitHub issue tracker. Include:

- Operating system and version
- Python version
- OpenVAS component versions
- Complete error messages and logs
- Steps to reproduce the issue

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Acknowledgments

- OpenVAS community for the excellent vulnerability scanner
- Greenbone Networks for OpenVAS development and maintenance
- Contributors and testers who helped improve this tool

## Support

For support and questions:

- GitHub Issues: https://github.com/example/openvas-cli-scanner/issues
- Documentation: https://github.com/example/openvas-cli-scanner/wiki
- Community Forum: https://community.greenbone.net/

---

**OpenVAS CLI Scanner** - Making vulnerability assessment accessible and automated.

