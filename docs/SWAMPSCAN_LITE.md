# SwampScan Lite - Simplified Vulnerability Scanner

SwampScan Lite is a lightweight version of SwampScan that works with downloaded signature files **without requiring the full OpenVAS backend infrastructure**. This approach is much simpler to install and use while still providing vulnerability scanning capabilities.

## 🎯 Key Benefits

- **No OpenVAS Required**: Works without complex OpenVAS installation and configuration
- **Simple Installation**: Just Python dependencies, no system services
- **Portable**: Can run anywhere Python is available
- **Fast Setup**: Get scanning in minutes, not hours
- **Lightweight**: Minimal resource usage
- **Flexible**: Use existing signatures or create custom ones

## 📋 Requirements

- Python 3.7 or higher
- Basic Python packages: `requests`, `pathlib`
- Network access for target scanning
- Vulnerability signature files (NASL format)

## 🚀 Quick Start

### 1. Download SwampScan Lite

```bash
# Clone the repository
git clone https://github.com/SourcePointSecurity/SwampScan.git
cd SwampScan

# Or download just the lite components
wget https://raw.githubusercontent.com/SourcePointSecurity/SwampScan/main/swampscan_lite.py
wget https://raw.githubusercontent.com/SourcePointSecurity/SwampScan/main/download_signatures.py
```

### 2. Install Python Dependencies

```bash
# Install required packages
pip3 install requests

# No other dependencies needed!
```

### 3. Download Vulnerability Signatures

```bash
# Option 1: Use existing OpenVAS signatures (if available)
python3 download_signatures.py --method copy --source-dir /var/lib/openvas/plugins

# Option 2: Create sample signatures for testing
python3 download_signatures.py --method samples

# Option 3: Try all methods
python3 download_signatures.py --method all
```

### 4. Run Your First Scan

```bash
# Basic scan
python3 swampscan_lite.py scanme.nmap.org

# Scan specific ports
python3 swampscan_lite.py target.com -p 80,443,22

# Save results to file
python3 swampscan_lite.py target.com -o results.json -f json
```

## 📖 Detailed Usage

### Command Line Options

```bash
python3 swampscan_lite.py [OPTIONS] TARGET [TARGET...]
```

**Targets:**
- `scanme.nmap.org` - Single hostname
- `192.168.1.1` - Single IP address  
- `target1.com target2.com` - Multiple targets

**Options:**
- `-p, --ports` - Ports to scan (default: common ports)
- `-o, --output` - Output file path
- `-f, --format` - Output format: txt, json, csv (default: txt)
- `--signature-dir` - Directory containing signature files
- `--max-signatures` - Maximum signatures to load (default: 1000)
- `-v, --verbose` - Enable verbose output

### Port Specifications

```bash
# Common ports (default)
python3 swampscan_lite.py target.com

# Specific ports
python3 swampscan_lite.py target.com -p 80,443,22

# Port ranges
python3 swampscan_lite.py target.com -p 1-1000

# Mixed specification
python3 swampscan_lite.py target.com -p 22,80,443,8000-8100
```

### Output Formats

**Text Format (Default):**
```bash
python3 swampscan_lite.py target.com -f txt -o scan.txt
```

**JSON Format:**
```bash
python3 swampscan_lite.py target.com -f json -o scan.json
```

**CSV Format:**
```bash
python3 swampscan_lite.py target.com -f csv -o scan.csv
```

## 🔧 Signature Management

### Understanding Signatures

SwampScan Lite uses NASL (Nessus Attack Scripting Language) files as vulnerability signatures. These files contain:

- Vulnerability detection logic
- CVE identifiers
- CVSS scores
- Descriptions and solutions
- Port and service requirements

### Signature Sources

**1. Existing OpenVAS Signatures:**
```bash
# Copy from existing OpenVAS installation
python3 download_signatures.py --method copy --source-dir /var/lib/openvas/plugins
```

**2. Sample Signatures:**
```bash
# Create sample signatures for testing
python3 download_signatures.py --method samples --target-dir ./signatures
```

**3. Custom Signatures:**
Create your own NASL files following the standard format:

```nasl
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999999");
  script_version("2025-01-01");
  script_name("Custom Vulnerability Check");
  script_category(ACT_GATHER_INFO);
  script_family("Custom Checks");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"summary", value:"Custom vulnerability description");
  script_tag(name:"solution", value:"Apply security patch");
  exit(0);
}

# Detection logic here
port = get_http_port(default:80);
# ... vulnerability detection code ...
```

### Managing Signature Directories

```bash
# Use custom signature directory
python3 swampscan_lite.py target.com --signature-dir /path/to/signatures

# Limit number of signatures loaded
python3 swampscan_lite.py target.com --max-signatures 500

# Organize signatures by category
mkdir -p signatures/{web,network,database}
# Place relevant NASL files in each directory
```

## 📊 Understanding Results

### Text Output Example

```
SwampScan Lite - Vulnerability Scan Report
==================================================

Scan Date: 2025-08-03 17:47:53
Targets: scanme.nmap.org
Ports: 22, 80, 443
Signatures Loaded: 1000

Target: scanme.nmap.org
------------------------------
Scan Time: 4.20 seconds
Vulnerabilities Found: 3

  Port 80: Apache Server Information Disclosure
    Severity: Medium (CVSS: 5.0)
    Description: Apache server reveals version information...
    CVEs: CVE-2023-1234
    Solution: Configure ServerTokens to Prod...

  Port 443: SSL Certificate Expiry Warning
    Severity: Low (CVSS: 2.6)
    Description: SSL certificate expires soon...
    Solution: Renew SSL certificate...
```

### JSON Output Structure

```json
{
  "scan_info": {
    "timestamp": "2025-08-03 17:47:53",
    "targets": ["scanme.nmap.org"],
    "ports": [22, 80, 443],
    "signatures_loaded": 1000,
    "scanner": "SwampScan Lite"
  },
  "results": {
    "scanme.nmap.org": {
      "scan_time": 4.20,
      "vulnerability_count": 3,
      "vulnerabilities": [
        {
          "target": "scanme.nmap.org",
          "port": 80,
          "protocol": "tcp",
          "vulnerability_name": "Apache Server Information Disclosure",
          "severity": "Medium",
          "cvss_score": 5.0,
          "description": "Apache server reveals version information...",
          "solution": "Configure ServerTokens to Prod...",
          "cve_ids": ["CVE-2023-1234"]
        }
      ]
    }
  }
}
```

## 🔍 Advanced Usage

### Batch Scanning

```bash
# Create target list file
echo "scanme.nmap.org" > targets.txt
echo "example.com" >> targets.txt

# Scan multiple targets
python3 swampscan_lite.py $(cat targets.txt) -o batch_scan.json -f json
```

### Custom Scanning Scripts

```python
#!/usr/bin/env python3
import sys
sys.path.append('./src')

from swampscan.scanner.signature_scanner import SignatureScanner

# Initialize scanner
scanner = SignatureScanner('./signatures')
scanner.load_signatures(max_signatures=500)

# Scan targets
targets = ['target1.com', 'target2.com']
for target in targets:
    results = scanner.scan_target(target, ports=[80, 443])
    print(f"{target}: {len(results)} vulnerabilities found")
```

### Integration with CI/CD

```yaml
# GitHub Actions example
name: Security Scan
on: [push]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Setup Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.8'
    - name: Install dependencies
      run: pip install requests
    - name: Download signatures
      run: python3 download_signatures.py --method samples
    - name: Run security scan
      run: python3 swampscan_lite.py ${{ secrets.TARGET_HOST }} -f json -o scan_results.json
    - name: Upload results
      uses: actions/upload-artifact@v2
      with:
        name: scan-results
        path: scan_results.json
```

## 🛠️ Troubleshooting

### Common Issues

**1. No signatures loaded:**
```bash
# Check signature directory exists
ls -la ./signatures/

# Try creating sample signatures
python3 download_signatures.py --method samples
```

**2. Permission denied errors:**
```bash
# Make scripts executable
chmod +x swampscan_lite.py download_signatures.py

# Check file permissions
ls -la *.py
```

**3. Network connectivity issues:**
```bash
# Test basic connectivity
ping scanme.nmap.org

# Check firewall settings
sudo ufw status
```

**4. Python import errors:**
```bash
# Install missing packages
pip3 install requests pathlib

# Check Python version
python3 --version
```

### Debug Mode

```bash
# Enable verbose output
python3 swampscan_lite.py target.com -v

# Check signature loading
python3 swampscan_lite.py target.com --max-signatures 10 -v
```

## 🔄 Comparison: Full vs Lite

| Feature | SwampScan Full | SwampScan Lite |
|---------|----------------|----------------|
| **Installation** | Complex (OpenVAS + deps) | Simple (Python only) |
| **Setup Time** | 1-2 hours | 5 minutes |
| **Dependencies** | OpenVAS, PostgreSQL, Redis | Python, requests |
| **Resource Usage** | High (multiple services) | Low (single process) |
| **Signature Updates** | Automatic feed sync | Manual download |
| **Vulnerability Detection** | Full NASL execution | Simplified matching |
| **Accuracy** | High (complete engine) | Medium (basic checks) |
| **Performance** | Slower (full analysis) | Faster (lightweight) |
| **Maintenance** | High (service management) | Low (file-based) |

## 🎯 Use Cases

**SwampScan Lite is ideal for:**

- **Quick Security Assessments**: Fast vulnerability checks
- **Development Environments**: Lightweight scanning in dev/test
- **CI/CD Integration**: Automated security checks in pipelines
- **Educational Purposes**: Learning vulnerability scanning concepts
- **Resource-Constrained Environments**: Limited CPU/memory scenarios
- **Portable Scanning**: Running on laptops, containers, etc.

**Use Full SwampScan when you need:**

- **Comprehensive Analysis**: Complete vulnerability assessment
- **Production Scanning**: Enterprise-grade security audits
- **Compliance Requirements**: Detailed reporting and documentation
- **Advanced Features**: Authentication, complex scan profiles
- **Maximum Accuracy**: Full NASL script execution

## 📚 Additional Resources

- **GitHub Repository**: https://github.com/SourcePointSecurity/SwampScan
- **NASL Documentation**: https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#nasl
- **Vulnerability Databases**: https://cve.mitre.org/
- **Security Best Practices**: https://owasp.org/

## 🤝 Contributing

Contributions to SwampScan Lite are welcome! Areas for improvement:

- **Enhanced Signature Parsing**: Better NASL interpretation
- **Additional Output Formats**: XML, SARIF, etc.
- **Performance Optimization**: Faster scanning algorithms
- **Signature Sources**: More vulnerability feed integrations
- **Detection Logic**: Improved vulnerability matching

## 📄 License

SwampScan Lite is released under the same license as SwampScan. See LICENSE file for details.

---

**Get started with SwampScan Lite today - vulnerability scanning made simple!** 🛡️

