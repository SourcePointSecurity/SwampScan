#!/usr/bin/env python3
"""
Signature Downloader for SwampScan Lite

This script downloads vulnerability signature files (NASL) from public sources
without requiring the full OpenVAS infrastructure.
"""

import os
import sys
import requests
import tarfile
import zipfile
import tempfile
import shutil
from pathlib import Path
from typing import List, Optional
import argparse
import logging


class SignatureDownloader:
    """Downloads vulnerability signatures from various sources."""
    
    def __init__(self, target_dir: str = "./signatures"):
        self.target_dir = Path(target_dir)
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Create target directory
        self.target_dir.mkdir(parents=True, exist_ok=True)
    
    def download_greenbone_community_feed(self) -> bool:
        """Download Greenbone Community Feed signatures."""
        print("🔄 Downloading Greenbone Community Feed...")
        
        # Note: This is a simplified approach
        # In practice, you'd need to handle the actual feed URLs and formats
        
        feed_urls = [
            "https://feed.community.greenbone.net/data/nvt-feed-current.tar.bz2",
            "https://feed.community.greenbone.net/data/scap-data-current.tar.bz2",
            "https://feed.community.greenbone.net/data/cert-data-current.tar.bz2"
        ]
        
        success = False
        
        for url in feed_urls:
            try:
                print(f"  Trying {url}...")
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    # Save and extract
                    filename = url.split('/')[-1]
                    temp_file = self.target_dir / filename
                    
                    with open(temp_file, 'wb') as f:
                        f.write(response.content)
                    
                    # Extract if it's an archive
                    if filename.endswith('.tar.bz2'):
                        self._extract_tar_bz2(temp_file)
                        success = True
                    
                    # Clean up temp file
                    temp_file.unlink()
                    
            except Exception as e:
                self.logger.debug(f"Failed to download {url}: {e}")
                continue
        
        if not success:
            print("❌ Could not download from official Greenbone feeds")
            print("   This may be due to access restrictions or feed format changes")
        
        return success
    
    def download_sample_signatures(self) -> bool:
        """Download sample NASL signatures for testing."""
        print("🔄 Creating sample vulnerability signatures...")
        
        # Create sample NASL files for common vulnerabilities
        sample_signatures = [
            {
                "filename": "http_version_detection.nasl",
                "content": self._create_http_version_nasl()
            },
            {
                "filename": "ssh_version_detection.nasl", 
                "content": self._create_ssh_version_nasl()
            },
            {
                "filename": "ssl_certificate_check.nasl",
                "content": self._create_ssl_cert_nasl()
            },
            {
                "filename": "apache_server_info.nasl",
                "content": self._create_apache_info_nasl()
            },
            {
                "filename": "nginx_server_info.nasl",
                "content": self._create_nginx_info_nasl()
            }
        ]
        
        samples_dir = self.target_dir / "samples"
        samples_dir.mkdir(exist_ok=True)
        
        for sig in sample_signatures:
            sig_file = samples_dir / sig["filename"]
            with open(sig_file, 'w') as f:
                f.write(sig["content"])
        
        print(f"✅ Created {len(sample_signatures)} sample signatures in {samples_dir}")
        return True
    
    def copy_existing_signatures(self, source_dir: str = "/var/lib/openvas/plugins") -> bool:
        """Copy existing NASL signatures if available."""
        source_path = Path(source_dir)
        
        if not source_path.exists():
            print(f"❌ Source directory not found: {source_path}")
            return False
        
        print(f"🔄 Copying signatures from {source_path}...")
        
        try:
            # Copy NASL files
            nasl_files = list(source_path.rglob("*.nasl"))
            
            if not nasl_files:
                print("❌ No NASL files found in source directory")
                return False
            
            copied_count = 0
            for nasl_file in nasl_files[:1000]:  # Limit to first 1000 files
                try:
                    # Create relative path structure
                    rel_path = nasl_file.relative_to(source_path)
                    target_file = self.target_dir / rel_path
                    
                    # Create parent directories
                    target_file.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Copy file
                    shutil.copy2(nasl_file, target_file)
                    copied_count += 1
                    
                except Exception as e:
                    self.logger.debug(f"Failed to copy {nasl_file}: {e}")
                    continue
            
            print(f"✅ Copied {copied_count} signature files")
            return copied_count > 0
            
        except Exception as e:
            print(f"❌ Failed to copy signatures: {e}")
            return False
    
    def _extract_tar_bz2(self, archive_path: Path):
        """Extract tar.bz2 archive."""
        try:
            with tarfile.open(archive_path, 'r:bz2') as tar:
                tar.extractall(self.target_dir)
        except Exception as e:
            self.logger.error(f"Failed to extract {archive_path}: {e}")
    
    def _create_http_version_nasl(self) -> str:
        """Create sample HTTP version detection NASL."""
        return '''# Sample HTTP Version Detection
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999001");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("HTTP Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"Detects the HTTP server version.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if(banner) {
  if("Apache" >< banner) {
    set_kb_item(name:"www/apache", value:TRUE);
    version = eregmatch(pattern:"Apache/([0-9.]+)", string:banner);
    if(version[1]) {
      set_kb_item(name:"www/apache/version", value:version[1]);
    }
  }
  
  if("nginx" >< banner) {
    set_kb_item(name:"www/nginx", value:TRUE);
    version = eregmatch(pattern:"nginx/([0-9.]+)", string:banner);
    if(version[1]) {
      set_kb_item(name:"www/nginx/version", value:version[1]);
    }
  }
}
'''
    
    def _create_ssh_version_nasl(self) -> str:
        """Create sample SSH version detection NASL."""
        return '''# Sample SSH Version Detection
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999002");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("SSH Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Service detection");
  script_require_ports("Services/ssh", 22);
  script_tag(name:"summary", value:"Detects the SSH server version.");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);
banner = get_ssh_server_banner(port:port);

if(banner) {
  if("OpenSSH" >< banner) {
    set_kb_item(name:"ssh/openssh", value:TRUE);
    version = eregmatch(pattern:"OpenSSH_([0-9.]+)", string:banner);
    if(version[1]) {
      set_kb_item(name:"ssh/openssh/version", value:version[1]);
    }
  }
}
'''
    
    def _create_ssl_cert_nasl(self) -> str:
        """Create sample SSL certificate check NASL."""
        return '''# Sample SSL Certificate Check
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999003");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("SSL Certificate Expiry Check");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("SSL and TLS");
  script_dependencies("ssl_cert_details.nasl");
  script_require_ports("Services/www", 443);
  script_tag(name:"summary", value:"Checks SSL certificate expiry.");
  script_tag(name:"insight", value:"SSL certificates should be renewed before expiry.");
  script_tag(name:"solution", value:"Renew SSL certificate before expiry date.");
  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

port = get_service(svc:"www", default:443, exit_on_fail:TRUE);
cert = get_server_cert(port:port);

if(cert) {
  expiry = cert_query(cert, "not-after");
  if(expiry) {
    days_left = (expiry - unixtime()) / 86400;
    if(days_left < 30) {
      security_message(port:port, data:"SSL certificate expires in " + days_left + " days");
    }
  }
}
'''
    
    def _create_apache_info_nasl(self) -> str:
        """Create sample Apache server info NASL."""
        return '''# Sample Apache Server Info
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999004");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Apache Server Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"Checks for Apache server information disclosure.");
  script_tag(name:"insight", value:"Apache server may reveal version information.");
  script_tag(name:"solution", value:"Configure ServerTokens to Prod in Apache configuration.");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if(banner && "Apache" >< banner) {
  if(egrep(pattern:"Server: Apache/[0-9.]+", string:banner)) {
    security_message(port:port, data:"Apache server version information disclosed in banner");
  }
}
'''
    
    def _create_nginx_info_nasl(self) -> str:
        """Create sample Nginx server info NASL."""
        return '''# Sample Nginx Server Info
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.999005");
  script_version("2025-01-01");
  script_tag(name:"last_modification", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"creation_date", value:"2025-01-01 00:00:00 +0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Nginx Server Information Disclosure");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 SwampScan");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"summary", value:"Checks for Nginx server information disclosure.");
  script_tag(name:"insight", value:"Nginx server may reveal version information.");
  script_tag(name:"solution", value:"Configure server_tokens off in Nginx configuration.");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");
  exit(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if(banner && "nginx" >< banner) {
  if(egrep(pattern:"Server: nginx/[0-9.]+", string:banner)) {
    security_message(port:port, data:"Nginx server version information disclosed in banner");
  }
}
'''


def create_parser():
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        description="Download vulnerability signatures for SwampScan Lite",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        "--target-dir",
        default="./signatures",
        help="Target directory for downloaded signatures (default: ./signatures)"
    )
    
    parser.add_argument(
        "--source-dir",
        default="/var/lib/openvas/plugins",
        help="Source directory to copy existing signatures from"
    )
    
    parser.add_argument(
        "--method",
        choices=["copy", "download", "samples", "all"],
        default="all",
        help="Download method (default: all)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    return parser


def main():
    """Main entry point."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    print("📥 SwampScan Signature Downloader")
    print("=" * 40)
    
    downloader = SignatureDownloader(args.target_dir)
    success = False
    
    if args.method in ["copy", "all"]:
        print("\n1. Trying to copy existing signatures...")
        if downloader.copy_existing_signatures(args.source_dir):
            success = True
        else:
            print("   No existing signatures found to copy")
    
    if args.method in ["download", "all"]:
        print("\n2. Trying to download from official feeds...")
        if downloader.download_greenbone_community_feed():
            success = True
        else:
            print("   Official feed download not available")
    
    if args.method in ["samples", "all"] or not success:
        print("\n3. Creating sample signatures...")
        if downloader.download_sample_signatures():
            success = True
    
    if success:
        print(f"\n✅ Signatures are ready in: {args.target_dir}")
        print(f"   Use with: python3 swampscan_lite.py --signature-dir {args.target_dir}")
    else:
        print("\n❌ Failed to obtain any signatures")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())

