#!/usr/bin/env python3
"""
Setup script for OpenVAS CLI Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    requirements = requirements_file.read_text().strip().split("\\n")
    requirements = [req.strip() for req in requirements if req.strip() and not req.startswith("#")]
else:
    requirements = [
        "requests>=2.25.0",
        "ipaddress>=1.0.23; python_version<'3.3'",
    ]

setup(
    name="openvas-cli-scanner",
    version="1.0.0",
    author="OpenVAS CLI Scanner Team",
    author_email="support@example.com",
    description="Python CLI interface to OpenVAS vulnerability scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/openvas-cli-scanner",
    project_urls={
        "Bug Reports": "https://github.com/example/openvas-cli-scanner/issues",
        "Source": "https://github.com/example/openvas-cli-scanner",
        "Documentation": "https://github.com/example/openvas-cli-scanner/wiki",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "black>=21.0",
            "flake8>=3.8",
            "mypy>=0.800",
        ],
        "docs": [
            "sphinx>=4.0",
            "sphinx-rtd-theme>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "openvas-cli-scanner=openvas_cli_scanner.cli:console_entry_point",
            "ovs-scan=openvas_cli_scanner.cli:console_entry_point",
        ],
    },
    include_package_data=True,
    zip_safe=False,
    keywords=[
        "openvas",
        "vulnerability",
        "scanner",
        "security",
        "penetration-testing",
        "network-security",
        "cli",
        "automation"
    ],
)

