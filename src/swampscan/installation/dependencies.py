"""
OpenVAS Dependencies Management

This module defines the specific requirements and dependencies for OpenVAS
components and provides utilities for dependency management.
"""

import os
import subprocess
import logging
from typing import Dict, List, Optional, Tuple, NamedTuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class ComponentType(Enum):
    """Types of OpenVAS components."""
    SYSTEM_TOOL = "system_tool"
    DEVELOPMENT_LIB = "development_lib"
    OPENVAS_BINARY = "openvas_binary"
    RUST_COMPONENT = "rust_component"


class InstallMethod(Enum):
    """Installation methods for components."""
    PACKAGE_MANAGER = "package_manager"
    SOURCE_COMPILE = "source_compile"
    RUST_CARGO = "rust_cargo"
    SCRIPT_INSTALL = "script_install"


@dataclass
class Dependency:
    """Represents a single dependency requirement."""
    name: str
    component_type: ComponentType
    install_method: InstallMethod
    required: bool = True
    min_version: Optional[str] = None
    package_names: Optional[Dict[str, str]] = None  # distro -> package name
    check_command: Optional[str] = None
    install_command: Optional[List[str]] = None
    description: Optional[str] = None
    
    def __post_init__(self):
        if self.package_names is None:
            self.package_names = {}


class DependencyManager:
    """Manages OpenVAS dependencies and requirements."""
    
    # Core system tools required for building and running OpenVAS
    SYSTEM_TOOLS = [
        Dependency(
            name="gcc",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="gcc --version",
            package_names={
                "debian": "gcc",
                "ubuntu": "gcc", 
                "centos": "gcc",
                "rhel": "gcc",
                "fedora": "gcc"
            },
            description="GNU Compiler Collection for building C components"
        ),
        Dependency(
            name="cmake",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="3.0",
            check_command="cmake --version",
            package_names={
                "debian": "cmake",
                "ubuntu": "cmake",
                "centos": "cmake",
                "rhel": "cmake", 
                "fedora": "cmake"
            },
            description="Cross-platform build system generator"
        ),
        Dependency(
            name="make",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="make --version",
            package_names={
                "debian": "make",
                "ubuntu": "make",
                "centos": "make",
                "rhel": "make",
                "fedora": "make"
            },
            description="GNU Make build automation tool"
        ),
        Dependency(
            name="pkg-config",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="pkg-config --version",
            package_names={
                "debian": "pkg-config",
                "ubuntu": "pkg-config",
                "centos": "pkgconfig",
                "rhel": "pkgconfig",
                "fedora": "pkgconfig"
            },
            description="Library compilation flags helper"
        ),
        Dependency(
            name="git",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="git --version",
            package_names={
                "debian": "git",
                "ubuntu": "git",
                "centos": "git",
                "rhel": "git",
                "fedora": "git"
            },
            description="Version control system for source code"
        ),
        Dependency(
            name="curl",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="curl --version",
            package_names={
                "debian": "curl",
                "ubuntu": "curl",
                "centos": "curl",
                "rhel": "curl",
                "fedora": "curl"
            },
            description="Command line tool for transferring data"
        ),
        Dependency(
            name="redis-server",
            component_type=ComponentType.SYSTEM_TOOL,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="redis-server --version",
            package_names={
                "debian": "redis-server",
                "ubuntu": "redis-server",
                "centos": "redis",
                "rhel": "redis",
                "fedora": "redis"
            },
            description="In-memory data structure store"
        )
    ]
    
    # Development libraries required for OpenVAS compilation
    DEVELOPMENT_LIBS = [
        Dependency(
            name="glib-2.0",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="2.42",
            check_command="pkg-config --exists glib-2.0",
            package_names={
                "debian": "libglib2.0-dev",
                "ubuntu": "libglib2.0-dev",
                "centos": "glib2-devel",
                "rhel": "glib2-devel",
                "fedora": "glib2-devel"
            },
            description="Low-level core library for GNOME applications"
        ),
        Dependency(
            name="json-glib-1.0",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="1.4.4",
            check_command="pkg-config --exists json-glib-1.0",
            package_names={
                "debian": "libjson-glib-dev",
                "ubuntu": "libjson-glib-dev",
                "centos": "json-glib-devel",
                "rhel": "json-glib-devel",
                "fedora": "json-glib-devel"
            },
            description="JSON parsing library for GLib"
        ),
        Dependency(
            name="libpcap",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="pkg-config --exists libpcap",
            package_names={
                "debian": "libpcap-dev",
                "ubuntu": "libpcap-dev",
                "centos": "libpcap-devel",
                "rhel": "libpcap-devel",
                "fedora": "libpcap-devel"
            },
            description="Packet capture library"
        ),
        Dependency(
            name="libgcrypt",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="1.6",
            check_command="pkg-config --exists libgcrypt",
            package_names={
                "debian": "libgcrypt20-dev",
                "ubuntu": "libgcrypt20-dev",
                "centos": "libgcrypt-devel",
                "rhel": "libgcrypt-devel",
                "fedora": "libgcrypt-devel"
            },
            description="Cryptographic library"
        ),
        Dependency(
            name="libgpgme",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="1.1.2",
            check_command="pkg-config --exists gpgme",
            package_names={
                "debian": "libgpgme-dev",
                "ubuntu": "libgpgme-dev",
                "centos": "gpgme-devel",
                "rhel": "gpgme-devel",
                "fedora": "gpgme-devel"
            },
            description="GnuPG Made Easy library"
        ),
        Dependency(
            name="libssh",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="0.6.0",
            check_command="pkg-config --exists libssh",
            package_names={
                "debian": "libssh-gcrypt-dev",
                "ubuntu": "libssh-gcrypt-dev",
                "centos": "libssh-devel",
                "rhel": "libssh-devel",
                "fedora": "libssh-devel"
            },
            description="SSH client library"
        ),
        Dependency(
            name="libksba",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="1.0.7",
            check_command="pkg-config --exists ksba",
            package_names={
                "debian": "libksba-dev",
                "ubuntu": "libksba-dev",
                "centos": "libksba-devel",
                "rhel": "libksba-devel",
                "fedora": "libksba-devel"
            },
            description="X.509 and CMS library"
        ),
        Dependency(
            name="gnutls",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            min_version="3.6.4",
            check_command="pkg-config --exists gnutls",
            package_names={
                "debian": "libgnutls28-dev",
                "ubuntu": "libgnutls28-dev",
                "centos": "gnutls-devel",
                "rhel": "gnutls-devel",
                "fedora": "gnutls-devel"
            },
            description="Secure communications library"
        ),
        Dependency(
            name="libcurl",
            component_type=ComponentType.DEVELOPMENT_LIB,
            install_method=InstallMethod.PACKAGE_MANAGER,
            check_command="pkg-config --exists libcurl",
            package_names={
                "debian": "libcurl4-gnutls-dev",
                "ubuntu": "libcurl4-gnutls-dev",
                "centos": "libcurl-devel",
                "rhel": "libcurl-devel",
                "fedora": "libcurl-devel"
            },
            description="Client-side URL transfer library"
        )
    ]
    
    # Rust toolchain components
    RUST_COMPONENTS = [
        Dependency(
            name="rustc",
            component_type=ComponentType.RUST_COMPONENT,
            install_method=InstallMethod.SCRIPT_INSTALL,
            check_command="rustc --version",
            install_command=["curl", "--proto", "=https", "--tlsv1.2", "-sSf", 
                           "https://sh.rustup.rs", "|", "sh", "-s", "--", "-y"],
            description="Rust compiler"
        ),
        Dependency(
            name="cargo",
            component_type=ComponentType.RUST_COMPONENT,
            install_method=InstallMethod.SCRIPT_INSTALL,
            check_command="cargo --version",
            description="Rust package manager and build tool"
        )
    ]
    
    # OpenVAS binary components
    OPENVAS_BINARIES = [
        Dependency(
            name="openvas-scanner",
            component_type=ComponentType.OPENVAS_BINARY,
            install_method=InstallMethod.SOURCE_COMPILE,
            check_command="openvas --version",
            description="OpenVAS vulnerability scanner (C implementation)"
        ),
        Dependency(
            name="openvasd",
            component_type=ComponentType.OPENVAS_BINARY,
            install_method=InstallMethod.RUST_CARGO,
            check_command="openvasd --version",
            description="OpenVAS daemon (Rust implementation)"
        ),
        Dependency(
            name="scannerctl",
            component_type=ComponentType.OPENVAS_BINARY,
            install_method=InstallMethod.RUST_CARGO,
            check_command="scannerctl --version",
            description="OpenVAS scanner control utility (Rust implementation)"
        )
    ]
    
    def __init__(self):
        """Initialize the dependency manager."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self._all_dependencies = None
    
    @property
    def all_dependencies(self) -> List[Dependency]:
        """Get all dependencies as a single list."""
        if self._all_dependencies is None:
            self._all_dependencies = (
                self.SYSTEM_TOOLS + 
                self.DEVELOPMENT_LIBS + 
                self.RUST_COMPONENTS + 
                self.OPENVAS_BINARIES
            )
        return self._all_dependencies
    
    def get_dependencies_by_type(self, component_type: ComponentType) -> List[Dependency]:
        """Get dependencies filtered by component type."""
        return [dep for dep in self.all_dependencies if dep.component_type == component_type]
    
    def get_dependencies_by_method(self, install_method: InstallMethod) -> List[Dependency]:
        """Get dependencies filtered by installation method."""
        return [dep for dep in self.all_dependencies if dep.install_method == install_method]
    
    def get_dependency_by_name(self, name: str) -> Optional[Dependency]:
        """Get a specific dependency by name."""
        for dep in self.all_dependencies:
            if dep.name == name:
                return dep
        return None
    
    def get_package_install_command(self, distro: str, dependencies: List[Dependency]) -> Optional[List[str]]:
        """
        Generate package manager install command for given dependencies.
        
        Args:
            distro: Linux distribution name
            dependencies: List of dependencies to install
            
        Returns:
            Install command as list of arguments, or None if not supported
        """
        # Filter dependencies that can be installed via package manager
        pkg_deps = [dep for dep in dependencies 
                   if dep.install_method == InstallMethod.PACKAGE_MANAGER]
        
        if not pkg_deps:
            return None
        
        # Get package names for the distribution
        packages = []
        for dep in pkg_deps:
            if distro in dep.package_names:
                packages.append(dep.package_names[distro])
            else:
                self.logger.warning(f"No package mapping for {dep.name} on {distro}")
        
        if not packages:
            return None
        
        # Generate command based on distribution
        if distro in ['debian', 'ubuntu']:
            return ['sudo', 'apt-get', 'install', '-y'] + packages
        elif distro in ['centos', 'rhel']:
            return ['sudo', 'yum', 'install', '-y'] + packages
        elif distro == 'fedora':
            return ['sudo', 'dnf', 'install', '-y'] + packages
        else:
            return None
    
    def validate_version(self, dependency: Dependency, installed_version: str) -> bool:
        """
        Validate if installed version meets minimum requirements.
        
        Args:
            dependency: Dependency with version requirements
            installed_version: Currently installed version
            
        Returns:
            True if version is sufficient, False otherwise
        """
        if not dependency.min_version:
            return True  # No version requirement
        
        try:
            return self._compare_versions(installed_version, dependency.min_version) >= 0
        except Exception as e:
            self.logger.warning(f"Could not compare versions for {dependency.name}: {e}")
            return True  # Assume OK if we can't compare
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two version strings.
        
        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        # Simple version comparison - split by dots and compare numerically
        def normalize_version(v):
            # Extract numeric parts from version string
            import re
            parts = re.findall(r'\\d+', v)
            return [int(x) for x in parts]
        
        v1_parts = normalize_version(version1)
        v2_parts = normalize_version(version2)
        
        # Pad shorter version with zeros
        max_len = max(len(v1_parts), len(v2_parts))
        v1_parts.extend([0] * (max_len - len(v1_parts)))
        v2_parts.extend([0] * (max_len - len(v2_parts)))
        
        # Compare part by part
        for p1, p2 in zip(v1_parts, v2_parts):
            if p1 < p2:
                return -1
            elif p1 > p2:
                return 1
        
        return 0
    
    def get_installation_order(self, dependencies: List[Dependency]) -> List[List[Dependency]]:
        """
        Get dependencies grouped by installation order.
        
        Returns:
            List of dependency groups in installation order
        """
        # Group dependencies by installation method in logical order
        order = [
            InstallMethod.PACKAGE_MANAGER,  # System packages first
            InstallMethod.SCRIPT_INSTALL,   # Rust toolchain
            InstallMethod.SOURCE_COMPILE,   # OpenVAS C components
            InstallMethod.RUST_CARGO        # Rust components last
        ]
        
        groups = []
        for method in order:
            group = [dep for dep in dependencies if dep.install_method == method]
            if group:
                groups.append(group)
        
        return groups
    
    def get_dependency_summary(self, dependencies: List[Dependency]) -> str:
        """Generate a human-readable summary of dependencies."""
        lines = []
        lines.append("OpenVAS Dependencies Summary")
        lines.append("=" * 30)
        
        # Group by type
        by_type = {}
        for dep in dependencies:
            if dep.component_type not in by_type:
                by_type[dep.component_type] = []
            by_type[dep.component_type].append(dep)
        
        for comp_type, deps in by_type.items():
            lines.append(f"\\n{comp_type.value.replace('_', ' ').title()}:")
            for dep in deps:
                required_text = "Required" if dep.required else "Optional"
                version_text = f" (>= {dep.min_version})" if dep.min_version else ""
                lines.append(f"  • {dep.name}{version_text} - {required_text}")
                if dep.description:
                    lines.append(f"    {dep.description}")
        
        return "\\n".join(lines)


# Global instance for easy access
dependency_manager = DependencyManager()


def get_all_dependencies() -> List[Dependency]:
    """Get all OpenVAS dependencies."""
    return dependency_manager.all_dependencies


def get_system_dependencies() -> List[Dependency]:
    """Get system tool dependencies."""
    return dependency_manager.get_dependencies_by_type(ComponentType.SYSTEM_TOOL)


def get_development_dependencies() -> List[Dependency]:
    """Get development library dependencies."""
    return dependency_manager.get_dependencies_by_type(ComponentType.DEVELOPMENT_LIB)


def get_rust_dependencies() -> List[Dependency]:
    """Get Rust component dependencies."""
    return dependency_manager.get_dependencies_by_type(ComponentType.RUST_COMPONENT)


def get_openvas_dependencies() -> List[Dependency]:
    """Get OpenVAS binary dependencies."""
    return dependency_manager.get_dependencies_by_type(ComponentType.OPENVAS_BINARY)


if __name__ == "__main__":
    # Test the dependency manager
    dm = DependencyManager()
    
    print(dm.get_dependency_summary(dm.all_dependencies))
    
    print("\\n\\nInstallation Order:")
    groups = dm.get_installation_order(dm.all_dependencies)
    for i, group in enumerate(groups, 1):
        print(f"\\n{i}. {group[0].install_method.value.replace('_', ' ').title()}:")
        for dep in group:
            print(f"   - {dep.name}")

