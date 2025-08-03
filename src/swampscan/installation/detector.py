"""
OpenVAS Installation Detector

This module provides functionality to detect existing OpenVAS installations
and identify missing components that need to be installed.
"""

import os
import subprocess
import shutil
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ComponentStatus:
    """Represents the status of an OpenVAS component."""
    name: str
    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None
    issues: List[str] = None
    
    def __post_init__(self):
        if self.issues is None:
            self.issues = []


@dataclass
class InstallationStatus:
    """Represents the overall OpenVAS installation status."""
    components: Dict[str, ComponentStatus]
    rust_toolchain: ComponentStatus
    system_dependencies: Dict[str, ComponentStatus]
    ready_for_scanning: bool
    missing_components: List[str]
    installation_required: bool


class OpenVASDetector:
    """Detects OpenVAS installation status and component availability."""
    
    # Required system dependencies for OpenVAS C implementation
    SYSTEM_DEPENDENCIES = {
        'gcc': 'gcc --version',
        'cmake': 'cmake --version',
        'pkg-config': 'pkg-config --version',
        'redis-server': 'redis-server --version',
        'git': 'git --version',
        'curl': 'curl --version',
        'make': 'make --version'
    }
    
    # Required development libraries (checked via pkg-config)
    PKG_CONFIG_LIBS = [
        'glib-2.0',
        'gio-2.0', 
        'json-glib-1.0',
        'libpcap',
        'libgcrypt',
        'libgpgme',
        'libssh',
        'libksba',
        'gnutls',
        'libcurl'
    ]
    
    # OpenVAS specific components
    OPENVAS_COMPONENTS = {
        'openvas-scanner': {
            'binary_paths': ['/usr/local/bin/openvas', '/usr/bin/openvas'],
            'check_command': 'openvas --version'
        },
        'openvasd': {
            'binary_paths': ['/usr/local/bin/openvasd', '/usr/bin/openvasd', 
                           '~/.cargo/bin/openvasd'],
            'check_command': 'openvasd --version'
        },
        'scannerctl': {
            'binary_paths': ['/usr/local/bin/scannerctl', '/usr/bin/scannerctl',
                           '~/.cargo/bin/scannerctl'],
            'check_command': 'scannerctl --version'
        }
    }
    
    def __init__(self):
        """Initialize the OpenVAS detector."""
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def detect_installation(self) -> InstallationStatus:
        """
        Perform comprehensive detection of OpenVAS installation status.
        
        Returns:
            InstallationStatus: Complete status of the OpenVAS installation
        """
        self.logger.info("Starting OpenVAS installation detection...")
        
        # Check system dependencies
        system_deps = self._check_system_dependencies()
        
        # Check Rust toolchain
        rust_status = self._check_rust_toolchain()
        
        # Check OpenVAS components
        components = self._check_openvas_components()
        
        # Check development libraries
        self._check_development_libraries(system_deps)
        
        # Determine overall status
        missing_components = []
        installation_required = False
        
        # Check for missing system dependencies
        for name, status in system_deps.items():
            if not status.installed:
                missing_components.append(f"system-{name}")
                installation_required = True
        
        # Check for missing OpenVAS components
        for name, status in components.items():
            if not status.installed:
                missing_components.append(name)
                installation_required = True
        
        # Check Rust toolchain
        if not rust_status.installed:
            missing_components.append("rust-toolchain")
            installation_required = True
        
        # Determine if ready for scanning - be more permissive for Ubuntu installations
        has_scanner = components.get('openvas-scanner', ComponentStatus('openvas-scanner', False)).installed
        has_gvmd = components.get('openvasd', ComponentStatus('openvasd', False)).installed
        has_scannerctl = components.get('scannerctl', ComponentStatus('scannerctl', False)).installed
        
        # Check if we have the core OpenVAS components (more flexible for Ubuntu)
        ready_for_scanning = (has_scanner and has_gvmd) or (has_scanner and has_scannerctl)
        
        # Override installation_required if we have working OpenVAS components
        if ready_for_scanning:
            installation_required = False
        
        status = InstallationStatus(
            components=components,
            rust_toolchain=rust_status,
            system_dependencies=system_deps,
            ready_for_scanning=ready_for_scanning,
            missing_components=missing_components,
            installation_required=installation_required
        )
        
        self.logger.info(f"Detection complete. Ready for scanning: {ready_for_scanning}")
        self.logger.info(f"Missing components: {missing_components}")
        
        return status
    
    def _check_system_dependencies(self) -> Dict[str, ComponentStatus]:
        """Check for required system dependencies."""
        self.logger.debug("Checking system dependencies...")
        dependencies = {}
        
        for name, check_cmd in self.SYSTEM_DEPENDENCIES.items():
            status = self._check_command_availability(name, check_cmd)
            dependencies[name] = status
            
        return dependencies
    
    def _check_rust_toolchain(self) -> ComponentStatus:
        """Check for Rust toolchain availability."""
        self.logger.debug("Checking Rust toolchain...")
        
        # Check for rustc
        rustc_status = self._check_command_availability('rustc', 'rustc --version')
        if not rustc_status.installed:
            return ComponentStatus('rust-toolchain', False, issues=['rustc not found'])
        
        # Check for cargo
        cargo_status = self._check_command_availability('cargo', 'cargo --version')
        if not cargo_status.installed:
            return ComponentStatus('rust-toolchain', False, issues=['cargo not found'])
        
        return ComponentStatus(
            'rust-toolchain', 
            True, 
            version=rustc_status.version,
            path=rustc_status.path
        )
    
    def _check_openvas_components(self) -> Dict[str, ComponentStatus]:
        """Check for OpenVAS component availability."""
        self.logger.debug("Checking OpenVAS components...")
        components = {}
        
        for name, config in self.OPENVAS_COMPONENTS.items():
            # First try to find the binary in known paths
            binary_path = None
            for path in config['binary_paths']:
                expanded_path = os.path.expanduser(path)
                if os.path.isfile(expanded_path) and os.access(expanded_path, os.X_OK):
                    binary_path = expanded_path
                    break
            
            if binary_path:
                # Try to get version information
                try:
                    result = subprocess.run(
                        config['check_command'].split(),
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    if result.returncode == 0:
                        version = self._extract_version(result.stdout)
                        components[name] = ComponentStatus(
                            name, True, version=version, path=binary_path
                        )
                    else:
                        components[name] = ComponentStatus(
                            name, False, path=binary_path,
                            issues=[f"Command failed: {result.stderr}"]
                        )
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    components[name] = ComponentStatus(
                        name, False, path=binary_path,
                        issues=[f"Command execution failed: {str(e)}"]
                    )
            else:
                # Try using which/whereis to find the binary
                which_result = shutil.which(name)
                if which_result:
                    components[name] = ComponentStatus(
                        name, True, path=which_result
                    )
                else:
                    components[name] = ComponentStatus(
                        name, False, issues=['Binary not found in PATH']
                    )
        
        return components
    
    def _check_development_libraries(self, system_deps: Dict[str, ComponentStatus]):
        """Check for required development libraries using pkg-config."""
        self.logger.debug("Checking development libraries...")
        
        pkg_config = system_deps.get('pkg-config')
        if not pkg_config or not pkg_config.installed:
            self.logger.warning("pkg-config not available, skipping library checks")
            return
        
        missing_libs = []
        for lib in self.PKG_CONFIG_LIBS:
            try:
                result = subprocess.run(
                    ['pkg-config', '--exists', lib],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode != 0:
                    missing_libs.append(lib)
            except (subprocess.TimeoutExpired, FileNotFoundError):
                missing_libs.append(lib)
        
        if missing_libs:
            # Add missing libraries to system dependencies
            system_deps['dev-libraries'] = ComponentStatus(
                'dev-libraries', False,
                issues=[f"Missing libraries: {', '.join(missing_libs)}"]
            )
        else:
            system_deps['dev-libraries'] = ComponentStatus(
                'dev-libraries', True
            )
    
    def _check_command_availability(self, name: str, command: str) -> ComponentStatus:
        """Check if a command is available and get its version."""
        try:
            # First check if command exists
            binary_path = shutil.which(name)
            if not binary_path:
                return ComponentStatus(name, False, issues=['Command not found in PATH'])
            
            # Try to execute the command to get version
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                version = self._extract_version(result.stdout)
                return ComponentStatus(name, True, version=version, path=binary_path)
            else:
                return ComponentStatus(
                    name, False, path=binary_path,
                    issues=[f"Command failed: {result.stderr}"]
                )
                
        except subprocess.TimeoutExpired:
            return ComponentStatus(
                name, False, path=binary_path,
                issues=['Command execution timed out']
            )
        except FileNotFoundError:
            return ComponentStatus(name, False, issues=['Command not found'])
        except Exception as e:
            return ComponentStatus(
                name, False, issues=[f"Unexpected error: {str(e)}"]
            )
    
    def _extract_version(self, output: str) -> Optional[str]:
        """Extract version information from command output."""
        lines = output.strip().split('\n')
        for line in lines:
            # Look for common version patterns
            import re
            version_patterns = [
                r'version\s+(\d+\.\d+\.\d+)',
                r'(\d+\.\d+\.\d+)',
                r'v(\d+\.\d+\.\d+)',
                r'Version\s+(\d+\.\d+\.\d+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return None
    
    def get_installation_summary(self, status: InstallationStatus) -> str:
        """Generate a human-readable summary of the installation status."""
        lines = []
        lines.append("OpenVAS Installation Status Summary")
        lines.append("=" * 40)
        
        # Overall status
        if status.ready_for_scanning:
            lines.append("✅ System is ready for vulnerability scanning")
        else:
            lines.append("❌ System requires additional setup")
        
        lines.append("")
        
        # System dependencies
        lines.append("System Dependencies:")
        for name, comp in status.system_dependencies.items():
            status_icon = "✅" if comp.installed else "❌"
            version_info = f" (v{comp.version})" if comp.version else ""
            lines.append(f"  {status_icon} {name}{version_info}")
            if comp.issues:
                for issue in comp.issues:
                    lines.append(f"      ⚠️  {issue}")
        
        lines.append("")
        
        # Rust toolchain
        rust_icon = "✅" if status.rust_toolchain.installed else "❌"
        rust_version = f" (v{status.rust_toolchain.version})" if status.rust_toolchain.version else ""
        lines.append(f"Rust Toolchain: {rust_icon} {rust_version}")
        if status.rust_toolchain.issues:
            for issue in status.rust_toolchain.issues:
                lines.append(f"  ⚠️  {issue}")
        
        lines.append("")
        
        # OpenVAS components
        lines.append("OpenVAS Components:")
        for name, comp in status.components.items():
            comp_icon = "✅" if comp.installed else "❌"
            comp_version = f" (v{comp.version})" if comp.version else ""
            lines.append(f"  {comp_icon} {name}{comp_version}")
            if comp.path:
                lines.append(f"      📁 {comp.path}")
            if comp.issues:
                for issue in comp.issues:
                    lines.append(f"      ⚠️  {issue}")
        
        if status.missing_components:
            lines.append("")
            lines.append("Missing Components:")
            for component in status.missing_components:
                lines.append(f"  ❌ {component}")
        
        return "\n".join(lines)


def detect_openvas_installation() -> InstallationStatus:
    """
    Convenience function to detect OpenVAS installation status.
    
    Returns:
        InstallationStatus: Complete status of the OpenVAS installation
    """
    detector = OpenVASDetector()
    return detector.detect_installation()


if __name__ == "__main__":
    # Test the detector
    logging.basicConfig(level=logging.INFO)
    detector = OpenVASDetector()
    status = detector.detect_installation()
    print(detector.get_installation_summary(status))

