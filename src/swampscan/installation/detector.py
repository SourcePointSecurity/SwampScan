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
            'binary_paths': ['/usr/local/bin/openvas-scanner', '/usr/bin/openvas-scanner'],
            'check_command': 'openvas-scanner --version'
        },
        'openvasd': {
            'binary_paths': ['/usr/local/bin/openvasd', '/usr/bin/openvasd', 
                           '~/.cargo/bin/openvasd'],
            'check_command': 'openvasd --help'  # openvasd doesn't support --version
        },
        'scannerctl': {
            'binary_paths': ['/usr/local/bin/scannerctl', '/usr/bin/scannerctl',
                           '~/.cargo/bin/scannerctl'],
            'check_command': 'scannerctl --help'  # scannerctl doesn't support --version
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
        
        # Determine if ready for scanning - be more permissive and informative
        has_scanner = components.get('openvas-scanner', ComponentStatus('openvas-scanner', False)).installed
        has_gvmd = components.get('openvasd', ComponentStatus('openvasd', False)).installed
        has_scannerctl = components.get('scannerctl', ComponentStatus('scannerctl', False)).installed
        
        # Check if we have the core OpenVAS components (flexible for different installations)
        ready_for_scanning = (has_scanner and has_gvmd) or (has_scanner and has_scannerctl)
        
        # If not ready, check if we can provide helpful guidance
        if not ready_for_scanning:
            # Check if this might be a partial installation that can be completed
            has_some_components = has_scanner or has_gvmd or has_scannerctl
            has_rust = rust_status.installed
            has_basic_deps = all(
                system_deps.get(dep, ComponentStatus(dep, False)).installed 
                for dep in ['gcc', 'cmake', 'pkg-config']
            )
            
            if has_some_components or (has_rust and has_basic_deps):
                # Reduce installation_required if we have some components
                self.logger.info("Partial OpenVAS installation detected - may only need component completion")
                
        # Override installation_required if we have working OpenVAS components
        if ready_for_scanning:
            installation_required = False
            self.logger.info("OpenVAS components detected and ready for scanning")
        elif not installation_required:
            # If we don't have components but also don't think installation is required,
            # we should probably require installation
            installation_required = True
        
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
                # Try to get version/help information
                try:
                    result = subprocess.run(
                        config['check_command'].split(),
                        capture_output=True,
                        text=True,
                        timeout=10
                    )
                    # For --help commands, success means the binary is functional
                    # For --version commands, we extract version info
                    if result.returncode == 0:
                        if '--version' in config['check_command']:
                            version = self._extract_version(result.stdout)
                        else:
                            # For --help commands, just confirm it's working
                            version = "Available (responds to --help)"
                        components[name] = ComponentStatus(
                            name, True, version=version, path=binary_path
                        )
                    else:
                        # Even if command fails, if binary exists and is executable, mark as available
                        # This handles cases where newer tools don't support expected flags
                        components[name] = ComponentStatus(
                            name, True, version="Available (binary found)", path=binary_path,
                            issues=[f"Command output: {result.stderr.strip()[:100]}"]
                        )
                except (subprocess.TimeoutExpired, FileNotFoundError) as e:
                    # Binary exists but command failed - still mark as available
                    components[name] = ComponentStatus(
                        name, True, version="Available (binary found)", path=binary_path,
                        issues=[f"Command test failed: {str(e)[:100]}"]
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
            
            # Add helpful next steps
            lines.append("")
            lines.append("📋 Next Steps:")
            if "rust-toolchain" in status.missing_components:
                lines.append("  1. Install Rust toolchain:")
                lines.append("     curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh")
                lines.append("     source ~/.cargo/env")
            
            if any("system-" in comp for comp in status.missing_components):
                lines.append("  2. Install missing system dependencies:")
                lines.append("     sudo apt-get update && sudo apt-get install -y \\")
                missing_sys_deps = [comp.replace("system-", "") for comp in status.missing_components if comp.startswith("system-")]
                if "dev-libraries" in [comp.name for comp in status.system_dependencies.values() if not comp.installed]:
                    lines.append("       libgpgme-dev libksba-dev libgnutls28-dev libgcrypt-dev \\")
                    lines.append("       libpcap-dev libglib2.0-dev libjson-glib-dev libssh-dev")
                for dep in missing_sys_deps:
                    if dep != "dev-libraries":
                        lines.append(f"       {dep}")
            
            if any(comp in status.missing_components for comp in ["openvas-scanner", "openvasd", "scannerctl"]):
                lines.append("  3. Complete OpenVAS installation:")
                lines.append("     swampscan --install --non-interactive")
                lines.append("     OR run the enhanced installation script:")
                lines.append("     ./scripts/install_swampscan.sh")
        
        elif not status.ready_for_scanning:
            lines.append("")
            lines.append("📋 Installation appears complete but components may need configuration.")
            lines.append("Try running: swampscan --install --non-interactive")
        
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

