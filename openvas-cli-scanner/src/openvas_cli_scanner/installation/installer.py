"""
OpenVAS Installer

This module provides functionality to automatically install OpenVAS components
and their dependencies based on the system detection results.
"""

import os
import subprocess
import tempfile
import shutil
import logging
import platform
from typing import Dict, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass

from .detector import InstallationStatus, ComponentStatus, OpenVASDetector

logger = logging.getLogger(__name__)


@dataclass
class InstallationResult:
    """Represents the result of an installation operation."""
    success: bool
    component: str
    message: str
    details: List[str] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = []


class OpenVASInstaller:
    """Handles automatic installation of OpenVAS components."""
    
    # System package mappings for different distributions
    DEBIAN_PACKAGES = {
        'system-deps': [
            'gcc', 'pkg-config', 'libssh-gcrypt-dev', 'libgnutls28-dev',
            'libglib2.0-dev', 'libjson-glib-dev', 'libpcap-dev', 'libgpgme-dev',
            'bison', 'libksba-dev', 'libsnmp-dev', 'libgcrypt20-dev', 
            'redis-server', 'libbsd-dev', 'libcurl4-gnutls-dev', 'krb5-multidev',
            'cmake', 'make', 'git', 'curl', 'build-essential', 'flex'
        ],
        'build-deps': [
            'libgvm-base-dev', 'libgvm-util-dev'
        ]
    }
    
    UBUNTU_PACKAGES = DEBIAN_PACKAGES  # Ubuntu uses same packages as Debian
    
    CENTOS_PACKAGES = {
        'system-deps': [
            'gcc', 'pkgconfig', 'libssh-devel', 'gnutls-devel',
            'glib2-devel', 'json-glib-devel', 'libpcap-devel', 'gpgme-devel',
            'bison', 'libksba-devel', 'net-snmp-devel', 'libgcrypt-devel',
            'redis', 'libbsd-devel', 'libcurl-devel', 'krb5-devel',
            'cmake', 'make', 'git', 'curl', 'gcc-c++'
        ]
    }
    
    def __init__(self, install_prefix: str = "/usr/local"):
        """
        Initialize the OpenVAS installer.
        
        Args:
            install_prefix: Installation prefix for compiled components
        """
        self.install_prefix = install_prefix
        self.logger = logging.getLogger(self.__class__.__name__)
        self.temp_dir = None
        
    def install_missing_components(self, status: InstallationStatus, 
                                 interactive: bool = True) -> List[InstallationResult]:
        """
        Install all missing components identified in the installation status.
        
        Args:
            status: Installation status from detector
            interactive: Whether to prompt user for confirmation
            
        Returns:
            List of installation results
        """
        results = []
        
        if not status.installation_required:
            self.logger.info("No installation required - system is ready")
            return results
        
        self.logger.info(f"Installing {len(status.missing_components)} missing components...")
        
        # Create temporary directory for downloads and builds
        self.temp_dir = tempfile.mkdtemp(prefix="openvas_install_")
        self.logger.debug(f"Using temporary directory: {self.temp_dir}")
        
        try:
            # Install system dependencies first
            if self._needs_system_packages(status):
                result = self._install_system_packages(interactive)
                results.append(result)
                if not result.success:
                    self.logger.error("Failed to install system packages, aborting")
                    return results
            
            # Install Rust toolchain if needed
            if not status.rust_toolchain.installed:
                result = self._install_rust_toolchain(interactive)
                results.append(result)
                if not result.success:
                    self.logger.warning("Rust installation failed, will try alternative methods")
            
            # Install OpenVAS C components if needed
            if self._needs_openvas_c_components(status):
                result = self._install_openvas_c_components(interactive)
                results.append(result)
            
            # Install OpenVAS Rust components if needed and Rust is available
            if self._needs_openvas_rust_components(status):
                # Re-check Rust availability after potential installation
                detector = OpenVASDetector()
                updated_status = detector.detect_installation()
                if updated_status.rust_toolchain.installed:
                    result = self._install_openvas_rust_components(interactive)
                    results.append(result)
                else:
                    results.append(InstallationResult(
                        False, "openvas-rust", 
                        "Rust toolchain not available for Rust components"
                    ))
            
        finally:
            # Clean up temporary directory
            if self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                self.logger.debug("Cleaned up temporary directory")
        
        return results
    
    def _needs_system_packages(self, status: InstallationStatus) -> bool:
        """Check if system packages need to be installed."""
        for name, component in status.system_dependencies.items():
            if not component.installed and name != 'dev-libraries':
                return True
        return False
    
    def _needs_openvas_c_components(self, status: InstallationStatus) -> bool:
        """Check if OpenVAS C components need to be installed."""
        return not status.components.get('openvas-scanner', ComponentStatus('openvas-scanner', False)).installed
    
    def _needs_openvas_rust_components(self, status: InstallationStatus) -> bool:
        """Check if OpenVAS Rust components need to be installed."""
        return (not status.components.get('openvasd', ComponentStatus('openvasd', False)).installed or
                not status.components.get('scannerctl', ComponentStatus('scannerctl', False)).installed)
    
    def _install_system_packages(self, interactive: bool) -> InstallationResult:
        """Install required system packages using the system package manager."""
        self.logger.info("Installing system packages...")
        
        # Detect the distribution
        distro = self._detect_distribution()
        if not distro:
            return InstallationResult(
                False, "system-packages",
                "Could not detect Linux distribution for package installation"
            )
        
        # Get package list for the distribution
        packages = self._get_packages_for_distro(distro)
        if not packages:
            return InstallationResult(
                False, "system-packages",
                f"No package list available for distribution: {distro}"
            )
        
        # Confirm installation if interactive
        if interactive:
            print(f"\\nAbout to install {len(packages)} system packages for {distro}:")
            print(f"Packages: {', '.join(packages[:10])}{'...' if len(packages) > 10 else ''}")
            response = input("Continue with installation? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                return InstallationResult(
                    False, "system-packages", "Installation cancelled by user"
                )
        
        # Install packages
        try:
            if distro in ['debian', 'ubuntu']:
                # Update package list first
                self._run_command(['sudo', 'apt-get', 'update'], "Updating package list")
                
                # Install packages
                cmd = ['sudo', 'apt-get', 'install', '-y'] + packages
                self._run_command(cmd, "Installing packages")
                
            elif distro in ['centos', 'rhel', 'fedora']:
                # Use yum or dnf
                pkg_manager = 'dnf' if shutil.which('dnf') else 'yum'
                cmd = ['sudo', pkg_manager, 'install', '-y'] + packages
                self._run_command(cmd, "Installing packages")
                
            else:
                return InstallationResult(
                    False, "system-packages",
                    f"Unsupported distribution for automatic installation: {distro}"
                )
            
            return InstallationResult(
                True, "system-packages", 
                f"Successfully installed {len(packages)} system packages"
            )
            
        except subprocess.CalledProcessError as e:
            return InstallationResult(
                False, "system-packages",
                f"Package installation failed: {e}",
                details=[str(e)]
            )
    
    def _install_rust_toolchain(self, interactive: bool) -> InstallationResult:
        """Install Rust toolchain using rustup."""
        self.logger.info("Installing Rust toolchain...")
        
        if interactive:
            print("\\nAbout to install Rust toolchain using rustup...")
            response = input("Continue with Rust installation? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                return InstallationResult(
                    False, "rust-toolchain", "Installation cancelled by user"
                )
        
        try:
            # Download and run rustup installer
            rustup_script = os.path.join(self.temp_dir, "rustup-init.sh")
            
            # Download rustup installer
            self._run_command([
                'curl', '--proto', '=https', '--tlsv1.2', '-sSf', 
                'https://sh.rustup.rs', '-o', rustup_script
            ], "Downloading rustup installer")
            
            # Make executable
            os.chmod(rustup_script, 0o755)
            
            # Run installer
            env = os.environ.copy()
            env['RUSTUP_INIT_SKIP_PATH_CHECK'] = 'yes'
            
            self._run_command([
                'sh', rustup_script, '-y', '--default-toolchain', 'stable'
            ], "Installing Rust toolchain", env=env)
            
            # Source the cargo environment
            cargo_env = os.path.expanduser("~/.cargo/env")
            if os.path.exists(cargo_env):
                # Add cargo to PATH for current session
                cargo_bin = os.path.expanduser("~/.cargo/bin")
                if cargo_bin not in os.environ.get('PATH', ''):
                    os.environ['PATH'] = f"{cargo_bin}:{os.environ.get('PATH', '')}"
            
            return InstallationResult(
                True, "rust-toolchain",
                "Successfully installed Rust toolchain"
            )
            
        except subprocess.CalledProcessError as e:
            return InstallationResult(
                False, "rust-toolchain",
                f"Rust installation failed: {e}",
                details=[str(e)]
            )
    
    def _install_openvas_c_components(self, interactive: bool) -> InstallationResult:
        """Install OpenVAS C components from source."""
        self.logger.info("Installing OpenVAS C components...")
        
        if interactive:
            print("\\nAbout to compile and install OpenVAS Scanner from source...")
            print("This may take 15-30 minutes depending on your system.")
            response = input("Continue with OpenVAS installation? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                return InstallationResult(
                    False, "openvas-scanner", "Installation cancelled by user"
                )
        
        try:
            # Clone the repository
            repo_dir = os.path.join(self.temp_dir, "openvas-scanner")
            self._run_command([
                'git', 'clone', 'https://github.com/greenbone/openvas-scanner.git', repo_dir
            ], "Cloning OpenVAS Scanner repository")
            
            # Create build directory
            build_dir = os.path.join(repo_dir, "build")
            os.makedirs(build_dir, exist_ok=True)
            
            # Configure build
            self._run_command([
                'cmake', f'-DCMAKE_INSTALL_PREFIX={self.install_prefix}', '..'
            ], "Configuring build", cwd=build_dir)
            
            # Build
            self._run_command([
                'make', '-j', str(os.cpu_count() or 4)
            ], "Building OpenVAS Scanner", cwd=build_dir)
            
            # Install
            self._run_command([
                'sudo', 'make', 'install'
            ], "Installing OpenVAS Scanner", cwd=build_dir)
            
            return InstallationResult(
                True, "openvas-scanner",
                "Successfully installed OpenVAS Scanner"
            )
            
        except subprocess.CalledProcessError as e:
            return InstallationResult(
                False, "openvas-scanner",
                f"OpenVAS Scanner installation failed: {e}",
                details=[str(e)]
            )
    
    def _install_openvas_rust_components(self, interactive: bool) -> InstallationResult:
        """Install OpenVAS Rust components (openvasd, scannerctl)."""
        self.logger.info("Installing OpenVAS Rust components...")
        
        if interactive:
            print("\\nAbout to compile and install OpenVAS Rust components...")
            print("This may take 10-20 minutes depending on your system.")
            response = input("Continue with Rust components installation? [y/N]: ")
            if response.lower() not in ['y', 'yes']:
                return InstallationResult(
                    False, "openvas-rust", "Installation cancelled by user"
                )
        
        try:
            # Clone the repository if not already done
            repo_dir = os.path.join(self.temp_dir, "openvas-scanner")
            if not os.path.exists(repo_dir):
                self._run_command([
                    'git', 'clone', 'https://github.com/greenbone/openvas-scanner.git', repo_dir
                ], "Cloning OpenVAS Scanner repository")
            
            rust_dir = os.path.join(repo_dir, "rust")
            
            # Build Rust components
            self._run_command([
                'cargo', 'build', '--release'
            ], "Building Rust components", cwd=rust_dir)
            
            # Install binaries to user's cargo bin directory
            cargo_bin = os.path.expanduser("~/.cargo/bin")
            os.makedirs(cargo_bin, exist_ok=True)
            
            target_dir = os.path.join(rust_dir, "target", "release")
            
            # Copy binaries
            for binary in ['openvasd', 'scannerctl']:
                src = os.path.join(target_dir, binary)
                dst = os.path.join(cargo_bin, binary)
                if os.path.exists(src):
                    shutil.copy2(src, dst)
                    os.chmod(dst, 0o755)
                    self.logger.info(f"Installed {binary} to {dst}")
            
            return InstallationResult(
                True, "openvas-rust",
                "Successfully installed OpenVAS Rust components"
            )
            
        except subprocess.CalledProcessError as e:
            return InstallationResult(
                False, "openvas-rust",
                f"Rust components installation failed: {e}",
                details=[str(e)]
            )
    
    def _detect_distribution(self) -> Optional[str]:
        """Detect the Linux distribution."""
        try:
            # Try to read /etc/os-release
            if os.path.exists('/etc/os-release'):
                with open('/etc/os-release', 'r') as f:
                    content = f.read()
                    if 'ubuntu' in content.lower():
                        return 'ubuntu'
                    elif 'debian' in content.lower():
                        return 'debian'
                    elif 'centos' in content.lower():
                        return 'centos'
                    elif 'rhel' in content.lower() or 'red hat' in content.lower():
                        return 'rhel'
                    elif 'fedora' in content.lower():
                        return 'fedora'
            
            # Fallback to platform detection
            system = platform.system().lower()
            if system == 'linux':
                # Try to detect based on available package managers
                if shutil.which('apt-get'):
                    return 'debian'  # Assume Debian-based
                elif shutil.which('yum') or shutil.which('dnf'):
                    return 'centos'  # Assume RHEL-based
            
            return None
            
        except Exception as e:
            self.logger.warning(f"Could not detect distribution: {e}")
            return None
    
    def _get_packages_for_distro(self, distro: str) -> List[str]:
        """Get the package list for a specific distribution."""
        if distro in ['debian', 'ubuntu']:
            return self.DEBIAN_PACKAGES['system-deps']
        elif distro in ['centos', 'rhel', 'fedora']:
            return self.CENTOS_PACKAGES['system-deps']
        else:
            return []
    
    def _run_command(self, cmd: List[str], description: str, 
                    cwd: Optional[str] = None, env: Optional[Dict] = None) -> str:
        """
        Run a command with logging and error handling.
        
        Args:
            cmd: Command to run as list of arguments
            description: Description for logging
            cwd: Working directory
            env: Environment variables
            
        Returns:
            Command output
            
        Raises:
            subprocess.CalledProcessError: If command fails
        """
        self.logger.info(f"{description}...")
        self.logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                check=True
            )
            
            if result.stdout:
                self.logger.debug(f"Command output: {result.stdout}")
            
            return result.stdout
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Command failed: {e}")
            if e.stdout:
                self.logger.error(f"Stdout: {e.stdout}")
            if e.stderr:
                self.logger.error(f"Stderr: {e.stderr}")
            raise


def install_openvas_components(status: InstallationStatus, 
                             interactive: bool = True,
                             install_prefix: str = "/usr/local") -> List[InstallationResult]:
    """
    Convenience function to install missing OpenVAS components.
    
    Args:
        status: Installation status from detector
        interactive: Whether to prompt for user confirmation
        install_prefix: Installation prefix for compiled components
        
    Returns:
        List of installation results
    """
    installer = OpenVASInstaller(install_prefix)
    return installer.install_missing_components(status, interactive)


if __name__ == "__main__":
    # Test the installer
    logging.basicConfig(level=logging.INFO)
    
    from .detector import detect_openvas_installation
    
    status = detect_openvas_installation()
    print("\\nDetection Results:")
    detector = OpenVASDetector()
    print(detector.get_installation_summary(status))
    
    if status.installation_required:
        print("\\nStarting installation...")
        results = install_openvas_components(status, interactive=True)
        
        print("\\nInstallation Results:")
        for result in results:
            status_icon = "✅" if result.success else "❌"
            print(f"{status_icon} {result.component}: {result.message}")
            if result.details:
                for detail in result.details:
                    print(f"    {detail}")
    else:
        print("\\nNo installation required!")

