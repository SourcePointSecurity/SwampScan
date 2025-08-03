"""
OpenVAS Installation Module

This module provides comprehensive functionality for detecting, installing,
and managing OpenVAS components and their dependencies.
"""

from .detector import (
    OpenVASDetector,
    InstallationStatus,
    ComponentStatus,
    detect_openvas_installation
)

from .installer import (
    OpenVASInstaller,
    InstallationResult,
    install_openvas_components
)

from .dependencies import (
    DependencyManager,
    Dependency,
    ComponentType,
    InstallMethod,
    dependency_manager,
    get_all_dependencies,
    get_system_dependencies,
    get_development_dependencies,
    get_rust_dependencies,
    get_openvas_dependencies
)

__all__ = [
    # Detector classes and functions
    'OpenVASDetector',
    'InstallationStatus', 
    'ComponentStatus',
    'detect_openvas_installation',
    
    # Installer classes and functions
    'OpenVASInstaller',
    'InstallationResult',
    'install_openvas_components',
    
    # Dependencies classes and functions
    'DependencyManager',
    'Dependency',
    'ComponentType',
    'InstallMethod',
    'dependency_manager',
    'get_all_dependencies',
    'get_system_dependencies',
    'get_development_dependencies', 
    'get_rust_dependencies',
    'get_openvas_dependencies'
]


def setup_openvas(interactive: bool = True, install_prefix: str = "/usr/local") -> bool:
    """
    Complete OpenVAS setup function that detects and installs missing components.
    
    Args:
        interactive: Whether to prompt user for confirmations
        install_prefix: Installation prefix for compiled components
        
    Returns:
        True if setup completed successfully, False otherwise
    """
    import logging
    
    logger = logging.getLogger(__name__)
    logger.info("Starting OpenVAS setup...")
    
    try:
        # Detect current installation status
        logger.info("Detecting current OpenVAS installation...")
        status = detect_openvas_installation()
        
        # Show detection results
        detector = OpenVASDetector()
        summary = detector.get_installation_summary(status)
        print(summary)
        
        if status.ready_for_scanning:
            logger.info("OpenVAS is already ready for scanning!")
            return True
        
        if not status.installation_required:
            logger.info("No installation required")
            return True
        
        # Install missing components
        logger.info(f"Installing {len(status.missing_components)} missing components...")
        results = install_openvas_components(status, interactive, install_prefix)
        
        # Check results
        success_count = sum(1 for r in results if r.success)
        total_count = len(results)
        
        print(f"\\nInstallation completed: {success_count}/{total_count} components installed successfully")
        
        # Show detailed results
        for result in results:
            status_icon = "✅" if result.success else "❌"
            print(f"{status_icon} {result.component}: {result.message}")
            if result.details:
                for detail in result.details:
                    print(f"    {detail}")
        
        # Re-check installation status
        logger.info("Verifying installation...")
        final_status = detect_openvas_installation()
        
        if final_status.ready_for_scanning:
            print("\\n🎉 OpenVAS setup completed successfully! System is ready for scanning.")
            return True
        else:
            print("\\n⚠️  Setup completed but system may not be fully ready for scanning.")
            print("Please check the installation results and resolve any remaining issues.")
            return False
            
    except Exception as e:
        logger.error(f"Setup failed with error: {e}")
        print(f"\\n❌ Setup failed: {e}")
        return False


def check_openvas_status() -> InstallationStatus:
    """
    Quick function to check OpenVAS installation status.
    
    Returns:
        Current installation status
    """
    return detect_openvas_installation()


def print_dependency_info():
    """Print information about OpenVAS dependencies."""
    print(dependency_manager.get_dependency_summary(get_all_dependencies()))

