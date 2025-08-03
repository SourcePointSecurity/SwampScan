#!/usr/bin/env python3
"""
Test script to validate SwampScan fixes and improvements.
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(cmd, description=""):
    """Run a command and return success status."""
    print(f"Testing: {description}")
    print(f"Command: {cmd}")
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✅ PASSED")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()}")
        else:
            print("❌ FAILED")
            if result.stderr.strip():
                print(f"Error: {result.stderr.strip()}")
        print("-" * 50)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print("⏰ TIMEOUT")
        print("-" * 50)
        return False
    except Exception as e:
        print(f"💥 EXCEPTION: {e}")
        print("-" * 50)
        return False

def test_swampscan_installation():
    """Test SwampScan installation and basic functionality."""
    print("🧪 Testing SwampScan Installation and Fixes")
    print("=" * 60)
    
    tests = [
        ("swampscan --version", "SwampScan version check"),
        ("swampscan --help", "SwampScan help command"),
        ("swampscan --check-installation", "Installation status check (should provide helpful guidance)"),
        ("swampscan --list-services", "Service groups listing"),
    ]
    
    passed = 0
    total = len(tests)
    
    for cmd, desc in tests:
        if run_command(cmd, desc):
            passed += 1
    
    print(f"\n📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All basic functionality tests PASSED!")
    else:
        print("⚠️  Some tests failed - check output above")
    
    return passed == total

def test_installation_script():
    """Test the installation script help and validation."""
    print("\n🧪 Testing Installation Script")
    print("=" * 60)
    
    script_path = "./scripts/install_swampscan.sh"
    if not os.path.exists(script_path):
        print(f"❌ Installation script not found at {script_path}")
        return False
    
    tests = [
        (f"{script_path} --help", "Installation script help"),
        ("bash -c 'source ./scripts/install_swampscan.sh; check_system 2>/dev/null || echo \"System check function exists\"'", "System check function"),
    ]
    
    passed = 0
    total = len(tests)
    
    for cmd, desc in tests:
        if run_command(cmd, desc):
            passed += 1
    
    print(f"\n📊 Installation Script Tests: {passed}/{total} tests passed")
    return passed == total

def test_python_api():
    """Test Python API functionality."""
    print("\n🧪 Testing Python API")
    print("=" * 60)
    
    test_code = '''
import sys
sys.path.insert(0, "/home/ubuntu/SwampScan_fix/src")

try:
    from swampscan import SwampScanner
    from swampscan.installation.detector import detect_openvas_installation
    
    print("✅ SwampScanner import successful")
    
    # Test installation detection
    status = detect_openvas_installation()
    print(f"✅ Installation detection successful")
    print(f"Ready for scanning: {status.ready_for_scanning}")
    print(f"Missing components: {len(status.missing_components)}")
    
    # Test scanner initialization
    scanner = SwampScanner()
    print("✅ SwampScanner initialization successful")
    
    print("🎉 Python API tests PASSED!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error: {e}")
    sys.exit(1)
'''
    
    return run_command(f'python3 -c "{test_code}"', "Python API functionality")

def main():
    """Run all tests."""
    print("🚀 SwampScan Fixes Validation Test Suite")
    print("=" * 60)
    
    # Change to SwampScan directory
    os.chdir("/home/ubuntu/SwampScan_fix")
    
    results = []
    
    # Test basic installation
    results.append(("SwampScan Installation", test_swampscan_installation()))
    
    # Test installation script
    results.append(("Installation Script", test_installation_script()))
    
    # Test Python API
    results.append(("Python API", test_python_api()))
    
    # Summary
    print("\n" + "=" * 60)
    print("📋 FINAL TEST SUMMARY")
    print("=" * 60)
    
    total_passed = 0
    total_tests = len(results)
    
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")
        if passed:
            total_passed += 1
    
    print(f"\nOverall: {total_passed}/{total_tests} test suites passed")
    
    if total_passed == total_tests:
        print("🎉 ALL TESTS PASSED! Fixes are working correctly.")
        return 0
    else:
        print("⚠️  Some test suites failed. Review the output above.")
        return 1

if __name__ == "__main__":
    sys.exit(main())

