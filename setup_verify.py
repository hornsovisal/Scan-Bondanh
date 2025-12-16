#!/usr/bin/env python3
"""
Setup Verification Script
Run this after installing requirements to verify your environment is ready.
Usage: python setup_verify.py
"""

import sys
import importlib

def check_dependency(module_name, package_name=None, optional=False):
    """Check if a module can be imported"""
    if package_name is None:
        package_name = module_name
    
    try:
        importlib.import_module(module_name)
        status = "✓" if sys.stdout.encoding else "[OK]"
        print(f"{status} {package_name:20} - Installed")
        return True
    except ImportError:
        if optional:
            status = "⚠" if sys.stdout.encoding else "[WARN]"
            print(f"{status} {package_name:20} - Not installed (optional)")
            return True
        else:
            status = "✗" if sys.stdout.encoding else "[FAIL]"
            print(f"{status} {package_name:20} - NOT FOUND (required)")
            return False

def main():
    print("=" * 60)
    print("Network Security Scanner - Environment Verification")
    print("=" * 60)
    print()
    
    print("Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"✓ Python {version.major}.{version.minor}.{version.micro} - OK")
    else:
        print(f"✗ Python {version.major}.{version.minor}.{version.micro} - Too old (need 3.7+)")
        return False
    
    print("\nChecking required dependencies...")
    
    all_good = True
    
    # Required dependencies
    all_good &= check_dependency("netifaces", "netifaces")
    all_good &= check_dependency("docx", "python-docx")
    all_good &= check_dependency("colorama", "colorama")
    
    # Optional dependencies
    print("\nChecking optional dependencies...")
    check_dependency("scapy.all", "scapy", optional=True)
    
    # Standard library (should always be available)
    print("\nChecking standard library modules...")
    check_dependency("socket", "socket (stdlib)")
    check_dependency("json", "json (stdlib)")
    check_dependency("re", "re (stdlib)")
    check_dependency("pathlib", "pathlib (stdlib)")
    check_dependency("datetime", "datetime (stdlib)")
    check_dependency("concurrent.futures", "concurrent.futures (stdlib)")
    
    print("\n" + "=" * 60)
    
    if all_good:
        print("✓ All required dependencies are installed!")
        print("\nYou can now run: python main.py")
        return True
    else:
        print("✗ Some required dependencies are missing.")
        print("\nPlease install them with:")
        print("  pip install -r requirements.txt")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
