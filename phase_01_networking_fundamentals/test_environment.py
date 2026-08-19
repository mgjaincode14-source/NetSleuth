"""
Phase 1: Environment & Dependency Verification Script
Checks installed packages, Python version, and network interface accessibility.
"""

import sys
import platform

def verify_environment():
    print("=" * 60)
    print("  🔍 NetSleuth AI - Phase 1: Environment Check")
    print("=" * 60)
    print(f"Python Version: {platform.python_version()} ({platform.platform()})")
    print(f"Executable:     {sys.executable}\n")

    packages = [
        ("scapy", "Packet Capture & Protocol Engine"),
        ("psutil", "System & Network Interface Metrics"),
        ("pydantic", "Data Schema Validation"),
        ("rich", "Terminal UI & Formatting"),
        ("fastapi", "Web API Framework"),
        ("uvicorn", "ASGI Web Server"),
        ("websockets", "Real-Time WebSocket Protocol"),
        ("pytest", "Test Suite Framework"),
        ("sklearn", "Machine Learning (Scikit-Learn)"),
    ]

    all_passed = True

    for pkg_name, description in packages:
        try:
            mod = __import__(pkg_name)
            version = getattr(mod, "__version__", "Installed")
            print(f"  [PASS] {pkg_name:<14} (v{version:<10}) -> {description}")
        except ImportError as e:
            print(f"  [FAIL] {pkg_name:<14} -> Missing! ({e})")
            all_passed = False

    print("-" * 60)
    if all_passed:
        print("  🎉 All Phase 1 dependencies are successfully installed!")
    else:
        print("  ❌ Some dependencies failed to load. Please run pip install -r requirements.txt")
    print("=" * 60)

    return all_passed

if __name__ == "__main__":
    success = verify_environment()
    sys.exit(0 if success else 1)
