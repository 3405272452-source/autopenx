#!/usr/bin/env python3
"""AutoPenX Environment Checker - Detects all dependencies and reports status.

Run this script to verify your system is ready to use AutoPenX.
It checks Python version, pip packages, external CLI tools, Playwright browsers,
and configuration files.

Usage:
    python check_environment.py          # Full check
    python check_environment.py --fix    # Auto-fix what's possible
"""
from __future__ import annotations

import importlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent
VENV_DIR = PROJECT_ROOT / ".venv"
REQUIREMENTS_FILE = PROJECT_ROOT / "requirements.txt"
ENV_FILE = PROJECT_ROOT / ".env"
ENV_EXAMPLE = PROJECT_ROOT / ".env.example"

MIN_PYTHON = (3, 10)

# Core pip packages (must be installed)
CORE_PACKAGES = [
    "openai", "requests", "beautifulsoup4", "lxml", "jinja2",
    "markdown", "fastapi", "uvicorn", "dotenv", "pydantic",
    "aiohttp", "yaml", "packaging",
]

# Optional pip packages (nice to have)
OPTIONAL_PACKAGES = [
    ("playwright", "Browser automation for login helper and SPA testing"),
    ("docker", "Docker container support (optional)"),
    ("hypothesis", "Property-based testing"),
    ("pytest", "Test framework"),
    ("gmpy2", "Fast RSA math (optional, pure Python fallback available)"),
    ("z3", "Constraint solver for Reverse challenges (optional)"),
    ("Crypto", "PyCryptodome for crypto challenges (optional)"),
]

# External CLI tools (all optional, with graceful fallback)
EXTERNAL_TOOLS = [
    ("nmap", "Network scanner", "https://nmap.org/download"),
    ("sqlmap", "SQL injection tool", "https://sqlmap.org"),
    ("binwalk", "Firmware/file analysis", "pip install binwalk"),
    ("steghide", "Steganography tool", "apt install steghide"),
    ("tshark", "Network traffic analyzer", "https://wireshark.org"),
    ("strings", "Binary string extraction", "Built into Linux/macOS, install binutils on Windows"),
    ("objdump", "Disassembler", "Part of binutils"),
    ("ltrace", "Library call tracer", "apt install ltrace (Linux only)"),
    ("strace", "System call tracer", "apt install strace (Linux only)"),
    ("ROPgadget", "ROP gadget finder", "pip install ROPgadget"),
    ("checksec", "Binary security checker", "apt install checksec"),
    ("exiftool", "Metadata extractor", "https://exiftool.org"),
    ("file", "File type detector", "Built into Linux/macOS"),
    ("john", "Password cracker", "https://www.openwall.com/john/"),
    ("fcrackzip", "ZIP password cracker", "apt install fcrackzip"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class Colors:
    """ANSI color codes (disabled on Windows without VT support)."""
    if sys.platform == "win32":
        os.system("")  # Enable VT100 on Windows 10+
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def ok(msg):
    print(f"  {Colors.GREEN}[OK]{Colors.RESET}    {msg}")

def warn(msg):
    print(f"  {Colors.YELLOW}[WARN]{Colors.RESET}  {msg}")

def fail(msg):
    print(f"  {Colors.RED}[FAIL]{Colors.RESET}  {msg}")

def info(msg):
    print(f"  {Colors.CYAN}[INFO]{Colors.RESET}  {msg}")


def check_python_version():
    """Check Python version >= 3.10."""
    v = sys.version_info
    version_str = f"{v.major}.{v.minor}.{v.micro}"
    if (v.major, v.minor) >= MIN_PYTHON:
        ok(f"Python {version_str} ({sys.executable})")
        return True
    else:
        fail(f"Python {version_str} - need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]}")
        return False


def check_venv():
    """Check virtual environment exists."""
    python_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "python.exe" if sys.platform == "win32" else "python"
    )
    if python_exe.exists():
        ok(f"Virtual environment: {VENV_DIR}")
        return True
    else:
        fail(f"Virtual environment not found at {VENV_DIR}")
        info("Fix: python -m venv .venv")
        return False


def check_pip_packages():
    """Check core pip packages are installed in the venv."""
    pip_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "pip.exe" if sys.platform == "win32" else "pip"
    )
    if not pip_exe.exists():
        fail("pip not found in venv")
        return False

    # Get installed packages
    try:
        result = subprocess.run(
            [str(pip_exe), "list", "--format=columns", "--disable-pip-version-check"],
            capture_output=True, text=True, timeout=30,
        )
        installed = set()
        for line in result.stdout.splitlines()[2:]:  # Skip header
            parts = line.split()
            if parts:
                installed.add(parts[0].lower().replace("-", "_"))
    except Exception:
        installed = set()

    # Map package import names to pip names
    import_to_pip = {
        "dotenv": "python_dotenv",
        "yaml": "pyyaml",
        "bs4": "beautifulsoup4",
        "cv2": "opencv_python",
    }

    all_ok = True
    missing = []
    for pkg in CORE_PACKAGES:
        pip_name = import_to_pip.get(pkg, pkg).lower().replace("-", "_")
        if pip_name in installed or pkg.lower().replace("-", "_") in installed:
            pass  # ok, don't print each one
        else:
            missing.append(pkg)
            all_ok = False

    if all_ok:
        ok(f"Core packages: all {len(CORE_PACKAGES)} installed")
    else:
        fail(f"Missing core packages: {', '.join(missing)}")
        info("Fix: .venv\\Scripts\\pip install -r requirements.txt")

    return all_ok


def check_optional_packages():
    """Check optional pip packages."""
    python_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "python.exe" if sys.platform == "win32" else "python"
    )

    available = 0
    total = len(OPTIONAL_PACKAGES)

    for pkg_name, description in OPTIONAL_PACKAGES:
        try:
            result = subprocess.run(
                [str(python_exe), "-c", f"import {pkg_name}"],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                available += 1
            else:
                warn(f"Optional: {pkg_name} - {description}")
        except Exception:
            warn(f"Optional: {pkg_name} - {description}")

    if available == total:
        ok(f"Optional packages: all {total} available")
    else:
        info(f"Optional packages: {available}/{total} available ({total - available} missing, non-critical)")


def check_external_tools():
    """Check external CLI tools availability."""
    available = []
    missing = []

    for tool_name, description, install_hint in EXTERNAL_TOOLS:
        path = shutil.which(tool_name)
        if path:
            available.append(tool_name)
        else:
            missing.append((tool_name, description, install_hint))

    if available:
        ok(f"External tools found: {', '.join(available)} ({len(available)}/{len(EXTERNAL_TOOLS)})")

    if missing:
        info(f"External tools not found ({len(missing)}):")
        for name, desc, hint in missing[:8]:  # Show first 8
            print(f"          - {name}: {desc}")
        if len(missing) > 8:
            print(f"          ... and {len(missing) - 8} more")
        info("These are optional. Tools will use fallback methods when unavailable.")


def check_playwright_browsers():
    """Check if Playwright browsers are installed."""
    python_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "python.exe" if sys.platform == "win32" else "python"
    )

    try:
        result = subprocess.run(
            [str(python_exe), "-c", "from playwright.sync_api import sync_playwright; print('ok')"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            warn("Playwright not installed (browser login helper won't work)")
            info("Fix: pip install playwright && playwright install chromium")
            return False
    except Exception:
        warn("Playwright check failed")
        return False

    # Check if chromium is installed
    playwright_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "playwright.exe" if sys.platform == "win32" else "playwright"
    )
    if playwright_exe.exists():
        try:
            result = subprocess.run(
                [str(playwright_exe), "install", "--dry-run", "chromium"],
                capture_output=True, text=True, timeout=15,
            )
            # If dry-run shows nothing to install, browsers are ready
            if "chromium" not in result.stdout.lower() or result.returncode == 0:
                ok("Playwright + Chromium browser ready")
                return True
        except Exception:
            pass

    # Try to verify by actually launching
    try:
        result = subprocess.run(
            [str(python_exe), "-c",
             "from playwright.sync_api import sync_playwright; "
             "p = sync_playwright().start(); "
             "b = p.chromium.launch(headless=True); b.close(); p.stop(); "
             "print('browser_ok')"],
            capture_output=True, text=True, timeout=30,
        )
        if "browser_ok" in result.stdout:
            ok("Playwright + Chromium browser ready")
            return True
        else:
            warn("Playwright installed but Chromium browser not found")
            info("Fix: playwright install chromium")
            return False
    except Exception:
        warn("Playwright browser check timed out")
        info("Fix: playwright install chromium")
        return False


def check_config():
    """Check .env configuration file."""
    if ENV_FILE.exists():
        content = ENV_FILE.read_text(encoding="utf-8", errors="replace")
        has_key = "DEEPSEEK_API_KEY=" in content and len(
            [l for l in content.splitlines() if l.startswith("DEEPSEEK_API_KEY=") and len(l.split("=", 1)[1].strip()) > 5]
        ) > 0
        if has_key:
            ok(".env configured with API key")
        else:
            warn(".env exists but DEEPSEEK_API_KEY is empty (LLM features disabled)")
            info("Add your DeepSeek API key to .env for full functionality")
        return True
    else:
        if ENV_EXAMPLE.exists():
            warn(".env not found (will be created from .env.example on first run)")
        else:
            fail(".env and .env.example both missing")
        return False


def check_directories():
    """Check required directories exist."""
    dirs = ["reports", "uploads", "logs"]
    for d in dirs:
        p = PROJECT_ROOT / d
        if not p.exists():
            p.mkdir(parents=True, exist_ok=True)
    ok(f"Directories: {', '.join(dirs)}")
    return True


def check_system_info():
    """Print system information."""
    print(f"  OS:       {platform.system()} {platform.release()} ({platform.machine()})")
    print(f"  Python:   {sys.version.split()[0]} ({sys.executable})")
    print(f"  Project:  {PROJECT_ROOT}")
    print()


def auto_fix():
    """Attempt to fix common issues automatically."""
    print(f"\n{Colors.BOLD}Attempting auto-fix...{Colors.RESET}\n")

    # Create venv if missing
    if not (VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "python.exe" if sys.platform == "win32" else "python"
    )).exists():
        print("  Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        ok("Virtual environment created")

    # Install requirements
    pip_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "pip.exe" if sys.platform == "win32" else "pip"
    )
    print("  Installing pip dependencies...")
    result = subprocess.run(
        [str(pip_exe), "install", "-r", str(REQUIREMENTS_FILE), "--disable-pip-version-check"],
        capture_output=True, text=True,
    )
    if result.returncode == 0:
        ok("Dependencies installed")
    else:
        fail(f"pip install failed: {result.stderr[:200]}")

    # Install playwright browsers
    playwright_exe = VENV_DIR / ("Scripts" if sys.platform == "win32" else "bin") / (
        "playwright.exe" if sys.platform == "win32" else "playwright"
    )
    if playwright_exe.exists():
        print("  Installing Playwright Chromium browser...")
        result = subprocess.run(
            [str(playwright_exe), "install", "chromium"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            ok("Chromium browser installed")
        else:
            warn(f"Playwright browser install issue: {result.stderr[:100]}")

    # Create .env from example
    if not ENV_FILE.exists() and ENV_EXAMPLE.exists():
        import shutil as _shutil
        _shutil.copy2(ENV_EXAMPLE, ENV_FILE)
        ok(".env created from .env.example")

    # Create directories
    for d in ["reports", "uploads", "logs"]:
        (PROJECT_ROOT / d).mkdir(parents=True, exist_ok=True)

    print("\n  Auto-fix complete. Run check again to verify.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print()
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  AutoPenX - Environment & Dependency Checker{Colors.RESET}")
    print(f"{Colors.BOLD}{'='*60}{Colors.RESET}")
    print()

    if "--fix" in sys.argv:
        auto_fix()
        print()
        return 0

    check_system_info()

    results = []

    print(f"{Colors.BOLD}[1/7] Python Version{Colors.RESET}")
    results.append(check_python_version())

    print(f"\n{Colors.BOLD}[2/7] Virtual Environment{Colors.RESET}")
    results.append(check_venv())

    print(f"\n{Colors.BOLD}[3/7] Core Python Packages{Colors.RESET}")
    results.append(check_pip_packages())

    print(f"\n{Colors.BOLD}[4/7] Optional Python Packages{Colors.RESET}")
    check_optional_packages()  # Don't count as failure

    print(f"\n{Colors.BOLD}[5/7] External CLI Tools{Colors.RESET}")
    check_external_tools()  # Don't count as failure

    print(f"\n{Colors.BOLD}[6/7] Playwright Browser{Colors.RESET}")
    check_playwright_browsers()  # Don't count as failure

    print(f"\n{Colors.BOLD}[7/7] Configuration & Directories{Colors.RESET}")
    results.append(check_config())
    results.append(check_directories())

    # Summary
    critical_pass = sum(1 for r in results if r)
    critical_total = len(results)

    print(f"\n{'='*60}")
    if critical_pass == critical_total:
        print(f"  {Colors.GREEN}{Colors.BOLD}READY{Colors.RESET} - All critical checks passed ({critical_pass}/{critical_total})")
        print(f"  You can start AutoPenX with: {Colors.CYAN}python -m uvicorn autopnex.web.api:app{Colors.RESET}")
    else:
        print(f"  {Colors.RED}{Colors.BOLD}NOT READY{Colors.RESET} - {critical_total - critical_pass} critical issue(s)")
        print(f"  Run with --fix to attempt auto-repair: {Colors.CYAN}python check_environment.py --fix{Colors.RESET}")
    print(f"{'='*60}\n")

    return 0 if critical_pass == critical_total else 1


if __name__ == "__main__":
    sys.exit(main())
