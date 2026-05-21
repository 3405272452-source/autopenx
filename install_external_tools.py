"""Download and install external tools for AutoPenX (Windows).

Downloads portable versions of tools that aren't available via pip.
All tools are placed in the 'external_tools/' directory.
"""
import os
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
TOOLS_DIR = PROJECT_ROOT / "external_tools"
TOOLS_DIR.mkdir(exist_ok=True)

# Add external_tools to PATH for this session
os.environ["PATH"] = str(TOOLS_DIR) + os.pathsep + os.environ.get("PATH", "")


def download_file(url: str, dest: Path, desc: str = "") -> bool:
    """Download a file with progress indication."""
    print(f"  Downloading {desc or url}...")
    try:
        urllib.request.urlretrieve(url, str(dest))
        print(f"  -> Saved to {dest.name}")
        return True
    except Exception as e:
        print(f"  [ERROR] Download failed: {e}")
        return False


def install_strings():
    """Install Sysinternals strings.exe (Windows equivalent of Unix strings)."""
    print("\n[1] Sysinternals Strings")
    dest = TOOLS_DIR / "strings.exe"
    if dest.exists():
        print("  Already installed.")
        return True

    zip_path = TOOLS_DIR / "strings.zip"
    url = "https://download.sysinternals.com/files/Strings.zip"
    if download_file(url, zip_path, "Sysinternals Strings"):
        try:
            with zipfile.ZipFile(zip_path) as zf:
                # Extract strings64.exe as strings.exe
                for name in zf.namelist():
                    if "strings64" in name.lower() or (name.lower() == "strings.exe"):
                        zf.extract(name, TOOLS_DIR)
                        extracted = TOOLS_DIR / name
                        if extracted.name != "strings.exe":
                            extracted.rename(dest)
                        print("  [OK] strings.exe installed")
                        break
            zip_path.unlink(missing_ok=True)
            return True
        except Exception as e:
            print(f"  [ERROR] Extract failed: {e}")
    return False


def install_exiftool():
    """Install ExifTool (Perl-based metadata reader, standalone Windows exe)."""
    print("\n[2] ExifTool")
    dest = TOOLS_DIR / "exiftool.exe"
    if dest.exists():
        print("  Already installed.")
        return True

    # ExifTool Windows standalone
    url = "https://exiftool.org/exiftool-13.27.zip"
    zip_path = TOOLS_DIR / "exiftool.zip"
    if download_file(url, zip_path, "ExifTool"):
        try:
            with zipfile.ZipFile(zip_path) as zf:
                for name in zf.namelist():
                    if name.endswith(".exe"):
                        zf.extract(name, TOOLS_DIR)
                        extracted = TOOLS_DIR / name
                        if extracted.name != "exiftool.exe":
                            extracted.rename(dest)
                        break
            zip_path.unlink(missing_ok=True)
            if dest.exists():
                print("  [OK] exiftool.exe installed")
                return True
            else:
                # Sometimes the exe is named differently
                for f in TOOLS_DIR.glob("exiftool*.exe"):
                    f.rename(dest)
                    print("  [OK] exiftool.exe installed")
                    return True
        except Exception as e:
            print(f"  [ERROR] Extract failed: {e}")
    return False


def install_objdump():
    """Install objdump from MinGW/binutils."""
    print("\n[3] objdump (from binutils)")
    dest = TOOLS_DIR / "objdump.exe"
    if dest.exists():
        print("  Already installed.")
        return True

    # Check if it's available via MinGW or MSYS2
    for search_path in [
        r"C:\msys64\usr\bin\objdump.exe",
        r"C:\MinGW\bin\objdump.exe",
        r"C:\mingw64\bin\objdump.exe",
    ]:
        if Path(search_path).exists():
            shutil.copy2(search_path, dest)
            print(f"  [OK] Copied from {search_path}")
            return True

    print("  [SKIP] objdump requires MinGW/MSYS2. Install MSYS2 from https://www.msys2.org/")
    print("         Then: pacman -S mingw-w64-x86_64-binutils")
    return False


def install_pip_tools():
    """Install Python-based tools via pip."""
    print("\n[4] Python-based tools (pip)")
    pip = str(PROJECT_ROOT / ".venv" / "Scripts" / "pip.exe")
    if not Path(pip).exists():
        print("  [ERROR] .venv not found. Run autopenx_bootstrap.cmd first.")
        return False

    packages = [
        ("binwalk", "binwalk"),
        ("z3-solver", "z3"),
        ("pycryptodome", "Crypto"),
        ("exifread", "exifread"),
    ]

    all_ok = True
    for pkg_name, import_name in packages:
        try:
            __import__(import_name)
            print(f"  [OK] {pkg_name} already installed")
        except ImportError:
            print(f"  Installing {pkg_name}...")
            result = subprocess.run(
                [pip, "install", pkg_name, "--disable-pip-version-check", "-q"],
                capture_output=True, text=True,
            )
            if result.returncode == 0:
                print(f"  [OK] {pkg_name} installed")
            else:
                print(f"  [WARN] {pkg_name} install failed: {result.stderr[:100]}")
                all_ok = False
    return all_ok


def install_tshark_hint():
    """Provide instructions for tshark (Wireshark)."""
    print("\n[5] tshark (Wireshark)")
    if shutil.which("tshark"):
        print("  [OK] tshark already available")
        return True

    # Check common Wireshark install paths
    for p in [r"C:\Program Files\Wireshark\tshark.exe", r"C:\Program Files (x86)\Wireshark\tshark.exe"]:
        if Path(p).exists():
            print(f"  [OK] Found at {p}")
            print(f"  NOTE: Add Wireshark to PATH or it will be found automatically.")
            return True

    print("  [SKIP] tshark requires Wireshark installation.")
    print("         Download: https://www.wireshark.org/download.html")
    print("         Or: winget install WiresharkFoundation.Wireshark")
    return False


def install_steghide_hint():
    """Provide instructions for steghide."""
    print("\n[6] steghide")
    if shutil.which("steghide"):
        print("  [OK] steghide already available")
        return True
    print("  [SKIP] steghide is Linux-only. On Windows, use zsteg (Ruby) or online tools.")
    print("         Alternative: The built-in stego_analyze uses strings/exifread as fallback.")
    return False


def update_path_config():
    """Create a .env.local file that adds external_tools to PATH."""
    print("\n[7] Updating PATH configuration")

    # Create a batch file that sets PATH before running AutoPenX
    path_setter = PROJECT_ROOT / "set_tools_path.cmd"
    path_setter.write_text(
        f'@echo off\nset "PATH={TOOLS_DIR};%PATH%"\n',
        encoding="ascii",
    )

    # Update the main startup bat to include external_tools in PATH
    startup_bat = PROJECT_ROOT / "一键启动Web界面.bat"
    content = startup_bat.read_text(encoding="utf-8")
    if "external_tools" not in content:
        # Add PATH setting after chcp line
        content = content.replace(
            'cd /d "%~dp0"',
            'cd /d "%~dp0"\nset "PATH=%~dp0external_tools;%PATH%"',
        )
        startup_bat.write_text(content, encoding="utf-8")
        print("  [OK] Updated startup script to include external_tools in PATH")
    else:
        print("  [OK] PATH already configured")

    return True


def final_check():
    """Run final availability check."""
    print("\n" + "=" * 50)
    print("  Final Tool Availability Check")
    print("=" * 50)

    tools = [
        ("nmap", "Network scanner"),
        ("sqlmap", "SQL injection"),
        ("ROPgadget", "ROP gadgets"),
        ("checksec", "Binary security"),
        ("strings", "String extraction"),
        ("exiftool", "Metadata"),
        ("objdump", "Disassembly"),
        ("tshark", "Traffic analysis"),
        ("binwalk", "File analysis"),
        ("steghide", "Steganography"),
    ]

    # Also check in external_tools dir
    env_path = str(TOOLS_DIR) + os.pathsep + os.environ.get("PATH", "")

    available = 0
    for name, desc in tools:
        # Check both system PATH and external_tools
        found = shutil.which(name) or shutil.which(name, path=str(TOOLS_DIR))
        if found:
            print(f"  [OK] {name:12s} - {desc}")
            available += 1
        else:
            print(f"  [--] {name:12s} - {desc} (not installed)")

    # Check Python packages
    print()
    py_pkgs = [("z3", "z3-solver"), ("Crypto", "pycryptodome"), ("binwalk", "binwalk")]
    for import_name, pkg_name in py_pkgs:
        try:
            sys.path.insert(0, str(PROJECT_ROOT / ".venv" / "Lib" / "site-packages"))
            __import__(import_name)
            print(f"  [OK] {pkg_name:12s} - Python package")
            available += 1
        except ImportError:
            print(f"  [--] {pkg_name:12s} - Python package (not installed)")

    total = len(tools) + len(py_pkgs)
    print(f"\n  Result: {available}/{total} tools available")
    return available


def main():
    print("=" * 50)
    print("  AutoPenX - External Tools Installer")
    print("=" * 50)
    print(f"  Tools directory: {TOOLS_DIR}")
    print()

    install_strings()
    install_exiftool()
    install_objdump()
    install_pip_tools()
    install_tshark_hint()
    install_steghide_hint()
    update_path_config()
    final_check()

    print("\n" + "=" * 50)
    print("  Installation complete!")
    print("  Restart AutoPenX to use the new tools.")
    print("=" * 50)


if __name__ == "__main__":
    main()
