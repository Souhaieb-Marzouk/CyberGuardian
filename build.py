#!/usr/bin/env python3
"""
CyberGuardian Build Script
==========================
Build standalone executable using PyInstaller.

Usage:
    python build.py              # Build executable
    python build.py --package    # Build and create ZIP package
    python build.py --clean      # Clean build artifacts
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path

# Configuration
APP_NAME = "CyberGuardian"
VERSION = "1.1.0"
MAIN_SCRIPT = "main.py"
ICON_PATH = "assets/icon.png"

# Ensure assets directory exists
ASSETS_DIR = Path("assets")
ASSETS_DIR.mkdir(exist_ok=True)


def check_and_create_assets():
    """Check assets directory and create necessary files."""
    print("Checking assets...")
    
    assets_dir = Path("assets")
    assets_dir.mkdir(exist_ok=True)
    
    # Create a placeholder icon if it doesn't exist
    icon_path = assets_dir / "icon.png"
    if not icon_path.exists():
        print("  Creating placeholder icon...")
        try:
            from PIL import Image, ImageDraw
            
            # Create a simple icon
            size = 64
            img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw a shield shape
            draw.ellipse([8, 8, 56, 56], fill='#00ff9d', outline='#00b8ff', width=2)
            draw.polygon([(32, 16), (48, 32), (32, 48), (16, 32)], fill='#0a0f0f')
            
            img.save(icon_path, 'PNG')
            print(f"  ✓ Created: {icon_path}")
        except ImportError:
            print("  Warning: PIL not installed, skipping icon creation")
            print("  The build will proceed without an icon")
    
    # Create checkmark image for checkboxes
    checkmark_path = assets_dir / "checkmark.png"
    if not checkmark_path.exists():
        try:
            from PIL import Image, ImageDraw
            
            size = 18
            img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
            draw = ImageDraw.Draw(img)
            
            # Draw checkmark
            draw.line([(3, 9), (7, 14)], fill='#0a0f0f', width=4)
            draw.line([(6, 13), (15, 4)], fill='#0a0f0f', width=4)
            
            img.save(checkmark_path, 'PNG')
            print(f"  ✓ Created: {checkmark_path}")
        except ImportError:
            pass
    
    return True


def get_pyinstaller_args():
    """Build PyInstaller arguments based on available files."""
    args = [
        '--name', APP_NAME,
        '--onefile',                    # Single executable file
        '--windowed',                   # No console window
        '--noconfirm',                  # Overwrite output directory
        '--clean',                      # Clean temp files
        
        # Hidden imports (modules that PyInstaller might miss)
        '--hidden-import', 'PyQt5',
        '--hidden-import', 'PyQt5.QtCore',
        '--hidden-import', 'PyQt5.QtGui',
        '--hidden-import', 'PyQt5.QtWidgets',
        '--hidden-import', 'psutil',
        '--hidden-import', 'yara',
        '--hidden-import', 'requests',
        '--hidden-import', 'keyring',
        '--hidden-import', 'keyring.backends',
        '--hidden-import', 'keyring.backends.Windows',
        
        # Exclude unnecessary modules
        '--exclude-module', 'tkinter',
        '--exclude-module', 'matplotlib',
        '--exclude-module', 'numpy',
        '--exclude-module', 'pandas',
        
        # Optimize
        '--optimize', '2',
        
        # UAC Admin (request admin privileges)
        '--uac-admin',
    ]
    
    # Add data files if assets directory exists and has files
    assets_dir = Path("assets")
    if assets_dir.exists() and list(assets_dir.iterdir()):
        args.extend(['--add-data', f'{assets_dir};assets'])
    
    # Add icon if it exists - MUST be .ico format on Windows
    icon_path = Path(ICON_PATH)
    if icon_path.exists() and sys.platform == 'win32':
        # Convert PNG to ICO if needed
        ico_path = icon_path.with_suffix('.ico')
        if not ico_path.exists() and icon_path.suffix.lower() == '.png':
            try:
                from PIL import Image
                img = Image.open(icon_path)
                img.save(ico_path, format='ICO', sizes=[(16,16), (32,32), (48,48), (64,64), (128,128), (256,256)])
                print(f"  Converted icon: {ico_path}")
            except Exception as e:
                print(f"  Warning: Could not convert icon: {e}")
        
        if ico_path.exists():
            args.extend(['--icon', str(ico_path)])
    
    # Platform-specific imports for Windows
    if sys.platform == 'win32':
        # pywin32 modules - critical for proper bundling
        args.extend([
            '--hidden-import', 'win32security',
            '--hidden-import', 'win32api',
            '--hidden-import', 'win32con',
            '--hidden-import', 'win32process',
            '--hidden-import', 'win32file',
            '--hidden-import', 'win32event',
            '--hidden-import', 'winerror',
            '--hidden-import', 'pywintypes',
            '--hidden-import', 'pythoncom',
            '--hidden-import', 'wmi',
        ])
        
        # Add pywin32 DLLs directory if available
        try:
            import pywintypes
            import pythoncom
            import os
            
            # Get pywin32 system directory
            pywin32_system = os.path.dirname(pywintypes.__file__)
            if os.path.exists(pywin32_system):
                # Add the pywin32_system32 directory which contains DLLs
                args.extend(['--add-binary', f'{pywin32_system};pywin32_system32'])
        except ImportError:
            pass  # pywin32 may not be installed yet
    
    return args


def check_prerequisites():
    """Check if all prerequisites are installed."""
    print("Checking prerequisites...")
    
    # Check Python version
    if sys.version_info < (3, 9):
        print("Error: Python 3.9 or higher is required")
        return False
    
    print(f"  ✓ Python {sys.version.split()[0]}")
    
    # Warn about very new Python versions
    if sys.version_info >= (3, 13):
        print("  ⚠ Warning: Python 3.13+ may have compatibility issues with pywin32")
        print("    Recommended: Python 3.10-3.12 for best compatibility")
    
    # Check PyInstaller
    try:
        import PyInstaller
        print(f"  ✓ PyInstaller installed")
    except ImportError:
        print("  ✗ PyInstaller not found")
        print("    Installing PyInstaller...")
        subprocess.run([sys.executable, '-m', 'pip', 'install', 'pyinstaller'], check=True)
        print("  ✓ PyInstaller installed")
    
    # Check required packages
    required = ['PyQt5', 'psutil', 'yara', 'requests', 'keyring']
    for package in required:
        try:
            __import__(package)
            print(f"  ✓ {package}")
        except ImportError:
            print(f"  ✗ {package} not found")
            return False
    
    # Windows-specific checks
    if sys.platform == 'win32':
        try:
            import pywintypes
            print(f"  ✓ pywintypes")
        except ImportError:
            print("  ✗ pywintypes not found")
            print("    Installing pywin32...")
            subprocess.run([sys.executable, '-m', 'pip', 'install', 'pywin32'], check=True)
            # Try to run post-install script
            print("    Running pywin32 post-install script...")
            try:
                import site
                site_packages = site.getsitepackages()[0]
                post_install = f'python "{site_packages}\\..\\Scripts\\pywin32_postinstall.py" -install'
                os.system(post_install)
            except Exception as e:
                print(f"    Warning: Could not run post-install: {e}")
                print("    Please run manually: python Scripts\\pywin32_postinstall.py -install")
            
            # Try importing again
            try:
                import pywintypes
                print(f"  ✓ pywintypes (after install)")
            except ImportError:
                print("  ✗ pywintypes still not available - run setup_windows.bat")
                return False
        
        try:
            import pythoncom
            print(f"  ✓ pythoncom")
        except ImportError:
            print("  ✗ pythoncom not found - pywin32 may not be properly installed")
            print("    Run: setup_windows.bat")
            return False
        
        try:
            import win32security
            print(f"  ✓ win32security")
        except ImportError:
            print("  ✗ win32security not found")
            print("    Run: pip install pywin32")
            return False
    
    return True


def clean_build():
    """Remove build artifacts."""
    print("Cleaning build artifacts...")
    
    dirs_to_remove = ['build', 'dist', '__pycache__']
    
    # Remove specific directories
    for dir_name in dirs_to_remove:
        path = Path(dir_name)
        if path.exists():
            try:
                shutil.rmtree(path, ignore_errors=True)
                print(f"  Removed: {path}")
            except Exception as e:
                print(f"  Warning: Could not remove {path}: {e}")
    
    # Remove .spec files
    for spec_file in Path('.').glob('*.spec'):
        try:
            spec_file.unlink()
            print(f"  Removed: {spec_file}")
        except Exception as e:
            print(f"  Warning: Could not remove {spec_file}: {e}")
    
    # Remove __pycache__ directories recursively
    for pycache in Path('.').rglob('__pycache__'):
        try:
            shutil.rmtree(pycache, ignore_errors=True)
        except:
            pass
    
    # Remove egg-info directories
    for egg_info in Path('.').glob('*.egg-info'):
        try:
            shutil.rmtree(egg_info, ignore_errors=True)
            print(f"  Removed: {egg_info}")
        except:
            pass
    
    print("  ✓ Clean complete")


def build_executable():
    """Build the executable using PyInstaller."""
    print(f"\nBuilding {APP_NAME} v{VERSION}...")
    
    # Check for Python 3.14+ compatibility issues
    if sys.version_info >= (3, 14):
        print("\n  ⚠ WARNING: Python 3.14+ detected!")
        print("  Python 3.14 has known issues with PyInstaller timestamp handling.")
        print("  If build fails, try using Python 3.11-3.12 instead.\n")
    
    # Check and create assets first
    check_and_create_assets()
    
    # Clean dist directory to avoid timestamp issues
    dist_dir = Path('dist')
    if dist_dir.exists():
        try:
            # Try to remove any existing exe files specifically
            for exe_file in dist_dir.glob('*.exe'):
                try:
                    exe_file.unlink()
                    print(f"  Removed existing: {exe_file}")
                except:
                    pass
        except:
            pass
    
    # Get PyInstaller arguments
    pyinstaller_args = get_pyinstaller_args()
    
    # Build command
    cmd = [sys.executable, '-m', 'PyInstaller'] + pyinstaller_args + [MAIN_SCRIPT]
    
    print(f"  Running PyInstaller...")
    print(f"  Command: {' '.join(cmd[:8])}... (truncated)")
    
    # Run PyInstaller
    result = subprocess.run(cmd, capture_output=False)
    
    if result.returncode != 0:
        print("  ✗ Build failed!")
        
        # Provide specific guidance for Python 3.14 timestamp error
        if sys.version_info >= (3, 14):
            print("\n  Python 3.14+ compatibility issue detected.")
            print("  Solutions:")
            print("    1. Use Python 3.11 or 3.12 (recommended)")
            print("    2. Try: pip install --upgrade pyinstaller")
            print("    3. Delete the .spec file and try again")
        
        return False
    
    executable_path = Path('dist') / f'{APP_NAME}.exe'
    if executable_path.exists():
        size_mb = executable_path.stat().st_size / (1024 * 1024)
        print(f"  ✓ Build successful!")
        print(f"  Output: {executable_path}")
        print(f"  Size: {size_mb:.1f} MB")
        return True
    else:
        print("  ✗ Executable not found after build")
        return False


def create_package():
    """Create distribution ZIP package."""
    import zipfile
    from datetime import datetime
    
    print("\nCreating distribution package...")
    
    dist_dir = Path('dist')
    exe_path = dist_dir / f'{APP_NAME}.exe'
    
    if not exe_path.exists():
        print("  ✗ Executable not found. Run build first.")
        return False
    
    # Create package directory
    package_dir = dist_dir / APP_NAME
    if package_dir.exists():
        shutil.rmtree(package_dir)
    package_dir.mkdir()
    
    # Copy executable
    shutil.copy2(exe_path, package_dir / f'{APP_NAME}.exe')
    print(f"  Added: {APP_NAME}.exe")
    
    # Copy additional files
    files_to_copy = [
        ('README.md', 'README.md'),
        ('LICENSE', 'LICENSE'),
        ('requirements.txt', 'requirements.txt'),
    ]
    
    for src, dst in files_to_copy:
        if Path(src).exists():
            shutil.copy2(src, package_dir / dst)
            print(f"  Added: {dst}")
    
    # Create data directories
    (package_dir / 'data' / 'yara_rules').mkdir(parents=True, exist_ok=True)
    (package_dir / 'logs').mkdir(exist_ok=True)
    (package_dir / 'quarantine').mkdir(exist_ok=True)
    print("  Created: data directories")
    
    # Create default config
    config_content = """{
    "general": {
        "show_popups": true,
        "sound_alerts": false,
        "auto_start_monitor": false
    },
    "scanning": {
        "scan_process_memory": true,
        "scan_process_behavior": true,
        "scan_file_yara": true,
        "scan_file_entropy": true
    },
    "api": {
        "virustotal_api_key": "",
        "abuseipdb_api_key": "",
        "deepseek_api_key": "",
        "openai_api_key": "",
        "gemini_api_key": ""
    }
}"""
    (package_dir / 'data' / 'config.json').write_text(config_content)
    print("  Created: default config.json")
    
    # Create quick start guide
    quickstart = f"""# {APP_NAME} v{VERSION} - Quick Start

## How to Run

1. Right-click {APP_NAME}.exe
2. Select "Run as Administrator" for full functionality

## Features

- Process Analysis: Scan running processes
- File Analysis: Scan files and folders
- Registry Analysis: Check persistence mechanisms  
- Network Analysis: Monitor connections
- Real-Time Monitoring: Continuous protection

## AI-Powered Analysis

Configure in Settings > AI Analysis:
- DeepSeek (recommended, affordable)
- OpenAI GPT-4
- Google Gemini

## Support

https://github.com/YOUR_USERNAME/cyberguardian

---
Built: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
    (package_dir / 'QUICKSTART.txt').write_text(quickstart)
    print("  Created: QUICKSTART.txt")
    
    # Create ZIP archive
    zip_path = dist_dir / f'{APP_NAME}_v{VERSION}.zip'
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for file_path in package_dir.rglob('*'):
            if file_path.is_file():
                arcname = file_path.relative_to(dist_dir)
                zipf.write(file_path, arcname)
    
    zip_size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"\n  ✓ Package created: {zip_path}")
    print(f"  Size: {zip_size_mb:.1f} MB")
    
    return True


def main():
    parser = argparse.ArgumentParser(description=f'Build {APP_NAME} executable')
    parser.add_argument('--package', '-p', action='store_true',
                        help='Create distribution ZIP package after build')
    parser.add_argument('--clean', '-c', action='store_true',
                        help='Clean build artifacts')
    parser.add_argument('--all', '-a', action='store_true',
                        help='Clean, build, and package')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print(f"  {APP_NAME} Build Script")
    print("=" * 60)
    print()
    
    if args.clean or args.all:
        clean_build()
        if args.clean:
            return
    
    if not check_prerequisites():
        print("\n  ✗ Prerequisites check failed!")
        print("  Run: pip install -r requirements.txt")
        sys.exit(1)
    
    if not build_executable():
        print("\n  ✗ Build failed!")
        sys.exit(1)
    
    if args.package or args.all:
        if not create_package():
            print("\n  ✗ Packaging failed!")
            sys.exit(1)
    
    print("\n" + "=" * 60)
    print("  Build completed successfully!")
    print("=" * 60)


if __name__ == '__main__':
    main()
