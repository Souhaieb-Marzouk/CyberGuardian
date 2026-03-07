# CyberGuardian Build Guide

## Complete Guide to Building a Standalone Windows Executable

This guide covers building CyberGuardian into a standalone `.exe` file that can run on any Windows computer without requiring Python to be installed.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Environment Setup](#2-environment-setup)
3. [Installing Dependencies](#3-installing-dependencies)
4. [Building the Executable](#4-building-the-executable)
5. [Testing the Executable](#5-testing-the-executable)
6. [Creating a Portable Package](#6-creating-a-portable-package)
7. [Troubleshooting](#7-troubleshooting)
8. [Advanced Options](#8-advanced-options)

---

## 1. Prerequisites

### System Requirements

| Requirement | Specification |
|-------------|---------------|
| Operating System | Windows 10/11 (64-bit) |
| Python | 3.9 - 3.12 (3.11 recommended) |
| RAM | 4GB minimum (8GB recommended) |
| Disk Space | 2GB free |

### ⚠️ Important: Python Version Compatibility

| Python Version | Status | Notes |
|----------------|--------|-------|
| 3.9 | ✅ Supported | Stable, good compatibility |
| 3.10 | ✅ Supported | Stable, good compatibility |
| 3.11 | ✅ **Recommended** | Best overall compatibility |
| 3.12 | ✅ Supported | Works well |
| 3.13+ | ❌ Not Recommended | PyInstaller/pywin32 compatibility issues |

> **If you have Python 3.13 or 3.14**, we strongly recommend installing Python 3.11 or 3.12 alongside it and using a virtual environment.

### Required Software

| Software | Purpose |
|----------|---------|
| Python 3.10-3.12 | Runtime and build environment |
| Visual C++ Build Tools | Compiling native extensions (yara-python, etc.) |
| Git | Optional, for version control |

---

## 2. Environment Setup

### Step 2.1: Install Python

1. Download Python 3.11 from https://www.python.org/downloads/release/python-3119/
2. During installation, check these options:
   - ✅ **Add Python to PATH**
   - ✅ **Install pip**
   - ✅ **Install for all users**

3. Verify installation:
   ```cmd
   python --version
   # Output: Python 3.11.x
   
   pip --version
   # Output: pip 23.x.x from ...
   ```

### Step 2.2: Install Visual C++ Build Tools

Some dependencies (yara-python, psutil) require C++ compilation:

1. Download from https://visualstudio.microsoft.com/visual-cpp-build-tools/
2. Run the installer
3. Select **"Desktop development with C++"**
4. Complete installation

### Step 2.3: (Optional) Install UPX for Compression

UPX reduces executable size by 30-70%:

1. Download from https://github.com/upx/upx/releases
2. Extract to a folder (e.g., `C:\upx`)
3. Add to system PATH:
   - Open System Properties → Environment Variables
   - Add `C:\upx` to PATH

---

## 3. Installing Dependencies

### Step 3.1: Create Virtual Environment

```cmd
# Navigate to project directory
cd C:\path\to\CyberGuardian

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip
```

### Step 3.2: Install Requirements

```cmd
# Install all dependencies
pip install -r requirements.txt
```

### Step 3.3: Run pywin32 Post-Install (Windows Only)

**This step is CRITICAL for Windows builds:**

```cmd
# Find and run the post-install script
python "%LOCALAPPDATA%\Programs\Python\Python311\Scripts\pywin32_postinstall.py" -install

# Or if using virtual environment:
python venv\Scripts\pywin32_postinstall.py -install
```

### Step 3.4: Verify Installation

```cmd
# Test core imports
python -c "import PyQt5; import psutil; import yara; import win32security; print('All dependencies OK')"
```

If you see "All dependencies OK", you're ready to build!

---

## 4. Building the Executable

### Option A: Automated Build (Recommended)

```cmd
# Run the build script
python build.py

# Or with clean build
python build.py --clean
```

### Option B: Build and Package

```cmd
# Build and create distribution ZIP
python build.py --clean --package
```

### Option C: Manual PyInstaller Command

```cmd
pyinstaller --onefile --windowed --noconfirm --clean ^
    --name CyberGuardian ^
    --uac-admin ^
    --hidden-import PyQt5 ^
    --hidden-import PyQt5.QtCore ^
    --hidden-import PyQt5.QtGui ^
    --hidden-import PyQt5.QtWidgets ^
    --hidden-import psutil ^
    --hidden-import yara ^
    --hidden-import win32security ^
    --hidden-import pywintypes ^
    --hidden-import pythoncom ^
    main.py
```

### Build Options

| Option | Description |
|--------|-------------|
| `--clean` | Clean build directories before building |
| `--package` | Create distribution ZIP after build |
| `--all` | Clean, build, and package |

### What the Build Script Does

1. **Checks Prerequisites** - Verifies all dependencies are installed
2. **Creates Assets** - Generates icon files if needed
3. **Runs PyInstaller** - Compiles Python to executable
4. **Validates Output** - Checks if executable was created

---

## 5. Testing the Executable

### Step 5.1: Locate the Executable

```cmd
# The executable is created in:
dist\CyberGuardian.exe
```

### Step 5.2: Basic Testing

1. **Launch Test**:
   ```cmd
   dist\CyberGuardian.exe
   ```

2. **Admin Mode Test**:
   - Right-click `CyberGuardian.exe`
   - Select "Run as Administrator"
   - Verify full functionality

### Step 5.3: Feature Testing Checklist

- [ ] GUI launches without errors
- [ ] Process scan works
- [ ] File scan works
- [ ] Network scan works
- [ ] Registry scan works
- [ ] YARA rules load correctly
- [ ] AI analysis works (if API keys configured)
- [ ] Reports can be exported
- [ ] Settings can be saved

### Step 5.4: Test on Clean Machine

1. Copy `CyberGuardian.exe` to USB drive
2. Test on another Windows PC without Python
3. Verify all features work correctly

---

## 6. Creating a Portable Package

### Using the Build Script

```cmd
# Build and create package in one command
python build.py --clean --package
```

This creates:
```
dist/CyberGuardian/
├── CyberGuardian.exe
├── README.md
├── LICENSE
├── requirements.txt
├── QUICKSTART.txt
└── data/
    ├── yara_rules/
    ├── logs/
    └── quarantine/
```

And packages it into:
```
dist/CyberGuardian_v1.1.0.zip
```

---

## 7. Troubleshooting

### Build Errors

#### Error: `ModuleNotFoundError: No module named 'pywintypes'`

**Cause:** pywin32 not properly installed or post-install script not run.

**Solution:**
```cmd
# Uninstall and reinstall pywin32
pip uninstall pywin32 -y
pip install pywin32

# Run post-install script
python "%LOCALAPPDATA%\Programs\Python\Python311\Scripts\pywin32_postinstall.py" -install

# Verify
python -c "import pywintypes; import pythoncom; print('OK')"
```

#### Error: `set_exe_build_timestamp failed`

**Cause:** Python 3.13/3.14 compatibility issue with PyInstaller.

**Solution:**
1. Use Python 3.11 or 3.12 instead
2. Or delete old build files:
   ```cmd
   del CyberGuardian.spec
   rmdir /s /q build dist
   python build.py --clean
   ```

#### Error: `Failed to retrieve attribute __file__ from module pythoncom`

**Cause:** pywin32 installation corrupted.

**Solution:**
```cmd
# Complete reinstall
pip uninstall pywin32 pywin32-ctypes -y
pip cache purge
pip install pywin32
python Scripts\pywin32_postinstall.py -install
```

#### Error: `yara-python compilation fails`

**Solution:**
```cmd
# Install pre-built wheels
pip uninstall yara-python -y
pip install yara-python --no-cache-dir

# Or use pipwin
pip install pipwin
pipwin install yara-python
```

### Runtime Errors

#### Application crashes on startup

1. Run with console to see errors:
   ```cmd
   # Build with console window
   python build.py --clean
   # Then edit build.py to remove --windowed
   ```

2. Check antivirus - some block packed executables

3. Run as Administrator

#### "Access Denied" during scanning

- Run executable as Administrator
- Check Windows Defender exclusions
- Verify file permissions

#### YARA rules not found

The build includes YARA rules automatically. If issues occur:
```cmd
# Verify rules are included
pyinstaller --add-data "data/yara_rules;yara_rules" main.py
```

### Python 3.13+ Specific Issues

If you must use Python 3.13+:

1. **Update PyInstaller:**
   ```cmd
   pip install --upgrade pyinstaller pyinstaller-hooks-contrib
   ```

2. **Clean build:**
   ```cmd
   del CyberGuardian.spec
   rmdir /s /q build dist
   python build.py
   ```

3. **If still failing**, consider using Python 3.11 in a virtual environment.

---

## 8. Advanced Options

### Reducing Executable Size

1. **Enable UPX Compression:**
   ```cmd
   pyinstaller --upx-dir=C:\upx --onefile main.py
   ```

2. **Exclude Unnecessary Modules:**
   The build script already excludes common heavy modules.

3. **Typical Sizes:**
   | Configuration | Size |
   |--------------|------|
   | With UPX | 30-50 MB |
   | Without UPX | 50-80 MB |

### Adding Custom Icon

1. Place `icon.ico` in project root
2. Build script automatically uses it
3. Icon should be 256x256 for best results

### Code Signing (Recommended for Distribution)

1. Obtain a code signing certificate
2. Sign the executable:
   ```cmd
   signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com dist\CyberGuardian.exe
   ```

### Creating an Installer

Use Inno Setup for a professional installer:

1. Download Inno Setup from https://jrsoftware.org/isinfo.php
2. Create `installer.iss`:
   ```iss
   [Setup]
   AppName=CyberGuardian
   AppVersion=1.1.0
   DefaultDirName={pf}\CyberGuardian
   DefaultGroupName=CyberGuardian
   OutputDir=dist
   OutputBaseFilename=CyberGuardian_Setup
   SetupIconFile=assets\icon.ico

   [Files]
   Source: "dist\CyberGuardian.exe"; DestDir: "{app}"
   Source: "README.md"; DestDir: "{app}"
   Source: "LICENSE"; DestDir: "{app}"

   [Icons]
   Name: "{group}\CyberGuardian"; Filename: "{app}\CyberGuardian.exe"
   Name: "{commondesktop}\CyberGuardian"; Filename: "{app}\CyberGuardian.exe"
   ```

3. Compile with Inno Setup Compiler

---

## Quick Reference Commands

```cmd
# Standard build
python build.py

# Clean build
python build.py --clean

# Build and package
python build.py --clean --package

# Full clean, build, package
python build.py --all
```

---

## Distribution Checklist

Before distributing:

- [ ] Tested on clean Windows 10 machine
- [ ] Tested on clean Windows 11 machine
- [ ] Tested with and without admin privileges
- [ ] All scan types work correctly
- [ ] AI analysis functional (if applicable)
- [ ] YARA rules included
- [ ] Real-time monitoring works
- [ ] Reports generate correctly
- [ ] No antivirus false positives
- [ ] README and LICENSE included
- [ ] (Optional) Code signed
- [ ] (Optional) Created installer

---

## Additional Resources

- **PyInstaller Documentation:** https://pyinstaller.org/
- **UPX Compression:** https://github.com/upx/upx
- **Inno Setup:** https://jrsoftware.org/isinfo.php
- **Code Signing:** https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptography-tools

---

*For issues, check the troubleshooting section above or visit: https://github.com/YOUR_USERNAME/CyberGuardian/issues*
