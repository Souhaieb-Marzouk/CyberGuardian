# CyberGuardian Portable EXE Build Guide

## Complete Step-by-Step Guide to Creating a Portable Windows Executable

This guide will walk you through the process of converting CyberGuardian into a standalone `.exe` file that can run on any Windows computer without requiring Python or dependencies to be installed.

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
- **Operating System**: Windows 10/11 (64-bit)
- **Python**: 3.10 or later (64-bit)
- **RAM**: Minimum 4GB (8GB recommended for build)
- **Disk Space**: At least 2GB free

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.10+ | Runtime and build environment |
| Visual C++ Build Tools | Latest | Compiling native extensions |
| Git | Latest | Optional, for version control |

---

## 2. Environment Setup

### Step 2.1: Install Python

1. Download Python 3.10+ from https://www.python.org/downloads/
2. During installation, check these options:
   - ✅ **Add Python to PATH**
   - ✅ **Install pip**
   - ✅ **Install for all users** (optional but recommended)

3. Verify installation:
   ```cmd
   python --version
   pip --version
   ```

### Step 2.2: Install Visual C++ Build Tools

Some dependencies require C++ compilation:

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

### Step 3.1: Create Virtual Environment (Recommended)

```cmd
# Navigate to project directory
cd C:\path\to\cyberguardian

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Upgrade pip
python -m pip install --upgrade pip
```

### Step 3.2: Install Required Packages

```cmd
# Install all dependencies
pip install -r requirements.txt

# Verify PyInstaller is installed
pip show pyinstaller
```

### Step 3.3: Verify Installation

```cmd
python -c "import PyQt5; import psutil; import yara; print('All dependencies OK')"
```

If no errors appear, you're ready to build!

---

## 4. Building the Executable

### Option A: Quick Build (Single Command)

```cmd
python build_exe.py
```

This creates a single executable file in the `dist/` folder.

### Option B: Custom Build Options

```cmd
# Clean build (recommended for first time)
python build_exe.py --clean

# Build with console window (for debugging)
python build_exe.py --console

# Build as directory (faster startup)
python build_exe.py --onedir

# Build with all optimizations
python build_exe.py --clean --onefile
```

### Option C: Manual PyInstaller Command

```cmd
pyinstaller --onefile --noconsole --uac-admin --name CyberGuardian main.py
```

### Build Options Explained

| Option | Description |
|--------|-------------|
| `--onefile` | Creates a single .exe file (slower startup, easier distribution) |
| `--onedir` | Creates a directory with .exe and dependencies (faster startup) |
| `--noconsole` | Hides console window (for GUI applications) |
| `--console` | Shows console window (for debugging) |
| `--uac-admin` | Requests administrator privileges |
| `--clean` | Cleans build cache before building |
| `--no-upx` | Disables UPX compression |

---

## 5. Testing the Executable

### Step 5.1: Locate the Executable

```cmd
# For --onefile builds
dist\CyberGuardian.exe

# For --onedir builds
dist\CyberGuardian\CyberGuardian.exe
```

### Step 5.2: Run Tests

1. **Basic Launch Test**:
   ```cmd
   dist\CyberGuardian.exe
   ```

2. **Admin Mode Test**:
   - Right-click `CyberGuardian.exe`
   - Select "Run as Administrator"
   - Verify the title bar shows "[ADMIN]"

3. **Feature Tests**:
   - Run a process scan
   - Run a file scan on a test folder
   - Check if YARA rules are loaded
   - Test AI analysis (if API keys configured)

### Step 5.3: Test on Clean Machine

1. Copy `CyberGuardian.exe` to a USB drive
2. Test on another Windows PC without Python installed
3. Verify all features work correctly

---

## 6. Creating a Portable Package

### Step 6.1: Create ZIP Package

```cmd
python build_exe.py --clean --onefile --package
```

This creates `dist/CyberGuardian_Portable_YYYYMMDD_HHMMSS.zip`

### Step 6.2: Manual Package Creation

1. Create a folder structure:
   ```
   CyberGuardian_Portable/
   ├── CyberGuardian.exe
   ├── README.txt
   └── config/
       └── (optional default config files)
   ```

2. Compress to ZIP:
   ```cmd
   # Using PowerShell
   Compress-Archive -Path "CyberGuardian_Portable" -DestinationPath "CyberGuardian_Portable.zip"
   ```

### Step 6.3: Create Installer (Optional)

For a professional installer, use Inno Setup or NSIS:

**Inno Setup Example** (`installer.iss`):
```iss
[Setup]
AppName=CyberGuardian
AppVersion=1.1.0
DefaultDirName={pf}\CyberGuardian
DefaultGroupName=CyberGuardian
OutputDir=dist
OutputBaseInstaller=CyberGuardian_Setup

[Files]
Source: "dist\CyberGuardian.exe"; DestDir: "{app}"

[Icons]
Name: "{group}\CyberGuardian"; Filename: "{app}\CyberGuardian.exe"
Name: "{commondesktop}\CyberGuardian"; Filename: "{app}\CyberGuardian.exe"
```

---

## 7. Troubleshooting

### Common Build Errors

#### Error: `ModuleNotFoundError: No module named 'xxx'`

**Solution**: Add hidden import to the build command:
```cmd
pyinstaller --hidden-import=xxx --onefile main.py
```

#### Error: `ImportError: DLL load failed`

**Solution**: 
1. Ensure you're using 64-bit Python
2. Install Visual C++ Redistributable
3. Copy missing DLLs to the exe directory

#### Error: `PyInstaller cannot find 'PyQt5'`

**Solution**:
```cmd
pip uninstall PyQt5
pip install PyQt5
pip install PyQt5-stubs
```

#### Error: `Permission denied` during build

**Solution**: Run command prompt as Administrator

#### Error: `yara-python` compilation fails

**Solution**:
```cmd
# Install pre-built wheels
pip install pipwin
pipwin install yara-python
```

### Runtime Errors

#### Application crashes on startup

1. **Check dependencies**: Run with `--console` to see errors
2. **Check antivirus**: Some security software blocks packed executables
3. **Run as Admin**: Some features require elevation

#### "Access Denied" errors

- Run as Administrator
- Check Windows Defender settings
- Verify file permissions

#### YARA rules not found

The build script should include YARA rules automatically. If not:
```cmd
pyinstaller --add-data "yara_rules;yara_rules" main.py
```

---

## 8. Advanced Options

### Reducing Executable Size

1. **Enable UPX compression**:
   ```cmd
   pyinstaller --upx-dir=C:\upx --onefile main.py
   ```

2. **Exclude unnecessary modules**:
   Edit `build.spec` and add to `excludes`:
   ```python
   excludes=['tkinter', 'matplotlib', 'numpy', 'pandas']
   ```

3. **Strip debug symbols**:
   ```cmd
   pyinstaller --strip --onefile main.py
   ```

### Adding Custom Icon

1. Create or obtain an `.ico` file (256x256 recommended)
2. Place in project root as `icon.ico`
3. Build with icon:
   ```cmd
   pyinstaller --icon=icon.ico --onefile main.py
   ```

### Code Signing (Recommended for Distribution)

1. Obtain a code signing certificate
2. Sign the executable:
   ```cmd
   signtool sign /f certificate.pfx /p password /t http://timestamp.digicert.com CyberGuardian.exe
   ```

### Creating Updates

1. Update version in `utils/config.py`
2. Update `build_exe.py` version info
3. Rebuild with `--clean`
4. Create new portable package

---

## Build Script Reference

### Full Command Options

```cmd
python build_exe.py [OPTIONS]

Options:
  --clean        Clean build directories before building
  --onefile      Build as single executable file
  --onedir       Build as directory (faster startup)
  --console      Build with console window (debugging)
  --no-upx       Disable UPX compression
  --debug        Enable debug mode
  --no-admin     Build without admin privilege request
  --package      Create portable ZIP package after build
```

### Expected Output

```
============================================================
  CYBERGUARDIAN BUILD PROCESS
============================================================

[*] Checking requirements...
    ✓ pyinstaller
    ✓ PyQt5
    ✓ psutil
    ✓ yara
    ...
[+] All requirements met
[+] UPX compression available

[*] Creating data directories...
    Created: yara_rules
    Created: config
    ...

[*] Running PyInstaller...

... (build output) ...

============================================================
  BUILD SUCCESSFUL!
============================================================

  Build time: 0:02:34
  Executable: dist\CyberGuardian.exe
  Size: 45.23 MB

  To run: CyberGuardian.exe
  Note: Run as Administrator for full functionality
```

---

## Distribution Checklist

Before distributing the executable:

- [ ] Tested on clean Windows 10/11 machine
- [ ] Tested with and without admin privileges
- [ ] Verified all scan types work correctly
- [ ] Checked AI analysis functionality
- [ ] Confirmed YARA rules are included
- [ ] Tested real-time monitoring
- [ ] Verified report generation
- [ ] Checked for false positives with antivirus
- [ ] Created README.txt for users
- [ ] (Optional) Code signed the executable
- [ ] (Optional) Created installer package

---

## Support

For issues or questions:
- Check the troubleshooting section above
- Review PyInstaller documentation: https://pyinstaller.org/
- Check the project repository for updates

---

<<<<<<< HEAD
*Last updated: 2026*
=======
*For issues, check the troubleshooting section above or visit: [https://github.com/Souhaieb-Marzouk/CyberGuardian/issues](https://github.com/Souhaieb-Marzouk/CyberGuardian/issues)*
>>>>>>> 3966fb43c2fba7d03f8de813ad8fc9c57ca1b62a
