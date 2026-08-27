# Fixing PyInstaller Build Errors with CyberGuardian

## Current Error: Timestamp Issue (Python 3.14)

The error:
```
OSError: [Errno 22] Invalid argument: 'E:\\CyberGuardian Original\\dist\\CyberGuardian.exe'
RuntimeError: Execution of 'set_exe_build_timestamp' failed
```

### Root Cause
This is a **Python 3.14 compatibility issue** with PyInstaller. Python 3.14 is very new and PyInstaller has not fully updated to handle it properly.

### Solution 1: Delete Spec File and Dist Folder (Quick Fix)

1. Close all Python processes
2. Delete these files/folders:
   ```cmd
   cd "E:\CyberGuardian Original"
   del CyberGuardian.spec
   rmdir /s /q build
   rmdir /s /q dist
   ```
3. Run build again:
   ```cmd
   python build.py --clean
   ```

### Solution 2: Use Python 3.11 or 3.12 (Recommended)

Python 3.14 has multiple compatibility issues with PyInstaller and pywin32.

1. **Install Python 3.11 or 3.12** from python.org
2. **Create a virtual environment:**
   ```cmd
   cd "E:\CyberGuardian Original"
   py -3.11 -m venv venv
   venv\Scripts\activate
   ```
3. **Install dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```
4. **Run pywin32 post-install:**
   ```cmd
   python venv\Scripts\pywin32_postinstall.py -install
   ```
5. **Build:**
   ```cmd
   python build.py --clean
   ```

### Solution 3: Upgrade PyInstaller

```cmd
pip install --upgrade pyinstaller
pip install --upgrade pyinstaller-hooks-contrib
python build.py --clean
```

---

## Previous Error: pywintypes not found

If you still get the pywintypes error:

1. **Run Command Prompt as Administrator**
2. **Run:**
   ```cmd
   pip uninstall pywin32 -y
   pip install pywin32
   python "%LOCALAPPDATA%\Programs\Python\Python312\Scripts\pywin32_postinstall.py" -install
   ```
   (Adjust the path for your Python version)

3. **Verify:**
   ```cmd
   python -c "import pywintypes; import pythoncom; print('OK')"
   ```

---

## Complete Build Steps for Windows

1. Open **Command Prompt as Administrator**
2. Navigate to project folder:
   ```cmd
   cd "E:\CyberGuardian Original"
   ```
3. Clean old build files:
   ```cmd
   del CyberGuardian.spec
   rmdir /s /q build dist
   ```
4. Run the build:
   ```cmd
   python build.py --clean
   ```

---

## Quick Reference: Python Version Compatibility

| Python Version | PyInstaller | pywin32 | Status |
|---------------|-------------|---------|--------|
| 3.9 | ✓ Works | ✓ Works | Supported |
| 3.10 | ✓ Works | ✓ Works | Recommended |
| 3.11 | ✓ Works | ✓ Works | **Best Choice** |
| 3.12 | ✓ Works | ✓ Works | Recommended |
| 3.13 | ⚠ Issues | ⚠ Issues | Not Recommended |
| 3.14 | ✗ Problems | ✗ Problems | Avoid for now |

---

## Alternative: Run Without Building

If building fails, you can run CyberGuardian directly:

```cmd
cd "E:\CyberGuardian Original"
pip install -r requirements.txt
python main.py
```

This bypasses the executable build entirely.
