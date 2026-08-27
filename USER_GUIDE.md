# CyberGuardian - Complete User Guide

## Table of Contents
1. [Project Hierarchy](#project-hierarchy)
2. [Installation Guide](#installation-guide)
3. [Quick Start](#quick-start)
4. [GUI Usage](#gui-usage)
5. [CLI Usage](#cli-usage)
6. [Detection Methods](#detection-methods)
7. [Understanding Results](#understanding-results)
8. [Configuration](#configuration)
9. [API Keys Setup](#api-keys-setup)
10. [Troubleshooting](#troubleshooting)

---

## Project Hierarchy

```
cyberguardian/
│
├── main.py                    # Main entry point (GUI/CLI)
├── start.bat                  # Windows quick-start script
├── requirements.txt           # Python dependencies
├── README.md                  # Project documentation
│
├── config/                    # Configuration files (auto-created)
│   └── config.yaml           # User settings
│
├── data/                      # Application data (auto-created)
│   └── whitelist.json        # Whitelist database
│
├── logs/                      # Log files (auto-created)
│   ├── cyberguardian.log     # Main log
│   ├── cyberguardian.json    # Structured JSON log
│   └── audit.log             # Security audit log
│
├── reports/                   # Generated reports (auto-created)
│   └── *.html/pdf/json       # Exported reports
│
├── cache/                     # Threat intel cache (auto-created)
│   ├── hash_cache.json       # Hash lookup results
│   ├── ip_cache.json         # IP reputation results
│   └── domain_cache.json     # Domain reputation results
│
├── yara_rules/                # Yara detection rules
│   ├── suspicious_apis.yar   # Suspicious API calls
│   ├── powershell_suspicious.yar  # PowerShell patterns
│   ├── crypto_mining.yar     # Crypto miner detection
│   ├── ransomware.yar        # Ransomware patterns
│   ├── backdoor.yar          # Backdoor/C2 detection
│   ├── packed_executable.yar # Packed binary detection
│   ├── webshell.yar          # Webshell detection
│   ├── anti_analysis.yar     # Anti-debug/VM detection
│   ├── credentials.yar       # Credential theft detection
│   └── dropper.yar           # Dropper patterns
│
├── scanners/                  # Scanner modules
│   ├── __init__.py
│   ├── base_scanner.py       # Base class for all scanners
│   ├── process_scanner.py    # Process analysis engine
│   ├── file_scanner.py       # File analysis engine
│   ├── registry_scanner.py   # Registry analysis engine
│   ├── network_scanner.py    # Network analysis engine
│   ├── realtime_monitor.py   # Real-time monitoring
│   └── yara_manager.py       # Yara rule management
│
├── ui/                        # User interface
│   ├── __init__.py
│   └── main_window.py        # PyQt5 main window
│
├── reporting/                 # Report generation
│   ├── __init__.py
│   └── generator.py          # HTML/PDF/JSON report generator
│
├── threat_intel/              # Threat intelligence
│   ├── __init__.py
│   └── intel.py              # Hash/IP/Domain lookup
│
├── utils/                     # Utilities
│   ├── __init__.py
│   ├── config.py             # Configuration management
│   ├── logging_utils.py      # Logging system
│   └── whitelist.py          # Whitelist management
│
└── assets/                    # Static assets
    └── (icons, images)
```

---

## Installation Guide

### Step 1: Prerequisites

**System Requirements:**
- Windows 10/11 (64-bit recommended)
- Python 3.10 or higher
- 4GB RAM minimum (8GB recommended)
- Administrator privileges (for full functionality)

**Check Python installation:**
```cmd
python --version
# Output should be: Python 3.10.x or higher
```

### Step 2: Download and Setup

```cmd
# Navigate to project directory
cd cyberguardian

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Verify Installation

```cmd
# Run quick test
python main.py --cli --process

# Expected output:
# [*] Starting process scan...
#    Completed: XX processes, X detections
```

### Step 4: (Optional) Install Additional Components

For enhanced PDF export:
```cmd
pip install weasyprint
# or
pip install pdfkit
```

---

## Quick Start

### GUI Mode (Recommended for Beginners)

```cmd
# Start GUI
python main.py
```

**First-time GUI steps:**
1. Click "🔍 Process Analysis" to scan running processes
2. Review any detections in the "⚠️ Detections" tab
3. Click "📄 Export Report" to save results

### CLI Mode (For Automation)

```cmd
# Quick system scan
python main.py --cli --scan-all

# Scan specific folder
python main.py --cli --file "C:\Users\Downloads"
```

---

## GUI Usage

### Main Window Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🛡️ CYBERGUARDIAN                              v1.1.0          │
├─────────────────────────────────────────────────────────────────┤
│  [Process] [File] [Registry] [Network] [Real-Time]              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │                    TAB CONTENT                          │   │
│  │                                                         │   │
│  │  Overview | Detections | Logs | Whitelist              │   │
│  │                                                         │   │
│  └─────────────────────────────────────────────────────────┘   │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  Status: Ready                    Mode: Manual                  │
└─────────────────────────────────────────────────────────────────┘
```

### Scan Buttons

| Button | Function | Typical Use |
|--------|----------|-------------|
| 🔍 Process Analysis | Scan running processes | Detect malware in memory, suspicious behavior |
| 📁 File Analysis | Scan files/folders | Scan downloads, external drives |
| 📝 Registry Analysis | Scan Windows registry | Find persistence mechanisms |
| 🌐 Network Analysis | Analyze connections | Detect C2, suspicious traffic |
| ⚡ Real-Time Monitor | Continuous monitoring | Background protection |

### Tabs Explained

**📊 Overview Tab:**
- Summary cards showing scan statistics
- Recent activity log
- Quick action buttons

**⚠️ Detections Tab:**
- Table of all detected threats
- Filter by risk level
- Click "View Details" for full information

**📋 Logs Tab:**
- Detailed application logs
- Useful for troubleshooting
- Can save to file

**✅ Whitelist Tab:**
- Manage trusted items
- Add/remove entries
- Prevent false positives

### Using Each Scanner

#### Process Analysis
1. Click "🔍 Process Analysis"
2. Wait for scan to complete
3. Review detections sorted by risk
4. For each detection:
   - Read the description
   - Check remediation steps
   - Terminate/quarantine as needed

#### File Analysis
1. Click "📁 File Analysis"
2. Select folder or file to scan
3. Review results
4. Quarantine or delete malicious files

#### Registry Analysis
1. Click "📝 Registry Analysis"
2. Scans autorun locations
3. Review suspicious entries
4. Export registry fixes if needed

#### Network Analysis
1. Click "🌐 Network Analysis"
2. Lists all connections
3. Shows process responsible
4. Block malicious IPs

#### Real-Time Monitoring
1. Click "⚡ Real-Time Monitor"
2. App minimizes to system tray
3. Alerts appear on detection
4. Double-click tray icon to restore

---

## CLI Usage

### Basic Commands

```bash
# Run all scans
python main.py --cli --scan-all

# Process scan only
python main.py --cli --process

# Scan specific path
python main.py --cli --file "C:\Suspicious\Folder"

# Registry scan
python main.py --cli --registry

# Network scan
python main.py --cli --network
```

### Real-Time Monitoring

```bash
# Start monitoring (Ctrl+C to stop)
python main.py --realtime
```

### Export Options

```bash
# Export as HTML
python main.py --cli --scan-all --export report.html

# Export as PDF
python main.py --cli --scan-all --export report.pdf --format pdf

# Export as JSON
python main.py --cli --scan-all --export report.json --format json
```

### Verbosity Control

```bash
# Verbose output (debug info)
python main.py --cli --process --verbose

# Quiet mode (errors only)
python main.py --cli --process --quiet
```

### Utility Commands

```bash
# List whitelist entries
python main.py --list-whitelist

# Update Yara rules
python main.py --update-rules
```

---

## Detection Methods

### Process Scanner Detection

| Method | Description | Risk Level |
|--------|-------------|------------|
| Yara Memory Scan | Matches process code against malware signatures | Critical/High |
| Parent-Child Analysis | Detects suspicious process relationships (e.g., Word→PowerShell) | High |
| Command Line Analysis | Identifies encoded/suspicious commands | High/Medium |
| Hash Lookup | Checks executable hash against VirusTotal | Critical/High |
| Signature Check | Flags unsigned executables from non-system paths | Low |
| Resource Monitoring | Detects crypto miners by CPU/memory usage | Medium |

### File Scanner Detection

| Method | Description | Risk Level |
|--------|-------------|------------|
| Yara Static Scan | Matches file content against malware signatures | Critical/High |
| PE Analysis | Detects packed executables, suspicious imports | High/Medium |
| Office Macro Analysis | Detects malicious VBA macros | High |
| Entropy Analysis | Identifies packed/encrypted content | Medium/Low |
| Steganography | Detects hidden data in images | Medium |
| Hash Reputation | Lookup against threat databases | Critical/High |

### Registry Scanner Detection

| Location | Threat Type | Risk Level |
|----------|-------------|------------|
| Run/RunOnce | Autorun persistence | Medium/High |
| Services | Malicious services | High |
| IFEO Debuggers | Process hijacking | Critical |
| Winlogon | Logon modification | High |
| AppInit DLLs | DLL injection | Critical |
| Shell Extensions | Explorer hooks | Medium |

### Network Scanner Detection

| Indicator | Threat Type | Risk Level |
|-----------|-------------|------------|
| Malicious IP | C2 server, malware hosting | Critical/High |
| Suspicious Port | Backdoor communication | High |
| Direct IP HTTP | DNS bypass, malware | Medium |
| Beaconing Pattern | C2 heartbeat | High |
| Unexpected Process | Hijacked application | High |

---

## Understanding Results

### Risk Levels

```
┌─────────────┬────────────────────────────────────────────────┐
│ CRITICAL    │ Immediate action required. Known malware or   │
│ (Red)       │ highly suspicious activity detected.          │
├─────────────┼────────────────────────────────────────────────┤
│ HIGH        │ Likely malicious. Strong indicators present.  │
│ (Orange)    │ Investigate and remediate promptly.           │
├─────────────┼────────────────────────────────────────────────┤
│ MEDIUM      │ Suspicious activity detected. Requires        │
│ (Yellow)    │ investigation but may be legitimate.          │
├─────────────┼────────────────────────────────────────────────┤
│ LOW         │ Potentially unwanted or unusual behavior.     │
│ (Green)     │ Review if concerned.                          │
├─────────────┼────────────────────────────────────────────────┤
│ INFO        │ Informational finding. No immediate action.   │
│ (Blue)      │                                              │
└─────────────┴────────────────────────────────────────────────┘
```

### Confidence Score

Each detection includes a confidence score (0-100%):
- **90-100%**: Very high confidence, likely true positive
- **70-89%**: High confidence, recommended action
- **50-69%**: Moderate confidence, investigate further
- **Below 50%**: Low confidence, may be false positive

### Sample Detection Output

```
┌──────────────────────────────────────────────────────────────┐
│ DETECTION: YARA_CRITICAL                                       │
├──────────────────────────────────────────────────────────────┤
│ Indicator:   malware.exe (PID: 1234)                          │
│ Path:        C:\Users\Downloads\malware.exe                   │
│ Risk Level:  CRITICAL                                         │
│ Confidence:  95%                                              │
├──────────────────────────────────────────────────────────────┤
│ Description: Critical malware signature: Emotet_Banking_Trojan│
│                                                              │
│ Detection Reason:                                            │
│ Yara rules matched: emotet_trickbot, banking_trojan          │
├──────────────────────────────────────────────────────────────┤
│ REMEDIATION STEPS:                                            │
│ 1. Terminate process immediately (PID: 1234)                  │
│ 2. Quarantine file: C:\Users\Downloads\malware.exe           │
│ 3. Run full anti-malware scan                                │
│ 4. Isolate system if critical                                │
├──────────────────────────────────────────────────────────────┤
│ EVIDENCE:                                                     │
│ {                                                             │
│   "yara_matches": ["emotet_trickbot", "banking_trojan"],     │
│   "sha256": "abc123...",                                      │
│   "detection_ratio": "65/72"                                  │
│ }                                                             │
└──────────────────────────────────────────────────────────────┘
```

---

## Configuration

### Configuration File Location

```
config/config.yaml
```

### Key Settings

```yaml
# Scan Settings
scan:
  process_scan_memory: true      # Enable Yara memory scan
  process_scan_behavior: true    # Enable heuristics
  file_scan_yara: true           # Enable file Yara scan
  file_scan_entropy: true        # Check file entropy
  network_resolve_dns: true      # Reverse DNS lookup
  network_threat_lookup: true    # Query threat intel

# Real-Time Monitoring
realtime_process_monitor: true   # Monitor new processes
realtime_file_monitor: true      # Monitor file changes
realtime_registry_monitor: true  # Monitor registry
realtime_network_monitor: true   # Monitor connections
realtime_poll_interval: 5        # Check interval (seconds)

# Performance
max_scan_threads: 4              # Concurrent scan threads
scan_timeout_seconds: 300        # Max scan duration

# Logging
log_level: INFO                  # DEBUG, INFO, WARNING, ERROR
log_max_size_mb: 10              # Max log file size
log_backup_count: 5              # Number of backup logs
```

---

## API Keys Setup

### VirusTotal (Free Tier)

1. Visit: https://www.virustotal.com/gui/my-apikey
2. Sign up for free account
3. Copy your API key
4. Set environment variable:

```cmd
# Windows Command Prompt
set CYBERGUARDIAN_VIRUSTOTAL_API_KEY=your_api_key_here

# PowerShell
$env:CYBERGUARDIAN_VIRUSTOTAL_API_KEY="your_api_key_here"

# Or create .env file in project root:
CYBERGUARDIAN_VIRUSTOTAL_API_KEY=your_api_key_here
```

**Rate Limits:**
- Free tier: 4 requests per minute
- Premium: Higher limits available

### AbuseIPDB (Free Tier)

1. Visit: https://www.abuseipdb.com/api
2. Create free account
3. Generate API key
4. Set environment variable:

```cmd
set CYBERGUARDIAN_ABUSEIPDB_API_KEY=your_api_key_here
```

**Rate Limits:**
- Free tier: 1,000 requests per day

### AlienVault OTX (Optional)

1. Visit: https://otx.alienvault.com/api
2. Register and get API key
3. Set environment variable:

```cmd
set CYBERGUARDIAN_ALIENVAULT_API_KEY=your_api_key_here
```

---

## Troubleshooting

### Common Issues and Solutions

#### "Permission denied" errors

**Problem:** Cannot access certain processes or files.

**Solution:**
```cmd
# Run as Administrator
# Right-click Command Prompt → Run as administrator
python main.py --cli --process
```

#### Yara compilation errors

**Problem:** Failed to compile Yara rules.

**Solution:**
```cmd
# Reinstall yara-python
pip uninstall yara-python
pip install yara-python

# If issues persist, try:
pip install yara-python --no-cache-dir
```

#### PyQt5 GUI not starting

**Problem:** GUI window doesn't appear.

**Solution:**
```cmd
# Reinstall PyQt5
pip install --upgrade PyQt5

# Test with CLI mode first
python main.py --cli --process
```

#### Network scan shows no connections

**Problem:** Empty network scan results.

**Solution:**
- Run as Administrator
- Check if firewall is blocking
- Some connections may be hidden by security software

#### High memory usage

**Problem:** Application uses too much memory.

**Solution:**
```yaml
# Edit config/config.yaml
max_scan_threads: 2  # Reduce from 4
scan_timeout_seconds: 120  # Reduce timeout
```

#### False positives

**Problem:** Too many false detections.

**Solution:**
1. Add items to whitelist via GUI (Whitelist tab)
2. Or edit `data/whitelist.json`
3. Check detection confidence - low scores may be false positives

#### Slow scans

**Problem:** Scans take too long.

**Solution:**
```yaml
# Edit config/config.yaml
scan:
  file_scan_stego: false      # Disable steganography check
  network_threat_lookup: false # Skip online lookups
```

### Log Analysis

Check logs for errors:
```cmd
# View recent logs
type logs\cyberguardian.log | more

# Search for errors
findstr /i "error" logs\cyberguardian.log
```

### Getting Help

1. Check logs in `logs/cyberguardian.log`
2. Run with `--verbose` flag for debug info
3. Verify all dependencies installed:
   ```cmd
   pip list | findstr "PyQt5 yara pefile olefile psutil"
   ```

---

## Best Practices

### Regular Scanning Routine

1. **Daily:** Quick process scan
2. **Weekly:** Full system scan (all modules)
3. **Monthly:** Review whitelist and update rules

### Responding to Detections

1. **Critical:** Isolate system, investigate immediately
2. **High:** Investigate within 24 hours
3. **Medium:** Review within 1 week
4. **Low:** Optional investigation

### Maintaining Whitelist

1. Review whitelist monthly
2. Remove outdated entries
3. Document why items were whitelisted
4. Export backup regularly

### Updating Detection Rules

```cmd
# Update Yara rules monthly
python main.py --update-rules

# Or manually add rules to yara_rules/
```

---

<<<<<<< HEAD
## Keyboard Shortcuts (GUI)

| Shortcut | Action |
|----------|--------|
| Ctrl+P | Process Scan |
| Ctrl+F | File Scan |
| Ctrl+R | Registry Scan |
| Ctrl+N | Network Scan |
| Ctrl+E | Export Report |
| Ctrl+Q | Quit Application |
| F5 | Refresh Results |
| Escape | Cancel Current Scan |

---

## Command Reference

```
CyberGuardian v1.1.0 - Windows Malware & Anomaly Detection Tool

USAGE:
    python main.py [OPTIONS]

OPTIONS:
    -c, --cli              Run in CLI mode (no GUI)
    -a, --scan-all         Run all available scans
    -p, --process          Scan running processes
    -f, --file PATH        Scan file or folder
    -r, --registry         Scan Windows registry
    -n, --network          Scan network connections
    --realtime             Start real-time monitoring
    -e, --export FILE      Export report to file
    --format FORMAT        Report format: html, pdf, json, text
    -v, --verbose          Enable verbose output
    -q, --quiet            Minimal output (errors only)
    --update-rules         Update Yara rules from remote
    --list-whitelist       List all whitelist entries
    --config FILE          Path to configuration file
    -h, --help             Show this help message

EXAMPLES:
    python main.py                           # Launch GUI
    python main.py --cli --scan-all          # CLI full scan
    python main.py --cli --process -v        # Verbose process scan
    python main.py --cli --file C:\Downloads # Scan Downloads folder
    python main.py --realtime                # Real-time monitoring
    python main.py --cli --scan-all -e report.html --format html
```

---

## Support & Contact

For issues, feature requests, or contributions:
1. Check the troubleshooting section above
2. Review logs for error details
3. Create an issue on the project repository with:
   - Error message
   - Steps to reproduce
   - System information (Windows version, Python version)
=======
*CyberGuardian v1.1.0 - For questions or issues, visit: [https://github.com/Souhaieb-Marzouk/CyberGuardian](https://github.com/Souhaieb-Marzouk/CyberGuardian)*
>>>>>>> 3966fb43c2fba7d03f8de813ad8fc9c57ca1b62a
