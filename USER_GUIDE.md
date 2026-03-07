# CyberGuardian - Complete User Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Project Hierarchy](#project-hierarchy)
3. [Installation Guide](#installation-guide)
4. [Quick Start](#quick-start)
5. [GUI Usage](#gui-usage)
6. [AI-Powered Analysis](#ai-powered-analysis)
7. [Detection Methods](#detection-methods)
8. [Understanding Results](#understanding-results)
9. [Configuration](#configuration)
10. [API Keys Setup](#api-keys-setup)
11. [Troubleshooting](#troubleshooting)

---

## Introduction

CyberGuardian is an open-source malware detection and threat hunting tool designed for **everyone** — from everyday computer users to professional security analysts. It provides transparent, understandable threat detection without requiring a security background.

### Who Is This For?

| User Type | Use Case |
|-----------|----------|
| **Everyday Users** | Scan downloaded files before opening, check if your computer is compromised, investigate abnormal behavior |
| **Power Users** | Monitor network connections, check for persistence mechanisms, verify software integrity |
| **Threat Hunters** | Investigate IOCs, hunt for malware persistence, analyze suspicious processes |
| **SOC Analysts** | Triage alerts, perform initial analysis, document findings with AI assistance |

---

## Project Hierarchy

```
CyberGuardian/
│
├── 📄 main.py                     # Application entry point
├── 📄 requirements.txt            # Python dependencies
├── 📄 build.py                    # PyInstaller build script
├── 📄 setup_windows.bat           # Windows automated setup
│
├── 📂 ui/
│   ├── __init__.py
│   └── main_window.py             # PyQt5 main GUI (3,900+ lines)
│
├── 📂 scanners/
│   ├── __init__.py
│   ├── base_scanner.py            # Abstract scanner base class
│   ├── process_scanner.py         # Process enumeration & analysis
│   ├── file_scanner.py            # File scanning with YARA
│   ├── network_scanner.py         # Network connection analysis
│   ├── registry_scanner.py        # Windows registry scanning
│   ├── memory_analyzer.py         # Memory forensics integration
│   ├── realtime_monitor.py        # Real-time protection monitor
│   └── yara_manager.py            # YARA rule management
│
├── 📂 ai_analysis/
│   ├── __init__.py
│   └── analyzer.py                # Multi-provider AI analysis engine
│
├── 📂 threat_intel/
│   ├── __init__.py
│   ├── intel.py                   # Threat intelligence aggregator
│   └── virustotal_checker.py      # VirusTotal API integration
│
├── 📂 analysis/
│   ├── __init__.py
│   └── deep_analysis_coordinator.py  # Coordinates deep analysis modes
│
├── 📂 reporting/
│   ├── __init__.py
│   └── generator.py               # HTML report generation
│
├── 📂 utils/
│   ├── __init__.py
│   ├── config.py                  # Configuration management
│   ├── logging_utils.py           # Logging setup
│   ├── whitelist.py               # Whitelist management
│   └── secure_storage.py          # Secure API key storage
│
├── 📂 config/
│   └── config.yaml                # Default configuration
│
├── 📂 assets/
│   ├── icon.png                   # Application icon
│   └── icon.ico                   # Windows executable icon
│
└── 📂 data/                       # Created at runtime
    ├── yara_rules/                # Custom YARA rules
    ├── logs/                      # Application logs
    ├── cache/                     # Threat intel cache
    └── quarantine/                # Quarantined files
```

---

## Installation Guide

### Step 1: Prerequisites

**System Requirements:**
- Windows 10/11 (64-bit)
- Python 3.9 - 3.12 (3.11 recommended for best compatibility)
- 4GB RAM minimum (8GB recommended)
- Administrator privileges (for full functionality)

> ⚠️ **Note**: Python 3.13+ may have compatibility issues with PyInstaller and pywin32. Use Python 3.10-3.12 for best results.

**Check Python installation:**
```cmd
python --version
# Output should be: Python 3.10.x, 3.11.x, or 3.12.x
```

### Step 2: Download and Setup

**Option A: Automated Setup (Recommended)**
```cmd
# Run the setup script as Administrator
setup_windows.bat
```

**Option B: Manual Setup**
```cmd
# Navigate to project directory
cd CyberGuardian

# Create virtual environment
python -m venv venv

# Activate virtual environment
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run pywin32 post-install (Windows only)
python Scripts\pywin32_postinstall.py -install
```

### Step 3: Verify Installation

```cmd
# Run quick test
python main.py

# Or test via CLI
python main.py --help
```

---

## Quick Start

### GUI Mode (Recommended)

```cmd
# Start the application
python main.py
```

**First-time GUI steps:**
1. Click **"Process Analysis"** to scan running processes
2. Review any detections in the results table
3. Click **"View Details"** for full analysis
4. Use **"Analyze with AI"** for intelligent threat assessment

### Common Use Cases

**"I downloaded a file and want to check if it's safe"**
1. Click **"File Analysis"** tab
2. Click **"Browse"** and select the file
3. Click **"Start Scan"**
4. Review results and AI analysis if needed

**"My computer is running slow/suspicious"**
1. Click **"Process Analysis"** tab
2. Enable **"Deep Analysis"** for thorough scan
3. Click **"Start Scan"**
4. Look for high CPU/memory processes or suspicious detections

**"I want to check what my computer is connecting to"**
1. Click **"Network Analysis"** tab
2. Enable **"Deep Analysis"** for DNS/hostname resolution
3. Click **"Start Scan"**
4. Review connections for suspicious IPs or unexpected destinations

---

## GUI Usage

### Main Window Layout

The CyberGuardian interface uses a cyberpunk-themed design with the following components:

| Component | Purpose |
|-----------|---------|
| **Tab Bar** | Switch between scanner types (Process, File, Network, Registry) |
| **Scan Controls** | Start/stop scans, configure deep analysis mode |
| **Results Table** | View detections sorted by risk level |
| **Detail Panel** | View full evidence and AI analysis for each detection |
| **Status Bar** | Show scan progress and current operation |

### Scanner Tabs

#### 🔹 Process Analysis

Scans all running processes for:
- Malware signatures (YARA rules)
- Suspicious process relationships (parent-child)
- Unusual command line arguments
- Memory anomalies
- Unsigned executables in suspicious locations

#### 🔹 File Analysis

Scans files and folders for:
- Malware signatures (YARA rules)
- High entropy (packed/encrypted content)
- Suspicious PE headers
- Embedded macros
- Hash reputation via VirusTotal

#### 🔹 Network Analysis

Analyzes network connections for:
- Connections to known malicious IPs
- Suspicious ports (backdoors, C2)
- Direct IP HTTP connections (DNS bypass)
- Unusual protocol behavior

#### 🔹 Registry Analysis

Scans Windows registry for:
- Persistence mechanisms (Run keys, Services)
- Hijacked file associations
- Malicious shell extensions
- Modified system settings

### Deep Analysis Mode

Enable **"Deep Analysis"** toggle for comprehensive scanning:
- Memory forensics for processes
- DNS cache inspection for networks
- Extended registry locations
- More thorough YARA rule matching

---

## AI-Powered Analysis

### Overview

CyberGuardian integrates with multiple AI providers for intelligent threat analysis:
- **DeepSeek** (Recommended - affordable and capable)
- **OpenAI GPT-4**
- **Google Gemini**

### Using AI Analysis

1. Open any detection by clicking **"View Details"**
2. Scroll to the **"AI-Powered Analysis"** section
3. Select your preferred AI provider
4. Click **"ANALYZE WITH AI"**

### What AI Analysis Provides

| Component | Description |
|-----------|-------------|
| **Verdict** | Legitimate / Suspicious / Malicious / Needs Investigation |
| **Confidence Score** | How certain the AI is about its assessment |
| **Risk Score** | Numerical risk rating (0-100) |
| **Technical Analysis** | Detailed explanation of why something is suspicious |
| **MITRE ATT&CK Mapping** | Relevant threat techniques if applicable |
| **Recommendations** | Actionable remediation steps |
| **Indicators** | Specific IOCs and suspicious behaviors |

### VirusTotal Integration

When AI analysis is triggered:
1. CyberGuardian extracts IOCs from the detection (IPs, hashes, domains, URLs)
2. Each IOC is checked against VirusTotal's database
3. Results are included in the AI prompt for context-aware analysis
4. Risk level is automatically adjusted based on VT findings

---

## Detection Methods

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

### Detection Types

| Type | Scanner | Example |
|------|---------|---------|
| `yara_match` | Process/File | YARA signature matched |
| `suspicious_process` | Process | Unusual process behavior |
| `malicious_ip` | Network | IP flagged by threat intel |
| `suspicious_port` | Network | Connection to backdoor port |
| `registry_persistence` | Registry | Autorun entry added |
| `high_entropy` | File | Packed/encrypted file |
| `network_direct_ip_http` | Network | HTTP without DNS resolution |

---

## Understanding Results

### Detection Detail Dialog

When you click **"View Details"** on a detection:

```
┌──────────────────────────────────────────────────────────────┐
│ DETECTION DETAILS                                            │
├──────────────────────────────────────────────────────────────┤
│ [Risk Badge]  CRITICAL                                       │
│ Type:         yara_match                                     │
│ Confidence:   95%                                            │
├──────────────────────────────────────────────────────────────┤
│ Indicator:    malware.exe (PID: 1234)                        │
│ Path:         C:\Users\Downloads\malware.exe                 │
├──────────────────────────────────────────────────────────────┤
│ Description:                                                 │
│ Critical malware signature detected: Emotet_Banking_Trojan   │
│                                                              │
│ Detection Reason:                                            │
│ YARA rules matched: emotet_trickbot, banking_trojan          │
├──────────────────────────────────────────────────────────────┤
│ EVIDENCE:                                                    │
│ {                                                            │
│   "yara_matches": ["emotet_trickbot", "banking_trojan"],    │
│   "sha256": "abc123...",                                     │
│   "virustotal_ratio": "65/72"                                │
│ }                                                            │
├──────────────────────────────────────────────────────────────┤
│ REMEDIATION STEPS:                                           │
│ 1. Terminate process immediately (PID: 1234)                 │
│ 2. Quarantine file: C:\Users\Downloads\malware.exe          │
│ 3. Run full anti-malware scan                               │
│ 4. Check for persistence mechanisms                         │
├──────────────────────────────────────────────────────────────┤
│ [AI-POWERED ANALYSIS]                                        │
│ Select Provider: [DeepSeek ▼]                                │
│ [ANALYZE WITH AI]                                            │
└──────────────────────────────────────────────────────────────┘
```

### Available Actions

| Action | Description |
|--------|-------------|
| **Kill Process** | Terminate the suspicious process |
| **Quarantine File** | Move file to secure quarantine |
| **Delete File** | Permanently delete the file |
| **Add to Whitelist** | Mark as trusted (prevents future alerts) |
| **Open Location** | Open file location in Explorer |

---

## Configuration

### Accessing Settings

Click the **Settings** button (gear icon) to configure:
- **General**: Theme, font size, popups, sound alerts
- **Scan**: Enable/disable specific detection methods
- **API Keys**: Configure threat intel and AI providers
- **YARA Rules**: Manage detection rules

### Configuration File

Settings are saved to:
```
config/config.yaml
```

Key settings:
```yaml
scan:
  process_scan_memory: true      # YARA memory scan
  process_scan_behavior: true    # Heuristic analysis
  file_scan_yara: true           # File YARA scan
  file_scan_entropy: true        # Entropy analysis
  network_resolve_dns: true      # Reverse DNS lookup
  network_threat_lookup: true    # Threat intel queries

realtime:
  process_monitor: true          # Monitor new processes
  file_monitor: true             # Monitor file changes
  poll_interval: 5               # Check interval (seconds)

performance:
  max_scan_threads: 4            # Concurrent threads
  scan_timeout_seconds: 300      # Max scan duration
```

---

## API Keys Setup

### VirusTotal (Threat Intelligence)

1. Visit: https://www.virustotal.com/gui/join-us
2. Create a free account
3. Navigate to API Key section
4. Copy your API key
5. In CyberGuardian: **Settings → API Keys → VirusTotal**

**Rate Limits (Free Tier):**
- 4 requests per minute
- 500-1000 requests per day

### AI Providers

#### DeepSeek (Recommended)
1. Visit: https://platform.deepseek.com
2. Create account and generate API key
3. In CyberGuardian: **Settings → AI Analysis → DeepSeek**

**Pricing:** Very affordable, excellent for threat analysis

#### OpenAI GPT-4
1. Visit: https://platform.openai.com
2. Generate API key
3. In CyberGuardian: **Settings → AI Analysis → OpenAI**

#### Google Gemini
1. Visit: https://makersuite.google.com
2. Get API key
3. In CyberGuardian: **Settings → AI Analysis → Gemini**

### Secure Storage

API keys are stored securely using:
- **Windows Credential Manager** (Windows)
- **Keychain** (macOS)
- **Secret Service** (Linux)

Keys are never stored in plain text files.

---

## Troubleshooting

### Common Issues

#### "Permission denied" errors

**Solution:** Run CyberGuardian as Administrator
- Right-click `CyberGuardian.exe` or Command Prompt
- Select "Run as administrator"

#### AI Analysis returns "Unable to parse AI response"

**Solution:**
1. Check your API key is valid
2. Ensure you have API credits
3. Try a different AI provider
4. Check internet connectivity

#### YARA rules not loading

**Solution:**
```cmd
# Verify YARA installation
pip show yara-python

# Reinstall if needed
pip uninstall yara-python
pip install yara-python
```

#### Network scan shows no connections

**Solution:**
- Run as Administrator
- Check firewall settings
- Some connections may be hidden by security software

#### False positives

**Solutions:**
1. Add to whitelist via detection details
2. Review confidence score - low scores may be false positives
3. Use AI analysis for additional context

### Checking Logs

Logs are stored in:
```
data/logs/cyberguardian.log
```

View recent errors:
```cmd
type data\logs\cyberguardian.log | findstr /i "error"
```

### Getting Help

1. Check logs for error details
2. Review this user guide
3. Check the BUILD_FIX.md for build-related issues
4. Open an issue on GitHub with:
   - Error message
   - Steps to reproduce
   - System information (Windows version, Python version)

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+P` | Start Process Scan |
| `Ctrl+F` | Start File Scan |
| `Ctrl+R` | Start Registry Scan |
| `Ctrl+N` | Start Network Scan |
| `Ctrl+E` | Export Report |
| `Ctrl+Q` | Quit Application |
| `F5` | Refresh Results |
| `Escape` | Cancel Current Scan |

---

## Best Practices

### For Everyday Users
- Scan downloaded files before opening
- Run a process scan weekly
- Pay attention to Critical and High risk detections
- Use AI analysis for guidance on what to do

### For Threat Hunters
- Enable Deep Analysis mode for comprehensive scans
- Cross-reference findings with VirusTotal results
- Document findings using the export feature
- Customize YARA rules for your environment

### For SOC Analysts
- Use as initial triage tool
- Correlate with SIEM alerts
- Export reports for incident documentation
- Integrate AI analysis into investigation workflow

---

*CyberGuardian v1.1.0 - For questions or issues, visit: https://github.com/YOUR_USERNAME/CyberGuardian*
