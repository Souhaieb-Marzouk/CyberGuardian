# 🛡️ CyberGuardian

<div align="center">

![CyberGuardian Logo](assets/icon.png)

**Open-Source Malware Detection & Threat Hunting Tool**

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![GitHub Stars](https://img.shields.io/github/stars/Souhaieb-Marzouk/CyberGuardian?style=social)](https://github.com/Souhaieb-Marzouk/CyberGuardian/stargazers)

*A transparent, educational, and highly customizable security tool for everyone*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Screenshots](#-screenshots) • [Contributing](#-contributing)

</div>

---

## 📖 About

CyberGuardian is an open-source malware detection and threat hunting tool built entirely in Python. It's designed to be **accessible to everyone** — from everyday computer users who want to verify their downloads to professional threat hunters investigating sophisticated attacks.

### Why CyberGuardian?

Traditional antivirus and EDR solutions are powerful, but they're often **black boxes**. They alert you to threats without explaining WHY something is suspicious, and they don't teach you the methodology behind malware analysis.

CyberGuardian solves this by providing:

- 🔍 **Transparency** — See exactly why every detection was triggered
- 📚 **Education** — Learn threat hunting methodology as you use it
- 🎯 **Simplicity** — Plain-language explanations, not technical jargon
- ⚙️ **Customization** — Modify detection rules, add your own YARA signatures
- 🤖 **AI Integration** — Intelligent analysis powered by multiple LLM providers

---

## 👥 Who Is This For?

| User Type | Use Case |
|-----------|----------|
| **Everyday Users** | Scan downloaded files before opening, check if your computer is compromised, investigate abnormal system behavior |
| **Power Users** | Monitor network connections, check for persistence mechanisms, verify software integrity |
| **Threat Hunters** | Investigate IOCs, hunt for malware persistence, analyze suspicious processes |
| **SOC Analysts** | Triage alerts, perform initial analysis, document findings with AI assistance |
| **Security Researchers** | Analyze malware behavior, test detection rules, study attack techniques |

---

## ✨ Features

### Core Scanning Capabilities

| Scanner | Description |
|---------|-------------|
| 🔹 **Process Analysis** | Detects suspicious processes, memory anomalies, code injection, and process masquerading |
| 🔹 **File Analysis** | YARA rule matching, entropy analysis, PE inspection, hash reputation checking |
| 🔹 **Network Analysis** | Identifies malicious connections, direct IP access, suspicious ports, C2 beacons |
| 🔹 **Registry Analysis** | Finds persistence mechanisms, hijacked associations, malicious services |

### Advanced Features

- 🧠 **AI-Powered Analysis** — Multi-provider LLM integration (DeepSeek, OpenAI, Gemini) with structured threat assessment
- 🌐 **VirusTotal Integration** — Automatic IOC checking against 70+ antivirus engines
- 📊 **Deep Analysis Mode** — Memory forensics, DNS cache inspection, ARP table analysis
- 📋 **MITRE ATT&CK Mapping** — Techniques identified and mapped to the framework
- 📝 **Comprehensive Reporting** — HTML export with full analysis details
- 🔐 **Secure API Storage** — System credential manager integration for API keys

---

## 🔬 Detection Methods Deep Dive

CyberGuardian employs multiple layers of detection across all scanners. Understanding these methods helps you interpret results and hunt for threats more effectively.

### 🖥️ Process Analysis — 6 Detection Methods

The Process Scanner analyzes all running processes on your system using six complementary detection techniques:

#### 1. YARA Memory Scanning
YARA rules are pattern-matching signatures that detect known malware families. When a process runs, CyberGuardian scans its executable file against a database of malware signatures. Matches are categorized by severity:
- **Critical**: Known malware families (Emotet, TrickBot, Cobalt Strike, etc.)
- **High**: Suspicious patterns with strong malicious indicators
- **Medium**: Potentially unwanted patterns requiring investigation

#### 2. Behavioral Heuristics
Analyzes parent-child process relationships to detect suspicious execution chains. Examples:
- Microsoft Word spawning PowerShell or CMD (document macro attack)
- Excel launching command-line tools
- Browsers spawning shells
- Notepad or Calculator making unexpected child processes

This catches **fileless malware** and **living-off-the-land** attacks that evade signature-based detection.

#### 3. Hash Reputation Lookup
Calculates SHA-256 hashes of running executables and checks them against VirusTotal's database of 70+ antivirus engines. Results include:
- Detection ratio (e.g., 45/72 engines)
- Threat names assigned by each vendor
- First submission date and last analysis

#### 4. Digital Signature Verification
Verifies whether executables are digitally signed by trusted publishers:
- Checks if the signature is valid and from a recognized Certificate Authority
- Flags unsigned executables running from non-system paths (Temp, AppData, Downloads)
- Identifies processes masquerading as legitimate software with invalid signatures

#### 5. Resource Usage Monitoring
Detects cryptominers and resource-hijacking malware by analyzing:
- CPU usage exceeding 50% sustained
- Memory usage exceeding 30% sustained
- Processes with high resource usage but no visible window

A process using 80% CPU with no user interface is a strong cryptominer indicator.

#### 6. Command-Line Analysis
Inspects process command lines for suspicious patterns:
- **Encoded PowerShell commands**: `-enc`, `-encodedcommand` with Base64 strings
- **Hidden windows**: `-w hidden`, `-windowstyle hidden`
- **Download cradles**: `DownloadString`, `Net.WebClient`, `Invoke-Expression`
- **LOLBAS execution**: Certutil downloads, BITS transfers, WMIC process creation
- **Remote execution**: MSHTA with HTTP URLs, Regsvr32 with remote scripts

---

### 📁 File Analysis — 7 Detection Methods

The File Scanner performs comprehensive static analysis on files and folders:

#### 1. YARA Static Scanning
Matches file contents against YARA malware signatures. Supports custom rules in `data/yara_rules/` for extending detection capabilities.

#### 2. Entropy Analysis
Calculates Shannon entropy to detect packed or encrypted content:
- **Entropy > 7.0**: High suspicion - likely packed, encrypted, or compressed
- **Normal entropy (5.0-6.5)**: Typical for legitimate executables
- Malware often uses packing to evade signature detection

#### 3. PE (Portable Executable) Analysis
Examines Windows executable structure for suspicious characteristics:
- **Suspicious imports**: `VirtualAlloc`, `WriteProcessMemory`, `CreateRemoteThread` (process injection indicators)
- **Packed sections**: UPX, ASPack, MPRESS, VMProtect detection
- **High entropy sections**: Sections with entropy > 7.0 indicate packing
- **TLS callbacks**: Potential anti-debug/anti-analysis techniques

#### 4. Office Document Analysis
Scans Microsoft Office files for malicious content:
- **Macro detection**: Identifies VBA macros in documents
- **Suspicious VBA patterns**: `CreateObject`, `Shell`, `PowerShell`, `AutoOpen`, `DownloadFile`
- **Embedded objects**: OLE objects and external links
- **OLE stream analysis**: Examines document structure for hidden payloads

#### 5. Steganography Detection
Detects hidden data embedded in images:
- **LSB (Least Significant Bit) analysis**: 1-bit, 2-bit, and 4-bit plane examination
- **EOF appended data**: Data hidden after legitimate image end markers
- **Embedded file signatures**: PE executables, ZIP archives hidden in images
- **Malicious patterns in extracted data**: URLs, IPs, executables, PowerShell scripts

This catches malware that hides payloads in innocent-looking images.

#### 6. Hash Reputation Checking
Calculates file hashes (MD5, SHA-256) and checks against VirusTotal:
- Determines if files are known malware
- Provides detection ratio and threat names
- Caches results for performance

#### 7. Suspicious Path Detection
Flags files in high-risk locations:
- Temporary folders (`%TEMP%`, `AppData\Local\Temp`)
- User directories (`Downloads`, `Desktop`)
- Public folders (`C:\Users\Public`)
- Programs running from unexpected locations

---

### 📝 Registry Analysis — 20+ Persistence Locations

The Registry Scanner examines Windows registry persistence mechanisms:

#### Persistence Locations Monitored
CyberGuardian scans **20+ autorun locations** including:
- **Run/RunOnce keys**: Programs executed at user logon
- **Services**: Malicious Windows services
- **Winlogon**: Logon process modifications
- **Image File Execution Options (IFEO)**: Debugger injection attacks
- **AppInit DLLs**: DLL injection via registry
- **Shell Extensions**: Explorer shell modifications
- **Browser Helper Objects (BHO)**: Browser hijacking
- **Active Setup**: Component installation at logon
- **Session Manager**: Boot-time execution
- **Scheduled Tasks Registry**: Task cache analysis

#### Detection Methods

1. **Suspicious Pattern Detection**: Scans registry values for:
   - Encoded PowerShell commands
   - Hidden window execution
   - LOLBAS execution (Certutil, BITSAdmin, Regsvr32, MSHTA)
   - Download cradles and remote execution
   - Execution from Temp/AppData/Public folders
   - Malware references (Mimikatz, Meterpreter, Cobalt Strike)

2. **YARA Rule Matching**: Applies malware signatures to registry values

3. **Entropy Analysis**: Detects Base64-encoded or encrypted payloads in registry

4. **IFEO Debugger Injection**: Critical detection for a stealthy persistence technique where malware makes itself run whenever a legitimate program is launched

5. **Service Path Hijacking**: Identifies services pointing to non-standard or user-writable locations

---

### 🌐 Network Analysis — Comprehensive Connection Intelligence

The Network Scanner provides deep visibility into network activity:

#### Standard Detection Methods

1. **Threat Intelligence Integration**
   - Real-time IP reputation checking against VirusTotal and AbuseIPDB
   - Domain reputation analysis
   - Abuse confidence scores and report counts
   - Country/geolocation data

2. **Suspicious Port Detection**
   Flags connections to ports commonly used by malware:
   - **4444, 4443**: Metasploit default ports
   - **5555, 6666, 8888, 9999**: Common backdoor ports
   - **12345, 12346**: NetBus trojan
   - **31337**: Elite/Backdoor port
   - **6667**: IRC (botnet communication)
   - **3389, 5900**: RDP/VNC (check for unauthorized exposure)

3. **Process Correlation**
   - Links every connection to its owning process
   - Identifies processes that shouldn't make network connections (Notepad, Calculator, Paint)
   - Provides full command line and executable path

4. **Beaconing Detection**
   - Analyzes connection timing patterns
   - Detects regular intervals suggesting C2 heartbeat
   - Identifies periodic connections to suspicious hosts

5. **Exposed Service Detection**
   - Identifies services listening on all interfaces (0.0.0.0)
   - Flags sensitive services exposed externally (RDP, VNC, SSH)

#### Deep Analysis Mode

When Deep Analysis is enabled, additional forensics are performed:

6. **DNS Cache Analysis**
   - Examines cached DNS entries
   - Identifies connections to malicious domains
   - Detects DNS hijacking attempts

7. **ARP Table Inspection**
   - Lists MAC address mappings
   - Identifies ARP spoofing attempts
   - Detects unknown devices on the network

8. **Network Adapter Information**
   - Lists all network interfaces
   - Identifies unexpected adapters
   - Monitors interface statistics

9. **Hosts File Analysis**
   - Checks for DNS redirection
   - Identifies malicious hosts entries

---

### 🧠 AI-Powered Analysis

When you request AI analysis on a detection, CyberGuardian sends comprehensive evidence to your chosen LLM provider (DeepSeek, OpenAI, or Gemini):

#### Information Sent to AI
- Detection type and risk level
- File paths, command lines, registry keys
- Network connection details
- Process relationships
- YARA rule matches
- **VirusTotal IOC results** (automatically included)

#### AI Response Structure
```
{
  "verdict": "malicious|suspicious|legitimate|needs_investigation",
  "confidence": 0.85,
  "risk_score": 75,
  "summary": "Executive summary of the threat",
  "detailed_analysis": "Technical deep-dive analysis",
  "recommendations": ["Step-by-step remediation"],
  "indicators": ["IOCs and suspicious behaviors"],
  "threat_type": "malware|apt|ransomware|trojan|backdoor|pua",
  "mitre_techniques": ["T1059.001", "T1055", ...]
}
```

#### VirusTotal IOC Integration
Before AI analysis, CyberGuardian automatically extracts and checks:
- **File hashes** (SHA-256, MD5)
- **IP addresses** from connections and command lines
- **Domains** from URLs and network strings
- **URLs** from process memory and command lines

Results are included in the AI analysis prompt, providing cross-referenced intelligence from 70+ antivirus engines.

---

### ⚡ Real-Time Monitoring

Enable Real-Time Monitoring for continuous protection:

#### What's Monitored

1. **New Process Creation**
   - Immediate analysis of every new process
   - Automatic memory analysis for high-risk processes (PowerShell, CMD, MSHTA, etc.)
   - Detection of code injection in running processes
   - IOC extraction from process memory

2. **File System Changes**
   - Monitors user directories, Downloads, Desktop, Temp folders
   - Analyzes new and modified files
   - Supports both watchdog (event-based) and polling modes

3. **Registry Modifications**
   - Monitors all autorun locations for changes
   - Immediate analysis of new persistence entries
   - Detects IFEO debugger injections in real-time

4. **Network Connections**
   - Detects new outbound connections
   - Threat intelligence lookup for every new IP/domain
   - Memory analysis for processes with suspicious connections
   - Beaconing pattern detection

#### Alert System
- Popup notifications for detections
- Configurable alert duration and sound
- Tray icon with status indication
- Event logging for investigation

---

### What's New in v1.1.0

- ✅ **Enhanced AI Response Parsing** — Robust JSON extraction with fallback handling
- ✅ **Improved VirusTotal Integration** — Better IOC detection and malicious IP filtering
- ✅ **Risk Level Adjustment** — Automatic risk elevation based on VT findings
- ✅ **Detailed Debug Logging** — Better troubleshooting for threat hunters
- ✅ **Windows Build Improvements** — pywin32 compatibility, Python version warnings
- ✅ **Automatic Icon Conversion** — PNG to ICO for executable builds

---

## 📁 Project Structure

```
CyberGuardian/
│
├── 📂 main.py                     # Application entry point
├── 📂 requirements.txt            # Python dependencies
├── 📂 build.py                    # PyInstaller build script
├── 📂 setup_windows.bat           # Windows automated setup
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
├── 📂 data/
│   ├── yara_rules/                # Custom YARA rules directory
│   ├── logs/                      # Application logs
│   └── quarantine/                # Quarantined files
│
├── 📂 docs/
│   └── screenshots/               # Documentation screenshots
│
├── 📄 README.md                   # This file
├── 📄 USER_GUIDE.md               # Detailed user documentation
├── 📄 BUILD_GUIDE.md              # Build instructions
├── 📄 BUILD_FIX.md                # Troubleshooting guide
├── 📄 CONTRIBUTING.md             # Contribution guidelines
└── 📄 LICENSE                     # MIT License
```

---

## 🚀 Installation

### Prerequisites

- **Python 3.9 - 3.12** (Python 3.11 recommended for best compatibility)
- **Windows** (Primary platform, Linux/macOS support planned)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/Souhaieb-Marzouk/CyberGuardian.git
cd CyberGuardian

# Create virtual environment (recommended)
python -m venv venv
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run pywin32 post-install (Windows only)
python Scripts\pywin32_postinstall.py -install

# Launch CyberGuardian
python main.py
```

### Automated Setup (Windows)

Run the provided setup script as Administrator:

```cmd
setup_windows.bat
```

### Build Standalone Executable

```bash
# Clean build
python build.py --clean

# Build with distribution package
python build.py --package
```

---

## 🎮 Usage

### Basic Scanning

1. **Launch CyberGuardian** — Run `python main.py` or the compiled executable
2. **Select a Scanner** — Choose from Process, File, Network, or Registry analysis
3. **Configure Options** — Enable Deep Analysis for comprehensive scanning
4. **Start Scan** — Click "Start Scan" and review results
5. **Investigate Detections** — Click "View Details" for full evidence and AI analysis

### AI-Powered Analysis

1. Open any detection detail
2. Select your AI provider (DeepSeek, OpenAI, or Gemini)
3. Click **"ANALYZE WITH AI"**
4. Review the comprehensive analysis including:
   - Verdict (Legitimate/Suspicious/Malicious)
   - Confidence score
   - Technical analysis
   - MITRE ATT&CK techniques
   - Actionable recommendations

### API Configuration

Configure API keys in **Settings → API Keys**:

| API | Purpose | Get Key |
|-----|---------|---------|
| VirusTotal | IOC reputation | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| DeepSeek | AI analysis | [platform.deepseek.com](https://platform.deepseek.com) |
| OpenAI | AI analysis | [platform.openai.com](https://platform.openai.com) |
| Gemini | AI analysis | [makersuite.google.com](https://makersuite.google.com) |

---

## 📸 Screenshots

### Main Dashboard
![Main Dashboard](docs/screenshots/main_dashboard.png)

### Process Analysis
![Process Analysis](docs/screenshots/process_analysis.png)

### AI-Powered Detection Analysis
![AI Analysis](docs/screenshots/ai_analysis.png)

### Network Analysis with Deep Mode
![Network Analysis](docs/screenshots/network_analysis.png)

---

## 🔧 Configuration

### YARA Rules

Add custom YARA rules to `data/yara_rules/`:

```
data/
└── yara_rules/
    ├── malware_rules.yar
    ├── custom_detection.yar
    └── ...
```

Rules are automatically loaded on startup.

### Whitelist

Manage whitelisted items in **Settings → Whitelist** or directly edit `data/whitelist.json`.

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Ways to Contribute

- 🐛 Report bugs and issues
- 💡 Suggest new features
- 📝 Improve documentation
- 🔧 Submit pull requests
- 🌟 Share the project

---

## 🗺️ Roadmap

### Coming Soon

| Feature | Status | Description |
|---------|--------|-------------|
| Linux/macOS Support | 🔄 Planned | Cross-platform compatibility |
| MITRE ATT&CK Navigator Export | 🔄 Planned | Visual technique mapping |
| One-Click Remediation | 🔄 Planned | Automated threat cleanup |
| Scheduled Scanning | 🔄 Planned | Automated regular scans |
| SIEM Integration | 📋 Planned | Splunk, ELK connectors |
| Case Management | 📋 Planned | Investigation tracking |

---

## ❓ FAQ

### Is CyberGuardian a replacement for antivirus?

**No.** CyberGuardian is designed to complement your existing security tools, not replace them. It provides transparency and educational value that traditional AV/EDR solutions lack.

### Do I need to be a security expert to use this?

**Absolutely not!** CyberGuardian is designed for everyone. Results are explained in plain language, and AI analysis provides clear recommendations.

### Is my data sent to the cloud?

**Only if you choose to.** Core detection happens locally. AI analysis and VirusTotal lookups are optional and require API keys that you control.

### Can I add my own detection rules?

**Yes!** Add YARA rules to `data/yara_rules/` and they'll be automatically loaded.

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com) for threat intelligence API
- [YARA](https://virustotal.github.io/yara/) for malware pattern matching
- [DeepSeek](https://deepseek.com), [OpenAI](https://openai.com), and [Google](https://ai.google.dev) for AI capabilities
- The open-source security community

---

## 📞 Contact

- **GitHub**: [Souhaieb-Marzouk/CyberGuardian](https://github.com/Souhaieb-Marzouk/CyberGuardian)
- **LinkedIn**: [Souhaieb Marzouk](https://www.linkedin.com/in/souhaiebmarzouk/)
- **Issues**: [GitHub Issues](https://github.com/Souhaieb-Marzouk/CyberGuardian/issues)

---

<div align="center">

**If you find CyberGuardian useful, please consider giving it a ⭐ star!**

[⬆ Back to Top](#-cyberguardian)

</div>
