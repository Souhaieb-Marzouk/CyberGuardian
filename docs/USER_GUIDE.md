# CyberGuardian — User Guide

This guide covers the Studio interface shipped with CyberGuardian 1.5.0.

## Contents

1. [First launch](#first-launch)
2. [The interface](#the-interface)
3. [Running scans](#running-scans)
4. [Triaging a finding](#triaging-a-finding)
5. [AI analysis](#ai-analysis)
6. [VirusTotal](#virustotal)
7. [Tools](#tools)
8. [Ransomware canaries](#ransomware-canaries)
9. [Settings and language](#settings-and-language)
10. [Exporting](#exporting)
11. [CLI](#cli)
12. [Troubleshooting](#troubleshooting)
13. [Where data is stored](#where-data-is-stored)

---

## First launch

CyberGuardian does not require an account or a connection. On first launch you get
an empty **Overview** with a health score of *No scan yet*.

Start with **Run a quick check** (process scan) or open **Scans** and choose the
scanner you need. Windows will ask for administrator rights; accept them for full
process, registry and event-log coverage.

## The interface

The window has seven pages in the top navigation:

| Page | Purpose |
|---|---|
| **Overview** | Health score, stat tiles, what was checked, findings that need attention |
| **Scans** | Five scanners with their results tables |
| **Findings** | Every detection from every scan, with a risk filter |
| **Canaries** | Ransomware decoys, incident alerts and reports |
| **Tools** | Startup, software updates, file/link checks, canaries, quarantine |
| **Logs** | Activity log of scans and actions |
| **Settings** | Theme, language, detection options, advanced settings |

The header shows the author byline and an **About** button. The status bar keeps the
copyright and project link visible.

## Running scans

Open **Scans** and pick a scanner:

- **Processes** — what is running now, with lineage, signatures, YARA and heuristics.
- **Files** — choose a folder; static analysis with YARA, entropy, PE, Office and
  steganography checks.
- **Network** — live connections and listeners with process attribution.
- **Registry** — autoruns, services, scheduled tasks and persistence keys.
- **Activity** — Security/System/PowerShell/Task Scheduler/Defender events.

Press **Run scan**. The **Stop** button cancels within a moment; the status becomes
*Stopped* and keeps the findings collected so far.

While a scan runs:

- the progress bar tracks items;
- detections appear in the table as they are found;
- **View details** opens the selected finding;
- **Export results** writes CSV or JSON for that scan.

**Deep analysis** (Settings → Detection) enables memory analysis for suspicious or
high-priority processes. It is slower and needs administrator rights.

**Online reputation** (Settings → Detection) adds VirusTotal hash lookups during
scans. It is off by default because the free API is rate-limited.

### Scan tables

Depending on the scanner, the table shows risk, process name, PID, PPID, parent,
user, finding type, YARA rule, confidence, path, endpoints, registry key, event ID
or file type. Hover the process name for its command line.

## Triaging a finding

Double-click a row (or **View details**). The dialog has four tabs.

### Details

- **Process tree** — `explorer.exe (PPID 1000) → chrome.exe (PID 7312)` when available.
- **Event fields** — a Splunk-style field/value table: PID, PPID, parent, user,
  signature, image path, command line, SHA-256, network endpoints, registry data,
  event identity, YARA rules and matched string identifiers.
- **Why it was flagged** — the rule or heuristic reason.
- **Raw evidence** — the complete JSON, copyable.

### Remediation

The recorded response steps for that detection type.

### AI analysis

See [AI analysis](#ai-analysis).

### VirusTotal Check

See [VirusTotal](#virustotal).

Actions at the bottom: **Add to whitelist**, **Open file location**, **Close**.

## AI analysis

1. Open **Settings → Advanced settings → API keys** and add a DeepSeek, OpenAI or
   Gemini key.
2. In the finding dialog, open **AI analysis** and press **Analyze with AI**.
3. If a VirusTotal key is configured and no check has run yet, CyberGuardian checks
   the IoCs first and then sends the analysis.
4. The report includes verdict, confidence, risk score, technical analysis, MITRE
   techniques and a four-stage plan:
   - verify before acting,
   - contain/isolate,
   - remove and restore,
   - confirm it is gone.
5. **Export report (HTML)** saves a self-contained report.

Results are cached per finding: close the dialog, reopen the same finding and the
report is still there. The language of the report follows the UI language.

The finding and its evidence are sent to the provider you chose. Nothing is sent
until you press the button.

## VirusTotal

The **VirusTotal Check** tab lists the IoCs detected in the finding — file hashes,
URLs, domains and public IPs — and checks them against VirusTotal.

- Requires a VirusTotal API key in **Settings → Advanced settings**.
- Free keys allow 4 requests per minute, so a finding with several IoCs can take a
  minute; the status line explains this.
- Results are cached and exportable as HTML.
- Private IPs and file names are filtered out to protect the quota.

## Tools

**Tools → Toolbox** opens five tabs:

| Tab | What you can do |
|---|---|
| **Startup** | Review Run/RunOnce keys, Startup folders, services and tasks; enable or disable with StartupApproved |
| **Software** | Inventory, latest versions via winget, update status; **Check for updates** and per-application **Update** |
| **Check a file or link** | Reputation verdict with signature, location and URL intelligence |
| **Ransomware canaries** | Install, check or remove the decoys (see below) |
| **Quarantine** | Restore or permanently delete quarantined files |

**Tools → PC health** shows the score, recommendations and what changed since the
last assessment.

### Software updates

**Check for updates** queries Windows Package Manager (read-only). Rows that have a
newer version get an **Update** button, which runs a silent `winget upgrade` after
confirmation. Package ids are validated before use. Some updates need administrator
rights; browsers and editors may need a restart afterwards.

## Ransomware canaries

Canaries are realistic decoy documents (DOCX, XLSX, CSV, TXT) placed in the folders
ransomware encrypts first:

- `Documents` — tax draft, payroll summary
- `OneDrive\Documents` — client contracts
- `Downloads` — invoices
- `Desktop` — recovery codes
- `Public\Documents` — employee handbook

Press **Arm canaries** to create them. CyberGuardian checks them every three seconds.
The first write, rename, delete or encryption triggers:

- a Windows tray notification;
- an alert with the file name and location;
- an incident report with a timestamped timeline, technical evidence (sizes,
  SHA-256, entropy) and a step-by-step response guide.

**Disarm** removes the files and clears the incident history.

> Canaries are real files. Remove them before uninstalling CyberGuardian or moving
> the machine.

## Settings and language

| Setting | Effect |
|---|---|
| Theme | Light or Dark; remembered across launches |
| Language | English or Français; applies to UI, dialogs, canary guidance, VirusTotal summaries and AI reports |
| Deep analysis | Enables memory analysis on supported scans |
| Online reputation | VirusTotal hash lookups during scans |
| Advanced settings | API keys, whitelist, YARA rules, quarantine |

The window size and position are remembered, and switching theme or language keeps
them.

## Exporting

| Button | Output |
|---|---|
| Scan page → **Export results** | CSV or JSON for that scan, including process context and YARA details |
| Findings → **Export all results** | CSV or JSON for every scan |
| AI tab → **Export report (HTML)** | Standalone HTML analysis report |
| VirusTotal tab → **Export report (HTML)** | Standalone HTML VirusTotal report |
| Tools → PC health | Health report sharing options |

CSV rows are flattened for spreadsheets (one row per YARA rule match). JSON keeps
the complete evidence.

## CLI

The engine can run without the interface:

```powershell
python main.py --cli --scan-all
python main.py --cli --process
python main.py --cli --file C:\path\to\folder
python main.py --cli --network
python main.py --cli --registry
python main.py --help
```

CLI output is plain text suitable for logs and ticketing.

## Troubleshooting

| Problem | Solution |
|---|---|
| Some processes or event channels are missing | Run as administrator |
| Scans are slow | Disable deep analysis; keep online reputation off |
| AI analysis fails | Check the provider key in Settings → Advanced settings; try again after a minute |
| VirusTotal says unconfigured | Add a VirusTotal API key; free keys are rate-limited |
| No YARA findings | Settings → Advanced settings → YARA → reload rules; the bundled rules are refreshed automatically on version changes |
| SmartScreen blocks the executable | Verify the SHA-256 from the release, then choose *More info → Run anyway* |
| Canary files left after uninstall | Delete the listed files or press **Disarm** before removing the app |
| Window off-screen after changing monitors | It is restored from saved geometry; delete the saved geometry with the app settings if needed |

## Where data is stored

| Data | Location |
|---|---|
| Configuration | `config/config.yaml` (source run) or the app data directory (installed) |
| API keys | Windows DPAPI-protected secure store |
| Whitelist | `data/whitelist.json` |
| Quarantine | `data/quarantine/` (encrypted) |
| Canary state | `cache/canaries.json` |
| Reports and exports | `reports/` and the path you choose |
| YARA rules | `yara_rules/` (bundled rules are rewritten on version change) |

See [ARCHITECTURE.md](ARCHITECTURE.md) for details.
