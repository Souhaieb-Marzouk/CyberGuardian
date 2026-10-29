# Changelog

All notable changes to CyberGuardian are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [1.4.0] - 2026-10-29

### Added

- **Tools panel** with five tabs: Startup impact, Software inventory, "Check a
  file or link", Ransomware canaries and the Quarantine vault.
- **Quarantine vault** (`core/quarantine.py`): DPAPI-encrypted containers,
  SHA-256 integrity checks, restore that never overwrites, 30-day retention.
- **Startup impact manager** (`core/startup.py`): Run/RunOnce keys, Startup
  folders, auto-start services and scheduled tasks, with explainable impact and
  reversible enable/disable through StartupApproved.
- **Ransomware canaries** (`core/canary.py`): decoy documents in user folders,
  change detection and one-click install/remove.
- **Reputation checker** (`core/reputation.py`): file and URL verdicts with
  evidence (signature, location, punycode, raw IP, risky TLDs, optional
  VirusTotal).
- **Software inventory** (`core/software.py`): installed applications compared
  against a local advisory feed, with update links.
- **PDF reports** (`reporting/pdf.py`): WeasyPrint with a ReportLab fallback,
  including the AI response playbook.

## [1.3.0] - 2026-10-29

### Added

- **Event log analysis** (`scanners/eventlog_scanner.py`): reads System,
  Application, Security, Defender, PowerShell and Task Scheduler channels via the
  Windows Event Log API with incremental cursors. Detects log clearing, new
  services, scheduled tasks, account creation/privilege changes, brute force,
  suspicious service paths, encoded PowerShell and LOLBAS command lines.
- **Guided AI response plan**: analysis now returns four ordered lists -
  verification, containment, remediation and validation - rendered in the result
  view and included in the JSON API.
- **PC Health dialog**: 0-100 score, plain-language status and recommendations.
- **"What changed on my PC" timeline**: snapshots startup entries, services and
  scheduled tasks and reports additions/removals since the previous run.
- **Automated tests and CI**: `tests/` suite and a GitHub Actions workflow that
  runs the tests on Python 3.10/3.12 and builds the executable.

### Changed

- New visual theme: deeper navy background, mint/cyan accents, consistent card
  and dialog styling.
- CLI: `--eventlog` (also included in `--scan-all`).

## [1.2.0] - 2026-10-28

Security and reliability release. No detection signatures were removed; several
detection paths that previously never executed now work.

### Security

- **Removed command injection in signature verification.** Executable paths were
  interpolated into a PowerShell command. Authenticode is now verified through
  `WinVerifyTrust` (with catalog fallback for system binaries) in
  `utils/signature_check.py`. This also removes ~200 `powershell.exe` spawns per
  process scan.
- **Fixed stored XSS in HTML reports.** Every field taken from scanned content is
  HTML-escaped, including the report title.
- **Hardened AI analysis.** Scanned strings are control-character-stripped,
  length-capped and delimited as untrusted data; the prompt states that embedded
  instructions must be ignored. Model output is validated (`confidence` 0-1,
  `risk_score` 0-100, MITRE IDs matching `T####(.###)`, allow-listed threat
  types).
- **API keys are no longer written to `config.yaml`.** Keys live in the OS
  credential store (keyring/DPAPI); plaintext keys found in existing configs are
  migrated and scrubbed. The Gemini key is sent in `x-goog-api-key` instead of
  the URL.
- **VirusTotal failures are no longer cached as "clean".** A 401/429/timeout
  previously produced a fabricated clean verdict cached for 24 hours.
- **Whitelist hardening.** Path traversal (`System32\..\Temp`) is rejected,
  empty signer names no longer match every publisher, the blanket
  `Services\` trust was removed (service persistence was silently whitelisted),
  and system process names outside protected directories are flagged as
  masquerading instead of being skipped.

### Fixed features (previously silent no-ops)

- VirusTotal IOC enrichment for AI analysis (called a non-existent method).
- YARA memory scanning during deep analysis (called a non-existent helper).
- Whitelist add/remove dialog calls (missing arguments raised `TypeError`).
- Registry deep-analysis parameter.
- Real-time detections are delivered through a Qt signal; they were scheduled
  with `QTimer.singleShot` from a plain Python thread and never displayed.
- System tray icon is shown; notifications work.
- `--update-rules` performs a real HTTPS manifest download with compile-time
  validation instead of logging "not yet implemented".
- CLI reports PDF/export failures instead of printing `None`.

### Detection quality

- **Steganography** was effectively inverted: magic-byte literals were
  double-escaped so nothing ever matched, while ordinary LSB statistics flagged
  normal photographs. Detection now requires an extracted payload and only
  specific indicators raise the threat level.
- **Beaconing** samples only re-established connections; persistent TLS sessions
  no longer become "beacons" after five polls.
- **Registry** scans use a corrected key list (duplicates and the non-existent
  `StartupFolder` key removed; `RunOnceEx`, `Policies\Explorer\Run`,
  `Winlogon\Notify`, `ShellServiceObjectDelayLoad`, per-user hives added),
  bounded recursion, string-only entropy checks, and signature-aware path checks
  (Defender services are no longer flagged).
- **Network**: local ports no longer whitelist connections (C2 on 443 was marked
  clean), `AF_LINK` works on Windows, `AccessDenied` degrades gracefully, DNS
  lookups are cached and time-boxed, and the ephemeral-port rule was removed.
- **Process**: CPU usage is sampled properly and history persists across scans
  (cryptominer detection was unreachable), YARA/hash work is cached per binary.
- Duplicate findings are collapsed; clean/malicious counters are per item.

### Performance

- Network scan on a typical host: **181 s → ~10 s** (DNS budget/cache).
- Registry scan: ~9,400 entries with a bounded number of findings instead of one
  LOW finding per service key.
- Per-binary YARA/hash caching removes repeated work for multi-process binaries.

### Robustness and packaging

- `closeEvent`/quit wait for running workers; destroying a live `QThread` no
  longer aborts the application.
- PE, OLE, VBA and registry handles are closed on all code paths.
- File walking skips junctions/symlinks and survives unreadable entries.
- Caches and recursion are bounded; 37 bare `except:` clauses replaced.
- PyInstaller builds bundle `yara_rules/`; the legacy `data/config.json`
  template was removed; `.gitignore` and README paths corrected.

### Known limitations

- Deep network collection parses English-only `ipconfig`/`arp`/`route` output.
- Reverse DNS remains a blocking call per lookup (bounded to 8 s per scan).
- YARA rule compilation requires `yara-python`; without it, YARA checks are
  skipped and the rest of the scanner still runs.

## [1.1.0] - 2025-01-01

- Enhanced AI response parsing with fallback handling.
- Improved VirusTotal integration and IOC filtering.
- Automatic risk adjustment based on VirusTotal findings.
- Windows build improvements (pywin32 compatibility, Python version checks).

## [1.0.0] - 2024-12-01

- Initial public release: process, file, network and registry scanners, real-time
  monitoring, AI analysis, VirusTotal integration and HTML reporting.
