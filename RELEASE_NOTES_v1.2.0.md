# CyberGuardian v1.2.0 — Security & Reliability Release

Security and reliability release. Detection signatures are unchanged, but several
detection paths that previously never executed now work — expect different (and
better-calibrated) results.

## Downloads

| Asset | Size | SHA-256 |
|---|---|---|
| `CyberGuardian_v1.2.0.zip` (recommended) | 41.8 MB | `00157F88028214CD4A22B287183BAEB20EC5FE22F637E08C618EFC5AE0B3B60E` |
| `CyberGuardian_v1.2.0.exe` (standalone) | 42.1 MB | `A612A6E37EFBF8B07559DD04A0EB3AA6FE4E825B26EA4477581481F55FFB539D` |

Requires Windows 10/11 (x64). Run **as Administrator** for registry, service and
memory analysis. The executable is not code-signed, so Windows SmartScreen may
show "Unknown publisher" — choose *More info → Run anyway*, or build from source.

## Security

- **Removed a command-injection vector.** Executable paths were interpolated into
  a PowerShell command during signature checks. Authenticode now uses
  `WinVerifyTrust` with catalog support for system binaries, and no longer spawns
  ~200 `powershell.exe` processes per scan.
- **Fixed stored XSS in HTML reports.** All fields taken from scanned content are
  escaped.
- **Hardened AI analysis.** Scanned strings are treated as untrusted data
  (delimited, length-capped, control characters stripped) and model output is
  validated and range-clamped.
- **API keys no longer written to `config.yaml`.** They live in the OS credential
  store; existing plaintext keys are migrated automatically.
- **VirusTotal failures are not cached as "clean"** anymore (401/429/timeouts
  previously became 24-hour false negatives).
- **Whitelist hardening:** path-traversal bypass fixed, empty-signer bypass fixed,
  blanket `Services\` trust removed, system-name masquerading now detected.

## Fixed features (were silent no-ops)

- VirusTotal IOC enrichment for AI analysis.
- YARA memory scanning in Deep Analysis.
- Whitelist add/remove dialog actions.
- Registry deep-analysis mode.
- Real-time detections (now delivered to the GUI; previously dropped).
- System tray icon and notifications.
- `--update-rules` (real HTTPS manifest update with compile validation).

## Detection quality

- Steganography: fixed broken magic-byte matching; normal images are no longer
  flagged, actual appended payloads are.
- Beaconing: persistent connections no longer produce false "beacons".
- Registry: corrected persistence key list, bounded recursion, no more "high
  entropy" finding for every service.
- Network: local ports no longer whitelist connections, `AF_LINK` fixed on
  Windows, DNS lookups cached and time-boxed, ephemeral-port noise removed.
- Process: cryptominer detection now reachable (proper CPU sampling + history).
- Duplicate findings collapsed; clean/malicious counters reconciled.

## Performance

- Network scan on a typical host: **181 s → ~10 s**.
- Registry scan: ~9,400 entries, bounded findings.
- Per-binary YARA/hash caching for multi-process applications.

## Upgrade notes

- On first launch, keys found in `config.yaml` are moved to the credential store
  and removed from the file.
- YARA rules now live in `%LOCALAPPDATA%\CyberGuardian\yara_rules`; the bundled
  defaults ship inside the executable and are regenerated if missing.
- Existing `data/whitelist.json` files remain compatible.

## Known limitations

- Deep network collection parses English-language `ipconfig`/`arp`/`route` output.
- Reverse DNS is a blocking call per lookup (bounded to 8 s per scan).
- YARA checks require the bundled `yara-python`; if it cannot load, other
  detection methods still run.

## Verification

- 25 Python modules parse cleanly; static analysis reports no undefined names.
- Live scans on Windows 11 x64: process, file, registry and network scanners.
- Build: Python 3.12.10 + PyInstaller 6.22.3, PyQt5 5.15.11, yara-python 4.5.4.

**Full changelog:** [CHANGELOG.md](CHANGELOG.md)
