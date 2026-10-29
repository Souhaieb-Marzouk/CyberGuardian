# CyberGuardian v1.4.1 — Hardened v1.4 Tools

**Release title:** `CyberGuardian v1.4.1 — Hardened v1.4 Tools`

## Release description

CyberGuardian 1.4.1 is a reliability and security-hardening release for the
v1.4 feature set. It fixes several paths where the tools did not do what the
interface promised, and where a failure could crash the app or lose data.

### Downloads

| Asset | Size | SHA-256 |
|---|---|---|
| `CyberGuardian_v1.4.1.zip` (recommended) | 46.0 MB | `B38FD51B507CCB2ED63E3A36AB7999AB99F459B930F77637F56B5FCBA522950E` |
| `CyberGuardian_v1.4.1.exe` (standalone) | 46.3 MB | `8AF26496BA3E366CDF86DE1050D63F068EA81AF7ADD542309DAC72BDB5842795` |

Windows 10/11 (x64). Run **as Administrator** for Security-log, registry,
service and memory coverage. The binary is unsigned, so SmartScreen may warn —
choose *More info → Run anyway*, or build from source.

### Highlights

- **Quarantine now works in the released executable.** Quarantining from a
  detection used to move the file into the PyInstaller temporary directory, so
  the "quarantined" file vanished when the app closed. It now goes into the
  encrypted, restorable vault (Tools → Quarantine).
- **Settings actually control scans.** The process, file, network and registry
  checkboxes in Settings > Scan were ignored; every check always ran. Each
  toggle now enables or disables its detection method.
- **No more overlapping scans or destroyed threads.** All scan buttons are
  disabled while a scan runs, a second scan request is refused, and closing a
  window no longer destroys a still-running worker.
- **Malformed input cannot crash a scan.** Bad URLs (ports, IPv6, whitespace in
  host names), malformed config values, invalid whitelist expiry dates and
  corrupt quarantine entries are handled with clear results.
- **Reporting fixed.** The HTML report no longer shows mojibake; the PDF
  fallback escapes `&`/`<` (which used to abort export); AI playbook text is
  escaped; `--export FILE` writes where you ask, and `--format text` works.
- **Secrets and logs.** API-key deletion works with modern `keyring`, with a
  DPAPI fallback when the credential manager is unavailable. ANSI colour codes
  no longer leak into file/JSON logs.
- **YARA included and fixed.** Two bundled rule files did not compile; both are
  fixed and repaired automatically on load. The Windows build now bundles
  YARA when `yara-python` is installed.
- **79 automated tests**, including a headless test that clicks every button in
  every window and a failure-injection suite.

### Upgrade notes

- Quarantine entries created by v1.4.0 in `quarantine/` next to the executable
  are not migrated automatically; restore those files manually before deleting
  the folder.
- Previously generated `yara_rules/*.yar` files are repaired in place on first
  launch. Custom rules are left untouched.
- Configuration is validated on load. Unknown or malformed values are ignored
  and logged; valid settings in the same file still apply.

### Verification

```powershell
python -m unittest discover -s tests -t . -v
python main.py --cli --scan-all
```

The test suite covers the UI, scanners, quarantine, reputation, configuration,
whitelists, startup classification, logging and reporting.
