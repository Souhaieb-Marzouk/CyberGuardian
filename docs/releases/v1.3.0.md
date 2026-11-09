# CyberGuardian v1.3.0 — Event Logs, Guided Remediation & PC Health

This release turns CyberGuardian from a point-in-time scanner into something that
also explains the past and tells non-technical users exactly what to do next.

## Downloads

| Asset | Size | SHA-256 |
|---|---|---|
| `CyberGuardian_v1.3.0.zip` (recommended) | 41.8 MB | `E3ECF0E384D275E5B17DA144A4FC63151458824DFE5E38D4B23EC775B9FF8924` |
| `CyberGuardian_v1.3.0.exe` (standalone) | 42.1 MB | `A9922EB2BD785C05F26E55CE726BF5097936EC3E7F79D312E97098D2CA86B208` |

Windows 10/11 (x64). Run **as Administrator** for Security-log, registry, service
and memory coverage. The binary is unsigned, so SmartScreen may warn — choose
*More info → Run anyway*, or build from source.

## New: Windows Event Log analysis

A new **Activity Logs** scan reads System, Application, Security, Defender,
PowerShell and Task Scheduler channels through the Windows Event Log API
(no `wevtutil`, no PowerShell). It uses a per-channel cursor, so each run only
analyses new events, and the first run establishes a baseline instead of
re-reporting months of history.

Highlights:

- **Log tampering** — Security log cleared (1102/104), audit policy changes.
- **Persistence** — new services (7045/4697), scheduled tasks (4698), user
  accounts (4720), privileged group changes (4732).
- **Credential attacks** — repeated failed logons correlated per account (4625),
  explicit credential use (4648), Kerberos anomalies.
- **Execution** — encoded PowerShell, download cradles, MSHTA, certutil/BITS,
  shadow-copy deletion, `wevtutil cl` in process-creation/script-block events.
- **Defender** — malware detections and real-time protection being disabled.

The Security channel requires elevation; other channels work for normal users and
the scanner reports which channels were inaccessible.

## New: guided remediation playbook in AI analysis

"Analyze with AI" now returns a structured, four-stage response plan instead of a
single remediation list:

1. **Verify before you act** — confirm the finding, compare publisher/signature,
   and see what a benign result looks like.
2. **Contain / isolate now** — threat-specific: network isolation for ransomware,
   process suspension, disabling services or tasks.
3. **Remove and restore** — quarantine, cleanup, credential rotation.
4. **Confirm it is gone** — verification steps and what to monitor afterwards.

The plan is rendered in the analysis view and included in `AnalysisResult.to_dict()`
for API/JSON consumers.

## New: PC Health and "what changed"

- **PC Health dialog** — a 0–100 score with a plain-language status ("Everything
  looks good", "Needs your attention today", "Act now"), per-severity counts and
  prioritised advice.
- **Change timeline** — snapshots startup entries, services and scheduled tasks,
  then lists what appeared or disappeared since the previous check.

## Interface

- New palette (deep navy with mint/cyan accents) for better contrast and a more
  modern look.
- New **Activity Logs** and **PC Health** actions in the main toolbar.

## Quality

- 12 automated tests covering event parsing, service/command detection,
  brute-force correlation, health scoring, timeline diffing and playbook parsing.
- GitHub Actions CI: tests on Python 3.10 and 3.12, plus an executable build job.

## CLI

```text
python main.py --cli --eventlog     # event log analysis only
python main.py --cli --scan-all     # now includes event logs
```

## Upgrade notes

- New configuration keys: `scan.eventlog_enabled` (default `true`) and
  `scan.eventlog_lookback_hours` (default `24`).
- Event log cursors and the change timeline are stored in
  `%LOCALAPPDATA%\CyberGuardian\cache\`; delete them to re-baseline.

## Known limitations

- Event log coverage is a curated high-signal set, not a full SIEM; Sysmon
  channels are not read yet.
- The Security channel needs Administrator; a non-admin scan still covers the
  other channels.
- Deep network collection still parses English-only `ipconfig`/`arp`/`route`
  output.

**Full changelog:** [CHANGELOG.md](../CHANGELOG.md)
