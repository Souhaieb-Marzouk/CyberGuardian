# Architecture

CyberGuardian is a local Windows security workstation built around a small scanner
contract, a shared evidence model and a Qt interface that never blocks on I/O.

## Entry points

| File | Role |
|---|---|
| `main.py` | Canonical entry point: Studio GUI by default, CLI with `--cli` |
| `main_studio.py` | Thin alias that always starts the Studio interface |
| `build.py` | PyInstaller packaging and release metadata |

`main.py` parses CLI arguments, runs the requested headless scanner, or imports
`ui.studio.run` and starts the Qt application.

## Layers

```
ui/            Studio window, pages, dialogs, design system, i18n strings
               (including the live traffic page and its guided dialogs)
  ↓ calls
scanners/      Process, file, network, registry, event log, memory, realtime
  ↓ produce
base_scanner   ScanResult / Detection / RiskLevel / ScanStatus
  ↑ consume
core/          Health, canaries, software, startup, quarantine, reputation,
               live traffic, firewall rules, IP enrichment
threat_intel/  Hash/IP/domain/URL reputation and VirusTotal client
ai_analysis/   Provider clients, prompt construction, tolerant JSON parsing
reporting/     HTML/PDF/CSV/JSON reports and exports
utils/         Config, i18n, whitelist, signatures, DPAPI storage, logging
```

### Scanner contract

Every scanner subclasses `BaseScanner` and implements:

```python
scan(target=None) -> ScanResult
```

Shared behaviour in the base class provides progress and detection callbacks,
`cancel()` / `is_cancelled()` / `reset_cancel()` and result accounting
(`total_items`, `clean_items`, `finalize_counts()`).

Scanners check `is_cancelled()` at item boundaries. The Studio worker also has a
watchdog that terminates a scan that does not reach a checkpoint, so Stop always
works. A cancelled scan keeps `ScanStatus.CANCELLED`; scanners must not overwrite it
with `COMPLETED` after the loop.

### Detections and evidence

`Detection` carries identity (`detection_type`, `indicator`, `indicator_type`), risk,
confidence, description/reason, remediation and free-form `evidence`.

`scanners/evidence.py` adds the context an analyst needs:

- `process`: name, PID, PPID, parent, path, directory, command line, user,
  start time, threads, handles, memory, signature, SHA-256,
- `file`: size, MIME, entropy, hashes, timestamps, PE/Office flags,
- `connection`: local/remote endpoints, hostname, protocol, state, owning process,
  age, bytes,
- `registry`: hive, key, value name/type/data,
- `event`: channel, event ID, provider, record ID, time, level and selected fields.

The UI renders these in the event-field table, the exporter flattens them for CSV
and the AI prompt receives them as untrusted, delimited data.

## YARA

- Bundled rules live in `scanners/default_rules.py`; `YaraManager` writes them to
  `yara_rules/` on first use.
- `BUILTIN_RULES_VERSION` in `scanners/yara_manager.py` forces a rewrite when rules
  change; user-supplied rule files are never overwritten.
- Rules are compiled per file and cached by mtime/size.
- Match strings are normalised across yara-python API versions in
  `_match_strings()` (older tuples, newer `StringMatch` objects).
- Precision policy: PE rules require `uint16(0) == 0x5A4D` and at least two specific
  indicators; script rules require `uint16(0) != 0x5A4D` and a real code construct;
  ambiguous heuristics are `low` severity and never reported as findings.
- File scans skip the application directory, which contains the rules themselves
  and test fixtures with malware strings.

## Scan pipeline

1. `ScanPage.start()` builds a scanner, reads the persisted options and starts a
   `ScanWorker` (`QThread`).
2. The worker wires progress/detection signals and calls `scan(target)`.
3. Detections are emitted as they happen; the result is emitted on completion.
4. `StudioWindow.on_scan_done` aggregates results for the Findings page, updates the
   Overview, writes the activity log and refreshes caches.
5. `FindingDialog` reads the detection and evidence; AI and VirusTotal results are
   cached per `detection_id + type + indicator`, so reopening a finding keeps them.

## Analysis

### AI

`ai_analysis/analyzer.py` builds a prompt from the detection, the evidence block and
(optionally) VirusTotal results. Scanned content is treated as untrusted: it is
length-capped, control characters are stripped and it is wrapped in delimiters to
resist prompt injection. The language of the prompt output follows `ui.language`.

Responses are parsed with `_loads_json_tolerant`, which repairs code fences, raw
newlines, trailing commas and truncated responses, then falls back to salvaging
complete key/value pairs.

### VirusTotal

`threat_intel/virustotal_checker.py` checks hashes, IPs, domains and URLs with
caching and rate limiting. The Studio tab filters private IPs and file-like
"domains", displays verdicts and feeds `IOCResult.to_dict()` into the AI prompt.


## Live traffic

`core/live_traffic.py` polls `psutil.net_connections(kind="inet")` once per second,
attributes every connection to its process (name, executable, user, PID/PPID,
parent, command line), caches process lookups for ten seconds and resolves
reverse DNS asynchronously. `psutil.net_io_counters()` provides accurate
per-adapter throughput; per-connection byte counters are not available without
packet capture and are deliberately not displayed.

Each `ConnectionView` carries the endpoints, protocol, state, age, adapter,
reverse name, service guess (port map), LAN/Internet classification and a list of
risk hints:

- `blacklist` — address or CIDR in `data/ip_blacklist.txt` (reloaded on change),
- `suspicious_port` — public remote port commonly used by attacks,
- `user_writable` — executable under `\Temp\`, `\Downloads\` or `Public`,
- `unknown_process` — no durable image path for a public connection,
- `exposed_listener` — RDP/VNC/Telnet listening on all interfaces.

Kernel rows (PID 0/4) and loopback traffic are never flagged. The UI translates
hint codes; nothing user-visible is hard-coded in the backend.

### Firewall rules

`core/firewall.py` creates one named rule per blocked direction:

```
CyberGuardian_<in|out>_<TCP|UDP>_<ip>_<port>
```

Rules are added/removed with `netsh advfirewall firewall`, require administrator
rights, and are persisted in `cache/firewall_rules.json` so the UI can show and
remove them later. Blocking is endpoint-based (all applications), which is what
Windows Firewall can enforce without per-process scope.

### IP enrichment

`core/ip_lookup.py` performs an explicit, opt-in `ipapi.co` request (country,
region, city, ASN/org) and caches the result for a week in
`cache/ip_lookup.json`. Private addresses are rejected; no lookup is performed
unless the user presses the button.

### Triage integration

The traffic page builds a `Detection` object with the connection and process
context and opens the standard `FindingDialog` on the **VirusTotal** or **AI**
tab (`initial_tab`, `auto_start`). This reuses the existing caches, HTML export
and AI prompt instead of duplicating triage logic.

## Localisation

`utils/i18n.py` contains the English and French catalogs (no Qt `.qm` files, so the
one-file build needs no extra data). `tr(key)` falls back to English, then to the
key. The language is persisted in `ui.language`; changing it rebuilds the window
while preserving geometry and page. Canary guidance has a dedicated French catalog.

## Storage

| Data | Location |
|---|---|
| Config | `config/config.yaml` (source) or `%APPDATA%\CyberGuardian` (installed) |
| API keys | Windows DPAPI secure store (`utils/secure_storage.py`) |
| Whitelist | `data/whitelist.json` |
| Quarantine | `data/quarantine/` — DPAPI-encrypted, SHA-256 verified |
| Canaries | `cache/canaries.json` |
| Event-log cursor | `cache/eventlog_cursor.json` |
| Timeline snapshots | `cache/timeline.json` |
| Reports | `reports/` |
| YARA rules | `yara_rules/` |
| Firewall rules | `cache/firewall_rules.json` |
| IP lookup cache | `cache/ip_lookup.json` |
| IP blacklist | `data/ip_blacklist.txt` |

None of these directories are committed.

## Interface

`ui/studio.py` contains the shell and pages; `ui/design_common.py` provides cards,
the gauge, chips, bars, fonts and shadows. The design tokens (`LIGHT`, `DARK`) are
plain dictionaries consumed by `qss()` and by the custom widgets, which keeps the
theme switch deterministic: a new window is built with the target tokens and the
old one is closed.

## Testing

- `tests/` contains 158 unit and headless UI tests.
- Qt runs with `QT_QPA_PLATFORM=offscreen`.
- `test_ui_buttons.py` clicks every button on the legacy dialog surfaces and fails
  if one raises.
- `test_yara_rules.py` enforces rule precision and true-positive detection.
- `test_i18n.py` enforces catalog parity and placeholder consistency.

Run everything with:

```powershell
python -m unittest discover -s tests -t .
```
