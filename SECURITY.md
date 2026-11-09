# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 1.5.x | Yes |
| 1.4.x and older | Best effort; upgrade recommended |

## Reporting a vulnerability

Please **do not open a public issue** for a security problem.

Use GitHub's private reporting:
[Security advisories → Report a vulnerability](https://github.com/Souhaieb-Marzouk/CyberGuardian/security/advisories/new)

Include:

- affected version and Windows build,
- component (`scanner`, `UI`, `AI`, `VirusTotal`, `quarantine`, `canaries`…),
- reproduction steps or a proof of concept,
- impact: what an attacker could read, change or delete,
- any crash dump or log excerpt (remove secrets first).

You can expect an acknowledgement within a few days. Please allow time for a fix
and a release before public disclosure.

## Scope

In scope:

- privilege escalation inside CyberGuardian,
- bypass of the quarantine integrity checks,
- code execution through a crafted detection, filename, command line or report,
- path traversal or unsafe file writes,
- prompt-injection that changes AI verdicts or executes actions,
- leakage of API keys or scan data to an unintended destination,
- denial of service that corrupts configuration, whitelist or quarantine state.

Out of scope:

- findings caused by malware already running with administrator rights,
- false positives/negatives of a YARA rule (report them as a regular bug),
- SmartScreen warnings for the unsigned executable,
- third-party provider outages (DeepSeek, OpenAI, Gemini, VirusTotal),
- social engineering of the user.

## Data handling

- Scans and evidence are local. Nothing is uploaded unless you start an AI analysis
  or a VirusTotal check.
- Those actions send the selected finding (indicator, evidence, process/file
  context) to the provider you configured.
- API keys are stored in the Windows DPAPI-protected store, never in the repository
  or in plain-text configuration.
- The whitelist, quarantine, canary state and reports are local files; protect them
  as you would any forensic material.

## Canaries and system changes

Canaries create real decoy files in user folders, and the startup/quarantine tools
can modify system state. These actions are explicit and reversible; review them
before applying, and press **Disarm** before uninstalling.

## Disclaimer

CyberGuardian is a defensive analysis tool provided as-is, without warranty. Do not
use it on systems you are not authorised to inspect.
