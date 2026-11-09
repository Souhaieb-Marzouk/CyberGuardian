# Contributing to CyberGuardian

Thanks for helping improve CyberGuardian. This project is a defensive Windows
security tool: changes must be testable, explainable and safe by default.

## Development setup

```powershell
git clone https://github.com/Souhaieb-Marzouk/CyberGuardian.git
cd CyberGuardian
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install pyinstaller        # only needed for packaging
python main.py                 # Studio interface
```

Python 3.12 is recommended. Python 3.14 is not supported by `yara-python`.

## Tests

The suite uses `unittest` and runs headless:

```powershell
python -m unittest discover -s tests -t . -v
```

Guidelines:

- add a regression test for every bug fix;
- keep UI tests offscreen (`QT_QPA_PLATFORM=offscreen` is set by the tests);
- for YARA changes, run `tests/test_yara_rules.py` — it enforces precision on benign
  files and true positives for representative malware patterns;
- for localisation changes, run `tests/test_i18n.py` — the English and French
  catalogs must have the same keys and placeholders.

## Where to change what

| Area | Location |
|---|---|
| Scanner logic | `scanners/` (subclass `BaseScanner`, emit `Detection` with evidence) |
| Evidence fields | `scanners/evidence.py` |
| YARA rules | `scanners/default_rules.py` (+ bump `BUILTIN_RULES_VERSION`) |
| Studio pages | `ui/studio.py` |
| Finding dialog / VirusTotal tab | `ui/findings.py` |
| Canaries | `core/canary.py`, `ui/canaries.py` |
| AI prompt and parsing | `ai_analysis/analyzer.py` |
| Reports/exports | `reporting/` |
| Language strings | `utils/i18n.py` |
| Attribution/version | `core/branding.py`, `build.py` |

## Adding a language string

1. add the key to both `CATALOG["en"]` and `CATALOG["fr"]` in `utils/i18n.py`;
2. keep `{placeholders}` identical in both languages;
3. use `tr("key", value=...)` in the UI;
4. run `tests/test_i18n.py`.

Evidence field labels also go through `field_label()` and `FIELD_LABELS_FR`.

## Adding a YARA rule

- put it in `scanners/default_rules.py` under the right file;
- require a real PE header for binary rules and non-PE content for script rules;
- use at least two specific indicators, never a single generic API or word;
- mark ambiguous heuristics `low` so they are recorded but not reported;
- bump `BUILTIN_RULES_VERSION` in `scanners/yara_manager.py` so existing installs
  refresh;
- add a true-positive test and a benign-file check in `tests/test_yara_rules.py`.

## Commit style

```
type(scope): short summary

- what changed and why
- user-visible impact
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`.

Examples:

```
fix(scanner): keep cancelled status after a stopped scan
feat(ui): add VirusTotal tab with HTML export
docs: rewrite README for the Studio release
```

## Pull requests

1. branch from `main` (`feature/…`, `fix/…`, `docs/…`);
2. keep the change focused and add tests;
3. run the full suite and the packaging build if you touched dependencies;
4. update `CHANGELOG.md` for user-visible changes;
5. describe the problem, the approach and how you tested it.

CI runs on Windows for Python 3.10 and 3.12 and must be green before merge.

## Security issues

Do not open a public issue. Follow [SECURITY.md](SECURITY.md).

## Licence

By contributing you agree that your changes are released under the project's MIT
License.
