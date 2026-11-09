# Building CyberGuardian

## Prerequisites

| Component | Version |
|---|---|
| Windows | 10 / 11 (x64) |
| Python | 3.9–3.12 (3.12 recommended) |
| pip | current |
| PyInstaller | 6.x |
| Administrator rights | recommended for scanning and packaging tests |

Python 3.14 is **not supported**: `yara-python` has no wheel for it and building from
source requires Visual Studio build tools.

## Set up the environment

```powershell
git clone https://github.com/Souhaieb-Marzouk/CyberGuardian.git
cd CyberGuardian
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller
```

## Run from source

```powershell
python main.py            # Studio interface
python main.py --help     # CLI options
```

`main_studio.py` is a convenience alias that always opens the Studio interface.

## Tests

```powershell
python -m unittest discover -s tests -t . -v
```

The suite is headless: Qt runs with the `offscreen` platform. It covers the
scanners, YARA precision, localisation, exports, VirusTotal parsing, cancellation,
the Studio UI button sweep and branding. Current status: 144 tests, 1 skipped.

## Build the portable executable

```powershell
python build.py --all
```

`build.py` performs a PyInstaller one-file build with:

- `main.py` as the entry point (Studio GUI, CLI still available),
- `assets/icon.png` as the icon,
- `--windowed` (no console window),
- `--uac-admin` (administrator manifest),
- the bundled Inter font and YARA rules.

Output goes to `dist/`:

| File | Description |
|---|---|
| `CyberGuardian.exe` | Portable single-file executable |
| `CyberGuardian_v<VERSION>.zip` | Portable package: exe, LICENSE, README, QUICKSTART, requirements |

`VERSION` is defined at the top of `build.py` and mirrored in `core/branding.py`;
keep both in sync.

### Verify the build

```powershell
Get-FileHash dist\CyberGuardian.exe -Algorithm SHA256
Get-FileHash dist\CyberGuardian_v1.5.0.zip -Algorithm SHA256
```

Publish both hashes in the release notes. The executable is unsigned; code signing
can be added without changing the build.

### Clean rebuild

```powershell
Remove-Item -Recurse -Force build, dist
python build.py --all
```

## Continuous integration

`.github/workflows/ci.yml` runs on Windows for Python 3.10 and 3.12:

1. install dependencies,
2. `python -m compileall -q .`,
3. the unit test suite,
4. a packaging build that uploads `dist/CyberGuardian.exe` and the zip as artifacts.

The build job runs after the tests pass. CI sets `PYTHONIOENCODING=utf-8` so the
check marks in build output do not break the Windows console.

## Versioning

CyberGuardian follows semantic versioning:

- MAJOR — incompatible changes to configuration, storage or scanner contracts,
- MINOR — new scanners, interface pages, features,
- PATCH — fixes and rule updates.

Release checklist:

1. update `VERSION` in `build.py` and `APP_VERSION` in `core/branding.py`;
2. update `CHANGELOG.md` and `docs/releases/`;
3. run the test suite;
4. `python build.py --all`;
5. record sizes and SHA-256;
6. tag `v<version>` and publish the release with both artifacts.

## Third-party components

| Component | Licence |
|---|---|
| PyQt5 / Qt | GPL v3 |
| yara-python / YARA | Apache 2.0 + BSD 3-Clause |
| psutil | BSD 3-Clause |
| Inter font (`assets/fonts/Inter.ttf`) | SIL Open Font License 1.1 (`assets/fonts/OFL.txt`) |
| pywin32 | PSF-based |

Keep `assets/fonts/OFL.txt` with the font; it ships inside the zip.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `yara-python` fails to build | Python 3.14 or missing MSVC build tools; use Python 3.12 |
| `ModuleNotFoundError: yara` in the exe | rebuild after installing `yara-python` in the active environment |
| Missing icon | run `python build.py --all` from the repository root |
| Antivirus flags the unsigned exe | expected for a security tool without a code-signing certificate; verify the SHA-256 |
| Build output shows `?` instead of check marks | set `PYTHONIOENCODING=utf-8` (CI already does) |
