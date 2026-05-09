# Evidence Collector & Compliance Pack

Evidence Collector & Compliance Pack is a defensive Android audit web app for collecting APK evidence, running basic MobSF/Mobisef-style dynamic analysis, generating summaries, mapping evidence to OWASP MASVS/MASWE/MASTG, and exporting a structured evidence ZIP.

## Defensive Scope

This project is defensive only. It installs a user-provided APK on an authorized Android emulator or device through `adb`, launches it, performs basic UI interaction, and collects screenshots, logs, and runtime state. It does not implement exploitation, bypasses, hooks, malware workflows, credential theft, or offensive automation.

## Required Tools

- Python 3.11+
- Node.js and npm
- Android Studio
- Android SDK Platform-Tools
- `adb` available in `PATH`, or `ADB_EXECUTABLE` set in `.env`
- Android emulator or authorized Android device
- Optional OpenRouter API key for AI summaries

## Stack

Backend:
- Python 3.11
- FastAPI
- SQLAlchemy
- Pydantic
- Alembic
- SQLite by default
- Jinja2 HTML reports

Frontend:
- React + Vite
- TypeScript
- Tailwind CSS
- Recharts

## Windows PowerShell Setup

Create the environment file:

```powershell
Copy-Item .env.example .env
```

Start the backend:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Start the frontend in a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173`; backend runs at `http://localhost:8000`.

## Android Setup

Start an emulator from Android Studio, or connect and authorize a physical device. Verify `adb`:

```powershell
adb devices -l
```

You should see exactly one device in `device` state for auto-selection. If several devices are connected, select the serial in the UI before running dynamic analysis.

## Dynamic Analysis

In the UI:

1. Create or select an audit case.
2. Select an emulator/device, or leave auto-detect enabled when exactly one device is connected.
3. Choose an APK file, or reuse the latest APK already uploaded for the case.
4. Click `Run Full Dynamic Analysis`.
5. Download the generated evidence pack.

The one-click workflow:
- Uploads or reuses the APK.
- Parses package metadata.
- Installs with `adb install -r -t`.
- Clears logcat.
- Launches the app.
- Waits after launch.
- Captures screenshots after launch, after monkey events, and at final state.
- Runs monkey UI events.
- Captures sanitized logcat, dumpsys package, activity top, meminfo, process list, and `/proc/net/tcp` when available.
- Detects target process presence, crash markers, and ANR markers.
- Generates `mobisef_dynamic.json`, `runtime_state.json`, `crash_summary.json`, `ai_summary.md`, `report.html`, and a ZIP evidence pack.

During Monkey execution, the emulator may navigate away from the target app. The tool records the foreground activity before and after Monkey and then re-focuses the target package before the final screenshot, so the final evidence represents the analyzed application when possible.

Relevant API endpoints:
- `POST /api/cases/{case_id}/run-full-dynamic-analysis`
- `POST /api/cases/{case_id}/upload-and-run-dynamic-analysis`
- `GET /api/exports/{export_id}/download`

## Environment Variables

```powershell
ADB_EXECUTABLE="adb"
DYNAMIC_ANALYSIS_ENABLED=true
DYNAMIC_ANALYSIS_MONKEY_EVENT_COUNT=120
DYNAMIC_ANALYSIS_LOG_LINE_COUNT=1000
DYNAMIC_ANALYSIS_WAIT_AFTER_LAUNCH_SECONDS=5
DYNAMIC_ANALYSIS_SCREENSHOT_COUNT=3
DYNAMIC_ANALYSIS_AUTO_EXPORT=true
OPENROUTER_API_KEY=""
```

If `OPENROUTER_API_KEY` is not set, the backend writes a deterministic fallback `10_reports/ai_summary.md`.

## Evidence ZIP Structure

Generated ZIPs contain:

```text
audit-evidence/
  00_case_metadata/
    case_metadata.json
    tool_versions.json
    dynamic_run_summary.json
  01_apk/
    uploaded.apk
  02_manifest/
    manifest_summary.json
    AndroidManifest.xml
  03_permissions/
    permissions.json
  04_components/
    components.json
  05_sbom/
    sbom.json
  06_logs/
    install_output.log
    launch_output.log
    monkey_output.log
    runtime_logcat_sanitized.log
    crash_log.txt
  07_screenshots/
    001_after_launch.png
    002_after_monkey.png
    003_final_state.png
  08_findings_import/
    mobisef_dynamic.json
    runtime_state.json
    crash_summary.json
  09_mas_mapping/
    masvs_mapping.json
    maswe_mapping.json
    mastg_mapping.json
  10_reports/
    report.html
    ai_summary.md
  11_hashes/
    hashes.json
  12_completeness/
    missing_evidence.json
```

Some optional files appear only when relevant evidence exists, such as `crash_log.txt`, `maswe_mapping.json`, or `mastg_mapping.json`.

## Common Errors

- `adb not found`: install Android SDK Platform-Tools or set `ADB_EXECUTABLE` in `.env`.
- `No Android emulator/device connected`: start an emulator or connect a device, then run `adb devices -l`.
- `multiple devices connected`: select a device serial in the UI.
- `device offline` or `unauthorized`: unlock the device, accept USB debugging, or restart the emulator.
- `APK file missing`: upload an APK or choose one in the full dynamic analysis panel.
- `package name not found`: the APK parser could not read package metadata; verify the APK is valid.
- `APK install failed`: check emulator Android version, APK signing, ABI compatibility, and install output.
- `app launch failed`: the APK may not expose a launcher activity or may crash immediately.

## Tests

Backend:

```powershell
cd backend
.\.venv\Scripts\python.exe -m pytest
```

Frontend:

```powershell
cd frontend
npm run test
```

## Existing Features

- Audit case creation
- APK upload and hashing
- Manifest, permission, component, and SBOM extraction
- Evidence persistence and indexing
- Screenshot and runtime log capture
- MASVS/MASWE/MASTG mapping
- Missing evidence engine
- OpenRouter-backed summaries with fallback behavior
- HTML report generation
- ZIP evidence pack export
