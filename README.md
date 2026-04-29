

# Evidence Collector & Compliance Pack

Evidence Collector & Compliance Pack is a defensive full-stack audit assistant for Android APK assessments. It helps auditors collect, normalize, hash, index, sanitize, map, and export audit evidence aligned to OWASP MASVS, MASWE, and MASTG.

## Defensive Scope

This project is intentionally defensive only.

- It does not implement exploitation workflows.
- It does not automate bypasses, hooks, malware, or offensive actions.
- It focuses on evidence collection, traceability, compliance preparation, and audit reporting.







## Stack
11:!1§23
§/§/5§/2!1/§
### Backend22
- Python 3.11

- FastAPI
- SQLAlchemy
- Pydantic
- Alembic
- SQLite by default
- Optional MySQL through environment variables
- Jinja2 for HTML reports

### Frontend
- React + Vite
- TypeScript
- Tailwind CSS
- shadcn/ui-style component setup
- Recharts

## Folder Structure

```text
backend/
  app/
    api/
      routes/
    core/
    db/
      models/
    mappings/
    schemas/
    services/
    templates/
    tests/
  alembic/
frontend/
  src/
    api/
    components/
    features/
    hooks/
    lib/
    pages/
    tests/
    types/
samples/
scripts/
```

## Core Features Implemented

- Audit case creation and listing
- Artifact uploads for APKs, screenshots, logs, MobSF JSON, and JADX exports
- APK integrity hashing with SHA-256, SHA-1, and MD5
- APK parsing service with androguard-first and archive fallback behavior
- Manifest summary extraction
- Permission inventory extraction
- Local archive-derived SBOM generation for APK contents and declared libraries
- Evidence item persistence with metadata, sensitivity, and traceability fields
- Evidence indexing to JSON and CSV
- Data-driven MASVS, MASWE, and MASTG mapping files
- Missing evidence rules engine
- Log sanitization for emails, tokens, IPs, and device identifiers
- HTML report generation
- ZIP evidence pack export
- React dashboard with visualizations and export controls
- Basic backend and frontend tests

## API Endpoints

- `POST /api/cases`
- `GET /api/cases`
- `GET /api/cases/{id}`
- `POST /api/cases/{id}/upload`
- `GET /api/android-devices`
- `POST /api/cases/{id}/capture-screenshot`
- `GET /api/cases/{id}/evidence`
- `GET /api/cases/{id}/mapping`
- `GET /api/cases/{id}/missing-evidence`
- `POST /api/cases/{id}/generate-report`
- `POST /api/cases/{id}/export`
- `GET /api/reports/{id}`
- `GET /api/exports/{id}/download`

## Local Setup

### 1. Environment

Copy the example environment file:

```powershell
Copy-Item .env.example .env
```

### 2. Backend

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend

Open a second terminal:

```powershell
cd frontend
npm install
npm run dev
```

Frontend runs at `http://localhost:5173` and backend runs at `http://localhost:8000`.

### Automatic UI Screenshot Capture

Automatic screenshot capture uses `adb` to grab the current screen from a connected Android device or emulator and save it as screenshot evidence.

- Install Android platform-tools so `adb` is available on your `PATH`, or set `ADB_EXECUTABLE` in `.env`.
- Connect a device or start an emulator, then confirm it appears in `adb devices`.
- In the UI, select an audit case and use the `Capture Screenshot` action in the evidence panel.

Relevant environment variables:

```powershell
ADB_EXECUTABLE="adb"
SCREENSHOT_CAPTURE_TIMEOUT_SECONDS=15
```

### AI Evidence Narratives

AI-generated evidence summaries and gap narratives can be enabled through OpenRouter. The default model target is configured for `Mistral 7B Instruct v0.3`, and you can override it in `.env` if your OpenRouter account uses a different model slug.

```powershell
OPENROUTER_API_KEY="your-openrouter-api-key"
OPENROUTER_BASE_URL="https://openrouter.ai/api/v1"
OPENROUTER_MODEL="mistralai/mistral-7b-instruct-v0.3"
OPENROUTER_SITE_URL="http://localhost:8000"
OPENROUTER_TIMEOUT_SECONDS=30
```

## Docker Compose

```powershell
docker compose up --build
```

## Tests

### Backend

```powershell
cd backend
pytest
```

### Frontend

```powershell
cd frontend
npm run test
```

## Seed Demo Data

Start the backend first, then run:

```powershell
python scripts/seed_demo.py
```

The seed payload is stored in [samples/demo_case.json](/d:/Desktop/projet mobile/samples/demo_case.json).

## Evidence Pack Export Flow

1. Create an audit case from the UI or `POST /api/cases`.
2. Upload an APK with `artifact_type=apk`.
3. Upload optional screenshots, logs, MobSF JSON, or JADX exports.
4. Review evidence, mapping coverage, and missing-evidence panels.
5. Generate the HTML report.
6. Build the ZIP evidence pack.
7. Download the bundle from `GET /api/exports/{id}/download`.

Generated evidence packs use this structure:

```text
audit-evidence/
  00_case_metadata/
  01_apk/
  02_manifest/
  03_permissions/
  04_components/
  05_sbom/
  06_logs/
  07_screenshots/
  08_findings_import/
  09_mas_mapping/
  10_reports/
  11_hashes/
  evidence_index.json
  evidence_index.csv
  evidence_traceability.json
```

## Sample Artifacts

- Demo case payload: [demo_case.json](/d:/Desktop/projet mobile/samples/demo_case.json)
- Example HTML report stub: [example_report.html](/d:/Desktop/projet mobile/samples/example_report.html)
- Example report metadata: [example_report.json](/d:/Desktop/projet mobile/samples/example_report.json)

## Notes

- SBOM generation is performed locally from APK metadata and archive contents without requiring an external scanner.
- PDF export is not implemented yet; HTML is the primary report output.
- MySQL support is configuration-ready through `MYSQL_DATABASE_URL`.
- Authentication is not enforced yet, but the backend structure is ready for auth middleware and dependency injection.

## Optional Future Work

- Real CycloneDX or Syft-backed SBOM generation pipeline
- PDF export from HTML
- Richer APK manifest and endpoint extraction heuristics
- Authn/authz layer for multi-user teams
- Evidence review annotations and approval states
- More complete MAS mapping datasets and versioning
- Background job queue for large uploads and report generation
