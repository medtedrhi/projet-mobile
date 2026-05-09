from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.upload import AndroidDeviceRead, UploadedArtifactRead
from app.services.apk_parser import ApkParserService
from app.services.case_service import CaseService

router = APIRouter(tags=["uploads"])
case_service = CaseService()
apk_parser = ApkParserService()


@router.post("/cases/{case_id}/upload", response_model=UploadedArtifactRead)
def upload_artifact(
    case_id: str,
    artifact_type: str = Form(...),
    source: str = Form("user-upload"),
    description: str | None = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    try:
        return case_service.upload_artifact(db, case_id, file, artifact_type, source, description)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.get("/android-devices", response_model=list[AndroidDeviceRead])
def list_android_devices():
    try:
        return case_service.list_connected_android_devices()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/apk/metadata")
def parse_apk_metadata(file: UploadFile = File(...)):
    content = file.file.read()
    if not content:
        raise HTTPException(status_code=400, detail="APK file is empty.")
    suffix = ".apk"
    import tempfile

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
            temp_file.write(content)
            temp_path = temp_file.name
        metadata = apk_parser.parse(Path(temp_path))
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"APK metadata could not be parsed: {exc}") from exc
    finally:
        if temp_path:
            try:
                Path(temp_path).unlink(missing_ok=True)
            except OSError:
                pass

    package_name = metadata.get("package_name")
    return {
        "app_name": package_name or Path(file.filename or "Android APK").stem,
        "package_name": package_name,
        "version_name": metadata.get("version_name"),
        "version_code": metadata.get("version_code"),
        "min_sdk": metadata.get("min_sdk"),
        "target_sdk": metadata.get("target_sdk"),
        "permissions_count": len(metadata.get("permissions") or []),
    }


@router.post("/cases/{case_id}/capture-screenshot", response_model=UploadedArtifactRead)
def capture_screenshot(
    case_id: str,
    device_serial: str | None = Query(None),
    source: str = Query("adb-capture"),
    description: str | None = Query(None),
    db: Session = Depends(get_db),
):
    try:
        return case_service.capture_screenshot(
            db,
            case_id,
            device_serial=device_serial,
            source=source,
            description=description,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cases/{case_id}/capture-runtime-logs", response_model=UploadedArtifactRead)
def capture_runtime_logs(
    case_id: str,
    device_serial: str | None = Query(None),
    source: str = Query("adb-logcat"),
    description: str | None = Query(None),
    line_count: int | None = Query(None, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    try:
        return case_service.capture_runtime_logs(
            db,
            case_id,
            device_serial=device_serial,
            source=source,
            description=description,
            line_count=line_count,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cases/{case_id}/run-dynamic-analysis", response_model=UploadedArtifactRead)
def run_dynamic_analysis(
    case_id: str,
    device_serial: str | None = Query(None),
    source: str = Query("adb-dynamic-analysis"),
    monkey_event_count: int | None = Query(None, ge=1, le=5000),
    log_line_count: int | None = Query(None, ge=1, le=5000),
    db: Session = Depends(get_db),
):
    try:
        return case_service.run_dynamic_apk_analysis(
            db,
            case_id,
            device_serial=device_serial,
            source=source,
            monkey_event_count=monkey_event_count,
            log_line_count=log_line_count,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cases/{case_id}/run-full-dynamic-analysis")
def run_full_dynamic_analysis(
    case_id: str,
    device_serial: str | None = Query(None),
    monkey_event_count: int | None = Query(None, ge=1, le=5000),
    log_line_count: int | None = Query(None, ge=1, le=5000),
    wait_after_launch_seconds: int | None = Query(None, ge=0, le=120),
    file: UploadFile | None = File(None),
    db: Session = Depends(get_db),
):
    try:
        return case_service.run_full_dynamic_analysis(
            db,
            case_id,
            file=file,
            device_serial=device_serial,
            monkey_event_count=monkey_event_count,
            log_line_count=log_line_count,
            wait_after_launch_seconds=wait_after_launch_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/cases/{case_id}/upload-and-run-dynamic-analysis")
def upload_and_run_dynamic_analysis(
    case_id: str,
    device_serial: str | None = Query(None),
    monkey_event_count: int | None = Query(None, ge=1, le=5000),
    log_line_count: int | None = Query(None, ge=1, le=5000),
    wait_after_launch_seconds: int | None = Query(None, ge=0, le=120),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    try:
        return case_service.run_full_dynamic_analysis(
            db,
            case_id,
            file=file,
            device_serial=device_serial,
            monkey_event_count=monkey_event_count,
            log_line_count=log_line_count,
            wait_after_launch_seconds=wait_after_launch_seconds,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
