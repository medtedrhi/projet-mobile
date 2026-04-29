from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.upload import AndroidDeviceRead, UploadedArtifactRead
from app.services.case_service import CaseService

router = APIRouter(tags=["uploads"])
case_service = CaseService()


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
