from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models.report import ExportBundle
from app.schemas.report import ExportBundleRead
from app.services.case_service import CaseService

router = APIRouter(tags=["exports"])
case_service = CaseService()


@router.post("/cases/{case_id}/export", response_model=ExportBundleRead)
def export_case(case_id: str, db: Session = Depends(get_db)):
    try:
        return case_service.export_case_bundle(db, case_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/exports/{export_id}/download")
def download_export(export_id: str, db: Session = Depends(get_db)):
    export = db.query(ExportBundle).filter(ExportBundle.id == export_id).first()
    if export is None:
        raise HTTPException(status_code=404, detail="Export not found")
    return FileResponse(path=Path(export.output_path), filename=Path(export.output_path).name, media_type="application/zip")
