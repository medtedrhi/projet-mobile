from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models.audit_case import AuditCase
from app.db.models.evidence import EvidenceItem
from app.core.config import get_settings
from app.core.security import ensure_within_root
from app.schemas.evidence import EvidenceItemRead

router = APIRouter(tags=["evidence"])


@router.get("/cases/{case_id}/evidence", response_model=list[EvidenceItemRead])
def get_evidence(case_id: str, db: Session = Depends(get_db)):
    audit_case = db.query(AuditCase).filter(AuditCase.id == case_id).first()
    if audit_case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return audit_case.evidence_items


@router.get("/cases/{case_id}/evidence/{evidence_id}/content")
def get_evidence_content(case_id: str, evidence_id: str, db: Session = Depends(get_db)):
    evidence = (
        db.query(EvidenceItem)
        .filter(EvidenceItem.id == evidence_id, EvidenceItem.case_id == case_id)
        .first()
    )
    if evidence is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    path = Path(evidence.normalized_path)
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file not found on disk")

    settings = get_settings()
    try:
        ensure_within_root(settings.uploads_dir, path)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Evidence path is outside the uploads directory") from exc

    return FileResponse(
        path=path,
        filename=evidence.original_filename or path.name,
        media_type=evidence.mime_type or "application/octet-stream",
    )
