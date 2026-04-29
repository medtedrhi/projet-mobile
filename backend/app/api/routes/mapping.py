from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models.audit_case import AuditCase
from app.schemas.mapping import MappingReferenceRead

router = APIRouter(tags=["mapping"])


@router.get("/cases/{case_id}/mapping", response_model=list[MappingReferenceRead])
def get_mapping(case_id: str, db: Session = Depends(get_db)):
    audit_case = db.query(AuditCase).filter(AuditCase.id == case_id).first()
    if audit_case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return audit_case.mapping_references


@router.get("/cases/{case_id}/missing-evidence")
def get_missing_evidence(case_id: str, db: Session = Depends(get_db)):
    audit_case = db.query(AuditCase).filter(AuditCase.id == case_id).first()
    if audit_case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    unique = {}
    for issue in audit_case.missing_issues:
        unique.setdefault(issue.rule_id, issue)
    return list(unique.values())
