from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.schemas.case import AuditCaseCreate, AuditCaseInsightsRead, AuditCaseRead
from app.services.case_service import CaseService

router = APIRouter(tags=["cases"])
case_service = CaseService()


@router.post("/cases", response_model=AuditCaseRead)
def create_case(payload: AuditCaseCreate, db: Session = Depends(get_db)):
    return case_service.create_case(db, payload.model_dump())


@router.get("/cases", response_model=list[AuditCaseRead])
def list_cases(db: Session = Depends(get_db)):
    return case_service.list_cases(db)


@router.get("/cases/{case_id}")
def get_case(case_id: str, db: Session = Depends(get_db)):
    case_service.refresh_mappings_and_issues(db, case_id)
    audit_case = case_service.get_case(db, case_id)
    if audit_case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return {"case": audit_case, "summary": case_service.build_case_summary(audit_case)}


@router.get("/cases/{case_id}/insights", response_model=AuditCaseInsightsRead)
def get_case_insights(case_id: str, db: Session = Depends(get_db)):
    case_service.refresh_mappings_and_issues(db, case_id)
    audit_case = case_service.get_case(db, case_id)
    if audit_case is None:
        raise HTTPException(status_code=404, detail="Case not found")
    return case_service.build_case_insights(audit_case)
