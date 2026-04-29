from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.api.deps import get_db
from app.db.models.report import GeneratedReport
from app.schemas.report import GeneratedReportRead
from app.services.case_service import CaseService

router = APIRouter(tags=["reports"])
case_service = CaseService()


@router.post("/cases/{case_id}/generate-report", response_model=GeneratedReportRead)
def generate_report(case_id: str, db: Session = Depends(get_db)):
    try:
        return case_service.generate_report(db, case_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.get("/reports/{report_id}", response_class=HTMLResponse)
def get_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(GeneratedReport).filter(GeneratedReport.id == report_id).first()
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    with open(report.output_path, "r", encoding="utf-8") as handle:
        return HTMLResponse(content=handle.read())
