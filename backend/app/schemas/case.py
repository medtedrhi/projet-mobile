from pydantic import BaseModel, Field

from app.schemas.common import TimestampedSchema


class AuditCaseCreate(BaseModel):
    app_name: str = Field(min_length=2, max_length=200)
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    auditor: str = Field(min_length=2, max_length=120)
    audit_date: str
    scope: str = Field(min_length=3, max_length=500)
    notes: str | None = None


class AuditCaseRead(TimestampedSchema):
    app_name: str
    package_name: str | None
    version_name: str | None
    version_code: str | None
    auditor: str
    audit_date: str
    scope: str
    notes: str | None
    status: str


class AuditCaseSummary(BaseModel):
    total_artifacts: int
    total_evidence_items: int
    total_mappings: int
    total_missing_issues: int
    completeness_score: float


class MissingNarrativeRead(BaseModel):
    title: str
    why_it_matters: str | None = None
    next_step: str
    narrative: str


class AuditCaseInsightsRead(BaseModel):
    collection_summary: str
    missing_narratives: list[str]
    missing_explanations: list[MissingNarrativeRead]
    provider_mode: str
    provider_label: str
