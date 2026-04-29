from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, UUIDMixin


class MissingEvidenceIssue(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "missing_evidence_issues"

    case_id: Mapped[str] = mapped_column(ForeignKey("audit_cases.id", ondelete="CASCADE"))
    rule_id: Mapped[str]
    category: Mapped[str]
    severity: Mapped[str]
    title: Mapped[str]
    rationale: Mapped[str] = mapped_column(Text)
    recommendation: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(default="open")

    audit_case = relationship("AuditCase", back_populates="missing_issues")
