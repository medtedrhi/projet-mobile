from sqlalchemy import Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.models.base import Base, TimestampMixin, UUIDMixin


class AuditCase(UUIDMixin, TimestampMixin, Base):
    __tablename__ = "audit_cases"

    app_name: Mapped[str]
    package_name: Mapped[str | None]
    version_name: Mapped[str | None]
    version_code: Mapped[str | None]
    auditor: Mapped[str]
    audit_date: Mapped[str]
    scope: Mapped[str]
    notes: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(default="draft")

    artifacts = relationship("UploadedArtifact", back_populates="audit_case", cascade="all, delete-orphan")
    evidence_items = relationship("EvidenceItem", back_populates="audit_case", cascade="all, delete-orphan")
    mapping_references = relationship("MappingReference", back_populates="audit_case", cascade="all, delete-orphan")
    missing_issues = relationship("MissingEvidenceIssue", back_populates="audit_case", cascade="all, delete-orphan")
    reports = relationship("GeneratedReport", back_populates="audit_case", cascade="all, delete-orphan")
    exports = relationship("ExportBundle", back_populates="audit_case", cascade="all, delete-orphan")
